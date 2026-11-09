# -*- coding: utf-8 -*-
"""Restauration RÉELLE bout en bout sur le faux kubectl à état, avec injection de panne à
chaque étape et reprise idempotente (B1, B2, B4, préflight B3)."""
import json
import os

import pytest

from conftest import read_state, write_state

VG_OLD1 = "11111111-1111-4111-8111-111111111111"
VG_OLD2 = "22222222-2222-4222-8222-222222222222"
VG_NEW1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
VG_NEW2 = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def pv(name, vg, claim):
    return {"apiVersion": "v1", "kind": "PersistentVolume", "metadata": {"name": name,
            "annotations": {"pv.kubernetes.io/provisioned-by": "csi.nutanix.com"}},
            "spec": {"accessModes": ["ReadWriteOnce"], "capacity": {"storage": "8Gi"},
                     "claimRef": {"kind": "PersistentVolumeClaim", "name": claim, "namespace": "app"},
                     "csi": {"driver": "csi.nutanix.com", "volumeHandle": "NutanixVolumes-" + vg,
                             "volumeAttributes": {"hypervisorAttachedDiskUUIDs": "disk-" + vg}},
                     "persistentVolumeReclaimPolicy": "Delete", "storageClassName": "nutanix-volume"},
            "status": {"phase": "Bound"}}


def pvc(name, pvname):
    return {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": name, "namespace": "app"},
            "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "8Gi"}},
                     "storageClassName": "nutanix-volume", "volumeName": pvname},
            "status": {"phase": "Bound"}}


def seed(H, replicas=2):
    st = read_state(H)
    st["pvs"] = {"pv-1": pv("pv-1", VG_OLD1, "data-1"), "pv-2": pv("pv-2", VG_OLD2, "data-2")}
    st["pvcs"] = {"app": {"data-1": pvc("data-1", "pv-1"), "data-2": pvc("data-2", "pv-2")}}
    st["deployments"] = {"app": {"web": {"apiVersion": "apps/v1", "kind": "Deployment",
                                         "metadata": {"name": "web", "namespace": "app"},
                                         "spec": {"replicas": replicas, "template": {"spec": {"volumes": [
                                             {"persistentVolumeClaim": {"claimName": "data-1"}},
                                             {"persistentVolumeClaim": {"claimName": "data-2"}}]}}}}}}
    st["pods"] = {"app": [{"metadata": {"name": "web-%d" % i, "namespace": "app", "labels": {"app": "web"},
                                        "ownerReferences": [{"kind": "ReplicaSet", "name": "web", "controller": True}]},
                           "spec": {"volumes": [{"persistentVolumeClaim": {"claimName": "data-1"}},
                                                {"persistentVolumeClaim": {"claimName": "data-2"}}]},
                           "status": {"phase": "Running", "containerStatuses": [{"ready": True}]}}
                          for i in range(replicas)]}
    write_state(H, st)


PAYLOAD = {"namespace": "app", "dry": False, "mode": "clone",
           "items": [{"pvc": "data-1", "new_ref": VG_NEW1, "new_name": "pv-new-1"},
                     {"pvc": "data-2", "new_ref": VG_NEW2, "new_name": "pv-new-2"}]}


def labels(res):
    return [l.get("label", "") for l in res["log"]]


def test_full_restore_success(H):
    seed(H)
    res = H._execute_restore_locked(dict(PAYLOAD))
    assert res["ok"] and not res["aborted"], labels(res)
    st = read_state(H)
    assert set(st["pvs"]) == {"pv-new-1", "pv-new-2"}, "anciens PV supprimés, nouveaux créés"
    assert st["pvcs"]["app"]["data-1"]["spec"]["volumeName"] == "pv-new-1"
    assert st["pvs"]["pv-new-1"]["spec"]["csi"]["volumeHandle"] == "NutanixVolumes-" + VG_NEW1
    # politique d'origine (Delete) rétablie à la fin ; Retain forcé pendant la séquence
    assert st["pvs"]["pv-new-1"]["spec"]["persistentVolumeReclaimPolicy"] == "Delete"
    assert st["deployments"]["app"]["web"]["spec"]["replicas"] == 2, "application redémarrée"
    assert H._load_txn("app") is None, "transaction effacée"
    assert any(l.startswith("Preflight") for l in labels(res))
    assert res["preflight"] and all(c["ok"] is not False for c in res["preflight"])


def test_retain_applied_before_any_deletion(H, tmp_path):
    seed(H)
    H._execute_restore_locked(dict(PAYLOAD))
    cmds = [json.loads(l) for l in open(tmp_path / "kubectl.log", encoding="utf-8")]
    first_delete = next(i for i, c in enumerate(cmds) if c and c[0] == "delete")
    retains = [i for i, c in enumerate(cmds) if c and c[0] == "patch" and "Retain" in " ".join(c)]
    assert retains and min(retains) < first_delete


def test_failure_then_resume_skips_done_volume(H, monkeypatch):
    seed(H)
    monkeypatch.setenv("FAKE_FAIL_AT", "apply:pv:pv-new-2")
    res = H._execute_restore_locked(dict(PAYLOAD))
    assert res["aborted"] and not res["ok"]
    st = read_state(H)
    assert st["deployments"]["app"]["web"]["spec"]["replicas"] == 0, "application laissée arrêtée"
    assert "pv-new-1" in st["pvs"] and "pv-new-2" not in st["pvs"]
    txn = H._load_txn("app")
    assert txn and txn["status"] == "in_progress"
    assert {v["pvc"]: v["status"] for v in txn["volumes"]} == {"data-1": "done", "data-2": "pending"}
    assert txn["workloads"] == [{"kind": "deployment", "name": "web", "replicas": 2}]
    # le volume 1 restauré est protégé (Retain) : une reprise ne doit pas le détruire
    assert st["pvs"]["pv-new-1"]["spec"]["persistentVolumeReclaimPolicy"] == "Retain"
    # --- reprise ---
    monkeypatch.delenv("FAKE_FAIL_AT")
    res2 = H._execute_restore_locked(dict(PAYLOAD))
    assert res2["ok"] and not res2["aborted"], labels(res2)
    assert any("already restored" in l for l in labels(res2))
    st = read_state(H)
    assert set(st["pvs"]) == {"pv-new-1", "pv-new-2"}
    assert st["deployments"]["app"]["web"]["spec"]["replicas"] == 2, "réplicas repris de la transaction"
    assert H._load_txn("app") is None


def test_resume_with_other_volumes_is_refused(H, monkeypatch):
    seed(H)
    monkeypatch.setenv("FAKE_FAIL_AT", "apply:pv:pv-new-2")
    H._execute_restore_locked(dict(PAYLOAD))
    monkeypatch.delenv("FAKE_FAIL_AT")
    other = dict(PAYLOAD, items=[{"pvc": "data-1", "new_ref": VG_NEW2, "new_name": "pv-other"}])
    res = H._execute_restore_locked(other)
    assert not res["ok"] and "interrupted" in (res.get("error") or "")


def test_restart_failure_keeps_transaction(H, monkeypatch):
    seed(H)
    monkeypatch.setenv("FAKE_FAIL_AT", "scale:deployments")
    # le scale-down échoue aussi -> abandon avant toute suppression
    res = H._execute_restore_locked(dict(PAYLOAD))
    assert res["aborted"]
    st = read_state(H)
    assert set(st["pvs"]) == {"pv-1", "pv-2"}, "rien n'a été supprimé"


def test_preflight_blocks_on_denied_rbac_before_stop(H, monkeypatch):
    seed(H)
    monkeypatch.setenv("FAKE_FAIL_AT", "auth:persistentvolumes")
    res = H._execute_restore_locked(dict(PAYLOAD))
    assert res["aborted"] and "preflight" in (res.get("error") or "")
    st = read_state(H)
    assert st["deployments"]["app"]["web"]["spec"]["replicas"] == 2, "application non arrêtée"
    assert set(st["pvs"]) == {"pv-1", "pv-2"}


def test_preflight_blocks_operator_owned_workload(H):
    seed(H)
    st = read_state(H)
    st["deployments"]["app"]["web"]["metadata"]["ownerReferences"] = [{"kind": "Cluster", "name": "pg", "controller": True}]
    write_state(H, st)
    res = H._execute_restore_locked(dict(PAYLOAD))
    assert res["aborted"] and "operator" in (res.get("error") or "")


def test_pvc_finalizer_not_forced_when_pod_active(H):
    """Un pod non géré (owner inconnu) monte le PVC : le préflight bloque avant tout arrêt."""
    seed(H)
    st = read_state(H)
    st["pods"]["app"].append({"metadata": {"name": "debug", "namespace": "app",
                                           "ownerReferences": [{"kind": "Job", "name": "dbg"}]},
                              "spec": {"volumes": [{"persistentVolumeClaim": {"claimName": "data-1"}}]},
                              "status": {"phase": "Running"}})
    write_state(H, st)
    res = H._execute_restore_locked(dict(PAYLOAD))
    assert res["aborted"] and "Unmanaged" in (res.get("error") or "")


def test_terminal_pods_are_ignored(H):
    seed(H)
    st = read_state(H)
    st["pods"]["app"].append({"metadata": {"name": "migrate-xyz", "namespace": "app",
                                           "ownerReferences": [{"kind": "Job", "name": "migrate"}]},
                              "spec": {"volumes": [{"persistentVolumeClaim": {"claimName": "data-1"}}]},
                              "status": {"phase": "Succeeded"}})
    write_state(H, st)
    res = H._execute_restore_locked(dict(PAYLOAD))
    assert res["ok"], labels(res)


def test_dry_run_touches_nothing(H):
    seed(H)
    res = H._execute_restore_locked(dict(PAYLOAD, dry=True))
    assert res["ok"] and res["dry"]
    st = read_state(H)
    assert set(st["pvs"]) == {"pv-1", "pv-2"} and st["deployments"]["app"]["web"]["spec"]["replicas"] == 2
    assert H._load_txn("app") is None


def test_backup_refused_during_operation_and_kinds(H):
    seed(H)
    r = H.action_backup("app", kind="manual")
    assert r["ok"] and r["kind"] == "manual" and not r["partial"]
    idx = json.load(open(os.path.join(r["dir"], "index.json"), encoding="utf-8"))
    assert idx["schema"] == 2 and idx["kind"] == "manual" and idx["complete"] and idx["files"]
    H.ACTION_LOCK.acquire()
    try:
        r2 = H.action_backup("app")
        assert not r2["ok"] and "running" in r2["error"]
        r3 = H.action_backup("app", internal=True)
        assert r3["ok"]
    finally:
        H.ACTION_LOCK.release()


def test_backup_partial_when_pv_unreadable(H, monkeypatch):
    seed(H)
    monkeypatch.setenv("FAKE_FAIL_AT", "get:pv:pv-2")
    r = H.action_backup("app")
    # Sauvegarde PARTIELLE = échec explicite (ok False), dossier conservé, aucune purge.
    assert not r["ok"] and r["partial"] and "PARTIAL" in r["error"] and "data-2" in r["error"]
    idx = json.load(open(os.path.join(r["dir"], "index.json"), encoding="utf-8"))
    assert idx["partial"] and idx["pv_errors"] and not idx["complete"]


def test_restart_failed_resume_keeps_transaction(H, monkeypatch):
    """Scale-up refusé après des volumes restaurés -> transaction restart_failed. Une reprise
    dont le scale-up échoue ENCORE garde la transaction (sinon un passage suivant rejouerait
    toute la séquence destructive, sans réplicas mémorisés) ; la reprise suivante réussit."""
    seed(H, replicas=0)                     # app déjà à 0 : rien à arrêter, le redémarrage vient de la transaction
    bk = H.action_backup("app", kind="pre_restore", internal=True)
    assert bk["ok"]
    prep = H.action_prepare_restore(dict(PAYLOAD))
    prepared = [r for r in prep["results"] if r.get("ok")]
    H._save_txn("app", {"status": "in_progress", "started": "2026-10-10T10:00:00", "mode": "clone",
                        "backup_dir": bk["dir"], "signature": H._txn_signature("clone", prepared),
                        "workloads": [{"kind": "deployment", "name": "web", "replicas": 2}],
                        "volumes": [{"pvc": r["pvc"], "new_pv": r["new_pv_name"], "status": "pending",
                                     "manifest": r["manifest"], "pvc_manifest": r.get("pvc_manifest")} for r in prepared]})
    monkeypatch.setenv("FAKE_FAIL_AT", "scale:deployments:web")
    res = H._execute_restore_locked(dict(PAYLOAD))
    assert res["aborted"] and not res["ok"]
    assert set(read_state(H)["pvs"]) == {"pv-new-1", "pv-new-2"}, "volumes restaurés"
    txn = H._load_txn("app")
    assert txn and txn["status"] == "restart_failed"
    # Reprise « redémarrage seul » qui échoue encore : transaction CONSERVÉE, volumes intacts.
    res2 = H._execute_restore_locked(dict(PAYLOAD))
    assert res2["aborted"] and not res2["ok"]
    txn = H._load_txn("app")
    assert txn and txn["status"] == "restart_failed", "la transaction doit survivre à un nouvel failed du redémarrage"
    assert txn["workloads"] == [{"kind": "deployment", "name": "web", "replicas": 2}]
    assert set(read_state(H)["pvs"]) == {"pv-new-1", "pv-new-2"}
    # Le redémarrage finit par réussir -> transaction effacée, réplicas repris de la transaction.
    monkeypatch.delenv("FAKE_FAIL_AT")
    res3 = H._execute_restore_locked(dict(PAYLOAD))
    assert res3["ok"], labels(res3)
    assert read_state(H)["deployments"]["app"]["web"]["spec"]["replicas"] == 2
    assert H._load_txn("app") is None


def test_advisory_preflight_failure_does_not_flip_verdict(H, monkeypatch):
    """Régression : un contrôle préflight CONSULTATIF en échec — ici le droit
    « get volumeattachments » refusé (RBAC least-privilege courant) — écrit une ligne
    ok=False dans le journal mais ne bloque pas. La restauration RÉUSSIE ne doit pas
    pour autant être renvoyée ok=False sans message (ancien verdict = repli du journal)."""
    seed(H)
    monkeypatch.setenv("FAKE_FAIL_AT", "auth:volumeattachments")
    res = H._execute_restore_locked(dict(PAYLOAD))
    assert any(c["name"] == "Reading VolumeAttachments" and c["ok"] is False
               for c in res["preflight"]), "le contrôle consultatif doit bien être en échec"
    assert res["ok"] and not res["aborted"] and res["error"] is None, labels(res)
    st = read_state(H)
    assert set(st["pvs"]) == {"pv-new-1", "pv-new-2"}
    assert st["deployments"]["app"]["web"]["spec"]["replicas"] == 2, "application redémarrée"
    assert H._load_txn("app") is None, "transaction effacée"


PAYLOAD_INPLACE = {"namespace": "app", "dry": False, "mode": "inplace",
                   "items": [{"pvc": "data-1", "new_ref": VG_OLD1}]}


def test_same_vg_restore_blocked_at_preflight_when_detach_unverifiable(H, monkeypatch):
    """Point 2 : le PV re-pointe le MÊME Volume Group (sur place) et le droit « get
    volumeattachments » est refusé -> le préflight BLOQUE avant d'arrêter l'application :
    rien n'est supprimé, aucune transaction, réplicas intacts."""
    seed(H)
    monkeypatch.setenv("FAKE_FAIL_AT", "auth:volumeattachments")
    res = H._execute_restore_locked(dict(PAYLOAD_INPLACE))
    assert not res["ok"] and res["aborted"], labels(res)
    assert "Blocking preflight" in (res["error"] or "") and "Nothing was changed" in res["error"]
    assert any(c["name"] == "Reading VolumeAttachments" and c["ok"] is False and "SAME Volume Group" in c["detail"]
               for c in res["preflight"]), res["preflight"]
    st = read_state(H)
    assert set(st["pvs"]) == {"pv-1", "pv-2"}, "aucun PV supprimé"
    assert st["pvcs"]["app"]["data-1"]["spec"]["volumeName"] == "pv-1"
    assert st["deployments"]["app"]["web"]["spec"]["replicas"] == 2, "application jamais arrêtée"
    assert H._load_txn("app") is None, "aucune transaction écrite"


def test_same_vg_restore_proceeds_when_detach_readable(H):
    """Contrôle positif du point 2 : même restauration sur place, droit présent -> la
    séquence va au bout (le blocage est bien CONDITIONNEL au droit manquant)."""
    seed(H)
    res = H._execute_restore_locked(dict(PAYLOAD_INPLACE))
    assert res["ok"] and not res["aborted"], labels(res)
    assert any(c["name"] == "Reading VolumeAttachments" and c["ok"] is True for c in res["preflight"])
    st = read_state(H)
    assert st["pvs"]["pv-1"]["spec"]["csi"]["volumeHandle"] == "NutanixVolumes-" + VG_OLD1
    assert st["deployments"]["app"]["web"]["spec"]["replicas"] == 2, "application redémarrée"


def test_wait_attachments_strict_fails_when_unreadable(H, monkeypatch):
    """Seconde ligne de défense : lecture des VolumeAttachments impossible -> non strict
    = on continue (True, clone) ; strict = échec (False, même VG), avec une ligne ok=False."""
    monkeypatch.setattr(H, "_volume_attachments_for_pv", lambda pv: ([], "forbidden: volumeattachments"))
    log = []
    assert H._wait_volume_attachments_gone("pv-1", 1, log) is True
    assert all(e["ok"] for e in log)
    log = []
    assert H._wait_volume_attachments_gone("pv-1", 1, log, strict=True) is False
    assert any((not e["ok"]) and "MUST be" in (e.get("stderr") or "") for e in log), log


def test_inplace_orchestrator_refuses_before_stopping_when_detach_unverifiable(H, monkeypatch):
    """Point 2, orchestrateur sur place (HYCU réécrit le MÊME VG) : droit « get
    volumeattachments » refusé -> refus au préflight, AVANT l'arrêt de l'application."""
    seed(H)
    H.SESSION_CREDS["hycu"] = {"mode": "basic"}
    monkeypatch.setattr(H, "_reject_stale_vgs", lambda *a, **k: None)
    monkeypatch.setattr(H, "_rest", lambda *a, **k: {"ok": True, "json": {}})
    monkeypatch.setenv("FAKE_FAIL_AT", "auth:volumeattachments")
    res = H.action_orchestrate_inplace({"namespace": "app", "dry": False,
                                        "items": [{"pvc": "data-1", "source_vg_uuid": VG_OLD1,
                                                   "restore_point_id": "rp-1"}]})
    assert not res["ok"], res
    assert "get volumeattachments" in res["error"] and "not stopped" in res["error"], res["error"]
    assert read_state(H)["deployments"]["app"]["web"]["spec"]["replicas"] == 2, "application jamais arrêtée"
