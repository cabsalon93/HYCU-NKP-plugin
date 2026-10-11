# -*- coding: utf-8 -*-
"""Volumes NAS (NFS) : détection, correspondance avec les partages HYCU, protection,
sauvegarde, parcours de restauration (refus des parcours Volume Group, récupération)."""
import json
import os

from conftest import read_state, write_state

NAS_PV = {"apiVersion": "v1", "kind": "PersistentVolume", "metadata": {"name": "nas-pv"},
          "spec": {"accessModes": ["ReadWriteMany"], "capacity": {"storage": "5Gi"},
                   "persistentVolumeReclaimPolicy": "Retain", "storageClassName": "",
                   "claimRef": {"kind": "PersistentVolumeClaim", "name": "data", "namespace": "app"},
                   "nfs": {"server": "nutanix-afs.amsdemo.ct", "path": "/pvc-k8s"}},
          "status": {"phase": "Bound"}}
NAS_PVC = {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "data", "namespace": "app"},
           "spec": {"accessModes": ["ReadWriteMany"], "storageClassName": "", "volumeName": "nas-pv",
                    "resources": {"requests": {"storage": "5Gi"}}}, "status": {"phase": "Bound"}}
SHARE = {"uuid": "sh-1", "shareName": "pvc-k8s", "sharePath": "/pvc-k8s", "fileServerName": "nutanix-afs",
         "status": "PROTECTED", "compliancyStatus": "GREEN", "protectionGroupName": "Gold"}


def seed_nas(H):
    st = read_state(H)
    st["pvs"] = {"nas-pv": NAS_PV}
    st["pvcs"] = {"app": {"data": NAS_PVC}}
    write_state(H, st)


def test_detect_nfs_volumes(H):
    assert H._pv_nfs_info(NAS_PV) == {"server": "nutanix-afs.amsdemo.ct", "path": "/pvc-k8s"}
    csi = {"spec": {"csi": {"driver": "nfs.csi.k8s.io", "volumeHandle": "x",
                            "volumeAttributes": {"server": "nas1", "share": "/exports", "subdir": "app1"}}}}
    assert H._pv_nfs_info(csi) == {"server": "nas1", "path": "/exports/app1"}
    block = {"spec": {"csi": {"driver": "csi.nutanix.com", "volumeHandle": "NutanixVolumes-11111111-1111-4111-8111-111111111111",
                              "volumeAttributes": {"iqn": "iqn.2010-06.com.nutanix:x"}}}}
    assert H._pv_nfs_info(block) is None


def test_match_share_rules(H):
    nfs = {"server": "nutanix-afs.amsdemo.ct", "path": "/pvc-k8s"}
    sh, kind, sub = H._match_share(nfs, [SHARE])
    assert sh["uuid"] == "sh-1" and kind == "exact" and sub == "/"
    sh, kind, sub = H._match_share({"server": "nutanix-afs", "path": "/pvc-k8s/app1"}, [SHARE])
    assert kind == "exact" and sub == "/app1", "PV sur un sous-dossier du partage"
    sh, kind, _ = H._match_share({"server": "10.0.0.5", "path": "/pvc-k8s"}, [SHARE])
    assert kind == "name", "même chemin, serveur non reconnu: suggestion à confirmer"
    other = dict(SHARE, uuid="sh-2", fileServerName="autre-nas")
    _sh, kind, _ = H._match_share({"server": "10.0.0.5", "path": "/pvc-k8s"}, [SHARE, other])
    assert kind == "ambiguous"
    nested = dict(SHARE, uuid="sh-3", shareName="app1", sharePath="nutanix-afs:/pvc-k8s/app1")
    sh, kind, sub = H._match_share({"server": "nutanix-afs", "path": "/pvc-k8s/app1/x"}, [SHARE, nested])
    assert sh["uuid"] == "sh-3" and kind == "exact" and sub == "/x", "le partage le plus précis l'emporte"
    assert H._match_share({"server": "nutanix-afs", "path": "/ailleurs"}, [SHARE])[1] == "none"


def test_hycu_match_mixes_vg_and_share(H, monkeypatch):
    monkeypatch.setattr(H, "_namespace_nutanix_vgs", lambda ns: ([
        {"pvc": "db", "pv": "pv-db", "nutanix_uuid": "11111111-1111-4111-8111-111111111111", "nfs": None},
        {"pvc": "data", "pv": "nas-pv", "nutanix_uuid": None,
         "nfs": {"server": "nutanix-afs.amsdemo.ct", "path": "/pvc-k8s"}}], None))
    monkeypatch.setattr(H, "_hycu_list_vgs", lambda: ([{"uuid": "hy-vg", "name": "pv-db",
                                                         "externalId": "11111111-1111-4111-8111-111111111111"}], None))
    monkeypatch.setattr(H, "_hycu_list_shares", lambda: ([SHARE], None))
    m = {x["pvc"]: x for x in H.action_hycu_match("app")["matches"]}
    assert m["db"]["hycu_vg_uuid"] == "hy-vg" and m["db"]["match_kind"] == "exact"
    assert m["data"]["volume_kind"] == "nfs" and m["data"]["hycu_share_uuid"] == "sh-1"
    assert m["data"]["trusted"] and m["data"]["policy"] == "Gold" and m["data"]["hycu_vg_uuid"] is None
    # la garde anti-stale accepte le partage (correspondance de confiance) et refuse un inconnu
    assert H._reject_stale_vgs("app", ["sh-1", "hy-vg"]) is None
    assert H._reject_stale_vgs("app", ["sh-x"])


def test_protect_assigns_and_backs_up_shares(H, monkeypatch):
    calls = []
    monkeypatch.setattr(H, "_rest", lambda system, method, path, body=None, **kw:
                        calls.append((path, body)) or {"ok": True, "json": {"uuid": "job"}, "raw": ""})
    monkeypatch.setattr(H, "_reject_stale_vgs", lambda ns, uuids, confirmed_by_name=None: None)
    monkeypatch.setattr(H, "_hycu_job_id", lambda j: (j or {}).get("uuid"))
    r = H.action_hycu_protect({"dry": False, "policy_uuid": "pol", "items": [
        {"namespace": "app", "vg_uuids": ["hy-vg"], "share_uuids": ["sh-1"]}]})
    assert r["ok"] and r["count"] == 2
    paths = [c[0] for c in calls]
    assert paths == ["/policies/pol/assign", "/schedules/backupVolumeGroup", "/schedules/backupShare"]
    assert calls[0][1]["volumeGroupUuidList"] == ["hy-vg"] and calls[0][1]["shareUuidList"] == ["sh-1"]
    assert calls[2][1] == {"uuidList": ["sh-1"], "forceFull": False}
    calls.clear()
    r2 = H.action_hycu_protect({"dry": False, "items": [{"namespace": "app", "share_uuids": ["sh-1"]}]})
    assert r2["ok"] and [c[0] for c in calls] == ["/schedules/backupShare"], "partages seuls"


def test_backup_records_nfs_volume(H):
    seed_nas(H)
    r = H.action_backup("app")
    assert r["ok"], r
    idx = json.load(open(os.path.join(r["dir"], "index.json"), encoding="utf-8"))
    assert idx["volumes"][0]["nfs"] == {"server": "nutanix-afs.amsdemo.ct", "path": "/pvc-k8s"}
    summ = H._catalog_summary(r["dir"], idx)
    assert summ["vol_nfs"] == {"data": "nutanix-afs.amsdemo.ct:/pvc-k8s"} and "data" not in summ["vol_refs"]


def test_volume_group_flows_refuse_nfs_clearly(H):
    seed_nas(H)
    res = H._prepare_one("app", {"pvc": "data", "new_ref": "11111111-1111-4111-8111-111111111111"}, "clone", None)
    assert not res["ok"] and res.get("nfs") and "NAS volume" in res["error"]


def test_copy_refused_but_recovery_reuses_export(H, monkeypatch):
    seed_nas(H)
    b = H.action_backup("app")
    assert b["ok"]
    # Copie d'une application VIVANTE : refusée (partagerait les données de production).
    r = H.action_clone_app({"namespace": "app", "target_namespace": "copie", "dry": True,
                            "backup_path": b["dir"], "items": [{"pvc": "data", "new_ref": ""}]})
    assert not r["ok"] and "NAS volume" in r["error"]
    # Récupération d'une application SUPPRIMÉE : PV recréé vers le même export, sans UUID.
    st = read_state(H)
    st["namespaces"] = []
    st["pvcs"] = {}
    write_state(H, st)
    r2 = H.action_clone_app({"namespace": "app", "target_namespace": "app", "dry": True, "from_backup_only": True,
                             "backup_path": b["dir"], "items": [{"pvc": "data", "new_ref": ""}]})
    assert r2.get("ok") or r2.get("dry"), r2
    assert any("same export" in w for w in (r2.get("warnings") or [])), r2.get("warnings")


def test_named_policy_assigns_hycu_policy_to_unassigned_share(H, monkeypatch):
    ok, err = H.save_config({"backup_policies": [{"name": "or", "namespaces": ["app"], "interval_hours": 4,
                                                  "keep": 3, "hycu_policy": "pol", "hycu_policy_name": "Gold"}]},
                            source="api")
    assert ok, err
    p = H._named_policies()[0]
    H.SESSION_CREDS["hycu"] = {"user": "x"}
    monkeypatch.setattr(H, "_hycu_list_vgs", lambda: ([], None))
    monkeypatch.setattr(H, "action_hycu_match", lambda ns, vg_items=None: {"ok": True, "matches": [
        {"matched": True, "trusted": True, "hycu_vg_uuid": None, "hycu_share_uuid": "sh-1", "policy": None},
        {"matched": True, "trusted": True, "hycu_vg_uuid": None, "hycu_share_uuid": "sh-2", "policy": "Silver"}]})
    calls = []
    monkeypatch.setattr(H, "_rest", lambda system, method, path, body=None, **kw:
                        calls.append((path, body)) or {"ok": True, "json": {}})
    ok, msg = H._policy_hycu_assign(p, ["app"])
    assert ok and calls == [("/policies/pol/assign", {"volumeGroupUuidList": [], "includeDependencies": False,
                                                      "shareUuidList": ["sh-1"]})]
    assert "1 volume(s) attached" in msg and "1 volume(s) already in another HYCU policy" in msg


def _fake_hycu(H, monkeypatch, calls):
    H.SESSION_CREDS["hycu"] = {"user": "x"}
    monkeypatch.setattr(H, "_hycu_list_shares", lambda: ([SHARE], None))

    def rest(system, method, path, body=None, **kw):
        calls.append((method, path, body))
        if path.startswith("/shares/sh-1/backups"):
            return {"ok": True, "json": {"entities": [{"uuid": "bk-old", "endTime": 1000},
                                                      {"uuid": "bk-new", "endTime": 2000000000000}]}}
        if "/browseShare?" in path:
            return {"ok": True, "json": {"entities": [{"fullItemName": "/nas-demo", "directory": True},
                                                      {"fullItemName": "/copie", "directory": True}],
                                         "metadata": {"flrSessId": "s1"}}}
        if "restoreShareItems" in path:
            return {"ok": True, "json": {"entities": [{"uuid": "job-1"}]}}
        if path.startswith("/jobs/"):
            return {"ok": True, "json": {"entities": [{"status": "OK"}]}}
        return {"ok": True, "json": {}}
    monkeypatch.setattr(H, "_rest", rest)


def test_copy_restores_share_into_namespace_folder(H, monkeypatch):
    seed_nas(H)
    b = H.action_backup("app")
    assert b["ok"]
    calls = []
    _fake_hycu(H, monkeypatch, calls)
    payload = {"namespace": "app", "target_namespace": "copie", "backup_path": b["dir"],
               "items": [{"pvc": "data", "new_ref": ""}]}
    r = H.action_clone_app(dict(payload, dry=True))
    assert r.get("ok") or r.get("dry"), r
    assert any("NAS copy" in w and "bk-" not in w for w in r["warnings"]), r["warnings"]
    assert any("will see the folder" in w for w in r["warnings"])
    assert not any("restoreShareItems" in c[1] for c in calls), "simulation: aucune restauration lancée"
    assert any("browseShareClose" in c[1] and "s1" in c[1] for c in calls), "session de parcours refermée"
    # Réel : restauration HYCU de la sauvegarde la plus récente dans « copie », puis PV vers ce dossier.
    monkeypatch.setattr(H, "_context_guard", lambda p: None)
    calls.clear()
    r2 = H.action_clone_app(dict(payload, dry=False))
    assert r2.get("ok"), r2.get("error") or r2
    rs = [c for c in calls if "restoreShareItems" in c[1]]
    assert len(rs) == 1 and "/bk-new/" in rs[0][1]
    body = rs[0][2]
    assert body["restoreTargetPath"] == "copie" and body["targetShareUuid"] == "sh-1"
    assert body["selectedItems"] == ["/nas-demo"], "le dossier cible lui-même n'est jamais recopié"
    pv = read_state(H)["pvs"].get("nas-pv-copie")
    assert pv and pv["spec"]["nfs"] == {"server": "nutanix-afs.amsdemo.ct", "path": "/pvc-k8s/copie"}, pv


def test_copy_of_subfolder_volume_and_failures(H, monkeypatch):
    calls = []
    _fake_hycu(H, monkeypatch, calls)
    plan, err = H._nfs_copy_plan({"server": "nutanix-afs", "path": "/pvc-k8s/app1"}, "data")
    assert not err and plan["sub"] == "/app1" and plan["root_path"] == "/pvc-k8s"
    body, pv_path, sel, _ = H._nfs_copy_target(plan, "copie")
    assert pv_path == "/pvc-k8s/copie/app1", "HYCU garde l'arborescence: copie/app1"
    assert sel == ["/nas-demo", "/copie"], "sous-dossier: rien n'est écarté"
    H.SESSION_CREDS.pop("hycu", None)
    _p, err = H._nfs_copy_plan({"server": "nutanix-afs", "path": "/pvc-k8s"}, "data")
    assert "Connect HYCU" in err
