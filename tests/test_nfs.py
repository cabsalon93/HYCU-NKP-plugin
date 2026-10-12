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
    browse = [c[1] for c in calls if "/browseShare?" in c[1]]
    assert browse and "path=&" in browse[0] and "flrSessId=hycu-k8s-" in browse[0], browse
    assert any("browseShareClose" in c[1] and "flrSessId=hycu-k8s-" in c[1] for c in calls), "session refermée"
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
    assert any("/browseShare?" in c[1] and "path=app1&" in c[1] for c in calls), "chemin relatif au partage"
    body, pv_path, sel, _skipped, flatten = H._nfs_copy_target(plan, "copie")
    assert pv_path == "/pvc-k8s/copie", "the copy's PV always points to <share>/<target folder>"
    assert sel == ["/app1"] and flatten == "app1", "the mounted folder is restored, then moved up one level"
    H.SESSION_CREDS.pop("hycu", None)
    _p, err = H._nfs_copy_plan({"server": "nutanix-afs", "path": "/pvc-k8s"}, "data")
    assert "Connect HYCU" in err


def test_copy_without_config_backup_uses_live_pvc(H, monkeypatch):
    """Copy started from the live cluster (no config backup yet): PV and PVC are read live."""
    seed_nas(H)
    calls = []
    _fake_hycu(H, monkeypatch, calls)
    r = H.action_clone_app({"namespace": "app", "target_namespace": "copie", "dry": True,
                            "backup_path": None, "items": [{"pvc": "data", "new_ref": ""}]})
    assert r.get("ok") or r.get("dry"), r.get("error") or r
    assert any("NAS copy" in w for w in r["warnings"]), r["warnings"]


def test_browse_retries_while_hycu_mounts_the_backup(H, monkeypatch):
    """HYCU answers 503 while it mounts the backup (seen in the real UI): retry, then list."""
    H.SESSION_CREDS["hycu"] = {"user": "x"}
    monkeypatch.setattr(H.time, "sleep", lambda s: None)
    answers = [{"ok": False, "status": 503, "error": "HTTP 503", "raw": ""},
               {"ok": True, "json": {"entities": [{"fullItemName": "nas-demo"}]}}]

    def rest(system, method, path, body=None, **kw):
        if "/browseShare?" in path:
            return answers.pop(0)
        return {"ok": True, "json": {}}
    monkeypatch.setattr(H, "_rest", rest)
    items, err = H._share_browse("bk", "/")
    assert err is None and [i["fullItemName"] for i in items] == ["nas-demo"]


def test_copy_takes_only_the_source_namespace_folder(H, monkeypatch):
    """A share serves several namespaces (one folder each): only the source namespace's folder is copied."""
    calls = []
    _fake_hycu(H, monkeypatch, calls)
    plan, err = H._nfs_copy_plan({"server": "nutanix-afs", "path": "/pvc-k8s"}, "data")
    assert not err
    plan["entries"] = [{"fullItemName": "/namespace3"}, {"fullItemName": "/nas-demo"}, {"fullItemName": "/other"}]
    body, pv_path, sel, left, flatten = H._nfs_copy_target(plan, "nas-demo-copy", "nas-demo")
    assert sel == ["/nas-demo"] and body["selectedItems"] == ["/nas-demo"] and flatten is None
    assert pv_path == "/pvc-k8s/nas-demo-copy", "the app keeps writing to /data/nas-demo inside the copy"
    assert left == ["namespace3", "other"] and plan["ns_folder"] == "nas-demo"
    # No folder named after the namespace: previous behaviour (whole root minus copies).
    plan.pop("ns_folder")
    _b, _p, sel2, _l, _f = H._nfs_copy_target(plan, "x-copy", "unknown-ns")
    assert sorted(sel2) == ["/namespace3", "/nas-demo", "/other"]


def test_flatten_job_outcomes(H, monkeypatch):
    """Post-restore Job: success, permission denied (root squash) and failure are told apart."""
    H.CONFIG["nas_job_image"] = "busybox:1.36"
    monkeypatch.setattr(H.time, "sleep", lambda s: None)
    applied, deleted = [], []

    def fake_apply(manifest, basename, dry, label):
        applied.append(manifest)
        return {"ok": True, "dry": False, "rc": 0, "stdout": "job created", "stderr": "", "label": label, "cmd": ""}

    def run_case(succeeded, exit_code, logs):
        applied.clear()
        monkeypatch.setattr(H, "_apply_manifest", fake_apply)
        monkeypatch.setattr(H, "kubectl_json", lambda args: (
            {"status": {"succeeded": 1}} if succeeded else {"status": {"failed": 1}}, None) if args[1] == "job"
            else ({"items": [{"status": {"containerStatuses": [{"state": {"terminated": {"exitCode": exit_code}}}]}}]}, None))
        monkeypatch.setattr(H, "kubectl", lambda args, **kw: (deleted.append(args) or {"ok": True, "stdout": "", "stderr": ""})
                            if args[0] == "delete" else {"ok": True, "stdout": logs, "stderr": ""})
        log = []
        return H._nas_flatten("copie", "nas1", "/pvc-k8s/copie", "app1", log, timeout=5), log

    (st, out), log = run_case(True, 0, "moved 2 entry(ies)")
    assert st == "ok" and "moved" in out
    job = applied[0]
    assert job["kind"] == "Job" and job["metadata"]["namespace"] == "copie"
    spec = job["spec"]["template"]["spec"]
    assert spec["volumes"][0]["nfs"] == {"server": "nas1", "path": "/pvc-k8s/copie"}
    assert spec["containers"][0]["command"][-1] == "app1" and spec["securityContext"]["runAsUser"] == 0
    assert any(a[0] == "delete" and a[1] == "job" for a in deleted), "the Job is removed afterwards"
    (st, _o), log = run_case(False, 3, "mv: can't rename: Permission denied")
    assert st == "denied" and any(e.get("rc") == 3 for e in log)
    (st, detail), _l = run_case(False, 5, "mv: no space")
    assert st == "error" and "exit 5" in detail


def test_copy_of_a_copy_keeps_the_tree_flat(H, monkeypatch):
    """Copy of a copy: HYCU gives <T2>/<T1>/..., the Job moves it up; the PV points to <T2>."""
    st = read_state(H)
    pv = json.loads(json.dumps(NAS_PV))
    pv["metadata"]["name"] = "nas-pv-copy"
    pv["spec"]["nfs"]["path"] = "/pvc-k8s/copie"
    pv["spec"]["claimRef"]["namespace"] = "copie"
    pvc = json.loads(json.dumps(NAS_PVC))
    pvc["metadata"]["namespace"] = "copie"
    pvc["spec"]["volumeName"] = "nas-pv-copy"
    st["pvs"] = {"nas-pv-copy": pv}
    st["pvcs"] = {"copie": {"data": pvc}}
    st["namespaces"] = ["copie"]
    write_state(H, st)
    calls = []
    _fake_hycu(H, monkeypatch, calls)
    monkeypatch.setattr(H, "_context_guard", lambda p: None)
    flat = []
    monkeypatch.setattr(H, "_nas_flatten", lambda ns, server, path, sub, log, **kw: flat.append((ns, path, sub)) or ("ok", ""))
    r = H.action_clone_app({"namespace": "copie", "target_namespace": "copie2", "dry": False,
                            "backup_path": None, "items": [{"pvc": "data", "new_ref": ""}]})
    assert r.get("ok"), r.get("error") or r
    body = [c for c in calls if "restoreShareItems" in c[1]][0][2]
    assert body["selectedItems"] == ["/copie"] and body["restoreTargetPath"] == "copie2"
    assert flat == [("copie2", "/pvc-k8s/copie2", "copie")]
    newpv = read_state(H)["pvs"]["nas-pv-copy-copie2"]
    assert newpv["spec"]["nfs"]["path"] == "/pvc-k8s/copie2", newpv["spec"]["nfs"]


def test_copy_falls_back_to_nested_path_when_nas_denies_the_move(H, monkeypatch):
    st = read_state(H)
    pv = json.loads(json.dumps(NAS_PV))
    pv["spec"]["nfs"]["path"] = "/pvc-k8s/app"
    st["pvs"] = {"nas-pv": pv}
    st["pvcs"] = {"app": {"data": NAS_PVC}}
    write_state(H, st)
    calls = []
    _fake_hycu(H, monkeypatch, calls)
    monkeypatch.setattr(H, "_share_backup_has", lambda bk, sub: True)   # the fake backup holds the folder
    monkeypatch.setattr(H, "_context_guard", lambda p: None)
    monkeypatch.setattr(H, "_nas_flatten", lambda ns, server, path, sub, log, **kw: ("denied", "Permission denied"))
    r = H.action_clone_app({"namespace": "app", "target_namespace": "copie", "dry": False,
                            "backup_path": None, "items": [{"pvc": "data", "new_ref": ""}]})
    assert r.get("ok"), r.get("error") or r
    assert read_state(H)["pvs"]["nas-pv-copie"]["spec"]["nfs"]["path"] == "/pvc-k8s/copie/app"
    assert any("root squash" in w for w in r["warnings"])


def test_copy_of_csi_nfs_volume_creates_a_native_nfs_pv(H, monkeypatch):
    """Source provisioned by nfs.csi.k8s.io: the copy is a static spec.nfs PV on the HYCU-created folder."""
    st = read_state(H)
    pv = json.loads(json.dumps(NAS_PV))
    pv["spec"].pop("nfs")
    pv["spec"]["storageClassName"] = "nfs-csi"
    pv["spec"]["csi"] = {"driver": "nfs.csi.k8s.io", "volumeHandle": "nutanix-afs.amsdemo.ct#pvc-k8s#app#",
                         "volumeAttributes": {"server": "nutanix-afs.amsdemo.ct", "share": "/pvc-k8s", "subdir": "app"}}
    st["pvs"] = {"nas-pv": pv}
    st["pvcs"] = {"app": {"data": NAS_PVC}}
    write_state(H, st)
    calls = []
    _fake_hycu(H, monkeypatch, calls)
    monkeypatch.setattr(H, "_share_backup_has", lambda bk, sub: True)   # the fake backup holds the folder
    monkeypatch.setattr(H, "_context_guard", lambda p: None)
    monkeypatch.setattr(H, "_nas_flatten", lambda ns, server, path, sub, log, **kw: ("ok", ""))
    r = H.action_clone_app({"namespace": "app", "target_namespace": "copie", "dry": False,
                            "backup_path": None, "items": [{"pvc": "data", "new_ref": ""}]})
    assert r.get("ok"), r.get("error") or r
    newpv = read_state(H)["pvs"]["nas-pv-copie"]["spec"]
    assert "csi" not in newpv and newpv["nfs"] == {"server": "nutanix-afs.amsdemo.ct", "path": "/pvc-k8s/copie"}
    body = [c for c in calls if "restoreShareItems" in c[1]][0][2]
    assert body["selectedItems"] == ["/app"] and body["restoreTargetPath"] == "copie"
    assert any("CSI NFS driver" in w for w in r["warnings"])


def test_copy_backs_up_the_share_when_latest_backup_lacks_the_folder(H, monkeypatch):
    """Source folder created after the latest share backup: real run backs up the share first."""
    st = read_state(H)
    pv = json.loads(json.dumps(NAS_PV))
    pv["spec"]["nfs"]["path"] = "/pvc-k8s/copie"
    st["pvs"] = {"nas-pv": pv}
    st["pvcs"] = {"app": {"data": NAS_PVC}}
    write_state(H, st)
    H.SESSION_CREDS["hycu"] = {"user": "x"}
    monkeypatch.setattr(H, "_hycu_list_shares", lambda: ([SHARE], None))
    monkeypatch.setattr(H.time, "sleep", lambda s: None)
    state = {"backed_up": False}
    calls = []

    def rest(system, method, path, body=None, **kw):
        calls.append((method, path, body))
        if path.startswith("/shares/sh-1/backups"):
            ents = [{"uuid": "bk-old", "endTime": 1000}]
            if state["backed_up"]:
                ents.append({"uuid": "bk-new", "endTime": 2000000000000})
            return {"ok": True, "json": {"entities": ents}}
        if "/browseShare?" in path:
            folders = ["/nas-demo"] + (["/copie"] if ("bk-new" in path and state["backed_up"]) else [])
            if "path=copie" in path:
                return {"ok": True, "json": {"entities": [{"fullItemName": "/copie/journal.txt"}] if "bk-new" in path else []}}
            return {"ok": True, "json": {"entities": [{"fullItemName": f} for f in folders]}}
        if path == "/schedules/backupShare":
            state["backed_up"] = True
            return {"ok": True, "json": {"entities": ["job-b"]}}
        if "restoreShareItems" in path:
            return {"ok": True, "json": {"entities": [{"uuid": "job-1"}]}}
        if path.startswith("/jobs/"):
            return {"ok": True, "json": {"entities": [{"status": "OK"}]}}
        return {"ok": True, "json": {}}
    monkeypatch.setattr(H, "_rest", rest)
    monkeypatch.setattr(H, "_context_guard", lambda p: None)
    monkeypatch.setattr(H, "_nas_flatten", lambda ns, server, path, sub, log, **kw: ("ok", ""))
    payload = {"namespace": "app", "target_namespace": "copie2", "backup_path": None, "items": [{"pvc": "data", "new_ref": ""}]}
    d = H.action_clone_app(dict(payload, dry=True))
    assert (d.get("ok") or d.get("dry")) and any("does not contain" in w for w in d["warnings"]), d.get("error") or d["warnings"]
    assert not any(c[1] == "/schedules/backupShare" for c in calls), "simulation never starts a backup"
    r = H.action_clone_app(dict(payload, dry=False))
    assert r.get("ok"), r.get("error") or r
    assert any(c[1] == "/schedules/backupShare" for c in calls), "real run backed up the share first"
    rs = [c for c in calls if "restoreShareItems" in c[1]]
    assert len(rs) == 1 and "/bk-new/" in rs[0][1], "restore taken from the fresh backup"
    assert any("Fresh share backup" in (l.get("label") or "") for l in r["log"])
