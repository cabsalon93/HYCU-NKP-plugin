# -*- coding: utf-8 -*-
"""Verrous des correctifs de l'analyse du 25/09 (lots 1-3) : gardes de récupération,
existence de VG (404 vs erreur), sauvegarde partielle, tri des points, rétention 0,
bornes PBKDF2, SigV4 canonique, nom de VG cloné, extraction bornée, garde d'exécution."""
import io
import json
import os
import shutil
import tempfile
import time
import zipfile
import hycu_k8s_nutanix as H

passed = failed = 0
def check(c, m):
    global passed, failed
    if c: passed += 1; print("  OK  ", m)
    else: failed += 1; print("  FAIL", m)

VG = "11111111-2222-3333-4444-555555555555"
tmp = tempfile.mkdtemp()
saved = dict(H.CONFIG)
S = {k: getattr(H, k) for k in ("kubectl_json", "action_context", "_rest", "resource_state",
                                 "_hycu_list_vgs", "action_nutanix_vgs", "action_prepare_restore",
                                 "_load_txn", "_context_guard")}
try:
    H.CONFIG.update({"backup_root": tmp, "config_backup_full": False, "namespace_filter": [],
                     "cluster_namespace_filters": {}, "namespace_label_selector": "",
                     "storage_min_free_mb": 0, "storage_quota_gb": 0, "s3_auto_upload": False,
                     "backup_collect_restore_contract": False, "require_context_confirm": False,
                     "allowed_contexts": [], "auto_backup_retention": "count"})
    H.CONFIG_PATH = os.path.join(tmp, "hycu_config.json")
    H._LOCAL_CTX.update({"name": "ctx-test", "at": time.time() + 9999})
    H.action_context = lambda: {"context": "ctx-test"}

    print("== C2 _vg_exists : 404 = absent, autre erreur = indéterminé ==")
    with H.CRED_LOCK:
        H.SESSION_CREDS["prismcentral"] = {"a": 1}
    H._rest = lambda *a, **k: {"ok": False, "status": 404, "error": "HTTP 404"}
    check(H._vg_exists(VG) is False, "404 -> False (VG supprimé)")
    H._rest = lambda *a, **k: {"ok": False, "status": 503, "error": "HTTP 503"}
    check(H._vg_exists(VG) is None, "503 -> None (jamais de restauration in-place sur un doute)")
    H._rest = lambda *a, **k: {"ok": False, "status": None, "error": "Connexion impossible"}
    check(H._vg_exists(VG) is None, "timeout -> None")
    H._rest = lambda *a, **k: {"ok": True, "status": 200, "json": {"uuid": VG}}
    check(H._vg_exists(VG) is True, "200 -> True")
    with H.CRED_LOCK:
        H.SESSION_CREDS["prismcentral"] = None
    check(H._vg_exists(VG) is None, "Prism non connecté -> None")

    print("\n== C6 points de restauration triés (plus récent d'abord) ==")
    with H.CRED_LOCK:
        H.SESSION_CREDS["hycu"] = {"a": 1}
    H._rest = lambda *a, **k: {"ok": True, "json": {"entities": [
        {"uuid": "old", "restorePointInMillis": 1000}, {"uuid": "new", "restorePointInMillis": 9000},
        {"uuid": "mid", "restorePointInMillis": 5000}]}}
    pts = H.action_hycu_restore_points("x")["points"]
    check([p["id"] for p in pts] == ["new", "mid", "old"], "ordre API quelconque -> points[0] = le plus récent")
    with H.CRED_LOCK:
        H.SESSION_CREDS["hycu"] = None

    print("\n== C3 PV illisible -> sauvegarde PARTIELLE, aucune purge ==")
    def kj(args):
        if args[:2] == ["get", "pvc"]:
            return {"items": [{"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                               "metadata": {"name": "data", "namespace": "app"},
                               "spec": {"volumeName": "pvc-x", "accessModes": ["ReadWriteOnce"],
                                        "resources": {"requests": {"storage": "1Gi"}}}}]}, None
        if args[:2] == ["get", "pv"]:
            return None, "Forbidden (RBAC)"
        return None, "unexpected"
    H.kubectl_json = kj
    # 3 anciennes sauvegardes complètes déjà présentes, rétention 1 : ne doivent PAS être purgées
    H.CONFIG["auto_backup_keep"] = 1
    for i in range(3):
        d = os.path.join(tmp, "_contexts", "ctx-test", "app", "2026-09-2%d_00-00-00_000000" % i)
        os.makedirs(d)
        with open(os.path.join(d, "index.json"), "w") as f:
            json.dump({"namespace": "app", "created": "2026-09-2%dT00:00:00" % i, "context": "ctx-test",
                       "cluster_id": "local", "volumes": []}, f)
    r = H.action_backup("app")
    check(not r["ok"] and r.get("partial") and "PARTIELLE" in r["error"], "backup marqué PARTIEL et non OK")
    idx = json.load(open(os.path.join(r["dir"], "index.json")))
    check(idx.get("partial") is True and idx["volumes"][0].get("pv_error"), "index.json : partial + pv_error")
    remaining = [b for b in H.list_backups("app") ]
    check(len(remaining) == 4, "aucune purge des versions complètes (%d présentes)" % len(remaining))

    print("\n== B6 rétention compteur 0 = illimité ==")
    check(H._prune_backups(tmp, "app", 0) == 0 and len(H.list_backups("app")) == 4, "keep=0 : rien supprimé")
    check(H._prune_backups(tmp, "app", 2) == 2 and len(H.list_backups("app")) == 2, "keep=2 : 2 supprimées (auditées)")
    recs = [json.loads(l) for l in open(os.path.join(tmp, "audit.log"))]
    check(any(x["event"] == "backup_prune" and x.get("removed") == 2 for x in recs), "audit backup_prune")

    print("\n== B17 PBKDF2 borné à l'écriture ==")
    H.CONFIG["pbkdf2_iterations"] = 500
    check(H._pbkdf2_iters() == 1000, "500 -> 1000 (déchiffrable)")
    H.CONFIG["pbkdf2_iterations"] = 10 ** 9
    check(H._pbkdf2_iters() == 10_000_000, "1e9 -> 1e7")
    H.CONFIG["pbkdf2_iterations"] = 200000

    print("\n== B1/B2 SigV4 : chaîne de requête canonique triée, chemin non ré-encodé ==")
    hd = {"host": "h", "x-amz-date": "20260925T000000Z"}
    a1 = H._sigv4_auth("GET", "h", "/b", "prefix=p&continuation-token=t", hd, "0" * 64, "r", "s3", "AK", "SK", "20260925T000000Z")
    a2 = H._sigv4_auth("GET", "h", "/b", "continuation-token=t&prefix=p", hd, "0" * 64, "r", "s3", "AK", "SK", "20260925T000000Z")
    check(a1 == a2, "ordre des paramètres sans effet sur la signature")
    e1 = H._sigv4_auth("GET", "h", "/b/pr%C3%A9", "", hd, "0" * 64, "r", "s3", "AK", "SK", "20260925T000000Z")
    e2 = H._sigv4_auth("GET", "h", "/b/pr%25C3%25A9", "", hd, "0" * 64, "r", "s3", "AK", "SK", "20260925T000000Z")
    check(e1 != e2, "un chemin déjà encodé n'est pas ré-encodé")

    print("\n== B3 nom de VG cloné : unicité conservée pour des PVC longs ==")
    H._rest = S["_rest"]
    H.action_hycu_restore_points = lambda src: {"ok": True, "points": [{"id": "rp", "restorable": True}]}
    long1 = "data-my-application-postgresql-primary-replica-0"
    long2 = "data-my-application-postgresql-primary-replica-1"
    r = H.action_hycu_provision_clone({"volumes": [{"pvc": long1, "source_vg_uuid": VG},
                                                   {"pvc": long2, "source_vg_uuid": VG}], "dry": True})
    names = [it["planned_name"] for it in r["items"]]
    check(r["ok"] and len(set(names)) == 2 and all(len(n) <= 60 for n in names), "2 noms distincts, <= 60 caractères")
    H.action_hycu_restore_points = S["_rest"] and H.action_hycu_restore_points

    print("\n== B4 repli HYCU : l'uuid interne n'est jamais pris pour l'UUID Nutanix ==")
    H.action_nutanix_vgs = lambda query="": {"ok": True, "vgs": []}
    H._hycu_list_vgs = lambda: ([{"uuid": "hycu-internal", "name": "vgx"}], None)   # sans externalId
    u, e = H._discover_vg_uuid_by_name("vgx")
    check(u is None and e, "sans externalId -> introuvable (pas de faux UUID)")

    print("\n== B16 extraction bornée (zip bomb) ==")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("dir/big.bin", b"\0" * (3 * 1024 * 1024))
    n, err = H._safe_extract_zip(buf.getvalue(), os.path.join(tmp, "x"), max_bytes=1024 * 1024)
    check(n == 0 and "archive rejetée" in (err or ""), "archive gonflée refusée avant écriture")

    print("\n== C1 récupération : namespace encore présent -> refus serveur ==")
    d = os.path.join(tmp, "_contexts", "ctx-test", "gone", "2026-09-24_00-00-00_000000")
    os.makedirs(d)
    pv = {"apiVersion": "v1", "kind": "PersistentVolume", "metadata": {"name": "pvc-g"},
          "spec": {"claimRef": {"name": "data", "namespace": "gone"},
                   "csi": {"driver": "csi.nutanix.com", "volumeHandle": "NutanixVolumes-" + VG}}}
    with open(os.path.join(d, "pv_pvc-g.json"), "w") as f: json.dump(pv, f)
    with open(os.path.join(d, "pvc_data.json"), "w") as f:
        json.dump({"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "data", "namespace": "gone"},
                   "spec": {"volumeName": "pvc-g", "accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}}}, f)
    with open(os.path.join(d, "index.json"), "w") as f:
        json.dump({"namespace": "gone", "created": "2026-09-24T00:00:00", "context": "ctx-test", "cluster_id": "local",
                   "volumes": [{"pvc": "data", "pv": "pvc-g", "pv_file": "pv_pvc-g.json", "pvc_file": "pvc_data.json"}]}, f)
    base = {"namespace": "gone", "target_namespace": "gone", "backup_path": d, "from_backup_only": True,
            "items": [{"pvc": "data", "new_ref": ""}], "dry": True}
    H.resource_state = lambda kind, name, ns=None: ("present", "")
    r = H.action_clone_app(dict(base))
    check(not r["ok"] and "existe encore" in r["error"], "namespace présent : refus (garde same_uuid non levée)")
    H.resource_state = lambda kind, name, ns=None: ("error", "kubectl KO")
    r = H.action_clone_app(dict(base))
    check(not r["ok"] and "par prudence" in r["error"], "existence invérifiable : refus par prudence")

    print("\n== C5 assistant Restaurer : refus AVANT destruction si réf = nom du VG / même UUID en clone ==")
    H._load_txn = lambda ns: None
    H._context_guard = lambda payload: None
    H.action_prepare_restore = lambda payload: {"ok": True, "results": [
        {"ok": True, "pvc": "data", "looks_like_vg_name": True, "same_uuid": False}]}
    r = H._execute_restore_locked({"namespace": "app", "mode": "clone", "dry": False, "items": [{"pvc": "data", "new_ref": VG}]})
    check(not r["ok"] and "NOM du Volume Group" in (r["error"] or ""), "nom de VG collé -> refus, rien détruit")
    H.action_prepare_restore = lambda payload: {"ok": True, "results": [
        {"ok": True, "pvc": "data", "looks_like_vg_name": False, "same_uuid": True}]}
    r = H._execute_restore_locked({"namespace": "app", "mode": "clone", "dry": False, "items": [{"pvc": "data", "new_ref": VG}]})
    check(not r["ok"] and "identique au VG SOURCE" in (r["error"] or ""), "même UUID en clone -> refus")
finally:
    for k, v in S.items():
        setattr(H, k, v)
    with H.CRED_LOCK:
        H.SESSION_CREDS["hycu"] = None; H.SESSION_CREDS["prismcentral"] = None
    H._LOCAL_CTX.update({"name": None, "at": 0.0})
    H.CONFIG.clear(); H.CONFIG.update(saved)
    shutil.rmtree(tmp, ignore_errors=True)

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
