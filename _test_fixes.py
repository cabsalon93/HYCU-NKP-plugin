# -*- coding: utf-8 -*-
"""Régressions des correctifs de sûreté/sécurité (revue de code) :
- V2 : reprise d'une restauration interrompue -> injecte txn.backup_dir comme backup_path
- V4 : redirection REST -> retire Authorization cross-host ; schéma non-http(s) refusé
- V7 : clone d'app -> refuse la réf du VG SOURCE (same_uuid) / le NOM du VG (looks_like_vg_name)
- V8 : clone d'app cross-ns -> applique l'allowlist namespace_filter au namespace CIBLE
- V9 : disque(s) du VG -> extId triés (ordre canonique, insensible au ré-ordonnancement)
"""
import hycu_k8s_nutanix as H

passed = failed = 0
def check(c, m):
    global passed, failed
    if c: passed += 1; print("  OK  ", m)
    else: failed += 1; print("  FAIL", m)


# --- Sauvegarde/restaure l'état global modifié par les tests -------------------
_ORIG = {k: getattr(H, k) for k in ("action_context", "_load_txn", "action_prepare_restore",
                                    "_load_old_pv", "_load_backup_pvc", "_rest_raw", "kubectl_json")}
_ORIG_FILTER = list(H.CONFIG.get("namespace_filter") or [])

VG = "7060521a-815d-472c-8864-68ab6d98b88b"          # UUID du VG (dans le volumeHandle)
PVCU = "44c5d5d7-5c80-4894-9adc-1c02f0368b10"          # UUID du nom de PV « pvc-<uuid> »
SRC_PV = {"kind": "PersistentVolume", "metadata": {"name": "pvc-" + PVCU},
          "spec": {"csi": {"driver": "csi.nutanix.com", "volumeHandle": "NutanixVolumes-" + VG,
                           "volumeAttributes": {"hypervisorAttachedDiskUUIDs": "disk-old"}}}}
SRC_PVC = {"kind": "PersistentVolumeClaim", "metadata": {"name": "mariadb-pvc", "namespace": "wordpress"},
           "spec": {"volumeName": "pvc-" + PVCU, "accessModes": ["ReadWriteOnce"]}}

print("\n== V2 : reprise injecte txn.backup_dir comme backup_path ==")
captured = {}
H.action_context = lambda: {"context_ok": True, "require_confirm": False, "context": "c"}
H._load_txn = lambda ns: {"backup_dir": "/safe/backup-init", "mode": "clone", "started": "t"}
def _fake_prepare(payload):
    captured["backup_path"] = payload.get("backup_path")
    return {"ok": False, "error": "(stop test)", "results": []}        # stoppe avant toute destruction
H.action_prepare_restore = _fake_prepare
H.CONFIG["namespace_filter"] = []
H._execute_restore_locked({"namespace": "wordpress", "mode": "clone", "dry": False, "items": []})
check(captured.get("backup_path") == "/safe/backup-init",
      "prepare reçoit le backup_dir de la transaction (reprise récupérable)")
# Sans transaction et sans backup_path explicite : reste None (lecture live, restore frais)
H._load_txn = lambda ns: None
captured.clear()
H._execute_restore_locked({"namespace": "wordpress", "mode": "clone", "dry": False, "items": []})
check(captured.get("backup_path") is None, "restore frais (pas de txn) : backup_path None -> lecture live")

print("\n== V4 : redirection REST ne fuit pas Authorization cross-host ==")
req = H.urllib.request.Request("https://hycu.example.com/rest/v1.0/vms", method="GET")
req.add_header("Authorization", "Bearer secret-token")
h = H._NoCredLeakRedirect()
nr = h.redirect_request(req, None, 302, "Found", {}, "https://evil.example.com/login")
check(nr is not None and "Authorization" not in nr.headers, "Authorization retiré sur redirection cross-host")
nr2 = h.redirect_request(req, None, 302, "Found", {}, "https://hycu.example.com/rest/v1.0/vms2")
check(nr2 is not None and nr2.headers.get("Authorization") == "Bearer secret-token",
      "Authorization conservé sur redirection same-host")
r_scheme = H._http_json("GET", "file:///etc/passwd", None, False)
check(r_scheme.get("ok") is False and "Schéma" in (r_scheme.get("error") or ""), "schéma file:// refusé sans I/O")

print("\n== V7 : clone d'app refuse la réf SOURCE / le nom du VG ==")
H.CONFIG["namespace_filter"] = []
H._load_old_pv = lambda ns, pvc, bp: (H.json.loads(H.json.dumps(SRC_PV)), "pvc-" + PVCU)
H._load_backup_pvc = lambda bp, pvc: H.json.loads(H.json.dumps(SRC_PVC))
base_clone = {"namespace": "wordpress", "target_namespace": "", "suffix": "-clone", "dry": True}
# réf = UUID du VG SOURCE -> same_uuid
res_same = H.action_clone_app({**base_clone, "items": [{"pvc": "mariadb-pvc", "new_ref": VG}]})
check(res_same.get("ok") is False and "SOURCE" in (res_same.get("error") or ""),
      "réf = VG source -> refus (same_uuid)")
# réf = UUID du NOM du VG (pvc-<uuid>) -> looks_like_vg_name
res_name = H.action_clone_app({**base_clone, "items": [{"pvc": "mariadb-pvc", "new_ref": PVCU}]})
check(res_name.get("ok") is False and "NOM" in (res_name.get("error") or ""),
      "réf = nom du VG -> refus (looks_like_vg_name)")

print("\n== V8 : clone d'app applique l'allowlist au namespace CIBLE ==")
H.CONFIG["namespace_filter"] = ["wordpress"]
res_ns = H.action_clone_app({"namespace": "wordpress", "target_namespace": "interdit",
                             "suffix": "", "dry": True, "items": [{"pvc": "mariadb-pvc", "new_ref": VG}]})
check(res_ns.get("ok") is False and "cible" in (res_ns.get("error") or "").lower()
      and "autoris" in (res_ns.get("error") or "").lower(),
      "namespace cible hors filtre -> refus")

print("\n== V9 : extId des disques triés (ordre canonique) ==")
H._rest_raw = lambda system, method, path, body=None, timeout=30: {
    "ok": True, "json": {"data": [{"extId": "zzz"}, {"extId": "aaa"}, {"extId": "mmm"}]}}
check(H._clone_vg_disk_uuids("vg") == "aaa,mmm,zzz", "extId triés indépendamment de l'ordre renvoyé")

# --- Restauration de l'état global --------------------------------------------
for k, v in _ORIG.items():
    setattr(H, k, v)
H.CONFIG["namespace_filter"] = _ORIG_FILTER

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
