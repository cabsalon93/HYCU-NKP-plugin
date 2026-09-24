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
H._load_old_pv = lambda ns, pvc, bp, root=None: (H.json.loads(H.json.dumps(SRC_PV)), "pvc-" + PVCU)
H._load_backup_pvc = lambda bp, pvc, root=None: H.json.loads(H.json.dumps(SRC_PVC))
base_clone = {"namespace": "wordpress", "target_namespace": "", "suffix": "-clone", "dry": True}
# réf = UUID du VG SOURCE -> same_uuid
res_same = H.action_clone_app({**base_clone, "items": [{"pvc": "mariadb-pvc", "new_ref": VG}]})
check(res_same.get("ok") is False and "SOURCE" in (res_same.get("error") or ""),
      "réf = VG source -> refus (same_uuid)")
# réf = UUID du NOM du VG (pvc-<uuid>) -> looks_like_vg_name
res_name = H.action_clone_app({**base_clone, "items": [{"pvc": "mariadb-pvc", "new_ref": PVCU}]})
check(res_name.get("ok") is False and "NOM" in (res_name.get("error") or ""),
      "réf = nom du VG -> refus (looks_like_vg_name)")

print("\n== Clone d'app : namespace CIBLE hors filtre autorisé ; SOURCE toujours filtrée ==")
H.CONFIG["namespace_filter"] = ["wordpress"]
NEW_VG = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_kj_v8 = H.kubectl_json
H.kubectl_json = lambda args: ({"items": []}, None)   # pas de workloads/services à cloner
# cible hors filtre -> ne doit PLUS être refusée pour cause de filtre (création permise)
res_tgt = H.action_clone_app({"namespace": "wordpress", "target_namespace": "ns-hors-filtre",
                              "suffix": "", "dry": True, "items": [{"pvc": "mariadb-pvc", "new_ref": NEW_VG}]})
check("non autoris" not in (res_tgt.get("error") or "").lower(),
      "namespace cible hors filtre -> plus de refus 'non autorisé'")
# source hors filtre -> toujours refusée (le filtre borne bien les sources)
res_src = H.action_clone_app({"namespace": "interdit-src", "target_namespace": "x",
                              "suffix": "", "dry": True, "items": [{"pvc": "mariadb-pvc", "new_ref": NEW_VG}]})
check(res_src.get("ok") is False and "autoris" in (res_src.get("error") or "").lower(),
      "namespace SOURCE hors filtre -> toujours refusé")
H.kubectl_json = _kj_v8

print("\n== V9 : extId des disques triés (ordre canonique) ==")
H._rest_raw = lambda system, method, path, body=None, timeout=30: {
    "ok": True, "json": {"data": [{"extId": "zzz"}, {"extId": "aaa"}, {"extId": "mmm"}]}}
check(H._clone_vg_disk_uuids("vg") == "aaa,mmm,zzz", "extId triés indépendamment de l'ordre renvoyé")

print("\n== HYCU : parsing de l'ID de job tolérant aux chaînes (bug protect 500) ==")
# /schedules/backupVolumeGroup renvoie des UUID de tâches en CHAÎNES : ne doit plus
# planter avec 'str' object has no attribute 'get'.
check(H._hycu_job_id({"entities": ["task-uuid-123"]}) == "task-uuid-123",
      "entities = liste de chaînes -> 1er UUID (plus de 'str'.get)")
check(H._hycu_job_id("bare-uuid") == "bare-uuid", "réponse = chaîne nue -> renvoyée")
check(H._hycu_job_id(["uuid-a", "uuid-b"]) == "uuid-a", "racine = liste de chaînes -> 1er")
check(H._hycu_job_id({"entities": [{"uuid": "obj-uuid"}]}) == "obj-uuid", "entities = objets -> uuid")
check(H._hycu_job_id({"jobUuid": "jid"}) == "jid", "dict simple -> jobUuid")
check(isinstance(H._hycu_first({"entities": ["s"]}), dict), "_hycu_first renvoie toujours un dict")
check(H._hycu_job_id({}) is None and H._hycu_job_id({"entities": []}) is None, "absence d'ID -> None (pas d'erreur)")

print("\n== Sauvegarde de TOUS les namespaces filtrés (nouvelle fonctionnalité) ==")
_ns_orig, _bk_orig = H.action_namespaces, H.action_backup
H.action_namespaces = lambda: {"ok": True, "namespaces": ["wordpress", "vide", "shop"], "error": None}
def _fake_bk(ns, dest=None):
    if ns == "vide":
        return {"ok": False, "error": "Aucun PVC trouvé dans le namespace 'vide'."}
    return {"ok": True, "dir": "/b/" + ns, "count": 2 if ns == "wordpress" else 3}
H.action_backup = _fake_bk
H.CONFIG["namespace_filter"] = ["wordpress", "vide", "shop"]
_rall = H.action_backup_all()
check(_rall["ok"] and _rall["backed_up"] == 2 and _rall["volumes"] == 5, "agrège 2 ns sauvegardés / 5 volumes")
check(any(x["ns"] == "vide" and x.get("skipped") for x in _rall["results"]),
      "namespace sans PVC -> ignoré (pas une erreur)")
check(_rall["filtered"] is True, "indique qu'un filtre est actif")
H.action_namespaces, H.action_backup = _ns_orig, _bk_orig

print("\n== Serveur HTTP : coupure client ignorée proprement (WinError 10053) ==")
class _OkWfile:
    def __init__(self): self.data = b""
    def write(self, b): self.data += b
class _OkHandler:
    def __init__(self): self.wfile = _OkWfile()
    def send_response(self, *a): pass
    def send_header(self, *a): pass
    def end_headers(self): pass
oh = _OkHandler()
H.Handler._send(oh, 200, '{"ok":true}')
check(oh.wfile.data == b'{"ok":true}', "connexion OK -> le corps est bien écrit (chemin normal inchangé)")

class _DeadWfile:
    def write(self, b): raise ConnectionAbortedError(10053, "client gone")
class _DeadHandler:
    def __init__(self): self.wfile = _DeadWfile()
    def send_response(self, *a): pass
    def send_header(self, *a): pass
    def end_headers(self): raise ConnectionAbortedError(10053, "client gone")
try:
    H.Handler._send(_DeadHandler(), 200, '{"ok":true}')
    check(True, "connexion coupée (end_headers/write) -> _send n'explose pas (plus de traceback)")
except Exception as e:
    check(False, "_send a propagé %r" % e)

print("\n== Sauvegarde : dossier de destination choisi par l'utilisateur ==")
import tempfile, os as _os, shutil as _sh
_root_def, _e0 = H._resolve_backup_dest("")
check(_e0 is None and _root_def == H.CONFIG["backup_root"], "destination vide -> backup_root par défaut")
_tmp = tempfile.mkdtemp()
_custom = _os.path.join(_tmp, "mes-sauvegardes")
_root, _e1 = H._resolve_backup_dest(_custom)
check(_e1 is None and _os.path.isdir(_root) and _os.path.abspath(_custom) == _root,
      "destination valide -> dossier créé + chemin absolu")
H.CONFIG["namespace_filter"] = []
H.action_context = lambda: {"context": "c"}
def _fake_kj(args):
    if args[:2] == ["get", "ns"]:
        return ({"items": [{"metadata": {"name": "wordpress"}}]}, None)
    if args[:2] == ["get", "pvc"]:
        return ({"items": [{"metadata": {"name": "mariadb-pvc"}, "spec": {}, "status": {"phase": "Bound"}}]}, None)
    return ({}, None)
H.kubectl_json = _fake_kj
_rb = H.action_backup("wordpress", _custom)
check(_rb.get("ok") and _rb.get("dir", "").startswith(_root), "action_backup écrit SOUS la destination choisie")
check(_os.path.isfile(_os.path.join(_rb["dir"], "index.json")), "index.json présent dans la destination")
_ra = H.action_backup_all(_custom)
check(_ra.get("ok") and _ra.get("root") == _root, "action_backup_all honore la destination commune")
_sh.rmtree(_tmp, ignore_errors=True)

print("\n== Restauration depuis un dossier personnalisé (lecture) ==")
H._load_old_pv = _ORIG["_load_old_pv"]          # restaurer les vraies fonctions (stubées plus haut)
H._load_backup_pvc = _ORIG["_load_backup_pvc"]
_tmp2 = tempfile.mkdtemp()
_inside = _os.path.join(_tmp2, "wordpress", "2026-01-01_00-00-00_0")
_os.makedirs(_inside, exist_ok=True)
check(H._safe_backup_path(_inside, _tmp2) == _os.path.realpath(_inside),
      "chemin sous le dossier perso DÉSIGNÉ -> autorisé")
check(H._safe_backup_path(_inside, None) is None,
      "même chemin SANS dossier perso -> refusé (sécurité par défaut conservée)")
check(H._safe_backup_path("/etc", _tmp2) is None, "chemin hors zone -> refusé même avec dossier perso")
with open(_os.path.join(_inside, "index.json"), "w", encoding="utf-8") as f:
    f.write('{"namespace":"wordpress","volumes":[{"pvc":"mariadb-pvc","pv":"pvc-x","pv_file":"pv_pvc-x.json"}]}')
with open(_os.path.join(_inside, "pv_pvc-x.json"), "w", encoding="utf-8") as f:
    f.write('{"kind":"PersistentVolume","metadata":{"name":"pvc-x"}}')
_bks = H.list_backups("wordpress", _tmp2)
check(len(_bks) == 1 and _bks[0]["path"] == _inside, "list_backups(dossier perso) trouve la sauvegarde")
_pv, _pvn = H._load_old_pv("wordpress", "mariadb-pvc", _inside, _tmp2)
check(_pv is not None and _pv.get("metadata", {}).get("name") == "pvc-x" and _pvn == "pvc-x",
      "_load_old_pv charge le PV depuis le dossier perso désigné")
_sh.rmtree(_tmp2, ignore_errors=True)

print("\n== Conteneur : surcharges par variables d'environnement (mode-agnostique) ==")
import os as _os2
_envsave = {k: _os2.environ.get(k) for k in ("HYCU_HOST", "HYCU_PORT", "HYCU_OPEN_BROWSER", "HYCU_BACKUP_ROOT")}
_cfgsave = dict(H.CONFIG)
_os2.environ["HYCU_HOST"] = "0.0.0.0"; _os2.environ["HYCU_PORT"] = "9999"
_os2.environ["HYCU_OPEN_BROWSER"] = "0"; _os2.environ["HYCU_BACKUP_ROOT"] = "/data/hycu-backups"
H.CONFIG["host"] = "127.0.0.1"; H.CONFIG["open_browser"] = True; H.CONFIG["port"] = 8765
H._apply_env_overrides()
check(H.CONFIG["host"] == "0.0.0.0", "HYCU_HOST surcharge host (bind conteneur)")
check(H.CONFIG["port"] == 9999 and isinstance(H.CONFIG["port"], int), "HYCU_PORT converti en int")
check(H.CONFIG["open_browser"] is False, "HYCU_OPEN_BROWSER=0 -> False")
check(H.CONFIG["backup_root"] == "/data/hycu-backups", "HYCU_BACKUP_ROOT surcharge le dossier")
# rien posé -> aucune surcharge (mode python direct inchangé)
for k in ("HYCU_HOST", "HYCU_PORT", "HYCU_OPEN_BROWSER", "HYCU_BACKUP_ROOT"):
    _os2.environ.pop(k, None)
H.CONFIG["host"] = "127.0.0.1"
H._apply_env_overrides()
check(H.CONFIG["host"] == "127.0.0.1", "sans variable d'env -> défaut conservé (mode python)")
for k, v in _envsave.items():
    (_os2.environ.__setitem__(k, v) if v is not None else _os2.environ.pop(k, None))
H.CONFIG.clear(); H.CONFIG.update(_cfgsave)

# --- Restauration de l'état global --------------------------------------------
for k, v in _ORIG.items():
    setattr(H, k, v)
H.CONFIG["namespace_filter"] = _ORIG_FILTER

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
