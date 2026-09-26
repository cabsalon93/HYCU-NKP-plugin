# -*- coding: utf-8 -*-
"""Secrets dans les sauvegardes : CHIFFRÉS avec la phrase du coffre (secrets.enc) quand
elle est disponible, recomposés à la lecture ; sinon en clair (mode auto, avec
avertissement), ou masqués. La récupération d'une application recrée ses Secrets."""
import json
import os
import shutil
import tempfile
import time
import hycu_k8s_nutanix as H

passed = failed = 0
def check(c, m):
    global passed, failed
    if c: passed += 1; print("  OK  ", m)
    else: failed += 1; print("  FAIL", m)


SEC = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "db-pass", "namespace": "front"},
       "type": "Opaque", "data": {"password": "c2VjcmV0"}}
DEP = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "api", "labels": {"app": "api"}},
       "spec": {"selector": {"matchLabels": {"app": "api"}},
                "template": {"metadata": {"labels": {"app": "api"}},
                             "spec": {"containers": [{"name": "c", "image": "x",
                                                      "envFrom": [{"secretRef": {"name": "db-pass"}}]}]}}}}
tmp = tempfile.mkdtemp()
saved = dict(H.CONFIG)
s_kj, s_ctx, s_rs, s_env, s_pw = H.kubectl_json, H.action_context, H.resource_state, H._vault_env_passphrase, H._VAULT_PW
try:
    H.CONFIG.update({"backup_root": tmp, "namespace_filter": [], "cluster_namespace_filters": {},
                     "namespace_label_selector": "", "config_backup_full": True,
                     "backup_collect_restore_contract": False, "storage_min_free_mb": 0, "storage_quota_gb": 0,
                     "allow_dr_restore": False, "require_context_confirm": False, "allowed_contexts": [],
                     "config_backup_include_secret_data": False})
    H.CONFIG.pop("backup_secrets", None)
    H.CONFIG_PATH = os.path.join(tmp, "hycu_config.json")
    H._LOCAL_CTX.update({"name": "ctx-sec", "at": time.time() + 9999})
    H.action_context = lambda: {"context": "ctx-sec", "kubectl_ok": True}
    H._vault_env_passphrase = lambda: ""
    def kj(args):
        if args[:2] == ["get", "pvc"]:
            return {"items": []}, None
        if args[0] == "get" and args[1].split(",")[0] == "deployment":
            return {"items": [json.loads(json.dumps(DEP)), json.loads(json.dumps(SEC))]}, None
        return {"items": []}, None
    H.kubectl_json = kj

    print("== Mode auto + coffre déverrouillé : Secrets CHIFFRÉS ==")
    H._VAULT_PW = "phrase-du-coffre-1"
    b = H.action_backup("front")
    check(b["ok"] and b["secrets"] == "encrypted" and not b.get("secrets_warning") and H.SECRETS_FILE in b["files"],
          "sauvegarde OK, mode effectif « encrypted », secrets.enc listé")
    res = json.load(open(os.path.join(b["dir"], "resources.json")))
    sec = [o for o in res["items"] if o["kind"] == "Secret"][0]
    check(res["secrets"] == "encrypted" and sec["data"]["password"] == "__REDACTED__"
          and sec["metadata"]["annotations"]["hycu.backup/secret-data"] == "encrypted",
          "resources.json : Secret MASQUÉ + annotation « encrypted » (rien en clair sur disque)")
    blob = open(os.path.join(b["dir"], H.SECRETS_FILE), "rb").read()
    check(blob.startswith(b"HV2B") and b"c2VjcmV0" not in blob, "secrets.enc : format HV2B, valeur absente en clair")
    check(H.decrypt_bytes(blob, "mauvaise") is None, "mauvaise phrase : indéchiffrable")
    idx = json.load(open(os.path.join(b["dir"], "index.json")))
    check(idx["secrets"] == "encrypted", "index.json : secrets=encrypted")
    items, err = H._load_backup_resources(b["dir"])
    sec2 = [o for o in items if o["kind"] == "Secret"][0]
    check(err is None and sec2["data"]["password"] == "c2VjcmV0" and not H._obj_is_redacted(sec2),
          "lecture avec la phrase : Secret recomposé (restaurable)")
    r = H.action_objects_list({"namespace": "front", "backup_path": b["dir"]})
    check(r["ok"] and not [x for x in r["items"] if x["kind"] == "Secret"][0]["redacted"], "liste des objets : Secret restaurable")

    print("\n== Coffre verrouillé : Secret chiffré NON recomposé (jamais appliqué masqué) ==")
    H._VAULT_PW = ""
    items, err = H._load_backup_resources(b["dir"])
    sec3 = [o for o in items if o["kind"] == "Secret"][0]
    check(err is None and H._obj_is_redacted(sec3) and H._obj_secret_encrypted(sec3), "sans phrase : Secret reste masqué")
    r = H.action_objects_list({"namespace": "front", "backup_path": b["dir"]})
    row = [x for x in r["items"] if x["kind"] == "Secret"][0]
    check(row["redacted"] and row["encrypted"], "liste des objets : marqué « chiffré » (coffre à déverrouiller)")
    H._VAULT_PW = "autre-phrase-999"
    items, _ = H._load_backup_resources(b["dir"])
    check(H._obj_is_redacted([o for o in items if o["kind"] == "Secret"][0]), "mauvaise phrase de coffre : reste masqué")
    inv = [x for x in H.action_dr_backups()["backups"] if x["namespace"] == "front"][0]
    check(inv["secrets"] == "encrypted", "inventaire DR : secrets=encrypted")

    print("\n== Phrase fournie par l'environnement (déploiement Kubernetes) ==")
    H._VAULT_PW = ""
    H._vault_env_passphrase = lambda: "phrase-du-coffre-1"
    items, _ = H._load_backup_resources(b["dir"])
    check([o for o in items if o["kind"] == "Secret"][0]["data"]["password"] == "c2VjcmV0", "HYCU_VAULT_PASSPHRASE : Secret recomposé")
    H._vault_env_passphrase = lambda: ""

    print("\n== Mode auto SANS phrase : en clair + avertissement explicite ==")
    b2 = H.action_backup("front")
    check(b2["ok"] and b2["secrets"] == "clear" and "EN CLAIR" in (b2.get("secrets_warning") or ""),
          "sans coffre : Secrets en clair, avertissement remonté")
    res2 = json.load(open(os.path.join(b2["dir"], "resources.json")))
    check([o for o in res2["items"] if o["kind"] == "Secret"][0]["data"]["password"] == "c2VjcmV0"
          and not os.path.isfile(os.path.join(b2["dir"], H.SECRETS_FILE)), "resources.json en clair, pas de secrets.enc")

    print("\n== Modes explicites ==")
    H.CONFIG["backup_secrets"] = "encrypted"
    b3 = H.action_backup("front")
    r3 = json.load(open(os.path.join(b3["dir"], "resources.json")))
    check(b3["secrets"] == "redacted" and [o for o in r3["items"] if o["kind"] == "Secret"][0]["data"]["password"] == "__REDACTED__",
          "« encrypted » sans phrase : MASQUÉ (jamais en clair)")
    H.CONFIG["backup_secrets"] = "redacted"
    b4 = H.action_backup("front")
    check(b4["secrets"] == "redacted" and not b4.get("secrets_warning"), "« redacted » : ancien comportement, sans avertissement")
    H.CONFIG["backup_secrets"] = "auto"
    H.CONFIG["config_backup_include_secret_data"] = True
    b5 = H.action_backup("front")
    check(b5["secrets"] == "clear" and not b5.get("secrets_warning"), "ancien réglage include_secret_data=true : clair assumé, sans avertissement")
    H.CONFIG["config_backup_include_secret_data"] = False

    print("\n== Récupération d'un namespace supprimé : le Secret est RECRÉÉ ==")
    H._VAULT_PW = "phrase-du-coffre-1"
    H.resource_state = lambda kind, name, ns=None: ("absent", "")
    applied = []
    real_apply = H._apply_manifest
    def capture(m, basename, dry, label):
        applied.append((m.get("kind"), (m.get("metadata") or {}).get("name"), (m.get("data") or {}).get("password")))
        return real_apply(m, basename, dry, label)
    H._apply_manifest = capture
    try:
        r = H.action_clone_app({"namespace": "front", "target_namespace": "front", "backup_path": b["dir"],
                                "items": [], "dry": True, "from_backup_only": True, "clone_refs": True})
    finally:
        H._apply_manifest = real_apply
    check(r["ok"] and ("Secret", "db-pass", "c2VjcmV0") in applied and ("Deployment", "api", None) in applied,
          "récupération : Secret déchiffré et recréé avec le workload")
    H._VAULT_PW = ""
    applied.clear()
    H._apply_manifest = capture
    try:
        r = H.action_clone_app({"namespace": "front", "target_namespace": "front", "backup_path": b["dir"],
                                "items": [], "dry": True, "from_backup_only": True, "clone_refs": True})
    finally:
        H._apply_manifest = real_apply
    check(r["ok"] and not any(k == "Secret" for k, _n, _p in applied)
          and any("Secret db-pass" in w for w in r.get("warnings", [])),
          "coffre verrouillé : Secret NON recréé (jamais masqué appliqué), signalé comme manquant")
finally:
    H.kubectl_json, H.action_context, H.resource_state, H._vault_env_passphrase, H._VAULT_PW = s_kj, s_ctx, s_rs, s_env, s_pw
    H._CATALOGS.clear()
    H.CONFIG.clear(); H.CONFIG.update(saved)
    shutil.rmtree(tmp, ignore_errors=True)

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
