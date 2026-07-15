# -*- coding: utf-8 -*-
"""Sauvegarde de configuration ÉTENDUE (au-delà des PV/PVC) + endpoint /metrics.
Vérifie : nettoyage des manifestes, masquage des Secrets, robustesse (type refusé
ignoré), écriture de resources.json, et le format Prometheus des métriques."""
import json
import os
import shutil
import tempfile
import hycu_k8s_nutanix as H

passed = failed = 0
def check(c, m):
    global passed, failed
    if c: passed += 1; print("  OK  ", m)
    else: failed += 1; print("  FAIL", m)


# ---- _clean_resource : status/meta retirés, Secret masqué par défaut ----
dep = {"kind": "Deployment", "status": {"replicas": 3},
       "metadata": {"name": "web", "uid": "u", "resourceVersion": "42",
                    "managedFields": [{"x": 1}], "annotations": {
                        "kubectl.kubernetes.io/last-applied-configuration": "{...}"}},
       "spec": {"replicas": 3}}
c = H._clean_resource(json.loads(json.dumps(dep)))
check("status" not in c, "Deployment : status retiré")
check("uid" not in c["metadata"] and "managedFields" not in c["metadata"], "métadonnées runtime retirées")
check("annotations" not in c["metadata"], "annotation last-applied retirée")

sec = {"kind": "Secret", "type": "Opaque", "metadata": {"name": "db"},
       "data": {"password": "cwd=", "user": "cm9vdA=="}, "stringData": {"x": "y"}}
c = H._clean_resource(json.loads(json.dumps(sec)))
check(c["data"] == {"password": "__REDACTED__", "user": "__REDACTED__"}, "Secret : données MASQUÉES par défaut")
check("stringData" not in c, "Secret : stringData retiré")
check(c["metadata"]["annotations"]["hycu.backup/secret-data"] == "redacted", "Secret : marqueur 'redacted'")
c2 = H._clean_resource(json.loads(json.dumps(sec)), include_secret_data=True)
check(c2["data"]["password"] == "cwd=", "Secret : données conservées si include_secret_data=True")

sa = {"kind": "ServiceAccount", "metadata": {"name": "sa"}, "secrets": [{"name": "sa-token-xxx"}]}
check("secrets" not in H._clean_resource(json.loads(json.dumps(sa))), "ServiceAccount : tokens auto retirés")

# ---- _backup_namespace_resources : robustesse + resources.json ----
tmp = tempfile.mkdtemp()
old_kj = H.kubectl_json
old_kinds = H.CONFIG.get("config_backup_kinds")
old_incl = H.CONFIG.get("config_backup_include_secret_data")
try:
    H.CONFIG["config_backup_kinds"] = ["deployment", "secret", "ingress"]
    H.CONFIG["config_backup_include_secret_data"] = False
    def fake(args):
        kind = args[1]
        if kind == "deployment":
            return {"items": [{"kind": "Deployment", "metadata": {"name": "web", "uid": "u"},
                               "status": {"x": 1}, "spec": {}}]}, None
        if kind == "secret":
            return {"items": [{"kind": "Secret", "metadata": {"name": "db"},
                               "data": {"p": "cwd="}}]}, None
        if kind == "ingress":
            return None, "error: the server doesn't have a resource type \"ingress\""  # RBAC/absent
        return {"items": []}, None
    H.kubectl_json = fake
    n, skipped = H._backup_namespace_resources("wordpress", tmp)
    check(n == 2, "2 objets exportés (Deployment + Secret)")
    check(skipped == ["ingress"], "type en erreur IGNORÉ (pas d'échec)")
    saved = json.load(open(os.path.join(tmp, "resources.json"), encoding="utf-8"))
    check(saved["namespace"] == "wordpress" and len(saved["items"]) == 2, "resources.json écrit")
    sec_item = [x for x in saved["items"] if x["kind"] == "Secret"][0]
    check(sec_item["data"]["p"] == "__REDACTED__", "Secret masqué dans resources.json")
    check("status" not in saved["items"][0], "manifeste nettoyé dans resources.json")
finally:
    H.kubectl_json = old_kj
    H.CONFIG["config_backup_kinds"] = old_kinds
    H.CONFIG["config_backup_include_secret_data"] = old_incl
    shutil.rmtree(tmp, ignore_errors=True)

# ---- action_metrics_text : format Prometheus ----
m = H.action_metrics_text()
check("hycu_up 1" in m, "métrique hycu_up présente")
check('hycu_build_info{version="' in m, "hycu_build_info avec label version")
check("# TYPE hycu_auto_backup_enabled gauge" in m, "en-tête TYPE présent")
check('hycu_connected{system="hycu"}' in m, "hycu_connected par système")
check(m.count("# HELP hycu_connected") == 1, "un seul bloc HELP pour hycu_connected multi-lignes")
check("__REDACTED__" not in m and "password" not in m, "aucune donnée sensible dans /metrics")

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
