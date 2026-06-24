# -*- coding: utf-8 -*-
"""Tests du clone des dépendances cross-namespace (Secrets/ConfigMaps/SA/Services)."""
import json
import hycu_k8s_nutanix as H

passed = failed = 0
def check(c, m):
    global passed, failed
    if c: passed += 1; print("  OK  ", m)
    else: failed += 1; print("  FAIL", m)

# Workload type WordPress (référence un Secret via envFrom, un ConfigMap via env, un SA)
WL = {"kind": "Deployment", "metadata": {"name": "wordpress"},
      "spec": {"selector": {"matchLabels": {"app": "wordpress"}},
               "template": {"metadata": {"labels": {"app": "wordpress"}},
                            "spec": {"serviceAccountName": "wp-sa",
                                     "imagePullSecrets": [{"name": "regcred"}],
                                     "volumes": [{"secret": {"secretName": "tls-secret"}},
                                                 {"configMap": {"name": "wp-config"}}],
                                     "containers": [{"name": "wp",
                                        "envFrom": [{"secretRef": {"name": "wordpress-db-secret"}}],
                                        "env": [{"valueFrom": {"configMapKeyRef": {"name": "wp-env"}}}]}]}}}}

print("\n== 1. _referenced_objects ==")
r = H._referenced_objects(WL)
check(r["secrets"] == {"regcred", "tls-secret", "wordpress-db-secret"}, "secrets détectés (envFrom+volume+imagePullSecret)")
check(r["configmaps"] == {"wp-config", "wp-env"}, "configmaps détectés (volume+env)")
check(r["serviceaccount"] == "wp-sa", "serviceAccount détecté")

print("\n== 2. _prepare_cloned_object : Service ==")
svc = {"kind": "Service", "metadata": {"name": "mariadb", "namespace": "wordpress",
        "uid": "x", "resourceVersion": "9"},
       "spec": {"clusterIP": "10.0.0.5", "clusterIPs": ["10.0.0.5"], "type": "ClusterIP",
                "selector": {"app": "mariadb"}, "ports": [{"port": 3306, "nodePort": 31000}]},
       "status": {"x": 1}}
o = H._prepare_cloned_object(svc, "restore")
check(o["metadata"]["namespace"] == "restore", "namespace -> cible")
check("uid" not in o["metadata"] and "resourceVersion" not in o["metadata"], "identité runtime retirée")
check("clusterIP" not in o["spec"] and "clusterIPs" not in o["spec"], "clusterIP(s) retiré(s)")
check("nodePort" not in o["spec"]["ports"][0], "nodePort retiré")
check("status" not in o, "status retiré")
check(o["metadata"]["labels"][H.CLONE_LABEL] == H.CLONE_LABEL_VAL, "label de clone posé")
check(o["spec"]["selector"] == {"app": "mariadb"}, "sélecteur conservé")

print("\n== 3. _prepare_cloned_object : Secret ==")
sec = {"kind": "Secret", "metadata": {"name": "s", "namespace": "wordpress", "uid": "u"},
       "type": "Opaque", "data": {"k": "dg=="}}
o2 = H._prepare_cloned_object(sec, "restore")
check(o2["metadata"]["namespace"] == "restore" and o2["data"] == {"k": "dg=="}, "secret re-namespacé, data conservée")

print("\n== 4. _services_for_workloads (mock kubectl) ==")
SVCS = {"items": [
    {"kind": "Service", "metadata": {"name": "mariadb", "namespace": "wordpress"},
     "spec": {"selector": {"app": "mariadb"}, "ports": [{"port": 3306}]}},
    {"kind": "Service", "metadata": {"name": "wordpress", "namespace": "wordpress"},
     "spec": {"selector": {"app": "wordpress"}, "ports": [{"port": 80}]}},
    {"kind": "Service", "metadata": {"name": "autre", "namespace": "wordpress"},
     "spec": {"selector": {"app": "rien"}, "ports": [{"port": 1}]}},
    {"kind": "Service", "metadata": {"name": "headless", "namespace": "wordpress"},
     "spec": {"ports": [{"port": 9}]}},  # sans selector -> ignoré
]}
H.kubectl_json = lambda args: (SVCS, None)
cloned_wls = [
    {"kind": "Deployment", "spec": {"template": {"metadata": {"labels": {"app": "mariadb"}}}}},
    {"kind": "Deployment", "spec": {"template": {"metadata": {"labels": {"app": "wordpress"}}}}},
]
svcs = H._services_for_workloads("wordpress", cloned_wls, "restore")
names = sorted(s["metadata"]["name"] for s in svcs)
check(names == ["mariadb", "wordpress"], "seuls les Services ciblant les pods clonés (mariadb, wordpress)")
check(all(s["metadata"]["namespace"] == "restore" for s in svcs), "Services re-namespacés vers cible")

print("\n== 5. _fetch_for_clone : ignore les tokens de SA ==")
H.kubectl_json = lambda args: ({"kind": "Secret", "metadata": {"name": "tok", "namespace": "wordpress"},
                                "type": "kubernetes.io/service-account.token"}, None)
check(H._fetch_for_clone("secret", "tok", "wordpress", "restore") is None, "token de SA non cloné")
H.kubectl_json = lambda args: ({"kind": "Secret", "metadata": {"name": "ok", "namespace": "wordpress"},
                                "type": "Opaque", "data": {}}, None)
got = H._fetch_for_clone("secret", "ok", "wordpress", "restore")
check(got is not None and got["metadata"]["namespace"] == "restore", "secret normal cloné + re-namespacé")

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
