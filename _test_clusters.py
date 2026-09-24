# -*- coding: utf-8 -*-
"""Multi-cluster (kubeconfigs chargés depuis l'interface) + découverte NKP.
Utilise _fake_kubectl.py : aucun cluster réel requis."""
import base64
import http.client
import json
import os
import shutil
import socketserver
import sys
import tempfile
import threading
import time
import hycu_k8s_nutanix as H

passed = failed = 0
def check(c, m):
    global passed, failed
    if c: passed += 1; print("  OK  ", m)
    else: failed += 1; print("  FAIL", m)


HERE = os.path.dirname(os.path.abspath(__file__))
tmp = tempfile.mkdtemp()


def jwt(exp):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return "%s.%s.sig" % (enc({"alg": "RS256"}), enc({"sub": "x", "exp": exp}))


def kubeconfig(ctx_users, current=""):
    """ctx_users = {contexte: entrée user}."""
    return json.dumps({
        "apiVersion": "v1", "kind": "Config", "current-context": current,
        "clusters": [{"name": c, "cluster": {"server": "https://%s:6443" % c,
                                             "certificate-authority-data": "Q0E="}} for c in ctx_users],
        "users": [{"name": "u-" + c, "user": u} for c, u in ctx_users.items()],
        "contexts": [{"name": c, "context": {"cluster": c, "user": "u-" + c}} for c in ctx_users]})


def pvc(name, pv):
    return {"metadata": {"name": name, "namespace": "app"},
            "spec": {"volumeName": pv, "resources": {"requests": {"storage": "1Gi"}}}, "status": {"phase": "Bound"}}


def pv(name):
    return {"metadata": {"name": name}, "spec": {"csi": {"driver": "csi.nutanix.com",
            "volumeHandle": "NutanixVolumes-11111111-2222-3333-4444-555555555555"}}}


SECRET_TOKEN = "s3cr3t-token-never-shown"
wl_kc = kubeconfig({"wl1-admin@wl1": {"client-certificate-data": "Y2VydA==", "client-key-data": "a2V5"}},
                   current="wl1-admin@wl1")
DATA = {
    "local-ctx": {"namespaces": ["app", "kube-system"], "pvcs": {"app": [pvc("data", "pv-local")]},
                  "pvs": {"pv-local": pv("pv-local")}},
    "prod": {"namespaces": ["app", "shop"], "pvcs": {"app": [pvc("data", "pv-prod")]},
             "pvs": {"pv-prod": pv("pv-prod")}},
    "down": {"unreachable": True},
    "rbac": {"forbidden_ns": True},
    "mgmt": {"namespaces": ["kommander"],
             "workspaces": [{"metadata": {"name": "team-a", "annotations": {H.NKP_DISPLAY_ANN: "Team A"}},
                             "status": {"namespaceRef": {"name": "team-a-x7k2"}}}],
             "kommanderclusters": [
                 {"metadata": {"name": "host-cluster", "namespace": "kommander"}, "spec": {}},
                 {"metadata": {"name": "wl1", "namespace": "team-a-x7k2"},
                  "spec": {"kubeconfigRef": {"name": "wl1-kubeconfig"}}, "status": {"phase": "Joined"}},
                 {"metadata": {"name": "wl2", "namespace": "team-a-x7k2"},
                  "spec": {"kubeconfigRef": {"name": "wl2-kubeconfig"}}}],
             "secrets": {"team-a-x7k2/wl1-kubeconfig": {"data": {
                 "value": base64.b64encode(wl_kc.encode()).decode()}},
                         "team-a-x7k2/evil-kubeconfig": {"data": {"value": base64.b64encode(kubeconfig(
                             {"evil": {"exec": {"command": "/bin/sh", "args": ["-c", "touch /tmp/pwned"]}}},
                             "evil").encode()).decode()}}}},
    "wl1-admin@wl1": {"namespaces": ["web"], "pvcs": {}},
}
data_path = os.path.join(tmp, "data.json")
with open(data_path, "w") as f:
    json.dump(DATA, f)
log_path = os.path.join(tmp, "kubectl.log")
os.environ.update({"FAKE_KUBE_DATA": data_path, "FAKE_LOCAL_CTX": "local-ctx", "FAKE_KUBE_LOG": log_path})

saved_cfg = dict(H.CONFIG)
saved_paths = (H.CONFIG_PATH, H.SECRETS_PATH)
try:
    H.CONFIG_PATH = os.path.join(tmp, "hycu_config.json")
    H.SECRETS_PATH = os.path.join(tmp, "hycu_secrets.enc")
    H.CONFIG.update({"kubectl_path": "%s %s" % (sys.executable, os.path.join(HERE, "_fake_kubectl.py")),
                     "kubeconfig_path": "", "kube_context": "", "backup_root": os.path.join(tmp, "bk"),
                     "namespace_filter": [], "cluster_namespace_filters": {}, "allowed_contexts": [],
                     "config_backup_full": False, "auto_backup_dest": "", "pbkdf2_iterations": 1000})
    H._LOCAL_CTX["at"] = 0.0

    print("== Analyse d'un kubeconfig ==")
    now = time.time()
    multi = kubeconfig({"prod": {"token": SECRET_TOKEN},
                        "expired": {"token": jwt(now - 60)},
                        "soon": {"token": jwt(now + 3600)},
                        "sso": {"exec": {"command": "/usr/local/bin/kubectl-oidc_login", "args": ["get-token"]}}})
    r = H.action_clusters_inspect({"kubeconfig": multi})
    auth = {c["name"]: c["auth"] for c in r.get("contexts", [])}
    check(r["ok"] and len(auth) == 4, "4 contextes détectés")
    check(auth["prod"]["type"] == "token" and auth["prod"]["level"] == "ok", "jeton sans expiration : OK")
    check(auth["expired"]["level"] == "error" and "EXPIRÉ" in auth["expired"]["warnings"][0], "jeton JWT expiré : erreur")
    check(auth["soon"]["level"] == "warn" and "24 h" in auth["soon"]["warnings"][0], "jeton expirant < 24 h : avertissement")
    check(auth["sso"]["type"] == "exec" and "kubectl-oidc_login" in auth["sso"]["warnings"][0], "plugin exec : avertissement")
    check(SECRET_TOKEN not in json.dumps(r), "l'analyse ne renvoie jamais le jeton")
    check(not H.action_clusters_inspect({"kubeconfig": "pas du json"})["ok"], "kubeconfig invalide refusé")
    check(not os.listdir(H._kc_dir()), "aucun fichier temporaire laissé par l'analyse")

    print("\n== Ajout / retrait ==")
    r = H.action_clusters_add({"name": "Prod", "kubeconfig": multi})
    check(not r["ok"] and r.get("need_context"), "plusieurs contextes sans courant : choix exigé")
    r = H.action_clusters_add({"name": "Down", "kubeconfig": kubeconfig({"down": {"token": "t"}}, "down")})
    check(not r["ok"] and "impossible" in r["error"], "cluster injoignable refusé : %s" % r.get("error", "")[:60])
    check(not os.listdir(H._kc_dir()), "kubeconfig refusé : fichier supprimé")
    r = H.action_clusters_add({"name": "RBAC", "kubeconfig": kubeconfig({"rbac": {"token": "t"}}, "rbac")})
    check(r["ok"] and "RBAC" in (r["cluster"]["warning"] or ""), "liste des namespaces refusée : accepté avec avertissement")
    H.action_clusters_remove({"id": r["cluster"]["id"]})
    r = H.action_clusters_add({"name": "Prod", "kubeconfig": multi, "context": "prod"})
    check(r["ok"] and r["cluster"]["id"] == "prod" and r["cluster"]["context"] == "prod", "cluster « Prod » ajouté")
    kc_file = H._get_cluster("prod")["kc_path"]
    check(oct(os.stat(kc_file).st_mode & 0o777) == "0o600", "kubeconfig stocké en 0600")
    check(not H.action_clusters_add({"name": "prod", "kubeconfig": multi, "context": "prod"})["ok"], "doublon refusé")
    check(not H.action_clusters_add({"name": "local", "kubeconfig": multi, "context": "prod"})["ok"], "nom « local » réservé")
    check(not H.action_clusters_add({"name": "local-ctx", "kubeconfig": multi, "context": "prod"})["ok"],
          "nom du contexte local réservé")
    lst = H.action_clusters()
    check([c["id"] for c in lst["clusters"]] == ["local", "prod"] and lst["clusters"][0]["name"] == "local-ctx",
          "liste : local (nom du contexte) + Prod")
    check(SECRET_TOKEN not in json.dumps(lst) and kc_file not in json.dumps(lst), "la liste n'expose ni jeton ni chemin")

    print("\n== Routage par cluster ==")
    check(H.action_namespaces()["namespaces"] == ["app", "kube-system"], "par défaut : cluster local")
    with H.use_cluster("prod"):
        check(H.action_namespaces()["namespaces"] == ["app", "shop"], "use_cluster(prod) : namespaces de Prod")
        ctx = H.action_context()
        check(ctx["context"] == "Prod" and ctx["kube_context"] == "prod" and ctx["kubectl_ok"], "contexte = nom du cluster")
        k = H.kubectl(["get", "ns"], dry=True)
        check("<kubeconfig>" in k["cmd"] and kc_file not in k["cmd"], "chemin du kubeconfig masqué dans les logs")
    n_before = sum(1 for _ in open(log_path))
    with H.use_cluster("inconnu"):
        r = H.action_namespaces()
        check(not r["ok"] and "inconnu" in r["error"], "cluster inconnu : erreur explicite")
        check(not H.action_context()["kubectl_ok"], "cluster inconnu : contexte non valide")
    check(sum(1 for _ in open(log_path)) == n_before, "cluster inconnu : AUCUNE commande exécutée (pas de repli local)")

    print("\n== Sauvegardes séparées par cluster ==")
    b_local = H.action_backup("app")
    with H.use_cluster("prod"):
        b_prod = H.action_backup("app")
        lp = H.list_backups("app")
    ll = H.list_backups("app")
    check(b_local["ok"] and b_prod["ok"], "sauvegarde sur les deux clusters")
    check(os.sep + os.path.join("_clusters", "prod", "app") + os.sep in b_prod["dir"], "Prod : <root>/_clusters/prod/app/…")
    check("_clusters" not in b_local["dir"], "local : disposition historique inchangée")
    check(len(lp) == 1 and lp[0]["index"]["cluster_id"] == "prod" and lp[0]["index"]["cluster"] == "Prod",
          "index : cluster enregistré")
    check(len(ll) == 1 and ll[0]["path"] == b_local["dir"], "les listes ne se mélangent pas")
    r = H.action_prepare_restore({"namespace": "app", "backup_path": b_prod["dir"],
                                  "items": [{"pvc": "data", "new_ref": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]})
    check(not r["ok"] and "inter-clusters" in r["error"], "garde : sauvegarde de Prod refusée sur le cluster local")
    with H.use_cluster("prod"):
        r = H.action_prepare_restore({"namespace": "app", "backup_path": b_prod["dir"],
                                      "items": [{"pvc": "data", "new_ref": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]})
        check(r["ok"], "même cluster : préparation acceptée")
        r = H.action_clone_app({"namespace": "app", "target_namespace": "copie", "backup_path": b_local["dir"],
                                "items": [{"pvc": "data", "new_ref": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]})
        check(not r["ok"] and "inter-clusters" in r["error"], "garde : clone depuis une sauvegarde locale refusé sur Prod")
        check(H._txn_path("app").startswith(os.path.join(H.CONFIG["backup_root"], "_clusters", "prod")),
              "transaction de restauration rangée sous le cluster")
    recs = [json.loads(l) for l in open(os.path.join(H.CONFIG["backup_root"], "audit.log"))]
    bk = [x for x in recs if x["event"] == "backup"]
    check([x["cluster"] for x in bk] == ["local-ctx", "Prod"], "audit : cluster enregistré à chaque action")
    check([j["cluster"] for j in H.action_jobs()["jobs"] if j["event"] == "backup"] == ["Prod", "local-ctx"],
          "tâches : colonne cluster")

    print("\n== Filtre de namespaces par cluster ==")
    with H.use_cluster("prod"):
        H.action_set_ns_filter({"filter": ["shop"]})
        check(H.action_namespaces()["namespaces"] == ["shop"], "Prod filtré sur « shop »")
    check(H.action_namespaces()["namespaces"] == ["app", "kube-system"], "le cluster local n'est pas affecté")
    check(H.CONFIG["cluster_namespace_filters"] == {"Prod": ["shop"]}, "filtre persistant par nom de cluster")
    with H.use_cluster("prod"):
        H.action_set_ns_filter({"filter": []})

    print("\n== Vue Applications multi-cluster ==")
    DATA["down"] = {"unreachable": True}
    a = H.action_applications_all()
    by = {(x["cluster_id"], x["name"]) for x in a["apps"]}
    check(("local", "app") in by and ("prod", "shop") in by, "applications des deux clusters, étiquetées")
    check(all(c["ok"] for c in a["clusters"]), "état par cluster")

    print("\n== Sauvegarde automatique multi-cluster ==")
    H.AUTO_BACKUP.update({"last_run": 0})
    ok = H._auto_backup_run(now=5000.0)
    s = H.AUTO_BACKUP["last_summary"]
    check(ok and "local-ctx :" in s and "Prod :" in s, "chaque cluster sauvegardé : %s" % s)
    with H.use_cluster("prod"):
        check(len(H.list_backups("app")) == 2, "nouvelle version sous le dossier de Prod")

    print("\n== Opérations longues : cluster hérité ==")
    with H.use_cluster("prod"):
        op = H._run_async(lambda p, log: {"ok": True, "cid": H._current_cid()}, {})
    for _ in range(100):
        st = H.action_op_status(op["op_id"])
        if st["done"]:
            break
        time.sleep(0.02)
    check(st["result"]["cid"] == "prod", "le thread de l'opération cible le cluster de la requête")

    print("\n== Coffre + verrouillage de session ==")
    r = H.action_save_credentials({"passphrase": "phrase-secrete-1"})
    check(r["ok"] and r["clusters"] == ["Prod"], "cluster enregistré dans le coffre chiffré")
    raw = open(H.SECRETS_PATH).read() + open(H.CONFIG_PATH).read()
    check(SECRET_TOKEN not in raw and "prod:6443" not in raw, "kubeconfig absent en clair (coffre + config)")
    H.UI_SESSION["id"] = "old"
    H.check_ui_session(None)
    check(H.action_clusters()["clusters"][1:] == [] and not os.path.exists(kc_file),
          "nouvelle session navigateur : clusters oubliés, fichier effacé")
    r = H.action_load_credentials({"passphrase": "phrase-secrete-1"})
    check(r["ok"] and r["clusters"] == ["Prod"] and H._get_cluster("prod")["context"] == "prod", "déverrouillage : cluster rechargé")

    print("\n== En-tête HTTP X-HYCU-Cluster ==")
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H.Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def get(path, cluster=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
        c.request("GET", path, headers={"X-HYCU-Cluster": cluster} if cluster else {})
        return json.loads(c.getresponse().read())
    check(get("/api/namespaces")["namespaces"] == ["app", "kube-system"], "sans en-tête : local")
    check(get("/api/namespaces", "prod")["namespaces"] == ["app", "shop"], "en-tête prod : Prod")
    check(not get("/api/namespaces", "zzz")["ok"], "en-tête inconnu : refus")
    check(get("/api/context", "prod")["context"] == "Prod", "/api/context suit l'en-tête")

    print("\n== Découverte NKP ==")
    check(not H.action_nkp_discover()["ok"], "cluster non-management : erreur claire")
    mg = H.action_clusters_add({"name": "mgmt", "kubeconfig": kubeconfig({"mgmt": {"token": "t"}}, "mgmt")})
    check(mg["ok"], "cluster de management ajouté")
    with H.use_cluster("mgmt"):
        d = H.action_nkp_discover()
        check(d["ok"] and d["workspaces"][0]["display"] == "Team A" and d["workspaces"][0]["clusters"] == 2,
              "workspace « Team A » (namespace résolu via status.namespaceRef)")
        cl = {c["name"]: c for c in d["clusters"]}
        check(cl["host-cluster"]["host"] and not cl["wl1"]["host"], "cluster de management repéré (host-cluster)")
        check(cl["wl1"]["workspace"] == "Team A" and cl["wl1"]["secret"] == "wl1-kubeconfig", "wl1 : workspace + Secret")
        check(not H.action_nkp_import({"items": [cl["wl1"]]})["ok"], "import sans acquittement des privilèges : refusé")
        r = H.action_nkp_import({"ack": True, "items": [cl["wl1"], cl["wl2"]]})
        res = {x["cluster"]: x for x in r["results"]}
        check(r["imported"] == 1 and res["team-a-x7k2/wl1"]["ok"], "wl1 importé depuis son Secret")
        check(not res["team-a-x7k2/wl2"]["ok"] and "illisible" in res["team-a-x7k2/wl2"]["error"],
              "wl2 : Secret absent -> erreur par cluster, sans bloquer les autres")
        again = {c["name"]: c for c in H.action_nkp_discover()["clusters"]}
        check(again["wl1"]["registered"] == "wl1" and not again["wl2"]["registered"],
              "redécouverte : wl1 marqué déjà importé")
        r = H.action_nkp_import({"ack": True, "items": [{"namespace": "team-a-x7k2", "name": "evil",
                                                         "secret": "evil-kubeconfig"}]})
        check(not r["results"][0]["ok"] and "exec" in r["results"][0]["error"] and not H._get_cluster("evil"),
              "import NKP : kubeconfig à plugin exec refusé (pas d'exécution de commande)")
    w = H._get_cluster("wl1")
    check(w["workspace"] == "Team A" and w["source"] == "nkp" and w["management"] == "mgmt", "wl1 rattaché au workspace")
    with H.use_cluster("wl1"):
        check(H.action_namespaces()["namespaces"] == ["web"], "wl1 joignable avec le kubeconfig importé")
    a = H.action_applications_all()
    check([x["workspace"] for x in a["apps"] if x["cluster_id"] == "wl1"] == ["Team A"],
          "Applications : workspace porté par chaque ligne")
    recs = [json.loads(l) for l in open(os.path.join(H.CONFIG["backup_root"], "audit.log"))]
    check(any(x["event"] == "nkp_import" and x["cluster"] == "wl1" and x["workspace"] == "Team A" for x in recs),
          "audit : import NKP tracé")
    check("hycu_clusters_registered 4" in H.action_metrics_text(), "métrique hycu_clusters_registered")
    srv.shutdown()
finally:
    H._wipe_clusters()
    H.CONFIG.clear(); H.CONFIG.update(saved_cfg)
    H.CONFIG_PATH, H.SECRETS_PATH = saved_paths
    shutil.rmtree(tmp, ignore_errors=True)

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
