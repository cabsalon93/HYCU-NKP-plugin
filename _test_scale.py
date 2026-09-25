# -*- coding: utf-8 -*-
"""Grands clusters (centaines / milliers de namespaces) :
- extraction LÉGÈRE des workloads (jsonpath -> objets synthétiques) et mode complet
  réservé au clone ; repli par namespace BORNÉ quand la liste cluster-wide est refusée ;
- CATALOGUE des sauvegardes (fichier plat JSON dérivé) : construction, réutilisation,
  invalidation (nouvelle sauvegarde, rétention, dossier sans index), consommateurs
  (page Applications, inventaire DR, quota, stockage) ;
- cache de l'inventaire Applications (TTL, fresh, single-flight) ;
- passage de sauvegarde : PV lus une fois, parallélisme, quota appliqué une fois."""
import datetime
import json
import os
import shutil
import tempfile
import threading
import time
import hycu_k8s_nutanix as H

passed = failed = 0
def check(c, m):
    global passed, failed
    if c: passed += 1; print("  OK  ", m)
    else: failed += 1; print("  FAIL", m)


tmp = tempfile.mkdtemp()
saved = dict(H.CONFIG)
s_run, s_kj, s_ns, s_wl, s_bk = H.run, H.kubectl_json, H.action_namespaces, H._list_namespace_workloads, H.action_backup
s_lock = H.ACTION_LOCK
try:
    H.CONFIG.update({"backup_root": tmp, "auto_backup_enabled": False, "auto_backup_dest": "",
                     "namespace_filter": [], "cluster_namespace_filters": {}, "namespace_label_selector": "",
                     "storage_min_free_mb": 0, "storage_quota_gb": 0, "apps_cache_ttl_s": 45,
                     "apps_fallback_max": 3, "backup_parallel": 4, "backup_pv_prefetch_min": 2})
    H.CONFIG_PATH = os.path.join(tmp, "hycu_config.json")
    H._LOCAL_CTX.update({"name": "ctx-scale", "at": time.time() + 9999})
    H._apps_cache_clear()

    print("== Extraction légère des workloads (jsonpath) ==")
    calls = []
    LIGHT_WL = ["shop\tDeployment\tweb\twp\t\t\t2\t\tdata\t\t",
                "shop\tStatefulSet\tdb\twp\tmariadb\t\t1\t\t\t\tdata",
                "shop\tJob\tcleanup-1\t\t\tredis\t\tCronJob\t\t\t",
                "shop\tCronJob\tcleanup\t\t\tredis\t\t\t\t\t",
                "other\tDeployment\tapi\t\t\t\t3\t\t\t\t"]
    LIGHT_PVC = ["shop\tdata", "shop\tdata-db-0", "other\tcache"]
    def fake_run(cmd, dry=False, label=None, timeout=None, input_text=None):
        calls.append(cmd)
        args = [c for c in cmd if c != "kubectl"]
        tpl = [a for a in args if a.startswith("jsonpath=")]
        if "-A" in args and tpl:
            lines = LIGHT_WL if "volumeClaimTemplates" in tpl[0] else LIGHT_PVC
            return {"ok": True, "dry": False, "cmd": " ".join(cmd), "stdout": "\n".join(lines), "stderr": "", "rc": 0, "label": ""}
        return {"ok": False, "dry": False, "cmd": " ".join(cmd), "stdout": "", "stderr": "Forbidden", "rc": 1, "label": ""}
    H.run = fake_run
    H.kubectl_json = lambda args: (None, "ne doit pas être appelé en mode léger : %s" % args)
    wl, pvcs, err = H._list_namespace_workloads(["shop", "other"])
    check(err is None and set(wl) == {"shop", "other"} and pvcs == {"shop": ["data", "data-db-0"], "other": ["cache"]},
          "2 appels cluster-wide, objets synthétiques par namespace")
    check(not any("-o" in c and "json" in c for c in calls), "aucun JSON complet demandé (mémoire)")
    apps = {a["name"]: a for a in H._apps_from_workloads("shop", wl["shop"], pvcs["shop"])}
    check(set(apps) == {"wp", "redis"} and apps["wp"]["type"] == "stateful" and apps["wp"]["pvcs"] == ["data", "data-db-0"]
          and apps["wp"]["workloads"][0]["replicas"] == 2 and apps["redis"]["type"] == "stateless"
          and [w["name"] for w in apps["redis"]["workloads"]] == ["cleanup"],
          "regroupement identique au mode JSON : étiquettes, réplicas, PVC, volumeClaimTemplates, Job dérivé ignoré")
    # objet UNIQUE : kubectl n'enveloppe pas dans .items -> sortie vide -> relecture JSON
    calls.clear()
    def fake_run_single(cmd, **kw):
        args = [c for c in cmd if c != "kubectl"]
        if any(a.startswith("jsonpath=") for a in args):
            return {"ok": True, "dry": False, "cmd": "", "stdout": "", "stderr": "", "rc": 0, "label": ""}
        return {"ok": False, "dry": False, "cmd": "", "stdout": "", "stderr": "x", "rc": 1, "label": ""}
    H.run = fake_run_single
    single = {"kind": "Deployment", "metadata": {"name": "solo", "namespace": "shop"}, "spec": {"template": {"spec": {}}}}
    H.kubectl_json = lambda args: ({"items": [single]} if "pvc" not in args else {"items": []}, None)
    wl, pvcs, err = H._list_namespace_workloads(["shop"])
    check(err is None and [w["metadata"]["name"] for w in wl["shop"]] == ["solo"], "objet unique : relecture JSON (cas kubectl sans .items)")
    # mode complet (clone) : JSON intégral
    H.kubectl_json = lambda args: ({"items": [single]} if "pvc" not in args else {"items": []}, None)
    wl, _p, err = H._list_namespace_workloads(["shop"], full=True)
    check(err is None and wl["shop"][0]["spec"] == single["spec"] and "template" in wl["shop"][0]["spec"], "mode complet : manifestes JSON entiers (clone)")

    print("\n== Repli par namespace BORNÉ ==")
    seen = []
    # cluster-wide (-A) refusé ; par namespace : jsonpath vide -> relecture JSON (comptée ci-dessous)
    H.run = lambda cmd, **kw: ({"ok": False, "dry": False, "cmd": "", "stdout": "", "stderr": "Error from server (Forbidden): cluster-wide", "rc": 1, "label": ""}
                              if "-A" in cmd else {"ok": True, "dry": False, "cmd": "", "stdout": "", "stderr": "", "rc": 0, "label": ""})
    def kj_ns(args):
        seen.append(args)
        return {"items": []}, None
    H.kubectl_json = kj_ns
    wl, pvcs, err = H._list_namespace_workloads(["a", "b", "c", "d"])
    check(wl == {} and "cluster-wide" in (err or "") and not any("-n" in a for a in seen),
          "4 namespaces > apps_fallback_max=3 : aucun appel par namespace, erreur explicite")
    seen.clear()
    wl, pvcs, err = H._list_namespace_workloads(["a", "b"])
    check(set(wl) == {"a", "b"} and sum(1 for a in seen if "-n" in a) == 4, "2 namespaces ≤ borne : repli par namespace (2 kinds × 2)")
    H.run, H.kubectl_json = s_run, s_kj

    print("\n== Catalogue des sauvegardes : construction, réutilisation, invalidation ==")
    croot = H._cluster_root(tmp)
    def mk(ns, when, volumes=("data",), extra=None):
        d = os.path.join(croot, ns, when)
        os.makedirs(d)
        idx = {"namespace": ns, "created": "2026-09-25T%s:00:00" % when[11:13], "context": "ctx-scale",
               "cluster_id": "local", "volumes": [{"pvc": v, "pv": "pv-" + v,
                                                    "analysis": {"old_volume_handle": "NutanixVolumes-11111111-2222-3333-4444-%012d" % i}}
                                                   for i, v in enumerate(volumes)]}
        idx.update(extra or {})
        with open(os.path.join(d, "index.json"), "w") as f:
            json.dump(idx, f)
        with open(os.path.join(d, "pv_x.json"), "w") as f:
            f.write("x" * 1000)
        return d
    for i in range(3):
        for j in range(2):
            mk("ns%d" % i, "2026-09-25_0%d-00-00_00000%d" % (j + 1, j))
    reads = []
    real_open = open
    cat = H._catalog_all(croot)
    check(set(cat) == {"ns0", "ns1", "ns2"} and all(len(v) == 2 for v in cat.values())
          and cat["ns0"][0]["ts"] > cat["ns0"][1]["ts"] and cat["ns0"][0]["size"] > 1000,
          "catalogue construit : 3 namespaces × 2 versions, plus récentes d'abord, tailles")
    check(os.path.isfile(os.path.join(croot, H.CATALOG_FILE)), "fichier _catalog.json écrit à côté des sauvegardes")
    # Réutilisation : aucun index.json relu tant que rien ne change.
    s_summary = H._catalog_summary
    cnt = {"n": 0}
    def counting_summary(path, idx):
        cnt["n"] += 1
        return s_summary(path, idx)
    H._catalog_summary = counting_summary
    cat2 = H._catalog_all(croot)
    check(cnt["n"] == 0 and cat2 == cat, "rien n'a changé : aucune version relue")
    # Nouvelle sauvegarde (dossier + index) -> seule la nouvelle version est lue.
    mk("ns1", "2026-09-25_03-00-00_000002")
    cat3 = H._catalog_all(croot)
    check(cnt["n"] == 1 and len(cat3["ns1"]) == 3 and cat3["ns1"][0]["ts"].startswith("2026-09-25_03"),
          "nouvelle sauvegarde : 1 seule lecture, version ajoutée en tête")
    # Dossier sans index.json (sauvegarde en cours d'écriture) : ignoré puis pris en compte.
    pend = os.path.join(croot, "ns2", "2026-09-25_04-00-00_000003")
    os.makedirs(pend)
    cat4 = H._catalog_all(croot)
    check(len(cat4["ns2"]) == 2, "dossier sans index : ignoré (sauvegarde en cours)")
    with open(os.path.join(pend, "index.json"), "w") as f:
        json.dump({"namespace": "ns2", "created": "2026-09-25T04:00:00", "cluster_id": "local", "volumes": []}, f)
    cat5 = H._catalog_all(croot)
    check(len(cat5["ns2"]) == 3, "index.json apparu sans changement du dossier parent : détecté (pending revérifié)")
    # Rétention -> oubli explicite -> version disparue du catalogue.
    removed = H._prune_backups(tmp, "ns1", 1)
    cat6 = H._catalog_all(croot)
    check(removed == 2 and len(cat6["ns1"]) == 1, "rétention : versions purgées retirées du catalogue")
    # Redémarrage (mémoire vidée) : le fichier suffit, aucune relecture d'index.
    cnt["n"] = 0
    H._CATALOGS.clear()
    cat7 = H._catalog_all(croot)
    check(cnt["n"] == 0 and cat7 == cat6, "après redémarrage : catalogue rechargé depuis le fichier, aucune relecture")
    # Catalogue corrompu : reconstruit.
    with open(os.path.join(croot, H.CATALOG_FILE), "w") as f:
        f.write("{corrompu")
    H._CATALOGS.clear()
    cat8 = H._catalog_all(croot)
    check(cat8 == cat6 and cnt["n"] >= 1, "catalogue corrompu : reconstruit depuis les index.json")
    H._catalog_summary = s_summary

    print("\n== Consommateurs du catalogue ==")
    H.action_namespaces = lambda: {"ok": True, "namespaces": ["ns0", "ns1"]}
    H._list_namespace_workloads = lambda names, full=False: ({n: [] for n in names}, {n: ["data"] for n in names}, None)
    r = H.action_applications()
    rows = {a["namespace"]: a for a in r["apps"]}
    check(set(rows) == {"ns0", "ns1", "ns2"} and rows["ns2"]["missing"] and rows["ns1"]["backups"] == 1
          and rows["ns0"]["backups"] == 2 and rows["ns0"]["protected"],
          "page Applications depuis le catalogue : versions, namespace supprimé listé")
    inv = H.action_dr_backups()["backups"]
    b0 = [b for b in inv if b["namespace"] == "ns0"][0]
    check(len(inv) == 6 and b0["restorable_here"] and b0["vol_refs"] == {"data": "11111111-2222-3333-4444-000000000000"}
          and b0["path"].endswith(os.path.join("ns0", b0["timestamp"])) and os.path.isdir(b0["path"]),
          "inventaire DR depuis le catalogue : chemins, UUID d'origine, restaurable ici")
    H._LOCAL_CTX.update({"name": "autre-ctx", "at": time.time() + 9999})
    check(not any(b["restorable_here"] for b in H.action_dr_backups()["backups"] if b["context"]), "autre contexte kubectl : plus restaurable ici (sauvegardes sans contexte : rattachées au local)")
    H._LOCAL_CTX.update({"name": "ctx-scale", "at": time.time() + 9999})
    dirs = H._all_backup_dirs(tmp)
    check(len(dirs) == 6 and all(os.path.isdir(p) and s > 0 and k == "local|" + os.path.basename(os.path.dirname(p)) for p, e, s, k in dirs),
          "quota : liste des sauvegardes (chemin, taille, clé) depuis le catalogue")
    st = H.action_storage()["roots"][0]
    check(st["backups_count"] == 6 and st["backups_bytes"] > 6000, "tuile Stockage : compte et volume depuis le catalogue")

    print("\n== Cache de l'inventaire Applications ==")
    H._apps_cache_clear()
    n_calls = {"n": 0}
    real_apps = H.action_applications
    def counting_apps():
        n_calls["n"] += 1
        time.sleep(0.05)
        return real_apps()
    H.action_applications = counting_apps
    r1 = H.action_applications_cached()
    r2 = H.action_applications_cached()
    check(n_calls["n"] == 1 and "cached_age" in r2 and r2["apps"] == r1["apps"], "2e appel servi par le cache (TTL)")
    r3 = H.action_applications_cached(fresh=True)
    check(n_calls["n"] == 2 and "cached_age" not in r3, "fresh=1 : recalcul forcé")
    n_calls["n"] = 0
    H._apps_cache_clear()
    out = []
    ths = [threading.Thread(target=lambda: out.append(H.action_applications_cached())) for _ in range(5)]
    [t.start() for t in ths]; [t.join() for t in ths]
    check(n_calls["n"] == 1 and len(out) == 5, "5 appels concurrents : un seul calcul (single-flight)")
    H.CONFIG["apps_cache_ttl_s"] = 0
    H.action_applications_cached(); H.action_applications_cached()
    check(n_calls["n"] == 3, "TTL 0 : cache désactivé")
    H.CONFIG["apps_cache_ttl_s"] = 45
    H.action_applications = real_apps

    print("\n== Passage de sauvegarde : PV lus une fois, parallélisme, quota une fois ==")
    H.action_namespaces = lambda: {"ok": True, "namespaces": ["n1", "n2", "n3", "n4"]}
    got = {"pv_calls": 0, "quota": 0, "threads": set(), "cache": []}
    def kj_pass(args):
        if args[:2] == ["get", "pv"]:
            got["pv_calls"] += 1
            return {"items": [{"metadata": {"name": "pv-a"}}, {"metadata": {"name": "pv-b"}}]}, None
        return {"items": []}, None
    H.kubectl_json = kj_pass
    def fake_backup(ns, dest=None, protect=None, pv_cache=None, defer_quota=False):
        got["threads"].add(threading.get_ident())
        got["cache"].append((ns, sorted(pv_cache or {}), defer_quota))
        time.sleep(0.05)
        return {"ok": True, "dir": os.path.join(tmp, ns), "count": 1, "pruned": 0}
    H.action_backup = fake_backup
    s_quota = H.enforce_storage_quota
    def fake_quota(root=None):
        got["quota"] += 1
        return 0, 0
    H.enforce_storage_quota = fake_quota
    t0 = time.time()
    r = H.action_backup_all()
    dt = time.time() - t0
    check(r["ok"] and r["backed_up"] == 4 and [x["ns"] for x in r["results"]] == ["n1", "n2", "n3", "n4"],
          "4 namespaces sauvegardés, ordre des résultats conservé")
    check(got["pv_calls"] == 1 and all(c == ["pv-a", "pv-b"] and d for _n, c, d in got["cache"]),
          "PV lus UNE fois pour le passage (cache transmis), quota différé par namespace")
    check(got["quota"] == 1, "quota global appliqué une seule fois en fin de passage")
    check(len(got["threads"]) > 1 and dt < 0.18, "namespaces traités en parallèle (%.2f s pour 4 × 0,05 s)" % dt)
    H.CONFIG["backup_pv_prefetch_min"] = 10
    got.update(pv_calls=0, cache=[])
    H.action_backup_all()
    check(got["pv_calls"] == 0 and all(c == [] for _n, c, _d in got["cache"]), "sous le seuil : pas de pré-lecture des PV (comme avant)")
    H.enforce_storage_quota = s_quota
finally:
    H.run, H.kubectl_json, H.action_namespaces, H._list_namespace_workloads, H.action_backup = s_run, s_kj, s_ns, s_wl, s_bk
    H._CATALOGS.clear(); H._apps_cache_clear()
    H.CONFIG.clear(); H.CONFIG.update(saved)
    shutil.rmtree(tmp, ignore_errors=True)

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
