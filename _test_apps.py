# -*- coding: utf-8 -*-
"""Applications DANS les namespaces : regroupement des workloads par étiquette
d'application, type stateful/stateless, page Applications (une ligne par application),
index `apps` à la sauvegarde, sauvegarde d'un namespace STATELESS, filtre des objets
d'une application (restauration stateless) et récupération stateless d'un namespace
supprimé (simulation)."""
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


def wl(kind, name, labels=None, claims=(), vct=(), replicas=1, owners=None, env_cm=None, env_sec=None, sa=None):
    ps = {"containers": [{"name": "c", "image": "x"}]}
    if claims:
        ps["volumes"] = [{"name": "v%d" % i, "persistentVolumeClaim": {"claimName": c}} for i, c in enumerate(claims)]
    if env_cm or env_sec:
        ps["containers"][0]["envFrom"] = ([{"configMapRef": {"name": env_cm}}] if env_cm else []) + \
                                         ([{"secretRef": {"name": env_sec}}] if env_sec else [])
    if sa:
        ps["serviceAccountName"] = sa
    meta = {"name": name, "labels": dict(labels or {})}
    if owners:
        meta["ownerReferences"] = [{"kind": o, "name": "x"} for o in owners]
    spec = {"selector": {"matchLabels": dict(labels or {"app": name})},
            "template": {"metadata": {"labels": dict(labels or {"app": name})}, "spec": ps}}
    if kind in ("Deployment", "StatefulSet"):
        spec["replicas"] = replicas
    if vct:
        spec["volumeClaimTemplates"] = [{"metadata": {"name": t}} for t in vct]
    if kind == "CronJob":
        spec = {"schedule": "* * * * *", "jobTemplate": {"spec": {"template": spec["template"]}}}
    return {"apiVersion": "apps/v1", "kind": kind, "metadata": meta, "spec": spec}


tmp = tempfile.mkdtemp()
saved = dict(H.CONFIG)
s_ns, s_wl, s_kj, s_rs = H.action_namespaces, H._list_namespace_workloads, H.kubectl_json, H.resource_state
try:
    H.CONFIG.update({"backup_root": tmp, "auto_backup_enabled": False, "auto_backup_dest": "",
                     "namespace_filter": [], "cluster_namespace_filters": {}, "namespace_label_selector": "",
                     "config_backup_full": True, "backup_collect_restore_contract": False,
                     "storage_min_free_mb": 0, "storage_quota_gb": 0, "allow_dr_restore": False,
                     "require_context_confirm": False, "allowed_contexts": []})
    H.CONFIG_PATH = os.path.join(tmp, "hycu_config.json")
    H._LOCAL_CTX.update({"name": "ctx-test", "at": time.time() + 9999})

    print("== Regroupement des workloads en applications ==")
    inst = {"app.kubernetes.io/instance": "wp", "app.kubernetes.io/name": "wordpress"}
    inst_db = {"app.kubernetes.io/instance": "wp", "app.kubernetes.io/name": "mariadb"}
    items = [wl("Deployment", "wp-wordpress", inst, claims=("wp-data",), env_cm="wp-cm", env_sec="wp-sec"),
             wl("StatefulSet", "wp-mariadb", inst_db, vct=("data",), replicas=2),
             wl("Deployment", "redis", {"app": "redis"}),                         # stateless
             wl("Deployment", "nolabel"),                                         # sans étiquette
             wl("CronJob", "cleanup", {"app": "redis"}),                          # rattaché à redis
             wl("Job", "cleanup-123", {"app": "redis"}, owners=["CronJob"]),      # dérivé : ignoré
             {"kind": "ReplicaSet", "metadata": {"name": "rs", "ownerReferences": [{"kind": "Deployment"}]}}]
    pvcs = ["wp-data", "data-wp-mariadb-0", "data-wp-mariadb-1", "data-wp-mariadb-2", "orphan"]
    apps = {a["name"]: a for a in H._apps_from_workloads("shop", items, pvcs)}
    check(set(apps) == {"wp", "redis", "nolabel", H.APP_UNASSIGNED}, "4 applications : wp, redis, nolabel + volumes orphelins")
    check(apps["wp"]["type"] == "stateful" and apps["wp"]["pvcs"] == ["wp-data", "data-wp-mariadb-0", "data-wp-mariadb-1", "data-wp-mariadb-2"],
          "wp = stateful : PVC monté + volumeClaimTemplates (tous les PVC existants du STS)")
    check([w["kind"] for w in apps["wp"]["workloads"]] == ["Deployment", "StatefulSet"], "wp regroupe Deployment + StatefulSet (même instance)")
    check(apps["redis"]["type"] == "stateless" and {w["name"] for w in apps["redis"]["workloads"]} == {"redis", "cleanup"},
          "redis = stateless (Deployment + CronJob par étiquette app) ; Job dérivé ignoré")
    check(apps["nolabel"]["type"] == "stateless" and apps["nolabel"]["workloads"][0]["name"] == "nolabel",
          "workload sans étiquette : application à lui seul")
    check(apps[H.APP_UNASSIGNED]["unassigned"] and apps[H.APP_UNASSIGNED]["pvcs"] == ["orphan"],
          "PVC qu'aucun workload ne monte -> pseudo-application « volumes sans workload »")
    only_sts = H._apps_from_workloads("db", [wl("StatefulSet", "pg", vct=("data",), replicas=3)])
    check(only_sts[0]["pvcs"] == ["data-pg-0", "data-pg-1", "data-pg-2"], "sans liste de PVC : un PVC par réplica")
    empty = H._apps_from_workloads("void", [], [])
    check(len(empty) == 1 and empty[0]["type"] == "empty" and empty[0]["whole_ns"], "namespace vide : une ligne « vide »")
    onlypvc = H._apps_from_workloads("raw", [], ["d1"])
    check(onlypvc[0]["type"] == "stateful" and onlypvc[0]["whole_ns"] and onlypvc[0]["pvcs"] == ["d1"],
          "PVC sans aucun workload : application = namespace (stateful)")

    print("\n== Objets d'une application dans l'instantané ==")
    svc_wp = {"kind": "Service", "metadata": {"name": "wp-svc"}, "spec": {"selector": inst}}
    svc_other = {"kind": "Service", "metadata": {"name": "redis-svc"}, "spec": {"selector": {"app": "redis"}}}
    cm_wp = {"kind": "ConfigMap", "metadata": {"name": "wp-cm"}}
    sec_wp = {"kind": "Secret", "metadata": {"name": "wp-sec"}}
    cm_shared = {"kind": "ConfigMap", "metadata": {"name": "shared"}}
    ing = {"kind": "Ingress", "metadata": {"name": "wp-ing", "labels": {"app.kubernetes.io/instance": "wp"}}}
    snap = items[:5] + [svc_wp, svc_other, cm_wp, sec_wp, cm_shared, ing]
    sel = H._app_object_indexes(snap, "wp")
    names = {(snap[i]["kind"], snap[i]["metadata"]["name"]) for i in sel}
    check(names == {("Deployment", "wp-wordpress"), ("StatefulSet", "wp-mariadb"), ("Service", "wp-svc"),
                    ("ConfigMap", "wp-cm"), ("Secret", "wp-sec"), ("Ingress", "wp-ing")},
          "wp : workloads + Service ciblant ses pods + ConfigMap/Secret référencés + objet étiqueté ; rien de redis ni du partagé")
    sel2 = {snap[i]["metadata"]["name"] for i in H._app_object_indexes(snap, "redis")}
    check(sel2 == {"redis", "cleanup", "redis-svc"}, "redis : Deployment + CronJob + son Service")
    check(H._app_object_indexes(snap, "") == set(range(len(snap))), "sans application : tous les objets")

    print("\n== Page Applications : une ligne par application, protection du namespace ==")
    def mk_backup(ns, when, volumes, apps_idx=None, resources=None):
        d = os.path.join(H._cluster_root(tmp), ns, when)
        os.makedirs(d)
        idx = {"namespace": ns, "created": "2026-09-25T0%s:00:00" % when[-1], "context": "ctx-test",
               "cluster_id": "local", "volumes": [{"pvc": v} for v in volumes]}
        if apps_idx is not None:
            idx["apps"] = apps_idx
        if resources is not None:
            idx["resources_count"] = len(resources)
            with open(os.path.join(d, "resources.json"), "w") as f:
                json.dump({"namespace": ns, "items": resources}, f)
        with open(os.path.join(d, "index.json"), "w") as f:
            json.dump(idx, f)
        return d
    mk_backup("shop", "2026-09-25_01-00-00_000001", ["wp-data", "data-wp-mariadb-0", "data-wp-mariadb-1"])
    mk_backup("gone", "2026-09-25_02-00-00_000002", ["d"],
              apps_idx=[{"name": "legacy", "type": "stateful", "pvcs": ["d"], "workloads": [{"kind": "Deployment", "name": "legacy"}]},
                        {"name": "sidecar", "type": "stateless", "pvcs": [], "workloads": [{"kind": "Deployment", "name": "sidecar"}]}])
    H.action_namespaces = lambda: {"ok": True, "namespaces": ["shop", "void"]}
    H._list_namespace_workloads = lambda names, full=False: ({"shop": items, "void": []}, {"shop": pvcs, "void": []}, None)
    r = H.action_applications()
    rows = {(a["namespace"], a["name"]): a for a in r["apps"]}
    check(r["ok"] and set(rows) == {("shop", "wp"), ("shop", "redis"), ("shop", "nolabel"), ("shop", H.APP_UNASSIGNED),
                                    ("void", "void"), ("gone", "legacy"), ("gone", "sidecar")},
          "lignes : 4 applications de shop, namespace vide, 2 applications du namespace SUPPRIMÉ (depuis son index)")
    wp = rows[("shop", "wp")]
    check(wp["type"] == "stateful" and wp["protected"] and wp["backups"] == 1 and wp["volumes"] == 4
          and wp["unbacked_pvcs"] == ["data-wp-mariadb-2"],
          "wp : protégé par la sauvegarde du namespace, volume créé depuis signalé (unbacked_pvcs)")
    check(rows[("shop", "redis")]["type"] == "stateless" and rows[("shop", "redis")]["protected"]
          and rows[("shop", "redis")]["unbacked_pvcs"] == [], "redis : stateless, protégé, rien à signaler")
    check(rows[("gone", "legacy")]["missing"] and rows[("gone", "sidecar")]["missing"]
          and rows[("gone", "sidecar")]["type"] == "stateless", "namespace supprimé : applications lues dans sa sauvegarde")
    check(rows[("void", "void")]["type"] == "empty" and not rows[("void", "void")]["protected"], "namespace vide : ligne « vide », non protégé")
    H._list_namespace_workloads = lambda names, full=False: ({}, {}, "forbidden")
    r2 = H.action_applications()
    check({a["name"] for a in r2["apps"] if a["namespace"] == "shop"} == {"shop"} and r2["workloads_error"] == "forbidden",
          "sans droits sur les workloads : repli une ligne par namespace + erreur exposée")

    print("\n== Sauvegarde d'un namespace STATELESS (aucun PVC) ==")
    calls = []
    def kj_stateless(args):
        calls.append(args)
        if args[:2] == ["get", "pvc"]:
            return {"items": []}, None
        if args[0] == "get" and args[1].split(",")[0] == "deployment":   # appel groupé ou type par type
            return {"items": [wl("Deployment", "api", {"app": "api"})]}, None
        return {"items": []}, None
    H.kubectl_json = kj_stateless
    H.action_context = (lambda _o=H.action_context: {"context": "ctx-test", "kubectl_ok": True})
    b = H.action_backup("front")
    check(b["ok"] and b["count"] == 0 and b["resources_count"] == 1, "namespace sans PVC mais avec workload : sauvegardé (0 volume)")
    with open(os.path.join(b["dir"], "index.json")) as f:
        idx = json.load(f)
    check(idx["volumes"] == [] and idx["apps"] == [{"name": "api", "workloads": [{"kind": "Deployment", "name": "api", "replicas": 1}], "type": "stateless"}],
          "index : volumes vides + applications stateless mémorisées")
    inv = [x for x in H.action_dr_backups()["backups"] if x["namespace"] == "front"]
    check(inv and inv[0]["stateless"] and inv[0]["apps"] == ["api"], "inventaire DR : sauvegarde marquée stateless")
    H.kubectl_json = lambda args: ({"items": []}, None)
    b2 = H.action_backup("nothing")
    check(not b2["ok"] and b2.get("skipped") and not os.path.isdir(os.path.join(H._cluster_root(tmp), "nothing")),
          "namespace sans PVC ni workload : ignoré, aucun dossier laissé")
    H.CONFIG["config_backup_full"] = False
    b3 = H.action_backup("nothing")
    check(not b3["ok"] and b3.get("skipped") and "Aucun PVC" in b3["error"], "instantané désactivé : ancien comportement (Aucun PVC)")
    H.CONFIG["config_backup_full"] = True

    print("\n== Liste des objets filtrée par application ==")
    H.kubectl_json = s_kj
    d = mk_backup("shop", "2026-09-25_03-00-00_000003", ["wp-data"], resources=snap)
    r = H.action_objects_list({"namespace": "shop", "backup_path": d, "app": "wp"})
    check(r["ok"] and r["app"] == "wp" and r["app_count"] == 6 and all("in_app" in x for x in r["items"]),
          "objets marqués in_app pour l'application wp")
    check([x["in_app"] for x in r["items"]][:6] == [True] * 6 and not any(x["in_app"] for x in r["items"][6:]),
          "objets de l'application triés en tête")
    r = H.action_objects_list({"namespace": "shop", "backup_path": d})
    check(r["ok"] and r["app"] is None and "in_app" not in r["items"][0], "sans application : liste inchangée")

    print("\n== Récupération STATELESS d'un namespace supprimé (simulation) ==")
    front = [x for x in H.action_dr_backups()["backups"] if x["namespace"] == "front"][0]
    H.resource_state = lambda kind, name, ns=None: ("absent", "")
    applied = []
    real_apply = H._apply_manifest
    def capture(m, basename, dry, label):
        applied.append((m.get("kind"), (m.get("metadata") or {}).get("name")))
        return real_apply(m, basename, dry, label)
    H._apply_manifest = capture
    try:
        r = H.action_clone_app({"namespace": "front", "target_namespace": "front", "backup_path": front["path"],
                                "items": [], "dry": True, "from_backup_only": True, "clone_refs": True})
    finally:
        H._apply_manifest = real_apply
    check(r["ok"], "récupération sans volume acceptée : %s" % (r.get("error") or "ok"))
    check(("Namespace", "front") in applied and ("Deployment", "api") in applied
          and not any(k == "PersistentVolume" for k, _ in applied),
          "namespace + workload recréés, aucun PV/PVC")
    check(any("stateless" in w for w in r.get("warnings", [])), "avertissement « application stateless »")
    rr = H.action_clone_app({"namespace": "shop", "target_namespace": "shop-copy", "backup_path": d,
                             "items": [], "dry": True})
    check(not rr["ok"] and "Aucun volume" in rr["error"], "clone ordinaire sans volume : toujours refusé")

    print("\n== Une application = TOUS ses workloads (stateless compris) — récupération et clone ==")
    # sauvegarde shop2 : wp-wordpress (monte wp-data), wp-mariadb (STS volumeClaimTemplates -> data-wp-mariadb-0),
    # front (stateless, application wp), redis (stateless, autre application)
    front_wp = wl("Deployment", "wp-front", inst)
    snap2 = [items[0], items[1], front_wp, items[2], svc_wp, svc_other, cm_wp, sec_wp]
    d2 = os.path.join(H._cluster_root(tmp), "shop2", "2026-09-25_04-00-00_000004")
    os.makedirs(d2)
    for pvcn in ("wp-data", "data-wp-mariadb-0"):
        pv = {"apiVersion": "v1", "kind": "PersistentVolume", "metadata": {"name": "pv-" + pvcn},
              "spec": {"storageClassName": "nutanix-volume", "capacity": {"storage": "1Gi"}, "accessModes": ["ReadWriteOnce"],
                       "claimRef": {"name": pvcn, "namespace": "shop2"},
                       "csi": {"driver": "csi.nutanix.com", "volumeHandle": "NutanixVolumes-11111111-2222-3333-4444-%012d" % len(pvcn)}}}
        pvc = {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": pvcn, "namespace": "shop2"},
               "spec": {"storageClassName": "nutanix-volume", "accessModes": ["ReadWriteOnce"],
                        "resources": {"requests": {"storage": "1Gi"}}, "volumeName": "pv-" + pvcn}}
        json.dump(pv, open(os.path.join(d2, "pv_pv-%s.json" % pvcn), "w"))
        json.dump(pvc, open(os.path.join(d2, "pvc_%s.json" % pvcn), "w"))
    json.dump({"namespace": "shop2", "items": snap2}, open(os.path.join(d2, "resources.json"), "w"))
    json.dump({"namespace": "shop2", "created": "2026-09-25T04:00:00", "context": "ctx-test", "cluster_id": "local",
               "resources_count": len(snap2),
               "volumes": [{"pvc": p, "pv": "pv-" + p, "pv_file": "pv_pv-%s.json" % p, "pvc_file": "pvc_%s.json" % p,
                            "analysis": {"old_volume_handle": "NutanixVolumes-11111111-2222-3333-4444-%012d" % len(p)}}
                           for p in ("wp-data", "data-wp-mariadb-0")]}, open(os.path.join(d2, "index.json"), "w"))
    H._CATALOGS.clear()
    H.resource_state = lambda kind, name, ns=None: ("absent", "")
    s_vg = H._vg_exists
    H._vg_exists = lambda u: True
    def run_rec(app=None):
        applied.clear()
        H._apply_manifest = capture
        try:
            body = {"namespace": "shop2", "target_namespace": "shop2", "backup_path": d2, "dry": True,
                    "from_backup_only": True, "clone_refs": True,
                    "items": [{"pvc": "wp-data", "new_ref": ""}, {"pvc": "data-wp-mariadb-0", "new_ref": ""}]}
            if app:
                body["app"] = app
            return H.action_clone_app(body), list(applied)
        finally:
            H._apply_manifest = real_apply
    r, ap = run_rec()
    kinds = {(k, n) for k, n in ap}
    check(r["ok"] and {("Deployment", "wp-wordpress"), ("StatefulSet", "wp-mariadb"), ("Deployment", "wp-front"), ("Deployment", "redis")} <= kinds,
          "récupération du namespace : workloads stateful (dont STS volumeClaimTemplates) ET stateless recréés : %s" % (r.get("error") or "ok"))
    check(any("sans volume du namespace" in w for w in r.get("warnings", [])), "avertissement listant les workloads sans volume ajoutés")
    r2, ap2 = run_rec(app="wp")
    kinds2 = {(k, n) for k, n in ap2}
    check(r2["ok"] and {("Deployment", "wp-wordpress"), ("StatefulSet", "wp-mariadb"), ("Deployment", "wp-front")} <= kinds2
          and ("Deployment", "redis") not in kinds2, "application ciblée : ses workloads stateless suivent, ceux des autres applications non")
    H._vg_exists = s_vg
    # clone LIVE d'une application stateful : les workloads sans volume de l'application suivent aussi
    H._list_namespace_workloads = lambda names, full=False: ({"shop": items + [front_wp]}, {"shop": pvcs}, None)
    s_fw, s_lop, s_lbp, s_kj2 = H._find_workloads_using_pvcs, H._load_old_pv, H._load_backup_pvc, H.kubectl_json
    H._find_workloads_using_pvcs = lambda ns, names: [json.loads(json.dumps(items[0]))]
    pv_wp = {"apiVersion": "v1", "kind": "PersistentVolume", "metadata": {"name": "pv-wp"},
             "spec": {"capacity": {"storage": "1Gi"}, "accessModes": ["ReadWriteOnce"], "claimRef": {"name": "wp-data", "namespace": "shop"},
                      "csi": {"driver": "csi.nutanix.com", "volumeHandle": "NutanixVolumes-11111111-2222-3333-4444-555555555555"}}}
    H._load_old_pv = lambda ns, pvc, bp, br=None, no_live=False: (json.loads(json.dumps(pv_wp)), "pv-wp")
    H._load_backup_pvc = lambda bp, pvc, br=None: {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "wp-data", "namespace": "shop"},
                                                   "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}, "volumeName": "pv-wp"}}
    applied.clear(); H._apply_manifest = capture
    try:
        r3 = H.action_clone_app({"namespace": "shop", "app": "wp", "suffix": "-copy", "dry": True,
                                 "items": [{"pvc": "wp-data", "new_ref": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]})
    finally:
        H._apply_manifest = real_apply
        H._find_workloads_using_pvcs, H._load_old_pv, H._load_backup_pvc, H.kubectl_json = s_fw, s_lop, s_lbp, s_kj2
    kinds3 = {(k, n) for k, n in applied}
    check(r3["ok"] and ("Deployment", "wp-wordpress-copy") in kinds3 and ("Deployment", "wp-front-copy") in kinds3
          and not any(n and n.startswith("redis") for _k, n in applied),
          "clone live de l'application wp : frontend stateless copié avec la base, redis non : %s" % (r3.get("error") or "ok"))

    print("\n== Clone d'une application STATELESS depuis le cluster (simulation) ==")
    H._list_namespace_workloads = lambda names, full=False: ({"shop": items}, {"shop": pvcs}, None)
    applied.clear()
    H._apply_manifest = capture
    try:
        r = H.action_clone_app({"namespace": "shop", "app": "redis", "suffix": "-copy", "items": [], "dry": True})
        same_applied = list(applied); applied.clear()
        r2 = H.action_clone_app({"namespace": "shop", "app": "redis", "target_namespace": "shop-copy",
                                 "items": [], "dry": True, "clone_refs": True})
        other_applied = list(applied)
        r3 = H.action_clone_app({"namespace": "shop", "app": "wp", "suffix": "-copy", "items": [], "dry": True})
        r4 = H.action_clone_app({"namespace": "shop", "app": "nope", "suffix": "-copy", "items": [], "dry": True})
    finally:
        H._apply_manifest = real_apply
    check(r["ok"] and ("Deployment", "redis-copy") in same_applied and ("CronJob", "cleanup-copy") in same_applied
          and not any(k in ("PersistentVolume", "PersistentVolumeClaim") for k, _ in same_applied),
          "même namespace : workloads de l'application copiés avec suffixe, aucun PV/PVC")
    check(r["preview"]["workloads"] == ["Deployment/redis-copy", "CronJob/cleanup-copy"] and not r["preview"]["pvcs"],
          "aperçu : workloads clonés, aucun volume")
    check(r2["ok"] and ("Namespace", "shop-copy") in other_applied and ("Deployment", "redis") in other_applied,
          "autre namespace : namespace cible + workloads recréés")
    check(not r3["ok"] and "monte le(s) volume(s)" in r3["error"], "application stateful demandée sans volume : refus explicite")
    check(not r4["ok"] and "introuvable" in r4["error"], "application inconnue : refus")
finally:
    H.action_namespaces, H._list_namespace_workloads, H.kubectl_json, H.resource_state = s_ns, s_wl, s_kj, s_rs
    H.CONFIG.clear(); H.CONFIG.update(saved)
    shutil.rmtree(tmp, ignore_errors=True)

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
