# -*- coding: utf-8 -*-
"""Restauration DR (reprise d'activité) : garde-fou allow_dr_restore, clone
« depuis la sauvegarde seule » (aucune lecture du cluster d'origine), remap de
StorageClass, inventaire /api/dr/backups."""
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


tmp = tempfile.mkdtemp()
saved = dict(H.CONFIG)
saved_kj = H.kubectl_json


def boom(args):
    raise AssertionError("lecture LIVE interdite en mode DR : kubectl %s" % args)


VG_OLD = "11111111-2222-3333-4444-555555555555"
VG_NEW = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
try:
    H.CONFIG.update({"backup_root": tmp, "allow_dr_restore": False, "namespace_filter": [],
                     "cluster_namespace_filters": {}, "namespace_label_selector": "",
                     "require_context_confirm": False, "allowed_contexts": [],
                     "storage_min_free_mb": 0, "storage_quota_gb": 0})
    H.CONFIG_PATH = os.path.join(tmp, "hycu_config.json")
    H._LOCAL_CTX.update({"name": "dr-site", "at": time.time() + 9999})

    # ---- Sauvegarde d'un cluster DISPARU (cluster_id "local", contexte prod-perdu) ----
    bdir = os.path.join(tmp, "_imports", "local-prod-perdu", "boutique", "2026-09-24_08-00-00_000000")
    os.makedirs(bdir)
    pv = {"apiVersion": "v1", "kind": "PersistentVolume",
          "metadata": {"name": "pvc-orig"},
          "spec": {"storageClassName": "nutanix-volume",
                   "capacity": {"storage": "1Gi"}, "accessModes": ["ReadWriteOnce"],
                   "claimRef": {"name": "data", "namespace": "boutique"},
                   "csi": {"driver": "csi.nutanix.com",
                           "volumeHandle": "NutanixVolumes-" + VG_OLD}}}
    pvc = {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
           "metadata": {"name": "data", "namespace": "boutique"},
           "spec": {"storageClassName": "nutanix-volume", "accessModes": ["ReadWriteOnce"],
                    "resources": {"requests": {"storage": "1Gi"}}, "volumeName": "pvc-orig"}}
    dep = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web"},
           "spec": {"selector": {"matchLabels": {"app": "web"}},
                    "template": {"metadata": {"labels": {"app": "web"}},
                                 "spec": {"volumes": [{"name": "d", "persistentVolumeClaim": {"claimName": "data"}}],
                                          "containers": [{"name": "c", "image": "x",
                                                          "envFrom": [{"configMapRef": {"name": "cm-app"}},
                                                                      {"secretRef": {"name": "sec-app"}}]}]}}}}
    svc = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "web"},
           "spec": {"selector": {"app": "web"}, "ports": [{"port": 80}]}}
    cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "cm-app"}, "data": {"k": "v"}}
    sec = {"apiVersion": "v1", "kind": "Secret",
           "metadata": {"name": "sec-app", "annotations": {"hycu.backup/secret-data": "redacted"}},
           "data": {"p": "__REDACTED__"}}
    with open(os.path.join(bdir, "pv_pvc-orig.json"), "w") as f:
        json.dump(pv, f)
    with open(os.path.join(bdir, "pvc_data.json"), "w") as f:
        json.dump(pvc, f)
    with open(os.path.join(bdir, "resources.json"), "w") as f:
        json.dump({"namespace": "boutique", "items": [dep, svc, cm, sec]}, f)
    with open(os.path.join(bdir, "index.json"), "w") as f:
        json.dump({"namespace": "boutique", "created": "2026-09-24T08:00:00",
                   "cluster": "prod-perdu", "cluster_id": "local", "context": "prod-perdu",
                   "resources_count": 4,
                   "volumes": [{"pvc": "data", "pv": "pvc-orig", "pv_file": "pv_pvc-orig.json",
                                "pvc_file": "pvc_data.json"}]}, f)

    print("== Inventaire /api/dr/backups ==")
    inv = H.action_dr_backups()
    check(inv["ok"] and not inv["allowed"], "inventaire disponible ; dérogation désactivée par défaut")
    b = [x for x in inv["backups"] if x["namespace"] == "boutique"]
    check(len(b) == 1 and b[0]["imported"] and b[0]["context"] == "prod-perdu"
          and b[0]["volumes"] == ["data"], "sauvegarde importée inventoriée (contexte, volumes)")

    print("\n== Garde-fou allow_dr_restore ==")
    H.kubectl_json = boom
    payload = {"namespace": "boutique", "target_namespace": "boutique", "backup_path": bdir,
               "items": [{"pvc": "data", "new_ref": VG_NEW}], "dry": True, "dr_restore": True,
               "dr_storageclass": "dr-class", "clone_refs": True}
    r = H.action_clone_app(dict(payload))
    check(not r["ok"] and "Autoriser la restauration DR" in r["error"],
          "dr_restore demandé mais réglage désactivé : refus explicite")
    H.CONFIG["allow_dr_restore"] = True
    r2 = H.action_clone_app({**{k: v for k, v in payload.items() if k != "dr_restore"},
                             "target_namespace": "boutique2"})
    check(not r2["ok"] and "contexte" in (r2["error"] or ""),
          "réglage activé mais SANS demande explicite : garde inter-contexte toujours appliquée")

    print("\n== Clone DR « depuis la sauvegarde seule » (simulation) ==")
    applied = []
    real_apply = H._apply_manifest
    def capture_apply(m, basename, dry, label):
        applied.append(json.loads(json.dumps(m)))
        return real_apply(m, basename, dry, label)
    H._apply_manifest = capture_apply
    try:
        r = H.action_clone_app(dict(payload))
    finally:
        H._apply_manifest = real_apply
    check(r["ok"], "clone DR simulé : %s" % (r.get("error") or "ok"))
    labels = [l.get("label") or "" for l in r["log"]]
    txt = json.dumps(r["log"], ensure_ascii=False)
    check(any("Namespace cible" in l for l in labels), "namespace cible recréé")
    check(any("PV cloné" in l for l in labels) and any("PVC cloné" in l for l in labels), "PV + PVC recréés")
    check(any("Deployment/web" in l or "Application clonée Deployment/web" in l for l in labels),
          "workload recréé depuis resources.json (cluster source jamais lu)")
    kinds_applied = {(m.get("kind"), (m.get("metadata") or {}).get("name")) for m in applied}
    check(("ConfigMap", "cm-app") in kinds_applied and ("Service", "web") in kinds_applied,
          "dépendances (ConfigMap, Service) recréées depuis la sauvegarde")
    check(("Secret", "sec-app") not in kinds_applied, "Secret MASQUÉ jamais appliqué")
    warns = " ".join(r.get("warnings") or [])
    check("sec-app" in warns and "MODE DR" in warns, "Secret masqué signalé + avertissement MODE DR")
    scs = {(m.get("kind"), (m.get("spec") or {}).get("storageClassName"))
           for m in applied if m.get("kind") in ("PersistentVolume", "PersistentVolumeClaim")}
    check(scs == {("PersistentVolume", "dr-class"), ("PersistentVolumeClaim", "dr-class")},
          "StorageClass remappée sur les PV/PVC recréés")
    vh = [((m.get("spec") or {}).get("csi") or {}).get("volumeHandle")
          for m in applied if m.get("kind") == "PersistentVolume"]
    check(vh == ["NutanixVolumes-" + VG_NEW], "volumeHandle dérivé du VG restauré sur le site cible")
    recs = [json.loads(l) for l in open(os.path.join(tmp, "audit.log"))]
    ca = [x for x in recs if x["event"] == "clone_app"]
    check(ca and ca[-1].get("dr") is True and ca[-1].get("storageclass") == "dr-class",
          "audit : clone_app marqué dr=true + storageclass")

    print("\n== Sécurités du mode DR ==")
    r = H.action_clone_app({**payload, "dr_storageclass": "Bad_Class!"})
    check(not r["ok"] and "StorageClass" in r["error"], "nom de StorageClass invalide refusé")
    r = H.action_clone_app({**payload, "backup_path": None})
    check(not r["ok"] and "sauvegarde source" in r["error"], "DR sans sauvegarde source : refus")
    r = H.action_clone_app({**payload, "items": [{"pvc": "data", "new_ref": VG_OLD}]})
    check(not r["ok"] and "SOURCE" in r["error"], "réf identique au VG source : toujours refusée en DR")

    print("\n== Application SUPPRIMÉE du cluster : récupération SANS dérogation DR ==")
    H.CONFIG["allow_dr_restore"] = False
    # Sauvegarde du contexte ACTIF (dr-site) : le namespace « atelier » a été détruit.
    adir = os.path.join(tmp, "_contexts", "dr-site", "atelier", "2026-09-24_09-00-00_000000")
    os.makedirs(adir)
    pv2 = json.loads(json.dumps(pv)); pv2["spec"]["claimRef"]["namespace"] = "atelier"
    dep2 = json.loads(json.dumps(dep))
    with open(os.path.join(adir, "pv_pvc-orig.json"), "w") as f:
        json.dump(pv2, f)
    with open(os.path.join(adir, "pvc_data.json"), "w") as f:
        json.dump({**pvc, "metadata": {"name": "data", "namespace": "atelier"}}, f)
    with open(os.path.join(adir, "resources.json"), "w") as f:
        json.dump({"namespace": "atelier", "items": [dep2, svc, cm, sec]}, f)
    with open(os.path.join(adir, "index.json"), "w") as f:
        json.dump({"namespace": "atelier", "created": "2026-09-24T09:00:00",
                   "cluster": "dr-site", "cluster_id": "local", "context": "dr-site",
                   "resources_count": 4,
                   "volumes": [{"pvc": "data", "pv": "pvc-orig", "pv_file": "pv_pvc-orig.json",
                                "pvc_file": "pvc_data.json",
                                "analysis": {"old_volume_handle": "NutanixVolumes-" + VG_OLD}}]}, f)

    inv = H.action_dr_backups()
    here = {x["namespace"]: x["restorable_here"] for x in inv["backups"]}
    check(here.get("atelier") is True and here.get("boutique") is False,
          "restorable_here : vrai pour la sauvegarde d'ici, faux pour l'étrangère")

    saved_ns_fn = H.action_namespaces
    H.action_namespaces = lambda: {"ok": True, "namespaces": ["autre-ns"]}
    try:
        apps = {a["name"]: a for a in H.action_applications()["apps"]}
    finally:
        H.action_namespaces = saved_ns_fn
    check("atelier" in apps and apps["atelier"]["missing"] and apps["atelier"]["protected"]
          and apps["atelier"]["backups"] >= 1,
          "namespace détruit : toujours listé (missing=true, sauvegardes comptées)")
    check("autre-ns" in apps and not apps["autre-ns"]["missing"],
          "namespace vivant : missing=false")

    rec = {"namespace": "atelier", "target_namespace": "atelier", "backup_path": adir,
           "items": [{"pvc": "data", "new_ref": VG_NEW}], "dry": True,
           "from_backup_only": True, "clone_refs": True}
    applied2 = []
    def capture2(m, basename, dry, label):
        applied2.append(json.loads(json.dumps(m)))
        return real_apply(m, basename, dry, label)
    H._apply_manifest = capture2
    try:
        r = H.action_clone_app(dict(rec))
    finally:
        H._apply_manifest = real_apply
    check(r["ok"], "récupération simulée sans allow_dr_restore : %s" % (r.get("error") or "ok"))
    kinds2 = {(m.get("kind"), (m.get("metadata") or {}).get("name")) for m in applied2}
    check(("PersistentVolume", "pvc-orig-clone") in kinds2 or any(k == "PersistentVolume" for k, _ in kinds2),
          "PV recréé depuis la sauvegarde")
    check(("Deployment", "web") in kinds2 and ("Service", "web") in kinds2 and ("ConfigMap", "cm-app") in kinds2,
          "workload + dépendances recréés depuis resources.json (cluster jamais lu)")
    check(("Secret", "sec-app") not in kinds2, "Secret MASQUÉ jamais appliqué en récupération")
    warns = " ".join(r.get("warnings") or [])
    check("n'existe plus sur le cluster" in warns and "MODE DR" not in warns,
          "avertissement « depuis la sauvegarde seule » (pas de bannière DR)")
    recs = [json.loads(l) for l in open(os.path.join(tmp, "audit.log"))]
    ca = [x for x in recs if x["event"] == "clone_app"][-1]
    check(ca.get("from_backup") is True and ca.get("dr") is False,
          "audit : from_backup=true, dr=false (récupération, pas dérogation)")
    r = H.action_clone_app({**rec, "backup_path": bdir, "namespace": "boutique",
                            "target_namespace": "boutique"})
    check(not r["ok"] and "contexte" in (r["error"] or ""),
          "récupération d'une sauvegarde d'un AUTRE contexte : refus sans dérogation DR")

    print("\n== Saisie minimale : réutilisation auto du VG d'origine (new_ref vide) ==")
    inv2 = [x for x in H.action_dr_backups()["backups"] if x["namespace"] == "atelier"][0]
    check(inv2.get("vol_refs", {}).get("data") == VG_OLD,
          "inventaire : UUID d'origine du VG exposé (pré-remplissage sans lecture live)")
    applied3 = []
    def capture3(m, basename, dry, label):
        applied3.append(json.loads(json.dumps(m)))
        return real_apply(m, basename, dry, label)
    H._apply_manifest = capture3
    try:
        # new_ref VIDE : le serveur doit déduire l'UUID d'origine depuis la sauvegarde.
        r = H.action_clone_app({**rec, "items": [{"pvc": "data", "new_ref": ""}]})
    finally:
        H._apply_manifest = real_apply
    check(r["ok"], "récupération sans aucun UUID saisi : %s" % (r.get("error") or "ok"))
    vh3 = [((m.get("spec") or {}).get("csi") or {}).get("volumeHandle")
           for m in applied3 if m.get("kind") == "PersistentVolume"]
    check(vh3 == ["NutanixVolumes-" + VG_OLD],
          "le PV recréé pointe sur le VG d'ORIGINE (déduit de la sauvegarde)")
    kinds3 = {(m.get("kind"), (m.get("metadata") or {}).get("name")) for m in applied3}
    check(("Deployment", "web") in kinds3, "workload recréé (réutilisation du VG d'origine)")

    print("\n== Sauvegarde SANS resources.json : dégradé (volumes seulement), pas de blocage ==")
    ndir = os.path.join(tmp, "_contexts", "dr-site", "sansres", "2026-09-24_10-00-00_000000")
    os.makedirs(ndir)
    pv3 = json.loads(json.dumps(pv2)); pv3["spec"]["claimRef"]["namespace"] = "sansres"
    with open(os.path.join(ndir, "pv_pvc-orig.json"), "w") as f:
        json.dump(pv3, f)
    with open(os.path.join(ndir, "pvc_data.json"), "w") as f:
        json.dump({**pvc, "metadata": {"name": "data", "namespace": "sansres"}}, f)
    # PAS de resources.json
    with open(os.path.join(ndir, "index.json"), "w") as f:
        json.dump({"namespace": "sansres", "created": "2026-09-24T10:00:00",
                   "cluster": "dr-site", "cluster_id": "local", "context": "dr-site",
                   "volumes": [{"pvc": "data", "pv": "pvc-orig", "pv_file": "pv_pvc-orig.json",
                                "pvc_file": "pvc_data.json",
                                "analysis": {"old_volume_handle": "NutanixVolumes-" + VG_OLD}}]}, f)
    invn = {x["namespace"]: x for x in H.action_dr_backups()["backups"]}
    check(invn.get("sansres", {}).get("has_resources") is False
          and invn.get("atelier", {}).get("has_resources") is True,
          "inventaire : has_resources distingue les sauvegardes avec/sans instantané")
    applied4 = []
    def capture4(m, basename, dry, label):
        applied4.append(json.loads(json.dumps(m)))
        return real_apply(m, basename, dry, label)
    H._apply_manifest = capture4
    try:
        r = H.action_clone_app({"namespace": "sansres", "target_namespace": "sansres",
                                "backup_path": ndir, "items": [{"pvc": "data", "new_ref": ""}],
                                "dry": True, "from_backup_only": True, "clone_refs": True})
    finally:
        H._apply_manifest = real_apply
    check(r["ok"], "récupération SANS resources.json : réussie (pas de blocage) : %s" % (r.get("error") or "ok"))
    kinds4 = {m.get("kind") for m in applied4}
    check("PersistentVolume" in kinds4 and "PersistentVolumeClaim" in kinds4 and "Deployment" not in kinds4,
          "volumes recréés, aucun workload (dégradé)")
    check(any("instantané de ressources" in w for w in (r.get("warnings") or [])),
          "avertissement clair : volumes seulement")
finally:
    H.kubectl_json = saved_kj
    H._LOCAL_CTX.update({"name": None, "at": 0.0})
    H.CONFIG.clear(); H.CONFIG.update(saved)
    shutil.rmtree(tmp, ignore_errors=True)

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
