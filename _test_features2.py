# -*- coding: utf-8 -*-
"""Rétention GFS, sélecteur d'étiquettes, rapport de conformité, chiffrement des
exports S3, restauration guidée des objets (resources.json)."""
import datetime
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


tmp = tempfile.mkdtemp()
saved = dict(H.CONFIG)
saved_fns = (H.kubectl, H.kubectl_json, H.action_namespaces, H._apply_manifest, H._context_guard)
try:
    H.CONFIG.update({"backup_root": tmp, "namespace_label_selector": "", "namespace_filter": [],
                     "cluster_namespace_filters": {}, "pbkdf2_iterations": 1000,
                     "auto_backup_retention": "count", "auto_backup_keep": 15})
    H.CONFIG_PATH = os.path.join(tmp, "hycu_config.json")

    print("== Rétention GFS ==")
    def mk(ns, when):
        d = os.path.join(tmp, ns, when.strftime("%Y-%m-%d_%H-%M-%S_%f"))
        os.makedirs(d)
        with open(os.path.join(d, "index.json"), "w") as f:
            json.dump({"namespace": ns, "created": when.isoformat()}, f)
        return d
    base = datetime.datetime(2026, 9, 24, 8, 0)
    # 2 sauvegardes/jour sur 30 jours : GFS 7j/4sem/3mois doit garder LA PLUS RÉCENTE
    # de chaque jour (7), de chaque semaine ISO (4) et de chaque mois (3), sans doublon.
    for i in range(30):
        for h in (0, 6):
            mk("app", base - datetime.timedelta(days=i, hours=h))
    H.CONFIG.update({"auto_backup_retention": "gfs", "auto_backup_keep_daily": 7,
                     "auto_backup_keep_weekly": 4, "auto_backup_keep_monthly": 3})
    backups = H.list_backups("app")
    keep = H._gfs_keep_paths(backups, 7, 4, 3)
    removed = H._prune_backups(tmp, "app", 999)
    left = H.list_backups("app")
    check(len(left) == len(keep) and removed == 60 - len(keep),
          "GFS : %d conservées, %d supprimées" % (len(left), removed))
    days = {b["index"]["created"][:10] for b in left}
    check(len([d for d in days]) >= 7, "au moins 7 jours distincts couverts")
    per_day = {}
    for b in left:
        per_day.setdefault(b["index"]["created"][:10], []).append(b["index"]["created"])
    check(all(max(v) == sorted(v)[-1] and len(v) == 1 for v in per_day.values()),
          "une seule sauvegarde par jour : la plus récente")
    check(left[0]["path"] == backups[0]["path"], "la plus récente est toujours conservée")
    # mode count intact
    H.CONFIG.update({"auto_backup_retention": "count", "auto_backup_keep": 15})
    mkd = [mk("cnt", base - datetime.timedelta(hours=i)) for i in range(5)]
    H._prune_backups(tmp, "cnt", 3)
    check(len(H.list_backups("cnt")) == 3, "mode « count » inchangé (garde N)")

    print("\n== Sélecteur d'étiquettes ==")
    CALLS = []
    def fake_kubectl(args, dry=False, label=None, timeout=None, input_text=None):
        CALLS.append(args)
        if args[:2] == ["get", "ns"] and "-l" in args:
            name = args[2] if not args[2].startswith("-") else None
            match = ["app", "shop"]
            if name:                                     # get ns <n> -l sel
                out = "namespace/%s" % name if name in match else ""
            else:
                out = "\n".join("namespace/%s" % n for n in match)
            return {"ok": True, "stdout": out, "stderr": "", "rc": 0, "dry": False, "cmd": ""}
        return {"ok": True, "stdout": "", "stderr": "", "rc": 0, "dry": False, "cmd": ""}
    def fake_kubectl_json(args):
        if args[:2] == ["get", "ns"]:
            names = ["app", "shop"] if "-l" in args else ["app", "shop", "autre"]
            return {"items": [{"metadata": {"name": n}} for n in names]}, None
        return None, "inconnu"
    H.kubectl, H.kubectl_json = fake_kubectl, fake_kubectl_json
    H.CONFIG["namespace_label_selector"] = "hycu.io/backup=true"
    r = H.action_namespaces()
    check(r["namespaces"] == ["app", "shop"], "liste des namespaces restreinte au sélecteur")
    check(H._namespace_allowed("app") and not H._namespace_allowed("autre"),
          "namespace hors sélecteur refusé par les gardes")
    H.kubectl = lambda *a, **k: {"ok": False, "stdout": "", "stderr": "boom", "rc": 1}
    check(not H._namespace_allowed("app"), "erreur kubectl = refus (fail-safe)")
    H.kubectl = fake_kubectl
    H.CONFIG["namespace_label_selector"] = ""

    print("\n== Rapport de conformité ==")
    now = datetime.datetime.now().timestamp()
    fake = {"generated": "2026-09-24T12:00:00", "version": H.VERSION,
            "apps": {"apps": [
                {"name": "wordpress", "cluster": "prod", "workspace": "Team A", "protected": True,
                 "compliant": True, "backups": 12, "last_backup": now, "volumes": 2},
                {"name": "bo<script>", "cluster": "local", "workspace": "", "protected": False,
                 "compliant": False, "backups": 0, "last_backup": None, "volumes": None}],
                "policy": {"enabled": True, "interval_hours": 24}},
            "jobs": {"counts": {"success": 4, "failed": 1, "simulation": 2},
                     "jobs": [{"ts": "2026-09-24T10:00:00", "event": "backup", "namespace": "wordpress",
                               "cluster": "prod", "status": "success"}]},
            "auto_backup": {"enabled": True, "interval_hours": 24, "keep": 15, "retention": "gfs",
                            "gfs": {"daily": 7, "weekly": 4, "monthly": 12}},
            "health": {"prod": {"ok": False, "error": "timeout", "at": now}},
            "s3": {"configured": True, "auto_upload": True, "encrypt": True}}
    html = H.report_html(fake)
    check("wordpress" in html and "Team A" in html and "Rapport de protection" in html, "HTML : contenu")
    check("<script>" not in html and "bo&lt;script&gt;" in html, "HTML : namespace hostile échappé")
    check("1/2" in html and "GFS 7 j / 4 sem / 12 mois" in html, "HTML : indicateurs + rétention GFS")
    check("activé (chiffré)" in html and "timeout" in html, "HTML : S3 chiffré + santé des clusters")
    en = H._tr_en(html)
    check("Kubernetes application protection report" in en and "Généré" not in en
          and "enabled (encrypted)" in en, "rapport traduit en anglais")
    csv = H.report_csv(fake)
    lines = csv.strip().splitlines()
    check(len(lines) == 3 and lines[1].startswith("prod;Team A;wordpress;wordpress;;oui;oui;12;"),
          "CSV : une ligne par application (namespace, application, type)")

    print("\n== Chiffrement des exports (HV2B) ==")
    blob = H.encrypt_bytes(b"donnees-zip" * 100, "phrase!")
    check(blob.startswith(b"HV2B") and H.decrypt_bytes(blob, "phrase!") == b"donnees-zip" * 100,
          "aller-retour chiffrement/déchiffrement")
    check(H.decrypt_bytes(blob, "mauvaise") is None, "mauvaise phrase refusée (scellé)")
    check(H.decrypt_bytes(blob[:-1] + b"x", "phrase!") is None, "fichier altéré refusé")
    old_iter = H.CONFIG["pbkdf2_iterations"]
    H.CONFIG["pbkdf2_iterations"] = 2000
    check(H.decrypt_bytes(blob, "phrase!") == b"donnees-zip" * 100,
          "itérations lues dans le blob (changement de config sans effet)")
    H.CONFIG["pbkdf2_iterations"] = old_iter
    with H.CRED_LOCK:
        H.SESSION_CREDS["s3"] = {"access": "a", "secret": "s"}
    H.CONFIG.update({"s3_encrypt": True, "s3_url": "http://127.0.0.1:1", "s3_bucket": "b"})
    bdir = os.path.join(tmp, "wp", "2026-09-24_09-00-00_000000")
    os.makedirs(bdir); open(os.path.join(bdir, "index.json"), "w").write("{}")
    ok, err = H.s3_upload_backup(bdir, "wp", "2026-09-24_09-00-00_000000")
    check(not ok and "phrase de chiffrement absente" in err,
          "chiffrement activé sans phrase : refus explicite (pas d'envoi en clair)")
    H.CONFIG["s3_encrypt"] = False
    with H.CRED_LOCK:
        H.SESSION_CREDS["s3"] = None

    print("\n== Restauration guidée des objets ==")
    rdir = os.path.join(tmp, "boutique", "2026-09-24_08-00-00_000000")
    os.makedirs(rdir)
    dep = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web"},
           "spec": {"replicas": 2}}
    secret = {"apiVersion": "v1", "kind": "Secret",
              "metadata": {"name": "db", "annotations": {"hycu.backup/secret-data": "redacted"}},
              "data": {"pass": "__REDACTED__"}}
    ing = {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": {"name": "front"},
           "spec": {"rules": []}}
    with open(os.path.join(rdir, "index.json"), "w") as f:
        json.dump({"namespace": "boutique", "created": "2026-09-24T08:00:00"}, f)
    with open(os.path.join(rdir, "resources.json"), "w") as f:
        json.dump({"namespace": "boutique", "items": [dep, secret, ing]}, f)

    def live_kubectl_json(args):
        if args[0] == "get" and args[1] == "deployment.apps":
            live = json.loads(json.dumps(dep)); live["spec"]["replicas"] = 5
            live["metadata"]["uid"] = "u"; live["status"] = {"x": 1}
            return live, None
        if args[0] == "get" and args[1] == "ingress.networking.k8s.io":
            return {}, None                              # absent du live
        return None, "inattendu: %s" % args
    H.kubectl_json = live_kubectl_json
    payload = {"namespace": "boutique", "backup_path": rdir}
    r = H.action_objects_list(payload)
    kinds = {(x["kind"], x["redacted"]) for x in r["items"]}
    check(r["ok"] and ("Deployment", False) in kinds and ("Secret", True) in kinds,
          "liste : objets de l'instantané, Secret masqué signalé")
    check(not H.action_objects_list({"namespace": "boutique",
                                     "backup_path": os.path.join(tmp, "wp", "2026-09-24_09-00-00_000000")})["ok"],
          "sauvegarde sans resources.json : erreur claire")
    idx = {x["kind"]: x["i"] for x in r["items"]}
    d = H.action_objects_diff({**payload, "indexes": [idx["Deployment"], idx["Ingress"], idx["Secret"]]})
    st = {x["kind"]: x for x in d["results"]}
    check(st["Deployment"]["status"] == "differs" and '"replicas": 2' in st["Deployment"]["diff"]
          and '"replicas": 5' in st["Deployment"]["diff"], "diff : réplicas 5 (live) -> 2 (sauvegarde)")
    check("uid" not in st["Deployment"]["diff"] and "status" not in st["Deployment"]["diff"],
          "diff : le live est nettoyé comme la sauvegarde (pas de bruit uid/status)")
    check(st["Ingress"]["status"] == "absent", "objet absent du live : sera recréé (kind.groupe résolu)")
    check(st["Secret"]["status"] == "redacted", "Secret masqué : signalé non restaurable")
    applied = []
    H._apply_manifest = lambda m, b, dry, label: (applied.append((m["kind"], dry)) or
        {"ok": True, "dry": dry, "cmd": "kubectl apply -f -", "stdout": "", "stderr": "", "rc": 0, "label": label})
    H._context_guard = lambda p: None
    r = H.action_objects_restore({**payload, "indexes": [idx["Deployment"], idx["Secret"], idx["Ingress"]],
                                  "dry": False})
    check(r["ok"] and r["applied"] == 2 and r["skipped"] == 1, "apply réel : 2 appliqués, Secret masqué ignoré")
    check(("Secret", False) not in [a for a in applied], "le Secret masqué n'est JAMAIS appliqué")
    check(not H.action_objects_restore({**payload, "indexes": []})["ok"], "aucune sélection : refus")
    recs = [json.loads(l) for l in open(os.path.join(tmp, "audit.log"))]
    check(any(x["event"] == "restore_objects" and x["count"] == 2 and x["skipped"] == 1 for x in recs),
          "audit : restore_objects tracé")
    print("\n== Garde-fous du stockage ==")
    import collections
    DU = collections.namedtuple("du", "total used free")
    old_du = H.shutil.disk_usage
    H.shutil.disk_usage = lambda p: DU(100 * 1024**3, 99 * 1024**3, 100 * 1024**2)   # 100 Mo libres
    H.CONFIG["storage_min_free_mb"] = 500
    r = H.action_backup("app")
    check(not r["ok"] and "REFUS" in r["error"], "plancher : sauvegarde refusée sous 500 Mo libres")
    recs = [json.loads(l) for l in open(os.path.join(tmp, "audit.log"))]
    check(any(x["event"] == "backup_refused_storage" for x in recs), "refus audité")
    H.shutil.disk_usage = old_du
    H.CONFIG["storage_min_free_mb"] = 0

    # quota global : 6 sauvegardes ~1 Mo, quota qui n'en tient que ~3
    qns = ("q1", "q2")
    qdirs = []
    for i in range(3):
        for ns in qns:
            d = os.path.join(tmp, ns, (base + datetime.timedelta(hours=i)).strftime("%Y-%m-%d_%H-%M-%S_%f"))
            os.makedirs(d)
            with open(os.path.join(d, "index.json"), "w") as f:
                json.dump({"namespace": ns, "created": (base + datetime.timedelta(hours=i)).isoformat()}, f)
            with open(os.path.join(d, "gros.bin"), "wb") as f:
                f.write(b"x" * (1024 * 1024))
            qdirs.append(d)
    # une transaction en cours protège la PREMIÈRE (la plus ancienne) de q1
    os.makedirs(os.path.join(tmp, "q1"), exist_ok=True)
    with open(os.path.join(tmp, "q1", "_restore_txn.json"), "w") as f:
        json.dump({"status": "in_progress", "backup_dir": qdirs[0]}, f)
    total0 = sum(H._dir_size(d)[0] for d in qdirs)
    H.CONFIG["storage_quota_gb"] = round((3.2 * 1024 * 1024) / 1024**3, 6)   # ~3 Mo
    removed, freed = H.enforce_storage_quota(tmp)
    left = [d for d in qdirs if os.path.isdir(d)]
    check(removed >= 2 and freed > 0, "quota : %d sauvegardes purgées (%d Ko libérés)" % (removed, freed // 1024))
    check(os.path.isdir(qdirs[0]), "sauvegarde d'une transaction en cours JAMAIS purgée")
    for ns in qns:
        latest = sorted([d for d in qdirs if os.sep + ns + os.sep in d])[-1]
        check(os.path.isdir(latest), "la plus récente de %s toujours conservée" % ns)
    check(any(json.loads(l)["event"] == "storage_quota_prune" for l in open(os.path.join(tmp, "audit.log"))),
          "purge de quota auditée")
    H.CONFIG["storage_quota_gb"] = 0
    os.remove(os.path.join(tmp, "q1", "_restore_txn.json"))

    st = H.action_storage()
    r0 = st["roots"][0]
    check(st["ok"] and r0["exists"] and r0["backups_count"] >= 4 and r0["disk_total"] > 0,
          "/api/storage : espace disque + versions comptées")

    print("\n== Hiérarchie par contexte (prod/dev, mêmes namespaces) ==")
    import time as _t
    def set_ctx(name):
        H._LOCAL_CTX.update({"name": name, "at": _t.time()})
    set_ctx("prod-ctx")
    d_prod = H.backup_dir("wordpress")
    check(os.sep + os.path.join("_contexts", "prod-ctx", "wordpress") + os.sep in d_prod + os.sep,
          "contexte prod : <root>/_contexts/prod-ctx/wordpress/…")
    with open(os.path.join(d_prod, "index.json"), "w") as f:
        json.dump({"namespace": "wordpress", "context": "prod-ctx", "cluster_id": "local",
                   "created": datetime.datetime.now().isoformat()}, f)
    set_ctx("dev-ctx")
    d_dev = H.backup_dir("wordpress")
    with open(os.path.join(d_dev, "index.json"), "w") as f:
        json.dump({"namespace": "wordpress", "context": "dev-ctx", "cluster_id": "local",
                   "created": datetime.datetime.now().isoformat()}, f)
    check("_contexts%sdev-ctx" % os.sep in d_dev and d_dev != d_prod,
          "contexte dev : dossier distinct — aucun mélange")
    # ancienne sauvegarde (disposition historique <root>/<ns>) prise sur prod
    old = os.path.join(tmp, "wordpress", "2020-01-01_00-00-00_000000")
    os.makedirs(old)
    with open(os.path.join(old, "index.json"), "w") as f:
        json.dump({"namespace": "wordpress", "context": "prod-ctx",
                   "created": "2020-01-01T00:00:00"}, f)
    set_ctx("prod-ctx")
    lp = H.list_backups("wordpress")
    check([b["path"] for b in lp] == [d_prod, old],
          "prod : sa sauvegarde + l'ancienne disposition (même contexte), sans celle de dev")
    set_ctx("dev-ctx")
    ld = H.list_backups("wordpress")
    check([b["path"] for b in ld] == [d_dev], "dev : uniquement la sienne (l'ancienne est filtrée)")
    check(H._backup_cluster_error(d_prod) and "prod-ctx" in H._backup_cluster_error(d_prod),
          "garde : restaurer une sauvegarde prod sur le contexte dev est refusé")
    set_ctx("prod-ctx")
    check(H._backup_cluster_error(d_prod) is None, "même contexte : restauration acceptée")
    check(H._txn_path("wordpress").startswith(os.path.join(tmp, "_contexts", "prod-ctx")),
          "transaction/état des réplicas rangés par contexte")
    H._LOCAL_CTX.update({"name": None, "at": 0.0})

    print("\n== Compaction du journal d'audit ==")
    now = datetime.datetime.now()
    with open(os.path.join(tmp, "audit.log"), "w") as f:
        f.write("ligne illisible à conserver\n")
        f.write(json.dumps({"ts": (now - datetime.timedelta(days=60)).isoformat(), "event": "backup"}) + "\n")
        f.write(json.dumps({"ts": (now - datetime.timedelta(days=2)).isoformat(), "event": "backup"}) + "\n")
    H.CONFIG["audit_retention_days"] = 31
    n = H._audit_compact()
    lines = open(os.path.join(tmp, "audit.log")).read().splitlines()
    check(n == 1 and len(lines) == 2 and "illisible" in lines[0], "purge > 31 j ; lignes non datées conservées")
    H.CONFIG["audit_retention_days"] = 0
    check(H._audit_compact() == 0, "0 = conservation illimitée (aucune purge)")
finally:
    H.shutil.disk_usage = old_du
    (H.kubectl, H.kubectl_json, H.action_namespaces, H._apply_manifest, H._context_guard) = saved_fns
    H.CONFIG.clear(); H.CONFIG.update(saved)
    shutil.rmtree(tmp, ignore_errors=True)

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
