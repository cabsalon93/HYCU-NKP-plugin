# -*- coding: utf-8 -*-
"""Vues « à la HYCU » : Applications (protection / conformité des namespaces) et
Tâches (historique tiré du journal d'audit). Lecture seule."""
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


def make_backup(root, ns, when, volumes=1):
    d = os.path.join(root, ns, when.strftime("%Y-%m-%d_%H-%M-%S_%f"))
    os.makedirs(d)
    with open(os.path.join(d, "index.json"), "w", encoding="utf-8") as f:
        json.dump({"namespace": ns, "created": when.isoformat(),
                   "volumes": [{"pvc": "p%d" % i} for i in range(volumes)]}, f)


tmp = tempfile.mkdtemp()
saved = {k: H.CONFIG.get(k) for k in ("backup_root", "auto_backup_enabled",
                                      "auto_backup_interval_hours", "auto_backup_dest")}
old_ns = H.action_namespaces
try:
    H.CONFIG.update({"backup_root": tmp, "auto_backup_enabled": False, "auto_backup_dest": ""})
    now = datetime.datetime.now()
    make_backup(tmp, "wordpress", now - datetime.timedelta(hours=2), volumes=2)
    make_backup(tmp, "wordpress", now - datetime.timedelta(days=3))
    make_backup(tmp, "vieux", now - datetime.timedelta(days=5))
    H.action_namespaces = lambda: {"ok": True, "namespaces": ["wordpress", "vieux", "neuf"]}

    print("== Applications ==")
    r = H.action_applications()
    apps = {a["name"]: a for a in r["apps"]}
    check(r["ok"] and len(apps) == 3, "3 namespaces listés")
    check(apps["wordpress"]["protected"] and apps["wordpress"]["compliant"], "sauvegarde récente : protégé + conforme")
    check(apps["wordpress"]["backups"] == 2 and apps["wordpress"]["volumes"] == 2,
          "compte des versions + volumes de la plus récente")
    check(apps["vieux"]["protected"] and not apps["vieux"]["compliant"], "sauvegarde de 5 j : protégé mais NON conforme (24 h)")
    check(not apps["neuf"]["protected"] and apps["neuf"]["last_backup"] is None, "jamais sauvegardé : non protégé")
    H.CONFIG.update({"auto_backup_enabled": True, "auto_backup_interval_hours": 168})
    check(H.action_applications()["apps"][1]["compliant"], "politique 7 j : la sauvegarde de 5 j redevient conforme")
    H.CONFIG["auto_backup_enabled"] = False

    # Dossier de la sauvegarde auto distinct : ses sauvegardes comptent aussi.
    other = os.path.join(tmp, "_auto")
    make_backup(other, "neuf", now - datetime.timedelta(hours=1))
    H.CONFIG["auto_backup_dest"] = other
    check(H.action_applications()["apps"][2]["protected"], "sauvegardes du dossier auto prises en compte")
    H.CONFIG["auto_backup_dest"] = ""

    print("\n== Tâches ==")
    today = now.date().isoformat()
    recs = [
        {"ts": today + "T08:00:00", "event": "connect", "system": "hycu"},          # ignoré
        {"ts": today + "T09:00:00", "event": "backup", "namespace": "wordpress", "count": 2},
        {"ts": today + "T10:00:00", "event": "restore_end", "namespace": "wordpress", "dry": True, "ok": True},
        {"ts": today + "T11:00:00", "event": "clone_app", "namespace": "wordpress",
         "target_namespace": "restorecab", "dry": False, "ok": False},
        {"ts": today + "T12:00:00", "event": "orchestrate_inplace", "namespace": "db", "dry": False,
         "ok": True, "aborted": True},
        {"ts": today + "T13:00:00", "event": "auto_backup", "ok": True, "summary": "3 namespace(s)"},
    ]
    with open(os.path.join(tmp, "audit.log"), "w", encoding="utf-8") as f:
        f.write("ligne corrompue\n")
        for rec in recs:
            f.write(json.dumps(rec) + "\n")
    j = H.action_jobs()
    check(j["ok"] and len(j["jobs"]) == 5, "5 tâches (connexion et ligne corrompue ignorées)")
    check(j["jobs"][0]["event"] == "auto_backup", "plus récente d'abord")
    st = {x["event"]: x["status"] for x in j["jobs"]}
    check(st["backup"] == "success", "sauvegarde : succès")
    check(st["restore_end"] == "simulation", "restauration dry-run : simulation")
    check(st["clone_app"] == "failed", "clone en échec : échec")
    check(st["orchestrate_inplace"] == "failed", "séquence interrompue (aborted) : échec")
    check(j["counts"] == {"success": 2, "failed": 2, "simulation": 1}, "compteurs")
    check(len(j["days"]) == 7 and j["days"][-1]["date"] == today and j["days"][-1]["failed"] == 2,
          "activité sur 7 jours (aujourd'hui en dernier)")
    check([x for x in j["jobs"] if x["event"] == "clone_app"][0]["target_namespace"] == "restorecab",
          "namespace cible du clone conservé")

    os.remove(os.path.join(tmp, "audit.log"))
    check(H.action_jobs()["jobs"] == [], "pas de journal : liste vide, sans erreur")
finally:
    H.action_namespaces = old_ns
    H.CONFIG.update(saved)
    shutil.rmtree(tmp, ignore_errors=True)

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
