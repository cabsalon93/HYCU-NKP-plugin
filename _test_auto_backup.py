# -*- coding: utf-8 -*-
"""Test de la sauvegarde automatique planifiée : calcul d'échéance, exécution
(avec runner factice), persistance de l'état, statut pour l'UI."""
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
old_root = H.CONFIG["backup_root"]
old_cfg = {k: H.CONFIG.get(k) for k in ("auto_backup_enabled", "auto_backup_interval_hours", "auto_backup_dest")}
H.CONFIG["backup_root"] = tmp
H.AUTO_BACKUP.update({"last_run": 0.0, "last_ok": None, "last_summary": "", "running": False})
try:
    # Désactivée -> jamais due.
    H.CONFIG["auto_backup_enabled"] = False
    check(not H._auto_backup_due(1e9), "désactivée : jamais due")

    # Activée, jamais exécutée -> due immédiatement.
    H.CONFIG["auto_backup_enabled"] = True
    H.CONFIG["auto_backup_interval_hours"] = 24
    check(H._auto_backup_due(1000.0), "activée sans historique : due immédiatement")

    # Exécution avec runner factice (succès) : état enregistré + persisté.
    calls = []
    def fake_runner(dest):
        calls.append(dest)
        return {"ok": True, "backed_up": 3, "volumes": 7}
    H.CONFIG["auto_backup_dest"] = ""
    ok = H._auto_backup_run(now=1000.0, runner=fake_runner)
    check(ok and calls == [None], "runner appelé (dest par défaut)")
    check(H.AUTO_BACKUP["last_run"] == 1000.0 and H.AUTO_BACKUP["last_ok"] is True,
          "dernier passage enregistré")
    check("3 namespace(s)" in H.AUTO_BACKUP["last_summary"], "résumé lisible")
    st = json.load(open(H._auto_backup_state_path(), encoding="utf-8"))
    check(st.get("last_run") == 1000.0, "état persisté sur disque")

    # Échéance : pas due avant l'intervalle, due après.
    check(not H._auto_backup_due(1000.0 + 23 * 3600), "pas due avant l'intervalle")
    check(H._auto_backup_due(1000.0 + 25 * 3600), "due après l'intervalle")

    # Intervalle invalide -> retombe sur 24 h ; plancher 15 min.
    H.CONFIG["auto_backup_interval_hours"] = "n'importe quoi"
    check(H._auto_backup_interval_s() == 24 * 3600.0, "intervalle invalide : 24 h par défaut")
    H.CONFIG["auto_backup_interval_hours"] = 0
    check(H._auto_backup_interval_s() == 24 * 3600.0, "0 = non renseigné : 24 h par défaut")
    H.CONFIG["auto_backup_interval_hours"] = 0.01
    check(H._auto_backup_interval_s() == 900.0, "plancher 15 min")

    # Échec du runner : consigné, mais last_run avance (pas de boucle en rafale).
    H.CONFIG["auto_backup_interval_hours"] = 24
    ok = H._auto_backup_run(now=2000.0, runner=lambda d: {"ok": False, "error": "kubectl indisponible"})
    check(not ok and H.AUTO_BACKUP["last_ok"] is False and "kubectl" in H.AUTO_BACKUP["last_summary"],
          "échec consigné")
    check(H.AUTO_BACKUP["last_run"] == 2000.0, "échec : prochaine tentative à l'intervalle suivant")

    # Statut pour l'UI.
    s = H.action_auto_backup_status()
    check(s["ok"] and s["enabled"] and s["last_run"] == 2000.0 and s["next_due"] == 2000.0 + 24 * 3600,
          "statut UI complet (échéance calculée)")

    # Redémarrage simulé : l'état est rechargé depuis le disque.
    H.AUTO_BACKUP.update({"last_run": 0.0, "last_ok": None, "last_summary": ""})
    H._load_auto_backup_state()
    check(H.AUTO_BACKUP["last_run"] == 2000.0, "état rechargé après redémarrage")
finally:
    H.CONFIG["backup_root"] = old_root
    for k, v in old_cfg.items():
        H.CONFIG[k] = v
    shutil.rmtree(tmp, ignore_errors=True)

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
