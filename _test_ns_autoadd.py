# -*- coding: utf-8 -*-
"""Test de _allow_namespace : un namespace créé par l'outil (clone d'app vers un
nouveau namespace) est ajouté automatiquement à la liste blanche namespace_filter,
sinon Vérifier/Restaurer le refuseraient juste après le clone.
"""
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
old_path = H.CONFIG_PATH
old_flt = H.CONFIG.get("namespace_filter")
H.CONFIG_PATH = os.path.join(tmp, "hycu_config.json")   # ne pas toucher la vraie config
try:
    # Filtre actif : le namespace créé est ajouté et persisté.
    H.CONFIG["namespace_filter"] = ["wordpress", "bo-dev"]
    log = []
    H._allow_namespace("restorecab", log)
    check(H.CONFIG["namespace_filter"] == ["wordpress", "bo-dev", "restorecab"],
          "namespace ajouté au filtre en mémoire")
    check(H._namespace_allowed("restorecab"), "namespace désormais autorisé")
    saved = json.load(open(H.CONFIG_PATH, encoding="utf-8"))
    check("restorecab" in saved.get("namespace_filter", []), "filtre persisté dans hycu_config.json")
    check(len(log) == 1 and log[0]["ok"] and "restorecab" in log[0]["label"],
          "entrée de log explicite pour l'opérateur")

    # Idempotent : déjà présent -> aucun doublon, pas de log supplémentaire.
    H._allow_namespace("restorecab", log)
    check(H.CONFIG["namespace_filter"].count("restorecab") == 1, "pas de doublon")
    check(len(log) == 1, "pas de log superflu quand déjà autorisé")

    # Filtre vide = tous les namespaces autorisés -> rien à faire.
    H.CONFIG["namespace_filter"] = []
    H._allow_namespace("autre", log)
    check(H.CONFIG["namespace_filter"] == [], "filtre vide : inchangé (tous autorisés)")

    # action_verify signale le cas au client (bouton « Autoriser »).
    H.CONFIG["namespace_filter"] = ["a"]
    r = H.action_verify("hors-liste")
    check(r.get("ns_not_allowed") is True and not r["ok"], "verify signale ns_not_allowed")
finally:
    H.CONFIG_PATH = old_path
    H.CONFIG["namespace_filter"] = old_flt
    shutil.rmtree(tmp, ignore_errors=True)

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
