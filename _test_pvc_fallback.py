# -*- coding: utf-8 -*-
"""Test du repli de récupération du PVC : sauvegarde -> live -> None.
Garantit qu'un restore-clone (rattacher) peut recréer le PVC SANS export préalable
(étape 1), tant que le PVC existe encore dans le cluster à la préparation."""
import hycu_k8s_nutanix as H

passed = failed = 0
def check(c, m):
    global passed, failed
    if c: passed += 1; print("  OK  ", m)
    else: failed += 1; print("  FAIL", m)

ns, pvc = "wordpress", "mariadb-pvc"

print("\n== 1. Sauvegarde présente -> utilisée ==")
H._load_backup_pvc = lambda bp, name: {"kind": "PersistentVolumeClaim",
                                       "metadata": {"name": name}, "_src": "backup"}
got = H._load_old_pvc(ns, pvc, "/un/backup")
check(got and got.get("_src") == "backup", "PVC pris dans la sauvegarde")

print("\n== 2. Pas de sauvegarde -> repli LIVE (nettoyé) ==")
H._load_backup_pvc = lambda bp, name: None
H.kubectl_json = lambda args: ({"kind": "PersistentVolumeClaim",
                                "metadata": {"name": pvc, "uid": "x", "resourceVersion": "9"},
                                "status": {"phase": "Bound"},
                                "spec": {"accessModes": ["ReadWriteOnce"]}}, None)
got2 = H._load_old_pvc(ns, pvc, None)
check(got2 is not None and got2["metadata"]["name"] == pvc, "PVC lu en live")
check("uid" not in got2["metadata"] and "resourceVersion" not in got2["metadata"], "identité runtime nettoyée")
check("status" not in got2, "status retiré")

print("\n== 3. Ni sauvegarde ni live -> None (sinistre) ==")
H.kubectl_json = lambda args: (None, "not found")
check(H._load_old_pvc(ns, pvc, None) is None, "None si PVC introuvable partout")

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
