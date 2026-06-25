# -*- coding: utf-8 -*-
"""Runner unique : compile le programme + lance toutes les suites _test_*.py et agrège.
Usage : python _test_all.py
"""
import subprocess
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
SUITES = [
    "_test_restore_model",   # build_new_pv : référence VG, purge disque, garde nom, legacy IQN
    "_test_restore_flow",    # ordre Retain / disque / suppression / apply (dry)
    "_test_clone_deps",      # clone cross-ns : Secrets/ConfigMaps/SA/Services
    "_test_detach",          # détachement VG manuel (PE v2)
    "_test_vg_v4",           # diagnostic config VG via Prism Central v4
    "_test_disk_fix",        # réécriture hypervisorAttachedDiskUUIDs (bloquant)
    "_test_async",           # opérations longues : _run_async + op_status
    "_test_txn",             # transaction de restauration (reprise idempotente)
    "_test_pvc_fallback",    # repli PVC sauvegarde -> live -> None (restore sans étape 1)
    "_test_inplace_refresh",  # rafraîchissement PV après restore in-place (disque changé)
    "_test_fixes",           # correctifs revue : V2 reprise, V4 redirection/schéma, V7/V8 clone, V9 tri disques
    "_test_download",        # téléchargement .zip d'une sauvegarde + garde anti-traversée
]


def run(cmd, label):
    r = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True)
    ok = (r.returncode == 0)
    print(("  OK  " if ok else "  FAIL") + "  " + label)
    if not ok:
        print("    --- stdout ---\n" + (r.stdout or "")[-1500:])
        print("    --- stderr ---\n" + (r.stderr or "")[-1500:])
    return ok


def main():
    print("== Compilation ==")
    comp = run([PY, "-m", "py_compile", "hycu_k8s_nutanix.py"], "py_compile hycu_k8s_nutanix.py")
    print("\n== Suites ==")
    results = [run([PY, s + ".py"], s) for s in SUITES]
    n_ok = sum(results) + (1 if comp else 0)
    n_tot = len(SUITES) + 1
    print("\n========================================")
    print("RÉSULTAT GLOBAL : %d / %d vert" % (n_ok, n_tot))
    return 0 if (comp and all(results)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
