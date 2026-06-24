# -*- coding: utf-8 -*-
"""Test des helpers de transaction de restauration (reprise idempotente)."""
import tempfile
import shutil
import hycu_k8s_nutanix as H

passed = failed = 0
def check(c, m):
    global passed, failed
    if c: passed += 1; print("  OK  ", m)
    else: failed += 1; print("  FAIL", m)

old_root = H.CONFIG["backup_root"]
H.CONFIG["backup_root"] = tempfile.mkdtemp()
try:
    ns = "ns1"
    check(H._load_txn(ns) is None, "aucune transaction au départ")
    H._save_txn(ns, {"status": "in_progress", "started": "t0", "mode": "clone",
                     "backup_dir": "/d", "volumes": []})
    t = H._load_txn(ns)
    check(t is not None and t["backup_dir"] == "/d" and t["mode"] == "clone", "transaction in_progress relue")
    H._save_txn(ns, {"status": "done"})
    check(H._load_txn(ns) is None, "statut 'done' -> considéré non en cours")
    H._save_txn(ns, {"status": "in_progress", "backup_dir": "/x"})
    H._clear_txn(ns)
    check(H._load_txn(ns) is None, "_clear_txn supprime le marqueur")
    H._clear_txn("inconnu")  # ne doit pas lever
    check(True, "_clear_txn sur ns inexistant : sans erreur")
finally:
    shutil.rmtree(H.CONFIG["backup_root"], ignore_errors=True)
    H.CONFIG["backup_root"] = old_root

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
