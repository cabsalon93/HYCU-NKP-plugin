# -*- coding: utf-8 -*-
"""Test du runner d'opérations longues (_run_async) + suivi (action_op_status)."""
import time
import hycu_k8s_nutanix as H

passed = failed = 0
def check(c, m):
    global passed, failed
    if c: passed += 1; print("  OK  ", m)
    else: failed += 1; print("  FAIL", m)


def slow_action(payload, log=None):
    log = log if log is not None else []
    log.append(H.logentry("étape 1"))
    time.sleep(0.05)
    log.append(H.logentry("étape 2"))
    return {"ok": True, "log": log, "aborted": False}


print("\n== 1. _run_async renvoie un op_id immédiatement ==")
start = H._run_async(slow_action, {"x": 1})
check(start["ok"] is True and start.get("op_id"), "op_id renvoyé sans bloquer")

print("\n== 2. suivi : progression puis résultat ==")
final = None
for _ in range(200):
    st = H.action_op_status(start["op_id"])
    if st["done"]:
        final = st; break
    time.sleep(0.01)
check(final is not None, "opération terminée (done=True)")
check(final["result"]["ok"] is True, "résultat ok")
check(len(final["result"]["log"]) == 2, "les 2 étapes sont dans le log")

print("\n== 3. op_id inconnu ==")
check(H.action_op_status("inexistant")["ok"] is False, "op inconnue rejetée")

print("\n== 4. l'action reçoit bien le log partagé ==")
shared_seen = {"n": 0}
def counting(payload, log=None):
    log.append(H.logentry("a")); shared_seen["n"] = len(log)
    return {"ok": True, "log": log}
s2 = H._run_async(counting, {})
for _ in range(200):
    if H.action_op_status(s2["op_id"])["done"]: break
    time.sleep(0.01)
check(shared_seen["n"] == 1, "l'action a écrit dans la liste partagée")

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
