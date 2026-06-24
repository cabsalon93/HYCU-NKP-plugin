# -*- coding: utf-8 -*-
"""Test de l'action de détachement manuel d'un VG (mock API Nutanix PE v2).
NB : `_detach_clone_vg` a été retiré (le bon correctif clone est _set_clone_disk_uuids) ;
seul `action_nutanix_detach_vg` reste, exposé pour un détachement MANUEL."""
import hycu_k8s_nutanix as H

passed = failed = 0
def check(c, m):
    global passed, failed
    if c: passed += 1; print("  OK  ", m)
    else: failed += 1; print("  FAIL", m)

VG = "7060521a-815d-472c-8864-68ab6d98b88b"
VM = "cabdemok8s-md-0-wljz5-75vms-dglvr-uuid"

calls = []
def fake_rest(system, method, path, body=None, timeout=30):
    calls.append((method, path, body))
    if method == "GET":
        return {"ok": True, "json": {"uuid": VG, "attachment_list": [{"vm_uuid": VM}]}}
    if method == "POST" and path.endswith("/detach"):
        return {"ok": True, "json": {"task_uuid": "t1"}}
    return {"ok": False, "error": "unexpected"}

H._rest = fake_rest
H.SESSION_CREDS["nutanix"] = {"mode": "basic"}
H._nutanix_source = lambda: "nutanix"

print("\n== 1. action_nutanix_detach_vg : détache la VM ==")
res = H.action_nutanix_detach_vg(VG)
check(res["ok"] is True, "ok")
check(res["detached"] == [VM], "VM détachée")
check(any(m == "POST" and p.endswith("/detach") and b.get("vm_uuid") == VM for m, p, b in calls),
      "POST .../detach avec vm_uuid envoyé")

print("\n== 2. VG déjà libre (aucune attachment) ==")
H._rest = lambda *a, **k: {"ok": True, "json": {"uuid": VG, "attachment_list": []}}
res2 = H.action_nutanix_detach_vg(VG)
check(res2["ok"] and res2.get("already_free") is True, "already_free")

print("\n== 3. UUID manquant / pas de source PE ==")
check(H.action_nutanix_detach_vg("")["ok"] is False, "uuid vide rejeté")
H._nutanix_source = lambda: None
check(H.action_nutanix_detach_vg(VG)["ok"] is False, "refus si pas de Prism Element")

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
