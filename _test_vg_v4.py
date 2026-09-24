# -*- coding: utf-8 -*-
"""Test du diagnostic v4 (mock de _rest_raw)."""
import hycu_k8s_nutanix as H

passed = failed = 0
def check(c, m):
    global passed, failed
    if c: passed += 1; print("  OK  ", m)
    else: failed += 1; print("  FAIL", m)

calls = []
def fake_raw(system, method, path, body=None, timeout=30):
    calls.append(path)
    if path.endswith("7060521a"):
        return {"ok": True, "json": {"name": "pvc-clone", "sharingStatus": "NOT_SHARED",
                                     "enabledAuthentications": "NONE"}}
    if "external-iscsi-attachments" in path:
        return {"ok": True, "json": {"data": []}}
    if "vm-attachments" in path:
        return {"ok": True, "json": {"data": [{"vmExtId": "vm-1"}]}}
    if "/disks" in path:
        return {"ok": True, "json": {"data": [{"diskSizeBytes": 8589934592}]}}
    return {"ok": True, "json": {}}

H._rest_raw = fake_raw
H.SESSION_CREDS["prismcentral"] = {"mode": "basic"}

r = H.action_nutanix_vg_v4("7060521a")
check(r["ok"] is True, "ok")
check(r["volume_group"]["name"] == "pvc-clone", "config VG récupérée")
check(r["external_iscsi_attachments"] == {"data": []}, "external-iscsi-attachments récupérés")
check(r["vm_attachments"]["data"][0]["vmExtId"] == "vm-1", "vm-attachments récupérés")
check(r["disks"]["data"][0]["diskSizeBytes"] == 8589934592, "disques récupérés")
check(any(p.endswith("7060521a") for p in calls), "GET config VG")
check(any("external-iscsi-attachments" in p for p in calls), "GET external-iscsi-attachments")
check(all(p.startswith("/api/volumes/v4.0.b1/config/volume-groups/") for p in calls), "chemin v4 brut (sans api_base v3)")

H.SESSION_CREDS.pop("prismcentral", None)
r2 = H.action_nutanix_vg_v4("x")
check(r2["ok"] is False and "Prism Central" in r2["error"], "exige Prism Central connecté")
check(H.action_nutanix_vg_v4("")["ok"] is False, "uuid vide rejeté")

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
