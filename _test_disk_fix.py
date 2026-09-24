# -*- coding: utf-8 -*-
"""Test du correctif hypervisorAttachedDiskUUIDs (disque du VG cloné via v4)."""
import hycu_k8s_nutanix as H

passed = failed = 0
def check(c, m):
    global passed, failed
    if c: passed += 1; print("  OK  ", m)
    else: failed += 1; print("  FAIL", m)

CLONE_VG = "7060521a-815d-472c-8864-68ab6d98b88b"
CLONE_DISK = "519fd2c6-e1bc-4228-a2eb-2b15676a0528"
HANDLE = "NutanixVolumes-" + CLONE_VG

def fake_raw(system, method, path, body=None, timeout=30):
    if "/disks" in path:
        return {"ok": True, "json": {"data": [{"extId": CLONE_DISK}]}}
    return {"ok": False, "error": "unexpected"}

H._rest_raw = fake_raw

print("\n== 1. _clone_vg_disk_uuids ==")
check(H._clone_vg_disk_uuids(CLONE_VG) == CLONE_DISK, "extId du disque du VG cloné lu via v4")

def fresh_pv():
    return {"spec": {"csi": {"driver": "csi.nutanix.com",
                             "volumeHandle": HANDLE,
                             "volumeAttributes": {"peClusterRef": "x"}}}}

print("\n== 2. _set_clone_disk_uuids : réel + PC connecté -> renseigne le PV, retourne True ==")
H.SESSION_CREDS["prismcentral"] = {"mode": "basic"}
pv = fresh_pv(); log = []
ret = H._set_clone_disk_uuids(pv, HANDLE, dry=False, log=log)
va = pv["spec"]["csi"]["volumeAttributes"]
check(ret is True, "retourne True (peut continuer)")
check(va.get("hypervisorAttachedDiskUUIDs") == CLONE_DISK, "hypervisorAttachedDiskUUIDs = disque du VG CLONÉ")
check(any("renseigné" in l.get("label", "") for l in log), "journalisé")

print("\n== 3. dry-run : aperçu, ne modifie pas le PV, retourne True ==")
pv2 = fresh_pv(); log2 = []
ret2 = H._set_clone_disk_uuids(pv2, HANDLE, dry=True, log=log2)
check(ret2 is True and "hypervisorAttachedDiskUUIDs" not in pv2["spec"]["csi"]["volumeAttributes"], "True + PV non modifié en dry")
check(log2 and log2[0]["dry"] is True, "aperçu journalisé")

print("\n== 4. PC non connecté -> retourne False (bloquant), n'altère pas le PV ==")
H.SESSION_CREDS.pop("prismcentral", None)
pv3 = fresh_pv(); log3 = []
ret3 = H._set_clone_disk_uuids(pv3, HANDLE, dry=False, log=log3)
check(ret3 is False, "retourne False -> l'appelant abandonnera")
check("hypervisorAttachedDiskUUIDs" not in pv3["spec"]["csi"]["volumeAttributes"], "PV non altéré sans PC")
check(any(l.get("ok") is False for l in log3), "entrée de log en erreur")

print("\n== 5. clone_fix_disk_uuids=False -> désactivé, retourne True ==")
H.SESSION_CREDS["prismcentral"] = {"mode": "basic"}
H.CONFIG["clone_fix_disk_uuids"] = False
pv4 = fresh_pv(); log4 = []
ret4 = H._set_clone_disk_uuids(pv4, HANDLE, dry=False, log=log4)
check(ret4 is True and "hypervisorAttachedDiskUUIDs" not in pv4["spec"]["csi"]["volumeAttributes"] and log4 == [],
      "True + rien quand désactivé")
H.CONFIG["clone_fix_disk_uuids"] = True

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
