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

print("\n== 4b. PV SOURCE sans hypervisorAttachedDiskUUIDs -> attribut NON ajouté (miroir de la source) ==")
H.SESSION_CREDS.pop("prismcentral", None)          # même sans Prism Central : rien à résoudre
pv5 = fresh_pv(); log5 = []
ret5 = H._set_clone_disk_uuids(pv5, HANDLE, dry=False, log=log5, source_had=False)
check(ret5 is True and "hypervisorAttachedDiskUUIDs" not in pv5["spec"]["csi"]["volumeAttributes"],
      "source sans l'attribut : True, PV cloné sans l'attribut (le CSI s'en passe, comme pour l'original)")
check(any("non ajouté" in l.get("label", "") for l in log5), "journalisé")
pv6 = fresh_pv(); pv6["spec"]["csi"]["volumeAttributes"]["hypervisorAttachedDiskUUIDs"] = "residu"; log6 = []
H._set_clone_disk_uuids(pv6, HANDLE, dry=False, log=log6, source_had=False)
check("hypervisorAttachedDiskUUIDs" not in pv6["spec"]["csi"]["volumeAttributes"], "un résidu est retiré")

print("\n== 4c. Vérification : raison d'un pod bloqué (événement Warning + attente conteneur) ==")
s_kj = H.kubectl_json
def kj_verify(args):
    if args[:2] == ["get", "pvc"]:
        return {"items": [{"metadata": {"name": "data"}, "spec": {"volumeName": "pv-1"}, "status": {"phase": "Bound"}}]}, None
    if args[:2] == ["get", "pv"]:
        return {"items": [{"metadata": {"name": "pv-1"}, "spec": {"csi": {"volumeHandle": "NutanixVolumes-x"}}}]}, None
    if args[:2] == ["get", "pods"]:
        return {"items": [{"metadata": {"name": "db-1"}, "status": {"phase": "Pending", "containerStatuses": [
                    {"ready": False, "state": {"waiting": {"reason": "ContainerCreating"}}}]}},
                          {"metadata": {"name": "web-1"}, "status": {"phase": "Running", "containerStatuses": [{"ready": True, "state": {"running": {}}}]}}]}, None
    if args[:2] == ["get", "events"]:
        return {"items": [
            {"type": "Warning", "reason": "FailedScheduling", "message": "old", "lastTimestamp": "2026-09-28T14:20:00Z", "count": 1, "involvedObject": {"kind": "Pod", "name": "db-1"}},
            {"type": "Warning", "reason": "FailedAttachVolume", "message": "AttachVolume.Attach failed: hypervisor Attach Client failed", "lastTimestamp": "2026-09-28T14:25:00Z", "count": 7, "involvedObject": {"kind": "Pod", "name": "db-1"}},
            {"type": "Normal", "reason": "Scheduled", "message": "ok", "lastTimestamp": "2026-09-28T14:26:00Z", "involvedObject": {"kind": "Pod", "name": "db-1"}},
            {"type": "Warning", "reason": "BackOff", "message": "ancien", "lastTimestamp": "2026-09-28T13:00:00Z", "involvedObject": {"kind": "Pod", "name": "web-1"}}]}, None
    return {"items": []}, None
H.kubectl_json = kj_verify
s_allowed = H._namespace_allowed
H._namespace_allowed = lambda ns: True
try:
    v = H.action_verify("ns")
finally:
    H.kubectl_json = s_kj
    H._namespace_allowed = s_allowed
pods = {p["name"]: p for p in v["pods"]}
check(v["ok"] and pods["db-1"]["issue"]["reason"] == "FailedAttachVolume" and pods["db-1"]["issue"]["count"] == 7
      and "Attach Client failed" in pods["db-1"]["issue"]["message"] and pods["db-1"]["waiting"] == "ContainerCreating",
      "pod bloqué : dernier événement Warning (le plus récent, pas le Normal) + raison d'attente")
check("issue" not in pods["web-1"], "pod Running et prêt : ancien Warning ignoré")
def kj_verify2(args):
    if args[:2] == ["get", "pods"]:
        return {"items": [{"metadata": {"name": "db-2"}, "spec": {"nodeName": "worker-1"}, "status": {"phase": "Pending", "containerStatuses": [
                    {"ready": False, "state": {"waiting": {"reason": "ContainerCreating"}}}]}}]}, None
    if args[:2] == ["get", "events"]:
        return {"items": [{"type": "Warning", "reason": "FailedScheduling", "message": "pod has unbound immediate PersistentVolumeClaims",
                           "lastTimestamp": "2026-09-28T14:20:00Z", "count": 1, "involvedObject": {"kind": "Pod", "name": "db-2"}}]}, None
    return kj_verify(args)
H.kubectl_json = kj_verify2
H._namespace_allowed = lambda ns: True
try:
    v2 = H.action_verify("ns")
finally:
    H.kubectl_json = s_kj
    H._namespace_allowed = s_allowed
check("issue" not in v2["pods"][0] and v2["pods"][0]["waiting"] == "ContainerCreating",
      "FailedScheduling d'avant la liaison du PVC : ignoré dès que le pod est placé sur un nœud")

print("\n== 4d. IQN du PV cloné aligné sur la cible iSCSI réelle du VG (HYCU : « hycu-clone-vg-… ») ==")
def fake_raw_vg(system, method, path, body=None, timeout=30):
    if "/disks" in path:
        return {"ok": True, "json": {"data": [{"extId": CLONE_DISK}]}}
    if path.endswith("/volume-groups/" + CLONE_VG):
        return {"ok": True, "json": {"data": {"extId": CLONE_VG, "targetName": "hycu-clone-vg-" + CLONE_VG}}}
    return {"ok": False, "error": "unexpected"}
H._rest_raw = fake_raw_vg
H.SESSION_CREDS["prismcentral"] = {"mode": "basic"}
check(H._vg_target_name(CLONE_VG) == "hycu-clone-vg-" + CLONE_VG, "targetName lu via v4")
check(H._iqn_for_target("iqn.2010-06.com.nutanix:ntnx-k8s-abc-tgt0", "hycu-clone-vg-abc") == "iqn.2010-06.com.nutanix:hycu-clone-vg-abc-tgt0"
      and H._iqn_for_target("iqn.2010-06.com.nutanix:ntnx-k8s-abc-98765-tgt0", "x") == "iqn.2010-06.com.nutanix:x-tgt0"
      and H._iqn_for_target("sans-deux-points", "x") is None, "IQN reconstruit : préfixe source, cible réelle, suffixe -tgtN")
def pv_iqn():
    p = fresh_pv(); p["spec"]["csi"]["volumeAttributes"]["iqn"] = "iqn.2010-06.com.nutanix:ntnx-k8s-" + CLONE_VG + "-tgt0"; return p
pv7 = pv_iqn(); log7 = []
check(H._fix_clone_iqn(pv7, HANDLE, dry=False, log=log7) is True
      and pv7["spec"]["csi"]["volumeAttributes"]["iqn"] == "iqn.2010-06.com.nutanix:hycu-clone-vg-" + CLONE_VG + "-tgt0"
      and any("aligné" in l.get("label", "") for l in log7), "réel : IQN réécrit avec la cible réelle du VG cloné")
pv8 = pv_iqn(); log8 = []
H._fix_clone_iqn(pv8, HANDLE, dry=True, log=log8)
check(pv8["spec"]["csi"]["volumeAttributes"]["iqn"].endswith("ntnx-k8s-" + CLONE_VG + "-tgt0") and log8 and log8[0]["dry"], "dry : aperçu, PV intact")
H.SESSION_CREDS.pop("prismcentral", None)
pv9 = pv_iqn(); log9 = []
check(H._fix_clone_iqn(pv9, HANDLE, dry=False, log=log9) is True and pv9["spec"]["csi"]["volumeAttributes"]["iqn"].endswith("ntnx-k8s-" + CLONE_VG + "-tgt0")
      and any(l.get("ok") is False for l in log9), "sans Prism Central : IQN dérivé conservé, avertissement (non bloquant)")
H.SESSION_CREDS["prismcentral"] = {"mode": "basic"}
H._rest_raw = lambda system, method, path, body=None, timeout=30: ({"ok": True, "json": {"data": {"targetName": "ntnx-k8s-" + CLONE_VG}}} if path.endswith(CLONE_VG) else fake_raw(system, method, path))
pv10 = pv_iqn(); log10 = []
H._fix_clone_iqn(pv10, HANDLE, dry=False, log=log10)
check(pv10["spec"]["csi"]["volumeAttributes"]["iqn"].endswith("ntnx-k8s-" + CLONE_VG + "-tgt0") and any("conforme" in l.get("label", "") for l in log10),
      "cible déjà conforme : IQN inchangé")
H._rest_raw = fake_raw

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
