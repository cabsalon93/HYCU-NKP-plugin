# -*- coding: utf-8 -*-
"""Test du rafraîchissement du PV après restore in-place (disque du VG changé par HYCU
-> NodeStage « failed to get symlink » -> recréation du PV avec le bon disque)."""
import json
import hycu_k8s_nutanix as H

passed = failed = 0
def check(c, m):
    global passed, failed
    if c: passed += 1; print("  OK  ", m)
    else: failed += 1; print("  FAIL", m)

OLD = "8e85cb99-a91f-4989-999f-b4a88977b439"
NEW = "12340000-0000-0000-0000-000000000000"
VG = "7060521a-815d-472c-8864-68ab6d98b88b"
PVC = {"kind": "PersistentVolumeClaim", "metadata": {"name": "mariadb-pvc", "namespace": "wordpress", "uid": "u"},
       "spec": {"volumeName": "pv1", "accessModes": ["ReadWriteOnce"]}, "status": {"phase": "Bound"}}
PV = {"kind": "PersistentVolume", "metadata": {"name": "pv1", "uid": "x"},
      "spec": {"csi": {"driver": "csi.nutanix.com", "volumeHandle": "NutanixVolumes-" + VG,
                       "volumeAttributes": {"hypervisorAttachedDiskUUIDs": OLD, "peClusterRef": "c"}},
               "persistentVolumeReclaimPolicy": "Delete"}, "status": {}}

def fake_kubectl_json(args):
    if args[:2] == ["get", "pvc"]:
        return (json.loads(json.dumps(PVC)), None)
    if args[:2] == ["get", "pv"]:
        return (json.loads(json.dumps(PV)), None)
    return ({}, None)

applied = []
H.kubectl_json = fake_kubectl_json
H.resource_state = lambda kind, name, ns=None: ("present", "")
H._delete_and_unblock = lambda kind, name, ns, log: True
H._wait_pvc_bound = lambda name, ns, log: True
H.kubectl = lambda args, dry=False, label=None, timeout=None: {"ok": True, "dry": False, "label": label, "cmd": "", "stdout": "", "stderr": "", "rc": 0}
H._apply_manifest = lambda manifest, base, dry, label: (applied.append(manifest), {"ok": True, "dry": dry, "label": label})[1]

print("\n== 1. Disque changé + PC connecté + réel -> recrée le PV avec le NOUVEAU disque ==")
H.SESSION_CREDS["prismcentral"] = {"mode": "basic"}
H._clone_vg_disk_uuids = lambda u: NEW
applied.clear(); log = []
ok, detail = H._refresh_pv_disk("wordpress", "mariadb-pvc", dry=False, log=log)
check(ok is True, "ok")
pv_applied = [m for m in applied if m.get("kind") == "PersistentVolume"]
check(len(pv_applied) == 1, "le PV est recréé")
check(pv_applied and pv_applied[0]["spec"]["csi"]["volumeAttributes"]["hypervisorAttachedDiskUUIDs"] == NEW,
      "hypervisorAttachedDiskUUIDs = nouveau disque")
check(pv_applied and pv_applied[0]["spec"]["csi"]["volumeHandle"] == "NutanixVolumes-" + VG, "même volumeHandle (même VG)")
check(pv_applied and pv_applied[0]["spec"].get("persistentVolumeReclaimPolicy") == "Retain",
      "PV recréé forcé en Retain (V10 : ne pas réarmer la destruction du VG)")

print("\n== 2. Disque INCHANGÉ -> no-op ==")
H._clone_vg_disk_uuids = lambda u: OLD
applied.clear(); log2 = []
ok2, _ = H._refresh_pv_disk("wordpress", "mariadb-pvc", dry=False, log=log2)
check(ok2 is True and not applied, "rien recréé si disque inchangé")

print("\n== 3. PC non connecté -> avertit, ne touche à rien ==")
H.SESSION_CREDS.pop("prismcentral", None)
H._clone_vg_disk_uuids = lambda u: NEW
applied.clear(); log3 = []
ok3, _ = H._refresh_pv_disk("wordpress", "mariadb-pvc", dry=False, log=log3)
check(ok3 is True and not applied, "non bloquant, aucune recréation sans PC")
check(any(l.get("ok") is False for l in log3), "avertissement journalisé")

print("\n== 4. dry-run : aperçu, aucune opération destructive ==")
H.SESSION_CREDS["prismcentral"] = {"mode": "basic"}
applied.clear(); log4 = []
ok4, _ = H._refresh_pv_disk("wordpress", "mariadb-pvc", dry=True, log=log4)
check(ok4 is True and not applied, "dry : aucun apply destructif")

print("\n== 5. État du PV INCERTAIN (erreur kubectl) -> AVORTE sans rien supprimer (V1) ==")
H._clone_vg_disk_uuids = lambda u: NEW
H.resource_state = lambda kind, name, ns=None: ("error", "Unable to connect to the server")
deleted = []
_orig_del = H._delete_and_unblock
H._delete_and_unblock = lambda kind, name, ns, log: (deleted.append((kind, name)), True)[1]
applied.clear(); log5 = []
ok5, detail5 = H._refresh_pv_disk("wordpress", "mariadb-pvc", dry=False, log=log5)
H._delete_and_unblock = _orig_del
H.resource_state = lambda kind, name, ns=None: ("present", "")
check(ok5 is False, "retourne un échec si l'état du PV est indéterminé")
check(not deleted, "AUCUNE suppression PVC/PV (le VG ne peut pas être détruit par erreur)")
check(not applied, "aucune recréation de PV")
check("état du PV" in (detail5 or "") or "vérification" in (detail5 or ""), "détail d'échec explicite")

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
