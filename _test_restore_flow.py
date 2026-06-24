# -*- coding: utf-8 -*-
"""Test d'intégration (dry-run, sans cluster) du flux _execute_restore_locked :
vérifie l'ordre Retain -> delete et la journalisation de la purge."""
import json
import hycu_k8s_nutanix as H

NEW_VG_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
REAL_PV = {
    "apiVersion": "v1", "kind": "PersistentVolume",
    "metadata": {"name": "pvc-44c5d5d7-5c80-4894-9adc-1c02f0368b10"},
    "spec": {
        "accessModes": ["ReadWriteOnce"], "capacity": {"storage": "8Gi"},
        "claimRef": {"kind": "PersistentVolumeClaim", "name": "mariadb-pvc", "namespace": "wordpress"},
        "csi": {"driver": "csi.nutanix.com", "fsType": "ext4",
                "volumeAttributes": {
                    "hypervisorAttachedDiskUUIDs": "946e6ccc-fdad-4bb2-84bb-963dcadbc353",
                    "peClusterRef": "0005791f-f9d6-21ed-5ea4-20677cd4d804",
                    "storage.kubernetes.io/csiProvisionerIdentity": "1782230665180-856-csi.nutanix.com"},
                "volumeHandle": "NutanixVolumes-5b4d284b-7109-4e82-4c71-7d0e36ecb5ab"},
        "persistentVolumeReclaimPolicy": "Delete",
        "storageClassName": "nutanix-volume", "volumeMode": "Filesystem"},
}

PV_NAME = "pvc-44c5d5d7-5c80-4894-9adc-1c02f0368b10"
PVC = {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
       "metadata": {"name": "mariadb-pvc", "namespace": "wordpress"},
       "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "8Gi"}},
                "storageClassName": "nutanix-volume"}}

# Neutraliser tout accès cluster.
H._load_old_pv = lambda ns, pvc, bp: (json.loads(json.dumps(REAL_PV)), PV_NAME)
H._load_backup_pvc = lambda bp, pvc: json.loads(json.dumps(PVC))
H._resolve_workloads = lambda ns: ([], [])
H._namespace_allowed = lambda ns: True
H.kubectl_json = lambda args: ({}, None)

payload = {"namespace": "wordpress", "dry": True, "mode": "clone",
           "items": [{"pvc": "mariadb-pvc", "new_ref": NEW_VG_UUID, "new_name": "pvc-clone-0000"}]}
res = H._execute_restore_locked(payload)

labels = [l.get("label", "") for l in res["log"]]
print("Étapes (dry-run) :")
for l in labels:
    print("   -", l)

passed = failed = 0
def check(c, m):
    global passed, failed
    if c: passed += 1; print("  OK  ", m)
    else: failed += 1; print("  FAIL", m)

joined = " || ".join(labels)
retain_idx = next((i for i, l in enumerate(labels) if "Retain" in l), -1)
delpvc_idx = next((i for i, l in enumerate(labels) if "Suppression PVC" in l), -1)
delpv_idx = next((i for i, l in enumerate(labels) if "Suppression PV " in l), -1)
disk_idx = next((i for i, l in enumerate(labels) if "hypervisorAttachedDiskUUIDs" in l), -1)

print()
check(retain_idx >= 0, "étape Retain (protection VG source) présente")
check(delpvc_idx >= 0 and retain_idx < delpvc_idx, "Retain AVANT suppression du PVC")
check(delpv_idx >= 0 and retain_idx < delpv_idx, "Retain AVANT suppression du PV")
check(disk_idx >= 0, "étape hypervisorAttachedDiskUUIDs (disque du VG cloné) journalisée")
check(disk_idx >= 0 and disk_idx < delpvc_idx, "étape disque AVANT suppression/apply")
check(res["dry"] is True and res["ok"] is True, "dry-run ok")
# reprotect non rempli en dry (sécurité)
check(res.get("reprotect") == [], "rappel re-protection vide en dry")

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
