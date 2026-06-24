# -*- coding: utf-8 -*-
"""Tests du nouveau modèle de référence VG (UUID) — basés sur le PV RÉEL du user
(CSI Nutanix moderne / NKP : VG attaché à la VM, AUCUN IQN dans le PV)."""
import json
import hycu_k8s_nutanix as H

# PV réel fourni par l'utilisateur (VM-attach, pas d'IQN).
REAL_PV = {
    "apiVersion": "v1", "kind": "PersistentVolume",
    "metadata": {
        "annotations": {"pv.kubernetes.io/provisioned-by": "csi.nutanix.com"},
        "name": "pvc-44c5d5d7-5c80-4894-9adc-1c02f0368b10",
    },
    "spec": {
        "accessModes": ["ReadWriteOnce"],
        "capacity": {"storage": "8Gi"},
        "claimRef": {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                     "name": "mariadb-pvc", "namespace": "wordpress"},
        "csi": {
            "driver": "csi.nutanix.com", "fsType": "ext4",
            "volumeAttributes": {
                "description": "CSI StorageClass nutanix-volume for cabdemok8s, PVC:mariadb-pvc, NS:wordpress",
                "hypervisorAttachedDiskUUIDs": "946e6ccc-fdad-4bb2-84bb-963dcadbc353",
                "peClusterRef": "0005791f-f9d6-21ed-5ea4-20677cd4d804",
                "storage.kubernetes.io/csiProvisionerIdentity": "1782230665180-856-csi.nutanix.com",
            },
            "volumeHandle": "NutanixVolumes-5b4d284b-7109-4e82-4c71-7d0e36ecb5ab",
        },
        "persistentVolumeReclaimPolicy": "Delete",
        "storageClassName": "nutanix-volume", "volumeMode": "Filesystem",
    },
}

OLD_VG_UUID = "5b4d284b-7109-4e82-4c71-7d0e36ecb5ab"
NEW_VG_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
SRC_DISK_UUID = "946e6ccc-fdad-4bb2-84bb-963dcadbc353"
PVC_UUID = "44c5d5d7-5c80-4894-9adc-1c02f0368b10"  # = UUID du NOM du VG (≠ UUID du VG)

passed = failed = 0
def check(cond, label):
    global passed, failed
    if cond:
        passed += 1; print("  OK  ", label)
    else:
        failed += 1; print("  FAIL", label)


print("\n== 1. Clone avec UUID nu du nouveau VG (cas NKP) ==")
built, err = H.build_new_pv(REAL_PV, NEW_VG_UUID, "pvc-clone-0000", "clone")
check(err is None, "pas d'erreur")
csi = built["manifest"]["spec"]["csi"]
check(csi["volumeHandle"] == "NutanixVolumes-" + NEW_VG_UUID, "volumeHandle -> nouveau VG uuid")
va = csi["volumeAttributes"]
check("hypervisorAttachedDiskUUIDs" not in va, "hypervisorAttachedDiskUUIDs SOURCE retiré (réécrit ensuite par le flux)")
check("storage.kubernetes.io/csiProvisionerIdentity" in va, "csiProvisionerIdentity CONSERVÉ (comme le PV source)")
check("hypervisorAttachedDiskUUIDs" in built["stripped"], "stripped[] le mentionne")
check(SRC_DISK_UUID not in json.dumps(built["manifest"]), "aucun UUID de disque SOURCE résiduel")
check(OLD_VG_UUID not in json.dumps(built["manifest"]), "aucun UUID de VG SOURCE résiduel")
check(built["manifest"]["metadata"]["name"] == "pvc-clone-0000", "nom du PV cloné appliqué")
check(built["same_uuid"] is False, "same_uuid False")
check(built["looks_like_vg_name"] is False, "looks_like_vg_name False")
check(built["new_volume_handle"] == "NutanixVolumes-" + NEW_VG_UUID, "new_volume_handle correct")
check(("peClusterRef" in va) and va["peClusterRef"] == "0005791f-f9d6-21ed-5ea4-20677cd4d804",
      "peClusterRef CONSERVÉ (même cluster)")

print("\n== 2. Clone avec volumeHandle complet collé ==")
built2, err2 = H.build_new_pv(REAL_PV, "NutanixVolumes-" + NEW_VG_UUID, "pvc-c2", "clone")
check(err2 is None and built2["manifest"]["spec"]["csi"]["volumeHandle"] == "NutanixVolumes-" + NEW_VG_UUID,
      "volumeHandle collé accepté")

print("\n== 3. Garde : UUID = NOM du VG (pvc-<uuid>) au lieu de l'UUID du VG ==")
built3, err3 = H.build_new_pv(REAL_PV, PVC_UUID, "x", "clone")
check(err3 is None and built3["looks_like_vg_name"] is True, "looks_like_vg_name détecté")

print("\n== 4. same_uuid : on resaisit l'UUID source ==")
built4, err4 = H.build_new_pv(REAL_PV, OLD_VG_UUID, "y", "clone")
check(err4 is None and built4["same_uuid"] is True, "same_uuid détecté")

print("\n== 5. Référence invalide (aucun UUID) ==")
r = H._prepare_one("wordpress", {"pvc": "mariadb-pvc", "new_ref": "pas-un-uuid"}, "clone", None)
check(r["ok"] is False and "UUID" in r["error"], "rejet d'une réf sans UUID")
r2 = H._prepare_one("wordpress", {"pvc": "mariadb-pvc", "new_ref": ""}, "clone", None)
check(r2["ok"] is False, "rejet d'une réf vide")

print("\n== 6. inplace : pas de purge, nom conservé ==")
built6, err6 = H.build_new_pv(REAL_PV, NEW_VG_UUID, "", "inplace")
check(err6 is None, "pas d'erreur")
check(built6["manifest"]["metadata"]["name"] == "pvc-44c5d5d7-5c80-4894-9adc-1c02f0368b10", "nom conservé (inplace)")
check(built6["stripped"] == [], "aucune purge en inplace")

print("\n== 7. Legacy iSCSI : PV AVEC IQN + new_ref = IQN complet ==")
legacy = json.loads(json.dumps(REAL_PV))
old_iqn = "iqn.2010-06.com.nutanix:hycu-" + OLD_VG_UUID + "-12345-tgt0"
new_iqn = "iqn.2010-06.com.nutanix:hycu-" + NEW_VG_UUID + "-67890-tgt0"
legacy["spec"]["csi"]["volumeAttributes"]["targetPortal"] = old_iqn
built7, err7 = H.build_new_pv(legacy, new_iqn, "pvc-legacy", "clone")
check(err7 is None, "pas d'erreur")
blob = json.dumps(built7["manifest"])
check(old_iqn not in blob, "ancien IQN supprimé")
check(new_iqn in blob, "nouvel IQN présent")
check(built7["manifest"]["spec"]["csi"]["volumeHandle"] == "NutanixVolumes-" + NEW_VG_UUID, "volumeHandle MAJ")

print("\n== 8. Préfixe volumeHandle auto-détecté (multi-clients) ==")
custom = json.loads(json.dumps(REAL_PV))
custom["spec"]["csi"]["volumeHandle"] = "AcmeCSI-" + OLD_VG_UUID
built8, _ = H.build_new_pv(custom, NEW_VG_UUID, "z", "clone")
check(built8["manifest"]["spec"]["csi"]["volumeHandle"] == "AcmeCSI-" + NEW_VG_UUID, "préfixe 'AcmeCSI-' conservé")

print("\n== 9. Legacy iSCSI SANS spec.csi.volumeHandle : réf = UUID nu du nouveau VG (V3) ==")
# Un vrai PV iSCSI hérité n'a PAS de csi.volumeHandle ; l'identité du VG vit dans l'IQN.
# analyse_pv doit prendre l'UUID DANS l'IQN (pas l'UUID « pvc-<uuid> » du nom de PV),
# sinon la réécriture laisse le nouveau PV pointer vers le VG SOURCE.
legacy_iscsi = {
    "apiVersion": "v1", "kind": "PersistentVolume",
    "metadata": {"name": "pvc-" + PVC_UUID},
    "spec": {
        "accessModes": ["ReadWriteOnce"], "capacity": {"storage": "8Gi"},
        "claimRef": {"kind": "PersistentVolumeClaim", "name": "mariadb-pvc", "namespace": "wordpress"},
        "iscsi": {"targetPortal": "10.10.0.5:3260", "lun": 0, "fsType": "ext4",
                  "iqn": "iqn.2010-06.com.nutanix:ntnx-k8s-" + OLD_VG_UUID + "-98765-tgt0"},
        "persistentVolumeReclaimPolicy": "Delete",
    },
}
info9 = H.analyse_pv(legacy_iscsi)
check(H.split_volume_handle(info9["old_volume_handle"] or "")[1] == OLD_VG_UUID,
      "analyse_pv extrait l'UUID du VG depuis l'IQN (pas l'UUID du nom de PV)")
built9, err9 = H.build_new_pv(legacy_iscsi, NEW_VG_UUID, "pvc-legacy-0000", "clone")
check(err9 is None, "pas d'erreur")
blob9 = json.dumps(built9["manifest"])
check(OLD_VG_UUID not in blob9, "UUID du VG SOURCE absent du PV reconstruit (plus de pointage vers le VG source)")
check(("ntnx-k8s-" + NEW_VG_UUID) in blob9, "IQN réécrit avec l'UUID du NOUVEAU VG")
check(built9["same_uuid"] is False and built9["looks_like_vg_name"] is False, "gardes anti-confusion OK")

print("\n----------------------------------------")
print("RÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
