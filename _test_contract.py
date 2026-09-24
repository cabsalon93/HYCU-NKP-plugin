# -*- coding: utf-8 -*-
"""Contrat de restauration (P1) : la sauvegarde collecte, best-effort, ce qui rend
la restauration sans saisie (UUID/nom du VG HYCU, disques, Prism Element, dernier
point de restauration). Ne doit JAMAIS échouer le backup si HYCU/Prism manquent."""
import json
import os
import shutil
import tempfile
import hycu_k8s_nutanix as H

passed = failed = 0
def check(c, m):
    global passed, failed
    if c: passed += 1; print("  OK  ", m)
    else: failed += 1; print("  FAIL", m)


VG = "11111111-2222-3333-4444-555555555555"
tmp = tempfile.mkdtemp()
saved = dict(H.CONFIG)
saved_kj = H.kubectl_json
saved_ctx = H.action_context
saved_list = H._hycu_list_vgs
saved_rp = H.action_hycu_restore_points
saved_disk = H._clone_vg_disk_uuids
saved_pe = H._vg_pe_uuid


def fake_kubectl(args):
    if args[:2] == ["get", "pvc"] and "-n" in args and args.index("-n") == 2:
        # get pvc -n <ns>  (liste)
        if len(args) == 4:
            return {"items": [{"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                               "metadata": {"name": "data", "namespace": "boutique"},
                               "spec": {"volumeName": "pvc-orig", "storageClassName": "nutanix-volume",
                                        "accessModes": ["ReadWriteOnce"],
                                        "resources": {"requests": {"storage": "1Gi"}}}}]}, None
    if args[:2] == ["get", "pv"]:
        return {"apiVersion": "v1", "kind": "PersistentVolume",
                "metadata": {"name": "pvc-orig"},
                "spec": {"storageClassName": "nutanix-volume",
                         "capacity": {"storage": "1Gi"}, "accessModes": ["ReadWriteOnce"],
                         "csi": {"driver": "csi.nutanix.com",
                                 "volumeHandle": "NutanixVolumes-" + VG}}}, None
    return None, "unexpected kubectl %s" % args


try:
    H.CONFIG.update({"backup_root": tmp, "config_backup_full": False,
                     "namespace_filter": [], "cluster_namespace_filters": {},
                     "namespace_label_selector": "", "storage_min_free_mb": 0,
                     "storage_quota_gb": 0, "s3_auto_upload": False,
                     "backup_collect_restore_contract": True})
    H.CONFIG_PATH = os.path.join(tmp, "hycu_config.json")
    H.kubectl_json = fake_kubectl
    H.action_context = lambda: {"context": "nkp-local"}

    def read_index():
        for dp, _, fn in os.walk(tmp):
            if "index.json" in fn:
                return json.load(open(os.path.join(dp, "index.json")))
        return None

    print("== HYCU + Prism connectés : contrat complet ==")
    with H.CRED_LOCK:
        H.SESSION_CREDS["hycu"] = {"access": "a", "secret": "b"}
        H.SESSION_CREDS["prismcentral"] = {"access": "a", "secret": "b"}
    H._hycu_list_vgs = lambda: ([{"uuid": "hy-" + VG, "name": "pvc-orig",
                                  "externalId": "NutanixVolumes-" + VG, "hasBackups": True}], None)
    H.action_hycu_restore_points = lambda src: {"ok": True, "points": [
        {"id": "rp-latest", "time": "2026-09-25 01:00", "restorable": True},
        {"id": "rp-old", "time": "2026-09-24 01:00", "restorable": True}]}
    H._clone_vg_disk_uuids = lambda u: "disk-aaa,disk-bbb"
    H._vg_pe_uuid = lambda u: "pe-99999999-0000-0000-0000-000000000000"

    r = H.action_backup("boutique")
    check(r["ok"], "sauvegarde OK")
    idx = read_index()
    c = (idx["volumes"][0] or {}).get("restore_contract") or {}
    check(c.get("vg_uuid") == VG, "contrat : UUID du VG source")
    check(c.get("hycu_source_uuid") == "hy-" + VG and c.get("vg_name") == "pvc-orig",
          "contrat : identité HYCU (source_uuid + nom du VG)")
    check(c.get("hycu_latest_backup", {}).get("uuid") == "rp-latest",
          "contrat : dernier point de restauration HYCU (le plus récent)")
    check(c.get("disk_extids") == ["disk-aaa", "disk-bbb"], "contrat : disques (extId via Prism)")
    check(c.get("pe_uuid", "").startswith("pe-"), "contrat : Prism Element (multi-PE)")
    check(idx.get("systems", {}).get("hycu") and idx["systems"].get("nutanix", {}).get("kind") == "prismcentral",
          "contrat : systèmes (endpoints HYCU/Prism) enregistrés")

    print("\n== Rien de connecté : backup OK, pas de contrat, aucune erreur ==")
    shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)
    with H.CRED_LOCK:
        H.SESSION_CREDS["hycu"] = None
        H.SESSION_CREDS["prismcentral"] = None
    r = H.action_backup("boutique")
    idx = read_index()
    check(r["ok"], "sauvegarde OK sans HYCU/Prism")
    check("restore_contract" not in (idx["volumes"][0] or {}), "aucun contrat collecté (best-effort)")
    check("systems" not in idx, "aucun bloc systems")

    print("\n== HYCU renvoie une erreur : backup TOUJOURS OK (best-effort) ==")
    shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)
    with H.CRED_LOCK:
        H.SESSION_CREDS["hycu"] = {"access": "a", "secret": "b"}
        H.SESSION_CREDS["prismcentral"] = None
    def boom_list():
        raise RuntimeError("HYCU indisponible")
    H._hycu_list_vgs = boom_list
    r = H.action_backup("boutique")
    idx = read_index()
    check(r["ok"], "sauvegarde OK malgré l'échec HYCU")
    # vg_uuid vient de l'analyse locale (pas d'appel) ; l'identité HYCU manque.
    c = (idx["volumes"][0] or {}).get("restore_contract") or {}
    check(c.get("vg_uuid") == VG and "hycu_source_uuid" not in c,
          "contrat dégradé : UUID local présent, identité HYCU absente, sans crash")
finally:
    with H.CRED_LOCK:
        H.SESSION_CREDS["hycu"] = None
        H.SESSION_CREDS["prismcentral"] = None
    H.kubectl_json = saved_kj
    H.action_context = saved_ctx
    H._hycu_list_vgs = saved_list
    H.action_hycu_restore_points = saved_rp
    H._clone_vg_disk_uuids = saved_disk
    H._vg_pe_uuid = saved_pe
    H.CONFIG.clear(); H.CONFIG.update(saved)
    shutil.rmtree(tmp, ignore_errors=True)

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
