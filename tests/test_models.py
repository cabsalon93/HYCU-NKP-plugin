# -*- coding: utf-8 -*-
"""derive_volume_handle (table de cas), nettoyage des manifestes, rétention, i18n/build."""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VG = "5b4d284b-7109-4e82-4c71-7d0e36ecb5ab"
PVCU = "44c5d5d7-5c80-4894-9adc-1c02f0368b10"


@pytest.mark.parametrize("ref,old,expected", [
    (VG, None, "NutanixVolumes-" + VG),
    ("NutanixVolumes-" + VG, None, "NutanixVolumes-" + VG),
    ("ntnx-k8s-" + VG, "ntnx-k8s-00000000-0000-0000-0000-000000000000", "ntnx-k8s-" + VG),
    ("iqn.2010-06.com.nutanix:ntnx-k8s-" + VG + "-12345-tgt0", None, "NutanixVolumes-" + VG),
    # IQN dont le nom de VG est « pvc-<uuid du PVC> » : l'UUID du VG est le DERNIER
    ("iqn.2010-06.com.nutanix:pvc-" + PVCU + "-" + VG + "-98765-tgt0", None, "NutanixVolumes-" + VG),
    ("pas-un-uuid", None, None),
    ("", None, None),
])
def test_derive_volume_handle(H, ref, old, expected):
    assert H.derive_volume_handle(ref, old) == expected


def test_derive_volume_handle_prefix_from_config(H):
    H.CONFIG["volume_handle_prefix"] = "custom-"
    assert H.derive_volume_handle(VG) == "custom-" + VG


REAL_PV = {
    "apiVersion": "v1", "kind": "PersistentVolume",
    "metadata": {"name": "pvc-" + PVCU, "uid": "u", "resourceVersion": "9", "creationTimestamp": "t",
                 "finalizers": ["kubernetes.io/pv-protection"],
                 "annotations": {"pv.kubernetes.io/bound-by-controller": "yes",
                                 "pv.kubernetes.io/provisioned-by": "csi.nutanix.com"}},
    "spec": {"accessModes": ["ReadWriteOnce"], "capacity": {"storage": "8Gi"},
             "claimRef": {"kind": "PersistentVolumeClaim", "name": "data", "namespace": "app", "uid": "cu", "resourceVersion": "3"},
             "csi": {"driver": "csi.nutanix.com", "volumeHandle": "NutanixVolumes-" + VG},
             "persistentVolumeReclaimPolicy": "Delete", "storageClassName": "nutanix-volume"},
    "status": {"phase": "Bound"},
}


def test_clean_pv_regression(H):
    pv = H.clean_pv(json.loads(json.dumps(REAL_PV)))
    assert "status" not in pv
    for k in ("uid", "resourceVersion", "creationTimestamp", "finalizers"):
        assert k not in pv["metadata"]
    assert "pv.kubernetes.io/bound-by-controller" not in (pv["metadata"].get("annotations") or {})
    cr = pv["spec"]["claimRef"]
    assert cr["name"] == "data" and "uid" not in cr and "resourceVersion" not in cr
    H.CONFIG["strip_claimref"] = True
    pv2 = H.clean_pv(json.loads(json.dumps(REAL_PV)))
    assert "claimRef" not in pv2["spec"]


def test_retention_never_prunes_pre_restore_backups(H, tmp_path):
    """Rétention compteur : automatiques ET manuelles purgées (les plus récentes gardées),
    JAMAIS la sauvegarde de sécurité prise avant une restauration (pre_restore)."""
    import datetime
    root = H.CONFIG["backup_root"]
    base = os.path.join(root, "app")
    now = datetime.datetime.now()

    def mk(i, kind):
        d = os.path.join(base, (now - datetime.timedelta(hours=i)).strftime("%Y-%m-%d_%H-%M-%S_%f"))
        os.makedirs(d)
        idx = {"schema": 2, "namespace": "app", "created": (now - datetime.timedelta(hours=i)).isoformat(), "volumes": []}
        if kind:
            idx["kind"] = kind
        json.dump(idx, open(os.path.join(d, "index.json"), "w"))
        return d
    autos = [mk(i, "auto") for i in range(1, 6)]
    manual = mk(10, "manual")
    pre = mk(11, "pre_restore")
    removed = H._prune_backups(root, "app", 2)
    assert removed == 4                      # 5 auto + 1 manuelle = 6 candidates, 2 gardées
    left = {b["path"] for b in H.list_backups("app", root)}
    assert pre in left and manual not in left
    assert set(autos[:2]) <= left and not (set(autos[2:]) & left)


def test_retention_protects_transaction_backup(H):
    import datetime
    root = H.CONFIG["backup_root"]
    base = os.path.join(root, "app")
    now = datetime.datetime.now()
    dirs = []
    for i in range(1, 5):
        d = os.path.join(base, (now - datetime.timedelta(hours=i)).strftime("%Y-%m-%d_%H-%M-%S_%f"))
        os.makedirs(d)
        json.dump({"schema": 2, "kind": "auto", "namespace": "app",
                   "created": (now - datetime.timedelta(hours=i)).isoformat(), "volumes": []},
                  open(os.path.join(d, "index.json"), "w"))
        dirs.append(d)
    H._save_txn("app", {"status": "in_progress", "backup_dir": dirs[-1], "volumes": []})
    H._prune_backups(root, "app", 1)
    assert os.path.isdir(dirs[-1]), "le dossier référencé par la transaction est conservé"
    assert not os.path.isdir(dirs[1])


def test_build_is_up_to_date():
    r = subprocess.run([sys.executable, os.path.join(ROOT, "build.py"), "--check"], capture_output=True,
                       text=True, encoding="utf-8", errors="replace", cwd=ROOT)
    assert r.returncode == 0, r.stdout + r.stderr


def test_page_is_english(H):
    assert '<html lang="en">' in H.HTML and "Dashboard" in H.HTML
    assert ">Tableau de bord<" not in H.HTML and ">Sauvegarder<" not in H.HTML
