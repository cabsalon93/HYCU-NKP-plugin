# -*- coding: utf-8 -*-
"""Fixtures communes : chaque test travaille dans un dossier temporaire (config, coffre,
sauvegardes, journal d'audit) et avec un faux kubectl — jamais le cluster du poste."""
import importlib
import json
import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

FAKE_RW = os.path.join(ROOT, "tests", "fake_kubectl_rw.py")


@pytest.fixture
def H(tmp_path, monkeypatch):
    """Module de l'outil isolé : CONFIG_PATH/SECRETS_PATH/backup_root sous tmp_path,
    kubectl = faux kubectl à état (tests/fake_kubectl_rw.py), contexte « test-ctx »."""
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"namespaces": ["app"], "pvcs": {}, "pvs": {}, "pods": {},
                                 "deployments": {}, "statefulsets": {}, "volumeattachments": [],
                                 "storageclasses": ["nutanix-volume"]}), encoding="utf-8")
    monkeypatch.setenv("FAKE_STATE", str(state))
    monkeypatch.setenv("FAKE_LOCAL_CTX", "test-ctx")
    monkeypatch.setenv("FAKE_KUBE_LOG", str(tmp_path / "kubectl.log"))
    monkeypatch.delenv("FAKE_FAIL_AT", raising=False)
    for e in ("HYCU_HOST", "HYCU_PORT", "HYCU_OPEN_BROWSER", "HYCU_BACKUP_ROOT", "HYCU_KUBECTL_PATH"):
        monkeypatch.delenv(e, raising=False)
    import hycu_k8s_nutanix as mod
    mod = importlib.reload(mod)
    mod.CONFIG_PATH = str(tmp_path / "hycu_config.json")
    mod.SECRETS_PATH = str(tmp_path / "hycu_secrets.enc")
    mod.load_config()
    mod.CONFIG.update({"backup_root": str(tmp_path / "hycu-backups"),
                       "kubectl_path": "%s %s" % (sys.executable, FAKE_RW),
                       "require_context_confirm": False, "wait_timeout": 2, "subprocess_margin": 5,
                       "clone_fix_disk_uuids": False, "config_backup_full": False,
                       "namespace_filter": []})
    mod._LOCAL_CTX["at"] = 0.0
    mod.state_path = str(state)
    yield mod


def read_state(H):
    return json.loads(open(H.state_path, encoding="utf-8").read())


def write_state(H, st):
    open(H.state_path, "w", encoding="utf-8").write(json.dumps(st, indent=1))
