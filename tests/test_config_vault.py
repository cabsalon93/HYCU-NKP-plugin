# -*- coding: utf-8 -*-
"""Schéma de configuration (A3) et coffre versionné (A5)."""
import json
import os

import pytest


def test_schema_covers_every_default(H):
    assert set(H.CONFIG_SCHEMA) == set(H.DEFAULT_CONFIG)


def test_invalid_types_are_rejected_not_persisted(H):
    ok, err = H.save_config({"wait_timeout": "abc"}, source="api")
    assert not ok and "wait_timeout" in err
    ok, err = H.save_config({"port": 99999}, source="api")
    assert not ok and "port" in err
    ok, err = H.save_config({"allowed_contexts": 12}, source="api")
    assert not ok
    assert not os.path.exists(H.CONFIG_PATH)


def test_coercion_and_persistence(H):
    ok, err = H.save_config({"wait_timeout": "120", "auto_backup_enabled": "true",
                             "allowed_contexts": "prod, dr"}, source="api")
    assert ok, err
    assert H.CONFIG["wait_timeout"] == 120 and H.CONFIG["auto_backup_enabled"] is True
    assert H.CONFIG["allowed_contexts"] == ["prod", "dr"]
    on_disk = json.load(open(H.CONFIG_PATH, encoding="utf-8"))
    assert on_disk["wait_timeout"] == 120
    assert "kubectl_path" not in on_disk          # valeur à chaud (fixture) non persistée


def test_env_overrides_are_never_persisted(H, monkeypatch):
    monkeypatch.setenv("HYCU_HOST", "0.0.0.0")
    H.load_config()
    assert H.CONFIG["host"] == "0.0.0.0"
    assert H.save_config({"clone_name_suffix": "-x"})[0]
    on_disk = json.load(open(H.CONFIG_PATH, encoding="utf-8"))
    assert "host" not in on_disk


def test_kubectl_path_validation(H):
    ok, err = H.save_config({"kubectl_path": "cmd /c calc"}, source="api")
    assert not ok and "binary" in err
    assert H.save_config({"kubectl_path": "microk8s kubectl"}, source="api")[0]


def test_container_mode_locks_path_keys(H, monkeypatch):
    monkeypatch.setenv("HYCU_HOST", "0.0.0.0")
    ok, err = H.save_config({"backup_root": "/tmp/x"}, source="api")
    assert not ok and "read-only" in err
    assert H.save_config({"backup_root": "/tmp/x"}, source="internal")[0]


def test_kubectl_argv_handles_spaces(H, tmp_path):
    exe = tmp_path / "Program Files" / "kubectl.exe"
    exe.parent.mkdir()
    exe.write_text("")
    H.CONFIG["kubectl_path"] = str(exe)
    assert H._kubectl_argv() == [str(exe)]
    H.CONFIG["kubectl_path"] = "microk8s kubectl"
    assert H._kubectl_argv() == ["microk8s", "kubectl"]


def test_vault_roundtrip_survives_iteration_change(H):
    H.CONFIG["pbkdf2_iterations"] = 100000
    blob = H.encrypt_secret(b'{"hycu": {"mode": "apikey", "key": "k"}}', "phrase-secrete")
    H.CONFIG["pbkdf2_iterations"] = 250000           # changement de configuration
    assert H.decrypt_secret(blob, "phrase-secrete") == b'{"hycu": {"mode": "apikey", "key": "k"}}'
    assert H.decrypt_secret(blob, "mauvaise") is None
    assert H.decrypt_secret(blob[:-6] + "AAAAAA", "phrase-secrete") is None   # altéré


def test_vault_legacy_blob_still_readable(H):
    """Ancien format (sans en-tête) : chiffré avec les itérations courantes."""
    import base64, hmac, hashlib, secrets
    H.CONFIG["pbkdf2_iterations"] = 100000
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(16)
    enc_key, mac_key = H._derive_keys("pw", salt)
    pt = b"legacy"
    ct = H._xor(pt, H._keystream(enc_key, nonce, len(pt)))
    tag = hmac.new(mac_key, salt + nonce + ct, hashlib.sha256).digest()
    blob = base64.b64encode(salt + nonce + ct + tag).decode()
    assert H.decrypt_secret(blob, "pw") == b"legacy"


def test_simulation_default(H):
    assert "default_lang" not in H.CONFIG, "interface 100 % anglophone : plus de langue configurable"
    assert H.CONFIG["simulation_mode_available"] is False


def test_container_mode_accepts_unchanged_locked_keys(H, monkeypatch):
    """En conteneur, l'interface renvoie tout le formulaire : une clé verrouillée INCHANGÉE
    passe ; un changement est refusé ; une valeur venue de l'environnement n'est pas écrite."""
    monkeypatch.setenv("HYCU_HOST", "0.0.0.0")
    monkeypatch.setenv("HYCU_ALLOWED_HOSTS", "from-env.example")
    H._rebuild_config()
    assert H._container_mode()
    ok, err = H.save_config({"kubectl_path": H.CONFIG["kubectl_path"], "wait_timeout": 300,
                             "allowed_hosts": ["from-env.example"]}, source="api")
    assert ok, err
    assert H.CONFIG["wait_timeout"] == 300 and "kubectl_path" not in H.USER_CONFIG
    assert "allowed_hosts" not in H.USER_CONFIG and H.CONFIG["allowed_hosts"] == ["from-env.example"]
    ok2, err2 = H.save_config({"kubectl_path": "/usr/bin/kubectl"}, source="api")
    assert not ok2 and "read-only" in err2
