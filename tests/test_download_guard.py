# -*- coding: utf-8 -*-
"""Custom backup folder guard: download and backup list never open an arbitrary folder."""
import json
import os


def _mk_backup(base, ns="app", ts="2026-01-01_00-00-00_000000"):
    d = os.path.join(base, ns, ts)
    os.makedirs(d)
    with open(os.path.join(d, "index.json"), "w", encoding="utf-8") as f:
        json.dump({"namespace": ns, "volumes": []}, f)
    return d


def test_custom_root_must_hold_backups(H, tmp_path):
    other = tmp_path / "elsewhere"
    secret_dir = other / "kube"
    secret_dir.mkdir(parents=True)
    (secret_dir / "config").write_text("token: xyz")
    # A folder without any backup is not a backup area, even if designated explicitly.
    assert H._safe_backup_path(str(secret_dir), str(other)) is None
    # Filesystem root and home directory are never accepted.
    root = os.path.abspath(os.sep)
    assert H._safe_backup_path(str(secret_dir), root) is None
    assert not H._extra_root_ok(os.path.realpath(os.path.expanduser("~")))
    # A real custom backup folder still works.
    bdir = _mk_backup(str(tmp_path / "custom"))
    assert H._safe_backup_path(bdir, str(tmp_path / "custom")) == os.path.realpath(bdir)
    # ...but a non-backup sibling inside it is refused.
    junk = tmp_path / "custom" / "junk"
    junk.mkdir()
    assert H._safe_backup_path(str(junk), str(tmp_path / "custom")) is None


def test_custom_root_containing_tool_config_is_refused(H, tmp_path):
    # tmp_path holds hycu_config.json and the vault (conftest): never a backup area.
    _mk_backup(str(tmp_path / "bk"))
    assert H.os.path.dirname(H.CONFIG_PATH) == str(tmp_path)
    assert not H._extra_root_ok(os.path.realpath(str(tmp_path)))
    assert H._safe_backup_path(str(tmp_path / "bk"), str(tmp_path)) is None


def test_backup_list_rejects_traversal_and_foreign_roots(H, tmp_path):
    assert H.list_backups("../..") == []
    assert H.list_backups("app", "/") == []
    (tmp_path / "nobackup" / "app").mkdir(parents=True)
    assert H.list_backups("app", str(tmp_path / "nobackup")) == []
