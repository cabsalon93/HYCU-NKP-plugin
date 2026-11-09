# -*- coding: utf-8 -*-
"""_write_json_atomic : écriture durable (fsync AVANT os.replace) et atomique — le
marqueur de reprise d'une restauration et le catalogue en dépendent (point 3)."""
import json
import os


def test_fsync_happens_before_replace_and_content_is_intact(H, monkeypatch, tmp_path):
    events = []
    real_fsync, real_replace = os.fsync, os.replace
    monkeypatch.setattr(H.os, "fsync", lambda fd: (events.append(("fsync", fd)), real_fsync(fd))[1])
    monkeypatch.setattr(H.os, "replace", lambda a, b: (events.append(("replace", b)), real_replace(a, b))[1])

    target = tmp_path / "txn.json"
    H._write_json_atomic(str(target), {"status": "in_progress", "n": 1}, mode=0o600)

    assert json.loads(target.read_text(encoding="utf-8")) == {"status": "in_progress", "n": 1}
    kinds = [k for k, _ in events]
    assert "fsync" in kinds and "replace" in kinds, events
    assert kinds.index("fsync") < kinds.index("replace"), "le fichier doit être durable avant d'être nommé"
    assert not [p for p in os.listdir(tmp_path) if p.startswith(".tmp-")], "pas de temporaire orphelin"


def test_failure_leaves_no_temp_file_and_keeps_previous_content(H, monkeypatch, tmp_path):
    target = tmp_path / "txn.json"
    target.write_text('{"status": "old"}', encoding="utf-8")

    class Boom(Exception):
        pass

    def bad_dump(*a, **k):
        raise Boom("disk full")
    monkeypatch.setattr(H.json, "dump", bad_dump)
    try:
        H._write_json_atomic(str(target), {"status": "new"})
        assert False, "l'erreur doit remonter"
    except Boom:
        pass
    assert json.loads(target.read_text(encoding="utf-8")) == {"status": "old"}, "l'ancien contenu est préservé"
    assert not [p for p in os.listdir(tmp_path) if p.startswith(".tmp-")], "temporaire nettoyé"
