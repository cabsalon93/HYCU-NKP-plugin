# -*- coding: utf-8 -*-
"""Politiques nommées (cible par nom / étiquettes, fréquence, rétention, politique HYCU)
et kit de l'outil (sauvegarde / restauration de l'outil lui-même)."""
import io
import json
import os
import zipfile

from conftest import read_state, write_state


def pol(name, **kw):
    p = {"name": name, "namespaces": [], "label_selector": "", "interval_hours": 4, "keep": 3, "enabled": True}
    p.update(kw)
    return p


def set_policies(H, policies):
    ok, err = H.save_config({"backup_policies": policies}, source="api")
    assert ok, err


def fake_selectors(H, monkeypatch, mapping, fail=False):
    """kubectl get ns -l <sel> -> namespaces de `mapping[sel]` ; le reste : vrai faux kubectl."""
    real = H.kubectl_json

    def kj(args):
        if args[:2] == ["get", "ns"] and "-l" in args:
            if fail:
                return None, "Forbidden"
            sel = args[args.index("-l") + 1]
            return {"items": [{"metadata": {"name": n}} for n in mapping.get(sel, [])]}, None
        return real(args)
    monkeypatch.setattr(H, "kubectl_json", kj)
    H._POLICY_SEL_CACHE.clear()


# ------------------------------------------------------------------ configuration
def test_policy_schema_validation(H):
    assert H.save_config({"backup_policies": [pol("or", namespaces=["app"])]}, source="api")[0]
    bad = [
        [pol("", namespaces=["app"])],                                   # nom vide
        [pol("or", namespaces=["app"]), pol("OR", namespaces=["x"])],    # doublon (casse ignorée)
        [pol("or")],                                                     # aucune cible
        [pol("or", namespaces=["App_Invalide"])],                        # nom de namespace invalide
        [pol("or", namespaces=["app"], interval_hours=0.1)],             # intervalle trop court
        [pol("or", namespaces=["app"], keep=-1)],
        [pol("or", label_selector="a=b; rm -rf /")],                     # caractères interdits
        [pol("default", namespaces=["app"])],                            # nom réservé
    ]
    for b in bad:
        ok, err = H.save_config({"backup_policies": b}, source="api")
        assert not ok and "backup_policies" in err, b


def test_policy_resolution_first_match_and_selector(H, monkeypatch):
    set_policies(H, [pol("or", label_selector="tier=gold", keep=30),
                     pol("argent", namespaces=["app", "shop"], keep=7)])
    fake_selectors(H, monkeypatch, {"tier=gold": ["shop", "billing"]})
    pmap, err = H._policy_map(["app", "shop", "billing", "misc"])
    assert err is None
    assert pmap["shop"]["name"] == "or", "première politique de la liste prioritaire"
    assert pmap["billing"]["name"] == "or" and pmap["app"]["name"] == "argent" and pmap["misc"] is None
    assert H._retention_for("shop") == (30, "count")
    assert H._retention_for("misc") == (H.CONFIG["auto_backup_keep"], None)


def test_selector_error_never_purges(H, monkeypatch):
    set_policies(H, [pol("or", label_selector="tier=gold", keep=30)])
    fake_selectors(H, monkeypatch, {}, fail=True)
    pmap, err = H._policy_map(["app"])
    assert err and pmap["app"] is None
    assert H._retention_for("app") == (0, "count"), "appartenance invérifiable : aucune purge"


# ------------------------------------------------------------------ périmètre des passages
def test_backup_all_scopes(H, monkeypatch):
    st = read_state(H)
    st["namespaces"] = ["app", "shop", "misc"]
    write_state(H, st)
    set_policies(H, [pol("argent", namespaces=["shop"], keep=7)])
    calls = []

    def fake_backup(ns, dest=None, **kw):
        calls.append((ns, kw.get("keep"), kw.get("retention_mode")))
        return {"ok": True, "count": 1, "dir": "/x/" + ns, "pruned": 0}
    monkeypatch.setattr(H, "action_backup", fake_backup)
    H.CONFIG["backup_parallel"] = 1
    H.action_backup_all(None, kind="auto", internal=True, policy_scope=None)
    assert sorted(c[0] for c in calls) == ["app", "misc"], "défaut : namespaces SANS politique nommée"
    assert all(c[1] is None for c in calls)
    calls.clear()
    p = H._named_policies()[0]
    H.action_backup_all(None, kind="auto", internal=True, policy_scope=p)
    assert calls == [("shop", 7, "count")], "politique : ses namespaces, avec sa rétention"
    calls.clear()
    H.action_backup_all(None)                                            # sauvegarde manuelle « tout »
    assert sorted(c[0] for c in calls) == ["app", "misc", "shop"]


def test_manual_backup_uses_policy_retention(H):
    import datetime
    root = H.CONFIG["backup_root"]
    base = os.path.join(root, "_contexts", "test-ctx", "app")
    now = datetime.datetime.now()
    for i in range(1, 6):
        d = os.path.join(base, (now - datetime.timedelta(hours=i)).strftime("%Y-%m-%d_%H-%M-%S_%f"))
        os.makedirs(d)
        json.dump({"schema": 2, "kind": "auto", "namespace": "app",
                   "created": (now - datetime.timedelta(hours=i)).isoformat(), "volumes": []},
                  open(os.path.join(d, "index.json"), "w"))
    set_policies(H, [pol("argent", namespaces=["app"], keep=2)])
    keep, mode = H._retention_for("app")
    removed = H._prune_backups(root, "app", keep, mode=mode)
    assert removed == 3 and len(H.list_backups("app", root)) == 2


# ------------------------------------------------------------------ ordonnanceur
def test_policy_due_and_run_state(H, monkeypatch):
    set_policies(H, [pol("argent", namespaces=["app"], interval_hours=2, keep=5)])
    p = H._named_policies()[0]
    assert H._policy_due(p, 1000.0), "jamais exécutée : due tout de suite"
    monkeypatch.setattr(H, "action_backup_all", lambda dest, kind="manual", internal=False, policy_scope=None:
                        {"ok": True, "results": [{"ns": "app", "ok": True, "count": 1, "pruned": 0}],
                         "root": "/x", "backed_up": 1, "volumes": 1})
    assert H._policy_run(p, now=5000.0) is True
    stt = H._policy_state("argent")
    assert stt["last_ok"] is True and stt["last_run"] == 5000.0 and "argent" in stt["last_summary"]
    assert not H._policy_due(p, 5000.0 + 3600) and H._policy_due(p, 5000.0 + 7200)
    status = H.action_auto_backup_status()
    assert status["policies"][0]["name"] == "argent" and status["policies"][0]["next_due"] == 5000.0 + 7200
    # état persisté puis rechargé
    H.AUTO_BACKUP["policies"] = {}
    H._load_auto_backup_state()
    assert H._policy_state("argent")["last_run"] == 5000.0


def test_policy_hycu_assign_only_unassigned_trusted(H, monkeypatch):
    set_policies(H, [pol("or", namespaces=["app"], hycu_policy="pol-uuid", hycu_policy_name="Gold")])
    p = H._named_policies()[0]
    H.SESSION_CREDS["hycu"] = {"user": "x"}
    monkeypatch.setattr(H, "_hycu_list_vgs", lambda: ([{"uuid": "v"}], None))
    monkeypatch.setattr(H, "action_hycu_match", lambda ns, vg_items=None: {"ok": True, "matches": [
        {"matched": True, "trusted": True, "hycu_vg_uuid": "vg-free", "policy": None},
        {"matched": True, "trusted": True, "hycu_vg_uuid": "vg-gold", "policy": "Gold"},
        {"matched": True, "trusted": True, "hycu_vg_uuid": "vg-silver", "policy": "Silver"},
        {"matched": True, "trusted": False, "hycu_vg_uuid": "vg-byname", "policy": None}]})
    calls = []
    monkeypatch.setattr(H, "_rest", lambda system, method, path, body=None, **kw:
                        calls.append((path, body)) or {"ok": True, "json": {}})
    ok, msg = H._policy_hycu_assign(p, ["app"])
    assert ok and calls == [("/policies/pol-uuid/assign",
                             {"volumeGroupUuidList": ["vg-free"], "includeDependencies": False})]
    assert "1 volume(s) rattaché(s)" in msg and "1 volume(s) déjà dans une autre politique" in msg


def test_compliance_window_follows_policy(H):
    set_policies(H, [pol("or", namespaces=["app"], interval_hours=2)])
    p = H._named_policies()[0]
    assert abs(H._backup_freshness_s(p) - 2 * 3600 * 1.1) < 1
    assert H._policy_view(p) == {"name": "or", "enabled": True, "interval_hours": 2.0}
    assert H._policy_view(None)["name"] == ""


# ------------------------------------------------------------------ kit de l'outil
def _kit_env(H, monkeypatch, store):
    H.SESSION_CREDS["s3"] = {"access": "a", "secret": "s"}
    H.CONFIG.update({"s3_url": "http://s3.local", "s3_bucket": "b", "s3_prefix": "hycu-backups"})

    def fake_s3(method, key="", body=b"", query="", want_body=False):
        if method == "PUT":
            store[key] = body
            return {"ok": True}
        if method == "GET" and key:
            return {"ok": True, "data": store[key]}
        xml = "<ListBucketResult>" + "".join(
            "<Contents><Key>%s</Key><Size>%d</Size><LastModified>2026-10-10T10:00:00.000Z</LastModified></Contents>"
            % (k, len(v)) for k, v in store.items()) + "</ListBucketResult>"
        return {"ok": True, "data": xml.encode()}
    monkeypatch.setattr(H, "_s3_request", fake_s3)


def test_tool_kit_roundtrip(H, monkeypatch):
    store = {}
    _kit_env(H, monkeypatch, store)
    set_policies(H, [pol("or", namespaces=["app"])])
    H.save_config({"namespace_filter": ["app", "shop"]}, source="api")
    open(H.SECRETS_PATH, "w").write("COFFRE-CHIFFRE")
    ok, key = H.s3_upload_tool_kit()
    assert ok and key.startswith("hycu-backups/_tool/hycu-tool-") and key.endswith(".zip")
    names = zipfile.ZipFile(io.BytesIO(store[key])).namelist()
    assert {"hycu_config.json", "hycu_secrets.enc", "manifest.json"} <= set(names)
    kits = H.action_tool_kit_list()
    assert kits["ok"] and kits["kits"][0]["key"] == key
    # Nouvelle instance : configuration différente, plus de coffre.
    backup_root = H.CONFIG["backup_root"]
    H.save_config({"backup_policies": [], "namespace_filter": []}, source="api")
    os.remove(H.SECRETS_PATH)
    r = H.action_tool_kit_restore({"key": key})
    assert r["ok"] and r["vault"], r
    assert H._named_policies()[0]["name"] == "or" and H.CONFIG["namespace_filter"] == ["app", "shop"]
    assert open(H.SECRETS_PATH).read() == "COFFRE-CHIFFRE"
    assert H.CONFIG["backup_root"] == backup_root, "réglages propres à la machine conservés"
    assert os.path.isdir(r["safety_copy"])
    assert not H.action_tool_kit_restore({"key": "hycu-backups/autre/chose.zip"})["ok"]


def test_tool_kit_encrypted_needs_passphrase(H, monkeypatch):
    store = {}
    _kit_env(H, monkeypatch, store)
    H.CONFIG["s3_encrypt"] = True
    H.SESSION_CREDS["s3"]["enc"] = "phrase-dr"
    ok, key = H.s3_upload_tool_kit()
    assert ok and key.endswith(".zip.enc")
    H.SESSION_CREDS["s3"].pop("enc")
    assert "phrase" in H.action_tool_kit_restore({"key": key})["error"]
    assert not H.action_tool_kit_restore({"key": key, "passphrase": "mauvaise"})["ok"]
    assert H.action_tool_kit_restore({"key": key, "passphrase": "phrase-dr"})["ok"]


def test_purge_versions_guards(H):
    import datetime
    root = H.CONFIG["backup_root"]
    base = os.path.join(root, "_contexts", "test-ctx", "app")
    now = datetime.datetime.now()
    dirs = []
    for i in range(1, 4):
        d = os.path.join(base, (now - datetime.timedelta(hours=i)).strftime("%Y-%m-%d_%H-%M-%S_%f"))
        os.makedirs(d)
        json.dump({"schema": 2, "kind": "auto", "namespace": "app",
                   "created": (now - datetime.timedelta(hours=i)).isoformat(), "volumes": []},
                  open(os.path.join(d, "index.json"), "w"))
        dirs.append(d)
    other = os.path.join(root, "_contexts", "test-ctx", "shop", "2026-01-01_00-00-00_000000")
    os.makedirs(other)
    json.dump({"namespace": "shop"}, open(os.path.join(other, "index.json"), "w"))
    H._save_txn("app", {"status": "in_progress", "backup_dir": dirs[2], "volumes": []})
    r = H.action_backups_delete({"ns": "app", "paths": [dirs[1], dirs[2], other, "/etc"]})
    assert r["removed"] == 1 and not r["ok"] and len(r["errors"]) == 3
    assert not os.path.isdir(dirs[1]) and os.path.isdir(dirs[2]) and os.path.isdir(other)
    H._clear_txn("app")
    r2 = H.action_backups_delete({"ns": "app", "paths": [dirs[0], dirs[2]]})
    assert r2["ok"] and r2["removed"] == 2 and H.list_backups("app", root) == []
    H.ACTION_LOCK.acquire()
    try:
        assert not H.action_backups_delete({"ns": "app", "paths": [other]})["ok"]
    finally:
        H.ACTION_LOCK.release()
