# -*- coding: utf-8 -*-
"""Serveur HTTP : garde Host/Origin, CSRF, /healthz sans rotation de session, langue par
défaut (E2), annulation d'opération."""
import io
import json
import re
import threading
import time


class FakeHandler:
    """Instancie Handler sans socket ; capture la réponse."""
    def __new__(cls, H, method, path, headers=None, body=b""):
        h = object.__new__(H.Handler)
        h.command = method
        h.path = path
        h.headers = {k: v for k, v in (headers or {}).items()}
        h.rfile = io.BytesIO(body)
        h.client_address = ("127.0.0.1", 12345)
        h.captured = {}
        h.wfile = io.BytesIO()

        def _send(code, data, ctype="application/json", extra_headers=None):
            h.captured = {"code": code, "body": data, "ctype": ctype, "headers": extra_headers or {}}
        h._send = _send
        return h


def _run(H, method, path, headers=None, body=None):
    hdr = {"Host": "127.0.0.1:8765"}
    hdr.update(headers or {})
    raw = json.dumps(body).encode() if body is not None else b""
    if body is not None:
        hdr["Content-Length"] = str(len(raw))
    h = FakeHandler(H, method, path, hdr, raw)
    (h.do_GET if method == "GET" else h.do_POST)()
    return h.captured


def test_foreign_host_rejected(H):
    c = _run(H, "GET", "/api/context", {"Host": "10.0.0.5:8765"})
    assert c["code"] == 403


def test_post_without_csrf_rejected(H):
    c = _run(H, "POST", "/api/config", {"Origin": "http://127.0.0.1:8765"}, {"config": {}})
    assert c["code"] == 403


def test_invalid_content_length_is_400(H):
    c = _run(H, "POST", "/api/config", {"Origin": "http://127.0.0.1:8765", "X-CSRF-Token": H.CSRF_TOKEN,
                                        "Content-Length": "abc"})
    assert c["code"] == 400


def test_healthz_does_not_rotate_session(H):
    H.UI_SESSION["id"] = "s1"
    H.SESSION_CREDS["hycu"] = {"mode": "apikey", "key": "k"}
    c = _run(H, "GET", "/healthz")
    assert c["code"] == 200 and c["body"] == "ok"
    assert H.UI_SESSION["id"] == "s1" and H.SESSION_CREDS["hycu"] is not None


def test_root_from_probe_does_not_rotate_session(H):
    H.UI_SESSION["id"] = "s1"
    H.SESSION_CREDS["hycu"] = {"mode": "apikey", "key": "k"}
    c = _run(H, "GET", "/", {"User-Agent": "python-urllib/3.12", "Accept": "*/*"})
    assert c["code"] == 200
    assert H.UI_SESSION["id"] == "s1" and H.SESSION_CREDS["hycu"] is not None


def test_root_from_browser_rotates_session(H):
    H.UI_SESSION["id"] = "s1"
    H.SESSION_CREDS["hycu"] = {"mode": "apikey", "key": "k"}
    c = _run(H, "GET", "/", {"Accept": "text/html,*/*", "User-Agent": "Mozilla/5.0"})
    assert c["code"] == 200 and "hycu_sess=" in c["headers"].get("Set-Cookie", "")
    assert H.SESSION_CREDS["hycu"] is None


def test_no_rotation_while_operation_running(H):
    H.UI_SESSION["id"] = "s1"
    H.SESSION_CREDS["hycu"] = {"mode": "apikey", "key": "k"}
    ev = threading.Event()

    def slow(payload, log=None):
        ev.wait(2)
        return {"ok": True, "log": []}
    H._run_async(slow, {})
    try:
        c = _run(H, "GET", "/", {"Accept": "text/html", "User-Agent": "Mozilla/5.0"})
        assert c["code"] == 200
        assert H.SESSION_CREDS["hycu"] is not None, "les identifiants ne sont pas effacés pendant une opération"
    finally:
        ev.set()


def test_page_is_english_only(H):
    c = _run(H, "GET", "/", {"Accept": "text/html", "User-Agent": "Mozilla/5.0"})
    assert '<html lang="en">' in c["body"]
    assert "hycu_lang" not in c["body"] and "langBtn" not in c["body"]
    assert not hasattr(H, "I18N_EN") and not hasattr(H, "HTML_EN")


def test_json_is_sent_as_is(H):
    c = _run(H, "GET", "/api/context", {"Cookie": "hycu_lang=fr"})
    assert c["code"] == 200 and "Tableau" not in c["body"]


def test_op_cancel(H):
    ev = threading.Event()

    def slow(payload, log=None):
        for _ in range(50):
            if H._op_cancel_requested():
                return {"ok": False, "error": "annulé", "log": []}
            time.sleep(0.05)
        return {"ok": True, "log": []}
    start = H._run_async(slow, {"namespace": "app"})
    lst = H.action_op_list()
    assert any(o["op_id"] == start["op_id"] for o in lst["running"])
    c = _run(H, "POST", "/api/op_cancel", {"Origin": "http://127.0.0.1:8765", "X-CSRF-Token": H.CSRF_TOKEN},
             {"id": start["op_id"]})
    assert c["code"] == 200
    for _ in range(100):
        st = H.action_op_status(start["op_id"])
        if st["done"]:
            break
        time.sleep(0.05)
    assert st["done"] and st["result"]["error"] == "annulé"


def test_allowed_hosts_dns_exposure(H):
    """Un nom DNS configuré (Ingress / reverse-proxy) est accepté pour Host et Origin ;
    tout autre nom reste refusé (anti-DNS-rebinding)."""
    c = _run(H, "GET", "/api/context", {"Host": "hycu.interne.exemple.fr"})
    assert c["code"] == 403
    ok, err = H.save_config({"allowed_hosts": "hycu.interne.exemple.fr, Hycu-DR.exemple.fr"}, source="api")
    assert ok, err
    c = _run(H, "GET", "/api/context", {"Host": "hycu.interne.exemple.fr:443"})
    assert c["code"] == 200
    c = _run(H, "GET", "/api/context", {"Host": "HYCU-DR.exemple.fr"})
    assert c["code"] == 200
    c = _run(H, "GET", "/api/context", {"Host": "autre.exemple.fr"})
    assert c["code"] == 403
    # Origin : le nom autorisé passe, un tiers non
    c = _run(H, "POST", "/api/op_cancel", {"Host": "hycu.interne.exemple.fr", "Origin": "https://hycu.interne.exemple.fr",
                                           "X-CSRF-Token": H.CSRF_TOKEN}, {"id": "x"})
    assert c["code"] == 200
    c = _run(H, "POST", "/api/op_cancel", {"Host": "hycu.interne.exemple.fr", "Origin": "https://attaquant.exemple.fr",
                                           "X-CSRF-Token": H.CSRF_TOKEN}, {"id": "x"})
    assert c["code"] == 403
    # valeur invalide refusée
    assert not H.save_config({"allowed_hosts": ["pas un hôte !"]}, source="api")[0]


def test_allowed_hosts_from_env(H, monkeypatch):
    monkeypatch.setenv("HYCU_ALLOWED_HOSTS", "hycu.exemple.fr,backup.exemple.fr")
    H.load_config()
    assert H.CONFIG["allowed_hosts"] == ["hycu.exemple.fr", "backup.exemple.fr"]
    assert H._host_is_local("backup.exemple.fr:8765")


def test_protect_many_namespaces_single_hycu_calls(H, monkeypatch):
    """Définir la politique sur plusieurs applications : garde anti-stale PAR namespace,
    puis UN SEUL appel d'assignation et UN SEUL lancement de sauvegarde pour tous les VG."""
    calls = []

    def fake_rest(system, method, path, body=None, **kw):
        calls.append((method, path, body))
        return {"ok": True, "json": {"uuid": "job-1", "status": "QUEUED"}, "raw": ""}
    checked = []
    monkeypatch.setattr(H, "_rest", fake_rest)
    monkeypatch.setattr(H, "_reject_stale_vgs",
                        lambda ns, uuids, confirmed_by_name=None: checked.append((ns, tuple(uuids))) or None)
    monkeypatch.setattr(H, "_hycu_job_id", lambda j: (j or {}).get("uuid"))
    r = H.action_hycu_protect({"dry": False, "policy_uuid": "pol-1", "items": [
        {"namespace": "app1", "vg_uuids": ["vg-a", "vg-b"]},
        {"namespace": "app2", "vg_uuids": ["vg-c"], "confirm_name_uuids": ["vg-c"]}]})
    assert r["ok"] and r["job_id"] == "job-1" and r["count"] == 3 and r["namespaces"] == ["app1", "app2"]
    assert checked == [("app1", ("vg-a", "vg-b")), ("app2", ("vg-c",))]
    assign = [c for c in calls if c[1].endswith("/assign")]
    backup = [c for c in calls if c[1].endswith("/backupVolumeGroup")]
    assert len(assign) == 1 and assign[0][2]["volumeGroupUuidList"] == ["vg-a", "vg-b", "vg-c"]
    assert len(backup) == 1 and backup[0][2]["uuidList"] == ["vg-a", "vg-b", "vg-c"]
    # Un namespace refusé par la garde -> rien n'est envoyé à HYCU.
    calls.clear()
    monkeypatch.setattr(H, "_reject_stale_vgs",
                        lambda ns, uuids, confirmed_by_name=None: "hors correspondance" if ns == "app2" else None)
    r2 = H.action_hycu_protect({"dry": False, "items": [{"namespace": "app1", "vg_uuids": ["vg-a"]},
                                                        {"namespace": "app2", "vg_uuids": ["vg-c"]}]})
    assert not r2["ok"] and "hors correspondance" in r2["error"] and not calls


def test_parallel_hycu_clones_are_serialized_not_refused(H, monkeypatch):
    """Plusieurs clones HYCU lancés en même temps (interface parallèle) : la section
    critique attend le verrou au lieu de répondre « une autre opération est en cours »."""
    import threading, time
    calls = []

    def fake_rest(system, method, path, body=None, **kw):
        time.sleep(0.2)
        calls.append(body.get("vgName"))
        return {"ok": True, "json": {"uuid": "job-" + body.get("vgName"), "status": "QUEUED"}, "raw": ""}
    monkeypatch.setattr(H, "_rest", fake_rest)
    monkeypatch.setattr(H, "_reject_stale_vgs", lambda ns, uuids, confirmed_by_name=None: None)
    monkeypatch.setattr(H, "_hycu_job_id", lambda j: (j or {}).get("uuid"))
    out = {}

    def run(name):
        out[name] = H.action_hycu_restore({"dry": False, "restore_point_id": "rp", "mode": "clone",
                                           "new_name": name, "source_uuid": "vg-src", "namespace": "app"})
    ths = [threading.Thread(target=run, args=("c%d" % i,)) for i in range(4)]
    [t.start() for t in ths]
    [t.join() for t in ths]
    assert all(r["ok"] and r["job_id"] == "job-" + n for n, r in out.items()), out
    assert sorted(calls) == ["c0", "c1", "c2", "c3"]
