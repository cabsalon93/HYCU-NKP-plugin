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


def test_default_language_is_english(H):
    c = _run(H, "GET", "/", {"Accept": "text/html", "User-Agent": "Mozilla/5.0"})
    assert 'const PAGE_LANG="en"' in c["body"]
    assert '<html lang="en">' in c["body"]
    H.CONFIG["default_lang"] = "fr"
    c = _run(H, "GET", "/", {"Accept": "text/html", "User-Agent": "Mozilla/5.0"})
    assert 'const PAGE_LANG="fr"' in c["body"]
    c = _run(H, "GET", "/", {"Accept": "text/html", "User-Agent": "Mozilla/5.0", "Cookie": "hycu_lang=en"})
    assert 'const PAGE_LANG="en"' in c["body"]


def test_json_translation_skips_commands(H):
    c = _run(H, "GET", "/api/context", {"Cookie": "hycu_lang=en"})
    assert c["code"] == 200
    out = H._tr_json_en({"error": "Non connecté à HYCU.", "cmd": "kubectl get ns exemple.com",
                         "stdout": "rien à supprimer"})
    assert out["cmd"] == "kubectl get ns exemple.com"          # jamais traduit (données)
    assert out["error"] != "Non connecté à HYCU."


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
