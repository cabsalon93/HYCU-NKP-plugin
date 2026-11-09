# -*- coding: utf-8 -*-
"""Durcissements de la revue : journal bulk écrit durablement, tri SigV4 par nom de
paramètre, worker bulk qui ne meurt jamais en silence."""
import hashlib
import hmac
import json
import os


def test_bulk_journal_uses_the_durable_atomic_writer(H, monkeypatch):
    calls = []
    real = H._write_json_atomic
    monkeypatch.setattr(H, "_write_json_atomic", lambda p, o, mode=0o600: (calls.append((p, mode)), real(p, o, mode=mode))[1])
    j = {"id": "abc", "items": [{"ns": "app", "status": "pending"}], "dry": True}
    H._bulk_save(j)
    assert calls and calls[0][0] == H._bulk_path() and calls[0][1] == 0o600, calls
    assert H._bulk_load() == j
    assert not [p for p in os.listdir(os.path.dirname(H._bulk_path())) if p.endswith(".tmp")], "plus de .tmp maison"


def test_sigv4_canonical_query_sorted_by_parameter_name(H):
    """Une clé préfixe d'une autre (« a » / « a-b ») : SigV4 attend « a=2&a-b=1 » ; un tri
    de chaînes « k=v » donnerait « a-b=1&a=2 » (« - » < « = ») et une signature fausse."""
    method, host, path = "GET", "bucket.example", "/"
    query = "a-b=1&a=2"
    amzdate, region, service = "20260101T000000Z", "us-east-1", "s3"
    access, secret = "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    payload_hash = hashlib.sha256(b"").hexdigest()
    headers = {"host": host, "x-amz-date": amzdate, "x-amz-content-sha256": payload_hash}

    # Référence : même algorithme, requête canonique écrite À LA MAIN dans l'ordre SigV4.
    signed = ";".join(sorted(headers))
    canonical = "\n".join([method, path, "a=2&a-b=1",
                           "".join("%s:%s\n" % (k, headers[k]) for k in sorted(headers)), signed, payload_hash])
    scope = "%s/%s/%s/aws4_request" % (amzdate[:8], region, service)
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    k = hmac.new(("AWS4" + secret).encode(), amzdate[:8].encode(), hashlib.sha256).digest()
    for part in (region, service, "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    expected_sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()

    auth = H._sigv4_auth(method, host, path, query, headers, payload_hash, region, service, access, secret, amzdate)
    assert auth.endswith("Signature=" + expected_sig), auth


def test_bulk_worker_records_unexpected_errors_instead_of_dying_silently(H, monkeypatch):
    audits = []
    monkeypatch.setattr(H, "audit", lambda event, **kw: audits.append((event, kw)))

    def boom(j):
        raise RuntimeError("disk on fire")
    monkeypatch.setattr(H, "_bulk_counts", boom)          # appelé APRÈS la boucle par namespace
    H.BULK["running"] = True
    j = {"id": "x", "items": [], "dry": True}
    H._bulk_worker(j, None, H.LOCAL_CID)                   # synchrone : ne doit pas lever
    assert j.get("error", "").startswith("Internal error: disk on fire"), j
    assert j.get("ended"), "fin horodatée malgré l'erreur"
    assert H._bulk_load() and H._bulk_load().get("error") == j["error"], "journal persisté avec l'erreur"
    assert any(ev == "bulk_restore_error" and "disk on fire" in kw.get("error", "") for ev, kw in audits), audits
    assert H.BULK["running"] is False and H.BULK["stop"] is False, "drapeaux toujours relâchés"
