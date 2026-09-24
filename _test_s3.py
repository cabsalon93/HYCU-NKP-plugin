# -*- coding: utf-8 -*-
"""Export S3 optionnel : signature SigV4 (vecteur officiel AWS), test de connexion,
envoi d'une sauvegarde .zip, crochet automatique post-sauvegarde (best-effort)."""
import hashlib
import http.server
import io
import json
import os
import shutil
import socketserver
import tempfile
import threading
import zipfile
import hycu_k8s_nutanix as H

passed = failed = 0
def check(c, m):
    global passed, failed
    if c: passed += 1; print("  OK  ", m)
    else: failed += 1; print("  FAIL", m)


print("== Signature SigV4 (vecteur officiel AWS, service iam) ==")
auth = H._sigv4_auth(
    "GET", "iam.amazonaws.com", "/", "Action=ListUsers&Version=2010-05-08",
    {"host": "iam.amazonaws.com", "x-amz-date": "20150830T123600Z",
     "content-type": "application/x-www-form-urlencoded; charset=utf-8"},
    hashlib.sha256(b"").hexdigest(), "us-east-1", "iam",
    "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830T123600Z")
check(auth.endswith("5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"),
      "signature identique au vecteur de la documentation AWS")
check("Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request" in auth
      and "SignedHeaders=content-type;host;x-amz-date" in auth, "portée et en-têtes signés")


# ---- Faux serveur S3 : enregistre les requêtes, répond 200 (ou 403 sur demande) ----
REQS = []
DENY = {"on": False}
STORE = {}                      # clé -> octets (les PUT y vont ; GET les ressert)


class FakeS3(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _handle(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        REQS.append({"method": self.command, "path": self.path,
                     "auth": self.headers.get("Authorization") or "",
                     "sha": self.headers.get("x-amz-content-sha256") or "",
                     "date": self.headers.get("x-amz-date") or "", "body": body})
        if DENY["on"]:
            payload = b"<Error><Code>AccessDenied</Code></Error>"
            self.send_response(403)
        else:
            from urllib.parse import urlparse, parse_qs, unquote
            u = urlparse(self.path)
            key = unquote(u.path.split("/sauvegardes/", 1)[1]) if "/sauvegardes/" in u.path else ""
            if self.command == "PUT" and key:
                STORE[key] = body
                payload = b""
            elif self.command == "GET" and "list-type=2" in (u.query or ""):
                pref = (parse_qs(u.query).get("prefix") or [""])[0]
                rows = "".join("<Contents><Key>%s</Key><Size>%d</Size>"
                               "<LastModified>2026-09-24T12:00:00.000Z</LastModified></Contents>"
                               % (k, len(v)) for k, v in sorted(STORE.items()) if k.startswith(pref))
                payload = ('<?xml version="1.0"?><ListBucketResult xmlns='
                           '"http://s3.amazonaws.com/doc/2006-03-01/"><IsTruncated>false'
                           "</IsTruncated>%s</ListBucketResult>" % rows).encode()
            elif self.command == "GET" and key in STORE:
                payload = STORE[key]
            else:
                payload = b"<ListBucketResult/>"
            self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_PUT = _handle


srv = socketserver.TCPServer(("127.0.0.1", 0), FakeS3)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

tmp = tempfile.mkdtemp()
saved = dict(H.CONFIG)
try:
    H.CONFIG.update({"s3_url": "http://127.0.0.1:%d" % port, "s3_bucket": "sauvegardes",
                     "s3_region": "eu-west-1", "s3_prefix": "hycu-backups",
                     "s3_path_style": True, "s3_auto_upload": False,
                     "backup_root": tmp})
    H.CONFIG_PATH = os.path.join(tmp, "hycu_config.json")

    print("\n== Connexion (test du bucket) ==")
    r = H.action_s3_connect({"access": "AKID", "secret": ""})
    check(not r["ok"], "clé secrète manquante refusée")
    r = H.action_s3_connect({"access": "AKID", "secret": "s3cret", "s3_auto_upload": True})
    check(r["ok"] and r["auto_upload"], "connexion OK (liste du bucket) + export auto activé")
    q = REQS[-1]
    check(q["method"] == "GET" and q["path"] == "/sauvegardes?list-type=2&max-keys=1",
          "test = GET de liste limité à 1 objet (lecture seule)")
    check(q["auth"].startswith("AWS4-HMAC-SHA256 Credential=AKID/") and "/eu-west-1/s3/aws4_request" in q["auth"],
          "requête signée SigV4 (région configurée)")
    check(b"s3cret" not in q["body"] and "s3cret" not in q["auth"] and "s3cret" not in q["path"],
          "la clé secrète ne transite jamais dans la requête")

    DENY["on"] = True
    r = H.action_s3_connect({"access": "AKID", "secret": "mauvaise"})
    check(not r["ok"] and "403" in r["error"] and H.SESSION_CREDS["s3"] is None,
          "clés refusées (403) : erreur + identifiants non conservés")
    DENY["on"] = False
    H.action_s3_connect({"access": "AKID", "secret": "s3cret"})

    print("\n== Envoi d'une sauvegarde ==")
    bdir = os.path.join(tmp, "wordpress", "2026-09-24_10-00-00_000000")
    os.makedirs(bdir)
    with open(os.path.join(bdir, "index.json"), "w") as f:
        json.dump({"namespace": "wordpress"}, f)
    with open(os.path.join(bdir, "pv_x.json"), "w") as f:
        f.write("{}")
    ok, key = H.s3_upload_backup(bdir, "wordpress", "2026-09-24_10-00-00_000000")
    check(ok and key == "hycu-backups/local/wordpress/2026-09-24_10-00-00_000000.zip",
          "clé de l'objet : <préfixe>/<cluster>/<ns>/<horodatage>.zip")
    q = REQS[-1]
    check(q["method"] == "PUT" and q["path"].endswith(".zip"), "PUT de l'objet .zip")
    check(q["sha"] == hashlib.sha256(q["body"]).hexdigest(), "x-amz-content-sha256 = SHA256 du corps")
    names = zipfile.ZipFile(io.BytesIO(q["body"])).namelist()
    check(any(n.endswith("index.json") for n in names) and any(n.endswith("pv_x.json") for n in names),
          "le zip contient les manifestes de la sauvegarde")

    print("\n== Crochet automatique post-sauvegarde (best-effort) ==")
    res = H._s3_after_backup({"ok": True, "dir": bdir, "count": 1})
    check(res.get("s3", {}).get("ok"), "export auto après une sauvegarde réussie")
    DENY["on"] = True
    res = H._s3_after_backup({"ok": True, "dir": bdir, "count": 1})
    check(res["ok"] and res["s3"]["ok"] is False and res["s3"]["error"],
          "échec d'export : la sauvegarde locale reste un SUCCÈS, erreur remontée")
    DENY["on"] = False
    H.CONFIG["s3_auto_upload"] = False
    res = H._s3_after_backup({"ok": True, "dir": bdir, "count": 1})
    check("s3" not in res, "export auto désactivé : aucun envoi")
    recs = [json.loads(l) for l in open(os.path.join(tmp, "audit.log"))]
    ups = [x for x in recs if x["event"] == "s3_upload"]
    check(len(ups) == 2 and ups[0]["ok"] and not ups[1]["ok"], "audit : chaque export tracé (succès puis échec)")
    check(H.action_jobs()["jobs"][0]["event"] == "s3_upload", "les exports apparaissent dans les Tâches")

    print("\n== Import depuis le bucket (chemin retour / DR) ==")
    H.CONFIG.update({"s3_encrypt": True})
    with H.CRED_LOCK:
        H.SESSION_CREDS["s3"] = {"access": "AKID", "secret": "s3cret", "enc": "phrase-dr"}
    ok, key_enc = H.s3_upload_backup(bdir, "wordpress", "2026-09-24_10-00-00_000000")
    check(ok and key_enc.endswith(".zip.enc") and key_enc in STORE, "export chiffré envoyé (présent dans le bucket)")
    lst = H.action_s3_list()
    objs = {o["key"]: o for o in lst.get("objects") or []}
    check(lst["ok"] and key_enc in objs and objs[key_enc]["encrypted"]
          and objs[key_enc]["namespace"] == "wordpress", "listing du bucket : export analysé (chiffré)")
    imp = H.action_s3_import({"items": [{"key": key_enc}]})
    res = imp["results"][0]
    dest = os.path.join(tmp, "_imports", "local", "wordpress", "2026-09-24_10-00-00_000000")
    check(imp["ok"] and res["ok"] and os.path.isfile(os.path.join(dest, "index.json")),
          "import : objet déchiffré et extrait sous _imports/…")
    with H.CRED_LOCK:
        H.SESSION_CREDS["s3"]["enc"] = ""
    imp = H.action_s3_import({"items": [{"key": key_enc}]})
    check(not imp["results"][0]["ok"] and "phrase" in imp["results"][0]["error"],
          "objet chiffré sans phrase : refus clair")
    imp = H.action_s3_import({"items": [{"key": key_enc}], "enc_passphrase": "mauvaise"})
    check(not imp["results"][0]["ok"] and "chiffrement" in imp["results"][0]["error"].replace("déchiffrement", "chiffrement"),
          "mauvaise phrase : refus (scellé)")
    # zip-slip : archive hostile déposée directement dans le bucket
    import io as _io, zipfile as _zip
    evil = _io.BytesIO()
    with _zip.ZipFile(evil, "w") as z:
        z.writestr("../../evasion.txt", "pwned")
    STORE["hycu-backups/local/wordpress/2026-09-24_11-00-00_000000.zip"] = evil.getvalue()
    imp = H.action_s3_import({"items": [{"key": "hycu-backups/local/wordpress/2026-09-24_11-00-00_000000.zip"}]})
    check(not imp["results"][0]["ok"] and "hors zone" in imp["results"][0]["error"]
          and not os.path.exists(os.path.join(tmp, "evasion.txt")),
          "zip-slip bloqué (aucun fichier hors zone)")
    H.CONFIG["s3_encrypt"] = False
    with H.CRED_LOCK:
        H.SESSION_CREDS["s3"] = {"access": "AKID", "secret": "s3cret"}

    print("\n== Style d'URL ==")
    H.CONFIG["s3_path_style"] = False
    url, host, path = H._s3_object_url("a/b.zip")
    check(host == "sauvegardes.127.0.0.1:%d" % port and path == "/a/b.zip",
          "style sous-domaine : bucket dans l'hôte")
    H.CONFIG["s3_path_style"] = True
    url, host, path = H._s3_object_url("a/b.zip")
    check(path == "/sauvegardes/a/b.zip", "style chemin : bucket dans le chemin")
finally:
    with H.CRED_LOCK:
        H.SESSION_CREDS["s3"] = None
    srv.shutdown()
    H.CONFIG.clear(); H.CONFIG.update(saved)
    shutil.rmtree(tmp, ignore_errors=True)

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
