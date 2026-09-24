# -*- coding: utf-8 -*-
"""Téléchargement (.zip) d'une sauvegarde : empaquetage correct + garde anti-traversée.
Permet de SORTIR une sauvegarde du conteneur/Pod vers le poste de l'opérateur (le serveur
ne peut pas écrire sur le disque du client en mode conteneur/K8s)."""
import os
import io
import json
import shutil
import tempfile
import zipfile
import hycu_k8s_nutanix as H

passed = failed = 0
def check(c, m):
    global passed, failed
    if c: passed += 1; print("  OK  ", m)
    else: failed += 1; print("  FAIL", m)


class FakeHandler(H.Handler):
    """Instancie le handler SANS socket et capture ce que _send renvoie."""
    def __init__(self):
        self.captured = {}
    def _send(self, code, body, ctype="application/json", extra_headers=None):
        self.captured = {"code": code, "body": body, "ctype": ctype,
                         "headers": extra_headers or {}}


_ORIG_ROOT = H.CONFIG.get("backup_root")
tmp = tempfile.mkdtemp(prefix="hycu-dl-test-")
other = tempfile.mkdtemp(prefix="hycu-dl-out-")
try:
    H.CONFIG["backup_root"] = tmp
    # Fabrique une sauvegarde réaliste : <root>/wordpress/<ts>/{index.json, pv_*.json}
    bdir = os.path.join(tmp, "wordpress", "2026-06-25_18-03-06_964031")
    os.makedirs(bdir)
    with open(os.path.join(bdir, "index.json"), "w", encoding="utf-8") as f:
        json.dump({"namespace": "wordpress", "volumes": [{"pvc": "mariadb"}]}, f)
    with open(os.path.join(bdir, "pv_pvc-abc.json"), "w", encoding="utf-8") as f:
        f.write("{}")

    print("\n== Téléchargement d'une sauvegarde valide ==")
    h = FakeHandler(); h._download_backup(bdir, None)
    c = h.captured
    check(c.get("code") == 200, "HTTP 200")
    check(c.get("ctype") == "application/zip", "Content-Type application/zip")
    cd = c.get("headers", {}).get("Content-Disposition", "")
    check("attachment" in cd and ".zip" in cd, "Content-Disposition attachment .zip")
    check("wordpress_2026-06-25_18-03-06_964031.zip" in cd, "nom de fichier <ns>_<horodatage>.zip")
    z = zipfile.ZipFile(io.BytesIO(c["body"]))
    names = z.namelist()
    check(any(n.endswith("index.json") for n in names), "le zip contient index.json")
    check(any(n.endswith("pv_pvc-abc.json") for n in names), "le zip contient le manifeste PV")

    print("\n== Téléchargement de TOUT le dossier racine ==")
    h = FakeHandler(); h._download_backup(tmp, tmp)
    check(h.captured.get("code") == 200, "HTTP 200 sur la racine (tout télécharger)")
    z = zipfile.ZipFile(io.BytesIO(h.captured["body"]))
    check(any("index.json" in n for n in z.namelist()), "le zip racine inclut la sauvegarde")

    print("\n== Garde anti-traversée ==")
    h = FakeHandler(); h._download_backup("/etc", None)
    check(h.captured.get("code") == 404, "chemin hors backup_root refusé (404)")
    h = FakeHandler(); h._download_backup(os.path.join(other, "x"), None)
    check(h.captured.get("code") == 404, "autre dossier non désigné refusé (404)")
    h = FakeHandler(); h._download_backup(os.path.join(tmp, "wordpress", "..", "..", "etc"), None)
    check(h.captured.get("code") == 404, "tentative ../ refusée (404)")

    print("\n== Dossier personnalisé EXPLICITEMENT désigné -> autorisé ==")
    cdir = os.path.join(other, "ns2", "2026-01-01_00-00-00_000000")
    os.makedirs(cdir)
    with open(os.path.join(cdir, "index.json"), "w", encoding="utf-8") as f:
        json.dump({"namespace": "ns2", "volumes": []}, f)
    h = FakeHandler(); h._download_backup(cdir, other)   # root=other -> ouvre cette zone
    check(h.captured.get("code") == 200, "dossier perso désigné via root -> 200")
finally:
    H.CONFIG["backup_root"] = _ORIG_ROOT
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.rmtree(other, ignore_errors=True)

print("\n%d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
