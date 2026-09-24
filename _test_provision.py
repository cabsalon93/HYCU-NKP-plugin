# -*- coding: utf-8 -*-
"""Auto-provisionnement (P2) : cloner un VG via HYCU (nom imposé) et DÉCOUVRIR son
nouvel UUID — pour remplir les items d'une restauration SANS saisie manuelle.
dry = plan (aucun clone) ; réel = clone + attente job + découverte ; repli si échec."""
import os
import shutil
import tempfile
import hycu_k8s_nutanix as H

passed = failed = 0
def check(c, m):
    global passed, failed
    if c: passed += 1; print("  OK  ", m)
    else: failed += 1; print("  FAIL", m)


SRC = "11111111-2222-3333-4444-555555555555"
NEW = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
tmp = tempfile.mkdtemp()
saved = dict(H.CONFIG)
s_restore = H.action_hycu_restore
s_job = H.action_hycu_job
s_vgs = H.action_nutanix_vgs
s_list = H._hycu_list_vgs
s_rp = H.action_hycu_restore_points

CALLS = []
try:
    H.CONFIG.update({"backup_root": tmp})
    H.CONFIG_PATH = os.path.join(tmp, "hycu_config.json")

    print("== Simulation (dry) : plan seulement, aucun clone HYCU ==")
    def boom_restore(p):
        raise AssertionError("action_hycu_restore ne doit PAS être appelé en simulation")
    H.action_hycu_restore = boom_restore
    H.action_hycu_restore_points = lambda src: {"ok": True, "points": [
        {"id": "rp-latest", "time": "2026-09-25 01:00", "restorable": True}]}
    r = H.action_hycu_provision_clone({"volumes": [{"pvc": "data", "source_vg_uuid": SRC}], "dry": True})
    check(r["ok"] and r["dry"], "plan simulé OK")
    check(r["items"][0]["new_ref"] is None and r["items"][0].get("planned_name", "").startswith("hycurestore-data-"),
          "plan : aucun UUID encore, nom de VG cible imposé")

    print("\n== Simulation informative : identité HYCU résolue (VG supprimé), point affiché ==")
    # Cas réel : sauvegarde ancienne -> on n'a que l'UUID Source (Nutanix) ; HYCU garde le
    # VG « Protected deleted » avec HYCU UUID != Source UUID.
    NSRC = "a6a2d63d-52fd-41b2-518f-a119566b744a"   # Source UUID (externalId Nutanix)
    NHY = "f10d53aa-9f88-43a2-86dc-c762bf39693d"    # HYCU UUID
    with H.CRED_LOCK:
        H.SESSION_CREDS["hycu"] = {"access": "a", "secret": "b"}
    H._hycu_list_vgs = lambda: ([{"uuid": NHY, "name": "pvc-afae3cb2", "externalId": NSRC, "hasBackups": True}], None)
    H.action_hycu_restore_points = lambda src: ({"ok": True, "points": [
        {"id": "rp-1", "time": "2026-09-24 04:00", "restorable": True}]} if src == NHY else {"ok": True, "points": []})
    r = H.action_hycu_provision_clone({"volumes": [{"pvc": "mariadb-pvc", "source_vg_uuid": NSRC,
                                                    "vg_name": "pvc-afae3cb2"}], "dry": True})
    check(r["ok"] and r["dry"], "simulation OK sur un VG supprimé (identité résolue)")
    check(r["items"][0].get("hycu_source") == NHY and r["items"][0].get("restore_point_id") == "rp-1",
          "plan : identité HYCU résolue depuis l'UUID Source + point de restauration trouvé")
    with H.CRED_LOCK:
        H.SESSION_CREDS["hycu"] = None
    H._hycu_list_vgs = s_list
    # Restaure le stub « point le plus récent » attendu par la section suivante.
    H.action_hycu_restore_points = lambda src: {"ok": True, "points": [
        {"id": "rp-latest", "time": "2026-09-25 01:00", "restorable": True}]}

    print("\n== Réel : clone HYCU + attente job + découverte de l'UUID ==")
    with H.CRED_LOCK:
        H.SESSION_CREDS["hycu"] = {"access": "a", "secret": "b"}
        H.SESSION_CREDS["prismcentral"] = {"access": "a", "secret": "b"}
    def fake_restore(p):
        CALLS.append(p)
        assert p["mode"] == "clone" and p["new_name"] and p["source_uuid"] == SRC and not p["dry"]
        return {"ok": True, "dry": False, "job_id": "job-1"}
    H.action_hycu_restore = fake_restore
    H.action_hycu_job = lambda jid: {"ok": True, "status": "OK", "progress": 100}
    # Prism voit le nouveau VG sous le nom imposé -> découverte.
    def fake_vgs(query=""):
        nm = CALLS[-1]["new_name"] if CALLS else ""
        return {"ok": True, "vgs": [{"name": nm, "uuid": NEW, "iqn": None}]}
    H.action_nutanix_vgs = fake_vgs
    r = H.action_hycu_provision_clone({"volumes": [{"pvc": "data", "source_vg_uuid": SRC}], "dry": False})
    check(r["ok"] and not r["dry"], "provisionnement réel OK")
    check(r["items"][0]["pvc"] == "data" and r["items"][0]["new_ref"] == NEW,
          "UUID du VG cloné découvert automatiquement (aucune saisie)")
    check(CALLS and CALLS[0]["restore_point_id"] == "rp-latest",
          "point de restauration le plus récent choisi par défaut")

    print("\n== VG supprimé du cluster : identité HYCU résolue depuis l'UUID Nutanix ==")
    HYU = "cccccccc-dddd-eeee-ffff-000000000000"     # uuid HYCU (≠ externalId Nutanix SRC)
    CALLS.clear()
    H._hycu_list_vgs = lambda: ([{"uuid": HYU, "name": "pvc-orig", "externalId": SRC, "hasBackups": True}], None)
    seen_src = {}
    def rp_by_src(src):
        seen_src["last"] = src
        # Seul l'uuid HYCU renvoie des points ; l'UUID Nutanix n'en renvoie pas.
        if src == HYU:
            return {"ok": True, "points": [{"id": "rp-x", "time": "t", "restorable": True}]}
        return {"ok": True, "points": []}
    H.action_hycu_restore_points = rp_by_src
    def fake_restore2(p):
        CALLS.append(p); return {"ok": True, "dry": False, "job_id": "job-2"}
    H.action_hycu_restore = fake_restore2
    H.action_hycu_job = lambda jid: {"ok": True, "status": "OK"}
    H.action_nutanix_vgs = lambda query="": {"ok": True, "vgs": [{"name": query, "uuid": NEW}]}
    r = H.action_hycu_provision_clone({"volumes": [{"pvc": "data", "source_vg_uuid": SRC, "vg_name": "pvc-orig"}],
                                       "dry": False})
    check(r["ok"] and r["items"][0]["new_ref"] == NEW,
          "VG source (Nutanix) résolu vers l'identité HYCU -> points trouvés -> clone -> UUID")
    check(CALLS and CALLS[0]["source_uuid"] == HYU, "le clone HYCU utilise l'uuid HYCU résolu")

    print("\n== Découverte : ambiguïté jamais tranchée au hasard ==")
    H.action_hycu_restore_points = lambda src: {"ok": True, "points": [
        {"id": "rp-latest", "time": "2026-09-25 01:00", "restorable": True}]}
    H._hycu_list_vgs = s_list
    H.action_nutanix_vgs = lambda query="": {"ok": True, "vgs": [
        {"name": query, "uuid": NEW}, {"name": query, "uuid": "99999999-0000-0000-0000-000000000000"}]}
    H._hycu_list_vgs = lambda: ([], None)
    u, e = H._discover_vg_uuid_by_name("dup")
    check(u is None and "ambigu" in (e or "").lower(), "deux VG du même nom -> refus (ambiguïté)")

    print("\n== Job HYCU en échec : remontée claire, pas d'items ==")
    H.action_nutanix_vgs = fake_vgs
    H.action_hycu_job = lambda jid: {"ok": True, "status": "FAILED"}
    r = H.action_hycu_provision_clone({"volumes": [{"pvc": "data", "source_vg_uuid": SRC}], "dry": False})
    check(not r["ok"] and "échec" in (r["error"] or "").lower(), "échec du job HYCU signalé")

    print("\n== Repli : HYCU non connecté en réel -> message clair ==")
    with H.CRED_LOCK:
        H.SESSION_CREDS["hycu"] = None
    r = H.action_hycu_provision_clone({"volumes": [{"pvc": "data", "source_vg_uuid": SRC}], "dry": False})
    check(not r["ok"] and "HYCU" in (r["error"] or ""), "sans HYCU : refus explicite (saisie manuelle possible)")
finally:
    with H.CRED_LOCK:
        H.SESSION_CREDS["hycu"] = None
        H.SESSION_CREDS["prismcentral"] = None
    H.action_hycu_restore = s_restore
    H.action_hycu_job = s_job
    H.action_nutanix_vgs = s_vgs
    H._hycu_list_vgs = s_list
    H.action_hycu_restore_points = s_rp
    H.CONFIG.clear(); H.CONFIG.update(saved)
    shutil.rmtree(tmp, ignore_errors=True)

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
