# -*- coding: utf-8 -*-
"""Restauration en masse (même cluster) : plan (namespaces supprimés, dernière sauvegarde
antérieure à l'instant de référence, présents ignorés, avertissements), exécution
séquentielle journalisée (simulation puis réel exigeant la simulation du même plan),
arrêt propre, reprise idempotente, sauvegarde automatique suspendue."""
import json
import os
import shutil
import tempfile
import threading
import time
import hycu_k8s_nutanix as H

passed = failed = 0
def check(c, m):
    global passed, failed
    if c: passed += 1; print("  OK  ", m)
    else: failed += 1; print("  FAIL", m)


tmp = tempfile.mkdtemp()
saved = dict(H.CONFIG)
s_kj, s_ctx, s_clone, s_env, s_pw = H.kubectl_json, H.action_context, H.action_clone_app, H._vault_env_passphrase, H._VAULT_PW
try:
    H.CONFIG.update({"backup_root": tmp, "auto_backup_dest": "", "namespace_filter": [], "cluster_namespace_filters": {},
                     "namespace_label_selector": "", "require_context_confirm": False, "allowed_contexts": [],
                     "auto_backup_enabled": True, "auto_backup_interval_hours": 1})
    H.CONFIG_PATH = os.path.join(tmp, "hycu_config.json")
    H._LOCAL_CTX.update({"name": "ctx-bulk", "at": time.time() + 9999})
    H.action_context = lambda: {"context": "ctx-bulk", "kubectl_ok": True, "context_ok": True, "require_confirm": False}
    H._vault_env_passphrase = lambda: ""
    H._VAULT_PW = ""
    H._CATALOGS.clear()
    croot = H._cluster_root(tmp)

    def mk(ns, when, volumes=("data",), **extra):
        d = os.path.join(croot, ns, when)
        os.makedirs(d)
        idx = {"namespace": ns, "created": when[:10] + "T" + when[11:13] + ":" + when[14:16] + ":00",
               "context": "ctx-bulk", "cluster_id": "local",
               "volumes": [{"pvc": v, "analysis": {"old_volume_handle": "NutanixVolumes-11111111-2222-3333-4444-%012d" % i}}
                           for i, v in enumerate(volumes)]}
        idx.update(extra)
        with open(os.path.join(d, "index.json"), "w") as f:
            json.dump(idx, f)
        with open(os.path.join(d, "resources.json"), "w") as f:
            json.dump({"namespace": ns, "items": []}, f)
        return d
    # shop : 2 versions (08:00 et 12:00) ; base : 1 version ; web : stateless ; alive : présent ;
    # late : seule version APRÈS l'instant de référence ; vide : ni volume ni workload ;
    # sec : Secrets chiffrés ; partial : version partielle puis complète.
    mk("shop", "2026-09-26_08-00-00_000001")
    d_shop_late = mk("shop", "2026-09-26_12-00-00_000002")
    mk("base", "2026-09-26_07-00-00_000001", volumes=("db",))
    mk("web", "2026-09-26_07-30-00_000001", volumes=(), apps=[{"name": "web", "type": "stateless", "workloads": [{"kind": "Deployment", "name": "web"}]}])
    mk("alive", "2026-09-26_07-00-00_000001")
    mk("late", "2026-09-26_12-30-00_000001")
    mk("vide", "2026-09-26_07-00-00_000001", volumes=())
    mk("sec", "2026-09-26_07-00-00_000001", secrets="encrypted")
    mk("partial", "2026-09-26_06-00-00_000001", partial=True)
    mk("partial", "2026-09-26_05-00-00_000001")
    H.kubectl_json = lambda args: ({"items": [{"metadata": {"name": "alive"}}, {"metadata": {"name": "kube-system"}}]}, None) \
        if args[:2] == ["get", "ns"] else ({"items": []}, None)

    print("== Plan ==")
    p = H.action_bulk_plan({"as_of": "2026-09-26T10:00"})
    got = {it["ns"]: it for it in p["items"]}
    sk = {s["ns"]: s["reason"] for s in p["skipped"]}
    check(p["ok"] and set(got) == {"shop", "base", "web", "sec", "partial"}, "retenus : namespaces absents avec une sauvegarde ≤ T")
    check(got["shop"]["timestamp"].startswith("2026-09-26_08") and got["shop"]["volumes"] == ["data"],
          "shop : la version de 08:00 (12:00 est après l'instant de référence)")
    check(got["web"]["stateless"] and got["web"]["volumes"] == [], "web : stateless retenu (workloads sans volume)")
    check("alive" in sk and "présent" in sk["alive"] and "late" in sk and "antérieure" in sk["late"]
          and "vide" in sk and "kube-system" not in sk, "ignorés : présent, aucune sauvegarde ≤ T, sans contenu")
    check(any("VERROUILLÉ" in w for w in got["sec"]["warnings"]), "Secrets chiffrés + coffre verrouillé : avertissement")
    check(got["partial"]["timestamp"].startswith("2026-09-26_05") and not got["partial"]["partial"],
          "partial : version COMPLÈTE préférée à la partielle plus récente")
    check(all(any("masqués" in w for w in got[n]["warnings"]) for n in ("shop", "base")), "sauvegardes anciennes : Secrets masqués signalés")
    p2 = H.action_bulk_plan({"as_of": "2026-09-26T10:00", "exclude": ["base"]})
    check("base" not in {it["ns"] for it in p2["items"]} and any(s["ns"] == "base" and "exclu" in s["reason"] for s in p2["skipped"]),
          "exclusion explicite honorée")
    p3 = H.action_bulk_plan({"as_of": "n'importe quoi"})
    check(not p3["ok"] and "invalide" in p3["error"], "instant de référence invalide refusé")
    H.kubectl_json = lambda args: (None, "Forbidden")
    p4 = H.action_bulk_plan({})
    check(not p4["ok"] and "refusé" in p4["error"], "liste des namespaces impossible : plan refusé")
    H.kubectl_json = lambda args: ({"items": [{"metadata": {"name": "alive"}}]}, None) if args[:2] == ["get", "ns"] else ({"items": []}, None)

    print("\n== Simulation : journal, ordre, verdicts ==")
    calls, gate = [], {"stop_after": None, "fail": set()}
    def fake_clone(payload, log=None):
        calls.append(payload)
        if log is not None:
            log.append({"ok": True, "dry": payload.get("dry"), "label": "Namespace cible « %s »" % payload["namespace"]})
        if payload["namespace"] in gate["fail"]:
            return {"ok": False, "error": "boom", "log": log or []}
        if gate["stop_after"] == payload["namespace"]:
            H.BULK["stop"] = True
        return {"ok": True, "dry": payload.get("dry"), "log": log or [], "warnings": ["w1"]}
    H.action_clone_app = fake_clone
    def wait_done():
        for _ in range(200):
            if not H.BULK["running"]:
                return True
            time.sleep(0.02)
        return False
    r = H.action_bulk_run({"as_of": "2026-09-26T10:00", "dry": True})
    check(r["ok"] and r["namespaces"] == 5 and wait_done(), "simulation lancée en arrière-plan et terminée")
    st = H.action_bulk_status()
    j = st["journal"]
    check(j["dry"] and j["done"] and st["counts"]["done"] == 5 and st["counts"]["failed"] == 0, "journal : 5 namespaces simulés OK")
    check([c["namespace"] for c in calls] == ["base", "partial", "sec", "shop", "web"], "exécution séquentielle, ordre du plan")
    c_shop = [c for c in calls if c["namespace"] == "shop"][0]
    check(c_shop["from_backup_only"] and c_shop["dry"] and c_shop["items"] == [{"pvc": "data", "new_ref": ""}]
          and c_shop["backup_path"].endswith("2026-09-26_08-00-00_000001") and c_shop["clone_refs"],
          "chaque namespace : récupération « depuis la sauvegarde seule », UUID d'origine déduits (new_ref vide)")
    c_web = [c for c in calls if c["namespace"] == "web"][0]
    check(c_web["items"] == [], "stateless : aucun volume transmis")
    check(j["items"][0]["run_warnings"] == ["w1"] and j["items"][0]["log"][0]["label"].startswith("Namespace cible"),
          "avertissements et étapes journalisés par namespace")
    check(os.path.isfile(os.path.join(croot, H.BULK_FILE)), "journal persistant écrit dans le dossier du cluster")
    check(any(json.loads(l)["event"] == "bulk_restore" for l in open(os.path.join(tmp, "audit.log"))), "run audité")

    print("\n== Réel : simulation du même plan exigée ==")
    r = H.action_bulk_run({"as_of": "2026-09-26T11:00", "dry": False})
    check(not r["ok"] and "SIMULATION" in r["error"], "autre instant de référence : réel refusé")
    r = H.action_bulk_run({"as_of": "2026-09-26T10:00", "exclude": ["web"], "dry": False})
    check(not r["ok"] and "SIMULATION" in r["error"], "autre liste de namespaces : réel refusé")
    calls.clear()
    r = H.action_bulk_run({"as_of": "2026-09-26T10:00", "dry": False})
    check(r["ok"] and not r["dry"] and wait_done() and all(not c["dry"] for c in calls) and len(calls) == 5,
          "même plan simulé : réel accepté, 5 récupérations réelles")

    print("\n== Arrêt propre et reprise idempotente ==")
    calls.clear()
    gate["stop_after"] = "partial"
    gate["fail"] = {"sec"}
    # nouveau plan simulé (l'ancien journal réel ne bloque pas une simulation)
    r = H.action_bulk_run({"as_of": "2026-09-26T10:00", "dry": True})
    check(r["ok"] and wait_done(), "simulation relancée")
    st = H.action_bulk_status(); j = st["journal"]
    sts = {it["ns"]: it["status"] for it in j["items"]}
    check(j["stopped"] and not j["done"] and sts == {"base": "done", "partial": "done", "sec": "stopped", "shop": "stopped", "web": "stopped"},
          "arrêt demandé pendant « partial » : namespace en cours terminé, suivants « stopped »")
    r = H.action_bulk_run({"resume": True, "dry": True})
    calls.clear(); gate["stop_after"] = None
    r = H.action_bulk_run({"resume": True, "dry": True}) if not H.BULK["running"] and not r["ok"] else r
    wait_done()
    st = H.action_bulk_status(); j = st["journal"]
    sts = {it["ns"]: it["status"] for it in j["items"]}
    check(set(c["namespace"] for c in calls) <= {"sec", "shop", "web"} and sts["base"] == "done" and sts["partial"] == "done"
          and sts["sec"] == "failed" and sts["shop"] == "done" and sts["web"] == "done",
          "reprise : seuls les restants sont rejoués (base/partial jamais refaits), échec de « sec » isolé")
    check(j["done"] and st["counts"]["failed"] == 1, "journal terminé avec 1 échec")
    r = H.action_bulk_run({"as_of": "2026-09-26T10:00", "dry": False})
    check(not r["ok"] and "SIMULATION" in r["error"], "simulation avec un échec : réel refusé")
    gate["fail"] = set(); calls.clear()
    r = H.action_bulk_run({"resume": True, "dry": True}); wait_done()
    check([c["namespace"] for c in calls] == ["sec"] and H.action_bulk_status()["counts"]["failed"] == 0, "reprise : seul l'échec est rejoué")
    r = H.action_bulk_run({"resume": True, "dry": True})
    check(not r["ok"] and "Rien à reprendre" in r["error"], "tout est recréé : rien à reprendre")

    print("\n== Garde-fous ==")
    H.BULK["running"] = True
    r = H.action_bulk_run({"dry": True})
    check(not r["ok"] and "déjà en cours" in r["error"], "un seul run à la fois")
    check(H._auto_backup_run(now=time.time(), runner=lambda dest: {"ok": True}) is None, "sauvegarde automatique suspendue pendant un run")
    H.BULK["running"] = False
    r = H.action_bulk_stop()
    check(not r["ok"], "arrêt sans run : refus")
    H.kubectl_json = lambda args: ({"items": [{"metadata": {"name": n}} for n in ("shop", "base", "web", "sec", "partial", "alive")]}, None) \
        if args[:2] == ["get", "ns"] else ({"items": []}, None)
    r = H.action_bulk_run({"as_of": "2026-09-26T10:00", "dry": True})
    check(not r["ok"] and "Rien à restaurer" in r["error"], "tous présents : rien à restaurer")
finally:
    H.kubectl_json, H.action_context, H.action_clone_app, H._vault_env_passphrase, H._VAULT_PW = s_kj, s_ctx, s_clone, s_env, s_pw
    H.BULK.update(running=False, stop=False)
    H._CATALOGS.clear(); H._apps_cache_clear()
    H.CONFIG.clear(); H.CONFIG.update(saved)
    shutil.rmtree(tmp, ignore_errors=True)

print("\nRÉSULTAT : %d OK, %d FAIL" % (passed, failed))
raise SystemExit(1 if failed else 0)
