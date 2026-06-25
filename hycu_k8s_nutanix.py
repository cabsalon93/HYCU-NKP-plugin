#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  Protection des applications Kubernetes sur Nutanix avec HYCU
  Outil web guidé — sauvegarde / restauration / vérification
  Version 2 — durcie, transactionnelle et adaptable multi-clients
================================================================================

OBJECTIF
  Remplacer la procédure manuelle (une vingtaine de commandes kubectl + édition
  de YAML à la main) par une interface web où l'opérateur ne fait que cliquer.
  Au moment de la restauration, la seule saisie demandée est la RÉFÉRENCE du
  Volume Group cloné/restauré : son UUID (CSI Nutanix moderne / NKP, où le VG est
  attaché directement à la VM worker — plus d'IQN), un volumeHandle, ou un IQN
  (clusters iSCSI hérités). Récupérable en un clic via Prism/HYCU. L'outil en
  dérive le volumeHandle, régénère le manifeste du PV, et enchaîne la séquence
  scale-down -> delete -> patch finalizer -> apply -> scale-up, puis vérifie.

ADAPTABILITÉ (multi-clients)
  Rien n'est codé en dur pour un environnement Nutanix précis :
    - le préfixe du volumeHandle (ex. « NutanixVolumes- ») est AUTO-DÉTECTÉ
      depuis le PV existant, donc l'outil suit le driver CSI du client ;
    - l'UUID du VG (et un IQN résiduel éventuel) est édité STRUCTURELLEMENT dans
      le manifeste, où qu'il se trouve (pas de remplacement aveugle du JSON) ;
    - les conventions (suffixe de nom de clone), les timeouts, la liste des
      contextes/namespaces autorisés sont CONFIGURABLES (onglet « Réglages »
      ou fichier hycu_config.json) ;
    - aucune dépendance externe : un seul fichier Python (stdlib), facile à
      déposer et lancer chez n'importe quel client.

PRÉREQUIS
  - Python 3.7 ou plus (aucune librairie externe à installer).
  - kubectl installé et configuré sur le contexte du bon cluster.
    L'outil utilise le contexte courant : vérifiez-le dans l'en-tête de la page.

LANCEMENT
  python3 hycu_k8s_nutanix.py
  puis ouvrir http://127.0.0.1:8765 (s'ouvre tout seul si possible)

SÉCURITÉ
  - Le serveur n'écoute que sur 127.0.0.1 (jamais exposé sur le réseau).
  - Protection anti-CSRF / anti-DNS-rebinding : vérification des en-têtes Host
    et Origin, et jeton anti-CSRF exigé sur toute action (POST).
  - Le mode « Simulation » (dry-run) est ACTIVÉ par défaut : aucune commande
    destructive n'est exécutée, l'outil montre seulement ce qu'il ferait.
  - Toute étape destructive (delete, patch finalizer) exige une confirmation,
    ainsi qu'une confirmation du contexte kubectl ciblé.
  - Les actions réelles sont JOURNALISÉES (audit.log) horodatées.
  - TESTEZ D'ABORD sur un namespace de test avant la production.

NOTE TECHNIQUE
  Les manifestes sont manipulés en JSON (kubectl applique du JSON aussi bien que
  du YAML), ce qui évite toute dépendance à un parseur YAML.
================================================================================
"""

import http.server
import socketserver
import json
import subprocess
import os
import re
import contextlib
import ssl
import hmac
import hashlib
import base64
import io
import zipfile
import secrets
import datetime
import threading
import time
import webbrowser
import urllib.parse
import urllib.request
import urllib.error

# ------------------------------------------------------------------------------
# Configuration (adaptable par client) — chargée depuis hycu_config.json si présent
# ------------------------------------------------------------------------------
CONFIG_PATH = os.path.join(os.getcwd(), "hycu_config.json")
# Coffre d'identifiants chiffré (optionnel), protégé par une phrase secrète maîtresse.
SECRETS_PATH = os.path.join(os.getcwd(), "hycu_secrets.enc")

DEFAULT_CONFIG = {
    "host": "127.0.0.1",            # jamais exposé hors machine locale
    "port": 8765,
    "kubectl_path": "kubectl",      # chemin/binaire kubectl (ex. "microk8s kubectl")
    "kube_context": "",             # contexte ciblé (vide = contexte courant du kubeconfig)
    "kubeconfig_path": "",          # fichier kubeconfig (vide = résolution par défaut)
    "backup_root": os.path.join(os.getcwd(), "hycu-backups"),
    "allowed_contexts": [],         # [] = tout contexte (mais confirmation demandée)
    "namespace_filter": [],         # [] = tous les namespaces ; sinon liste blanche
    "wait_timeout": 120,            # secondes : attente max d'une suppression / Bound
    "subprocess_margin": 30,        # marge subprocess au-dessus de kubectl wait
    "clone_name_suffix": "0000",    # convention HYCU pour le nom du PV cloné
    "volume_handle_prefix": "",     # "" = auto-détection depuis le PV existant
    "strip_claimref": False,        # True = retirer claimRef (laisse le PVC rebinder)
    # CSI Nutanix (NKP) : `volumeAttributes.hypervisorAttachedDiskUUIDs` = extId du
    # DISQUE du VG ; c'est lui qui fait choisir au CSI l'attach par hyperviseur (qui
    # marche) plutôt que l'attach iSCSI externe (qui échoue ici). Sur le PV reconstruit,
    # cette valeur pointe le disque SOURCE -> on la RETIRE (True), puis on la RÉÉCRIT
    # avec le disque du VG cloné (clone_fix_disk_uuids).
    "clone_strip_runtime_attrs": True,
    # Réécrit `hypervisorAttachedDiskUUIDs` avec l'extId du disque du VG cloné, lu via
    # l'API Prism Central v4 (la même que le CSI). SANS ça, le CSI bascule sur l'attach
    # iSCSI externe et l'attachement échoue (pods bloqués). Nécessite Prism Central.
    "clone_fix_disk_uuids": True,
    # En clone RÉEL, si le disque du VG cloné est introuvable (Prism Central absent /
    # VG vide), ABANDONNER avant de recréer le PV plutôt que livrer un PV qui ne
    # s'attachera pas. True = sécurité (recommandé).
    "clone_require_disk_uuids": True,
    # Sauvegarde de sécurité des manifestes PV/PVC du namespace AVANT toute restauration
    # réelle (le seul filet en cas d'échec d'apply). True = sauvegarder d'abord, abandonner
    # si la sauvegarde échoue.
    "backup_before_restore": True,
    # Restore in-place HYCU : HYCU remplace le DISQUE du VG (nouvel extId) -> le
    # hypervisorAttachedDiskUUIDs du PV devient périmé et le montage échoue
    # ("failed to get symlink for disk ..."). True = après le restore, recréer le PV
    # (volumeAttributes immuable) avec le disque à jour. Nécessite Prism Central.
    "inplace_refresh_pv_disk": True,
    # Avant de supprimer l'ANCIEN PV pendant un restore-clone, le passer en Retain :
    # avec reclaimPolicy=Delete (défaut Nutanix), supprimer le PV/PVC déclenche la
    # SUPPRESSION du Volume Group Nutanix source par le CSI (perte de données / casse
    # la chaîne de sauvegarde HYCU). True = protéger le VG source (fortement conseillé).
    "retain_source_pv": True,
    "require_context_confirm": True,  # exiger la confirmation du contexte avant action réelle
    "open_browser": True,
    "logo_path": "",                  # chemin explicite d'un logo (sinon hycu_logo.* à côté du programme)
    "remember_credentials": False,    # True = un coffre chiffré hycu_secrets.enc existe
    "pbkdf2_iterations": 200000,      # itérations PBKDF2 pour la phrase secrète
    # ---- Connecteurs HYCU / Nutanix (endpoints NON secrets ; identifiants en RAM) ----
    "hycu_url": "",                       # ex. https://hycu.exemple.com:8443
    "hycu_api_base": "/rest/v1.0",        # base REST HYCU (port 8443 ; v5.2 vérifié)
    "hycu_test_path": "/volumegroups",    # endpoint GET de test (vérifié sur 5.2)
    "hycu_verify_tls": False,             # appliances souvent en certificat auto-signé
    "nutanix_url": "",                    # ex. https://prism-element.exemple.com:9440
    "nutanix_api_base": "/PrismGateway/services/rest/v2.0",  # Prism Element v2
    "nutanix_verify_tls": False,
    "prismcentral_url": "",               # ex. https://prism-central.exemple.com:9440
    "prismcentral_api_base": "/api/nutanix/v3",  # Prism Central API v3
    "prismcentral_verify_tls": False,
}

CONFIG = dict(DEFAULT_CONFIG)


def _apply_env_overrides():
    """Surcharges par variables d'environnement (mode conteneur / 12-factor).
    Priorité : env > hycu_config.json > défauts. Permet une IMAGE mode-agnostique
    sans modifier le code ni le fichier de config (ex. HYCU_HOST=0.0.0.0,
    HYCU_OPEN_BROWSER=0, HYCU_BACKUP_ROOT=/data/hycu-backups). En mode « python »
    direct, aucune de ces variables n'est posée -> comportement par défaut inchangé."""
    def _b(v):
        return str(v).strip().lower() in ("1", "true", "yes", "on")
    mapping = {
        "HYCU_HOST": ("host", str),
        "HYCU_PORT": ("port", int),
        "HYCU_OPEN_BROWSER": ("open_browser", _b),
        "HYCU_BACKUP_ROOT": ("backup_root", str),
        "HYCU_KUBECTL_PATH": ("kubectl_path", str),
    }
    for env, (key, conv) in mapping.items():
        val = os.environ.get(env)
        if val is None or val == "":
            continue
        try:
            CONFIG[key] = conv(val)
        except (ValueError, TypeError):
            print("Variable d'env %s ignorée (valeur invalide : %r)." % (env, val))


def load_config():
    """Charge hycu_config.json par-dessus les valeurs par défaut (clés inconnues ignorées),
    puis applique les surcharges d'environnement (mode conteneur)."""
    global CONFIG
    CONFIG = dict(DEFAULT_CONFIG)
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, encoding="utf-8") as f:
                user = json.load(f)
            for k, v in (user or {}).items():
                if k in DEFAULT_CONFIG:
                    CONFIG[k] = v
        except Exception as e:  # config illisible : on garde les défauts
            print("Configuration illisible (%s) : valeurs par défaut utilisées." % e)
    _apply_env_overrides()
    return CONFIG


def save_config(updates):
    """Met à jour et persiste la configuration (uniquement les clés connues)."""
    global CONFIG
    for k, v in (updates or {}).items():
        if k in DEFAULT_CONFIG:
            CONFIG[k] = v
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(CONFIG, f, indent=2, ensure_ascii=False)
        return True, None
    except Exception as e:
        return False, str(e)


# Version horodatée de la build (format AAAAMMJJ-HHMM). À incrémenter à chaque
# changement notable du programme ; affichée dans l'en-tête de l'interface.
VERSION = "20260625-1730"

# Jeton anti-CSRF généré au démarrage, injecté dans la page et exigé sur les POST.
CSRF_TOKEN = secrets.token_urlsafe(32)

# Identifiants HYCU/Nutanix gardés UNIQUEMENT en mémoire, le temps de la session
# du serveur. Jamais écrits sur disque. Effacés à l'arrêt et sur déconnexion.
SESSION_CREDS = {"hycu": None, "nutanix": None, "prismcentral": None}   # creds en RAM par système
CRED_LOCK = threading.Lock()

# Hôtes considérés comme locaux (anti-DNS-rebinding). ::1 = IPv6 loopback.
ALLOWED_HOSTS = ("127.0.0.1", "localhost", "::1")


def _host_is_local(hostport):
    """Extrait le nom d'hôte d'un en-tête Host (gère « host:port » et « [::1]:port »)
    et vérifie qu'il désigne la boucle locale."""
    if not hostport:
        return False
    h = hostport.strip()
    if h.startswith("["):                      # [::1] ou [::1]:port
        end = h.find("]")
        h = h[1:end] if end != -1 else h[1:]
    elif h.count(":") == 1:                     # host:port (IPv4 / nom)
        h = h.rsplit(":", 1)[0]
    return h in ALLOWED_HOSTS

# Sérialise les opérations destructives : un seul restore/backup à la fois.
ACTION_LOCK = threading.Lock()

# UUID standard 8-4-4-4-12, utilisé pour extraire l'UUID d'un IQN.
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
# Repère une chaîne IQN dans un manifeste (RFC iqn.AAAA-MM.domaine:cible).
IQN_RE = re.compile(r"iqn\.[0-9]{4}-[0-9]{2}\.[A-Za-z0-9._\-:]+")
# Nom de ressource Kubernetes valide (RFC 1123, sous-domaine).
K8S_NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$")


# ------------------------------------------------------------------------------
# Journal d'audit (append-only) des actions réelles
# ------------------------------------------------------------------------------
def audit(event, **fields):
    """Écrit une ligne JSON horodatée dans backup_root/audit.log."""
    try:
        os.makedirs(CONFIG["backup_root"], exist_ok=True)
        rec = {"ts": datetime.datetime.now().isoformat(), "event": event}
        rec.update(fields)
        with open(os.path.join(CONFIG["backup_root"], "audit.log"), "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        # L'audit ne doit jamais casser l'action ; mais en conteneur (volume non
        # inscriptible), un échec silencieux masquerait l'absence de trace -> on
        # journalise au moins sur stderr (capté par `docker logs` / K8s).
        try:
            import sys
            print("AUDIT non écrit (%s) : %s" % (e, json.dumps(
                {"event": event, **fields}, ensure_ascii=False)), file=sys.stderr)
        except Exception:
            pass


# ------------------------------------------------------------------------------
# Réponses & journal — fabriques homogènes (schéma garanti, consommé par le JS)
# ------------------------------------------------------------------------------
def _ok(**data):
    """Réponse de succès standard : {"ok": True, "error": None, ...données}."""
    return {"ok": True, "error": None, **data}


def _err(message, **extra):
    """Réponse d'échec standard : {"ok": False, "error": message, ...extra}."""
    return {"ok": False, "error": message, **extra}


def logentry(label, ok=True, dry=False, cmd="", stdout="", stderr="", rc=0, **extra):
    """Une entrée de log d'étape, au schéma stable attendu par le rendu JS
    (ok/dry/label/cmd/stdout/stderr/rc + clés éventuelles : planned, job_id…)."""
    return {"ok": ok, "dry": dry, "label": label, "cmd": cmd,
            "stdout": stdout, "stderr": stderr, "rc": rc, **extra}


class _Busy(Exception):
    """Levée quand une action destructive est déjà en cours (ACTION_LOCK pris)."""


@contextlib.contextmanager
def action_lock(skip=False):
    """Sérialise les actions destructives. `skip=True` (ex. dry-run) n'acquiert rien.
    Lève _Busy si le verrou est déjà pris. Libère toujours en sortie."""
    got = bool(skip) or ACTION_LOCK.acquire(blocking=False)
    if not got:
        raise _Busy("Une autre opération est déjà en cours. Réessayez.")
    try:
        yield
    finally:
        if not skip:
            ACTION_LOCK.release()


# ------------------------------------------------------------------------------
# Opérations longues asynchrones (progression live) — exécutées en thread, suivies
# par /api/op_status. Le `log` partagé grossit pendant l'exécution ; le client poll.
# ------------------------------------------------------------------------------
OPERATIONS = {}                 # op_id -> {"log": [...], "done": bool, "result": dict|None}
OP_LOCK = threading.Lock()


def _run_async(fn, payload):
    """Lance `fn(payload, log=<liste partagée>)` dans un thread démon et renvoie un
    op_id immédiatement. Le client interroge /api/op_status pour la progression."""
    op_id = secrets.token_hex(8)
    shared = []
    with OP_LOCK:
        # purge : ne garder qu'un historique borné d'opérations terminées
        done_ids = [k for k, v in OPERATIONS.items() if v["done"]]
        for k in done_ids[:-20]:
            OPERATIONS.pop(k, None)
        OPERATIONS[op_id] = {"log": shared, "done": False, "result": None}

    def worker():
        try:
            res = fn(payload, log=shared)
        except Exception as e:  # filet : ne jamais laisser un thread mourir sans verdict
            res = {"ok": False, "error": "Erreur interne : %s" % e, "log": shared}
        with OP_LOCK:
            OPERATIONS[op_id]["result"] = res
            OPERATIONS[op_id]["done"] = True

    threading.Thread(target=worker, daemon=True).start()
    return {"ok": True, "op_id": op_id}


def action_op_status(op_id):
    """État courant d'une opération longue : log partiel + (si terminée) résultat.
    `list(op["log"])` est atomique sous le GIL (pas de course avec les append)."""
    with OP_LOCK:
        op = OPERATIONS.get(op_id)
    if not op:
        return {"ok": False, "error": "Opération inconnue ou expirée."}
    return {"ok": True, "done": op["done"], "log": list(op["log"]),
            "result": op["result"] if op["done"] else None}


# ------------------------------------------------------------------------------
# Exécution de commandes
# ------------------------------------------------------------------------------
def run(cmd, dry=False, label=None, timeout=None):
    """Exécute une commande (liste d'arguments). Renvoie un dict de résultat.
    Si dry=True, ne lance rien et renvoie la commande qui aurait été exécutée.
    Le timeout subprocess est volontairement supérieur au timeout 'kubectl wait'
    pour ne pas tuer la commande avant son propre verdict."""
    pretty = " ".join(cmd)
    if dry:
        return {"ok": True, "dry": True, "cmd": pretty, "stdout": "", "stderr": "",
                "rc": None, "label": label or pretty}
    if timeout is None:
        timeout = CONFIG["wait_timeout"] + CONFIG["subprocess_margin"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"ok": p.returncode == 0, "dry": False, "cmd": pretty,
                "stdout": (p.stdout or "").strip(), "stderr": (p.stderr or "").strip(),
                "rc": p.returncode, "label": label or pretty}
    except FileNotFoundError:
        return {"ok": False, "dry": False, "cmd": pretty, "stdout": "", "rc": -1,
                "stderr": "Commande introuvable : '%s' est-il installé et dans le PATH ?" % cmd[0],
                "label": label or pretty}
    except subprocess.TimeoutExpired:
        return {"ok": False, "dry": False, "cmd": pretty, "stdout": "", "rc": -1,
                "stderr": "Délai dépassé (%ss)." % timeout, "label": label or pretty}
    except Exception as e:  # pragma: no cover
        return {"ok": False, "dry": False, "cmd": pretty, "stdout": "", "rc": -1,
                "stderr": str(e), "label": label or pretty}


def _kubectl_base():
    """Binaire kubectl (« kubectl », « microk8s kubectl »…) + ciblage explicite du
    cluster : --kubeconfig et --context sont ajoutés à TOUTES les commandes si
    configurés, pour viser le bon cluster sans dépendre du contexte courant."""
    base = CONFIG["kubectl_path"].split()
    kc = (CONFIG.get("kubeconfig_path") or "").strip()
    if kc:
        base += ["--kubeconfig", kc]
    ctx = (CONFIG.get("kube_context") or "").strip()
    if ctx:
        base += ["--context", ctx]
    return base


def kubectl(args, dry=False, label=None, timeout=None):
    return run(_kubectl_base() + args, dry=dry, label=label, timeout=timeout)


def kubectl_json(args):
    """Lance kubectl avec -o json (jamais en dry-run : lecture seule) et parse.
    Renvoie (data, erreur)."""
    r = run(_kubectl_base() + args + ["-o", "json"], dry=False)
    if not r["ok"]:
        return None, r["stderr"]
    try:
        return json.loads(r["stdout"]), None
    except json.JSONDecodeError as e:
        return None, "Réponse JSON illisible : %s" % e


def resource_state(kind, name, ns=None):
    """État fiable d'une ressource : 'present' | 'absent' | 'error'.
    Distingue 'absent' d'une 'erreur' (corrige le cas où get échoue pour une
    raison réseau et où l'on conclurait à tort à une suppression)."""
    args = ["get", kind, name, "--ignore-not-found", "-o", "name"]
    if ns:
        args += ["-n", ns]
    r = run(_kubectl_base() + args, dry=False)
    if not r["ok"]:
        # Avec --ignore-not-found, un objet réellement absent sort en rc=0 (stdout
        # vide). Donc un échec ici est une VRAIE erreur (RBAC, réseau, contexte,
        # namespace inexistant) et ne doit jamais être interprété comme 'absent'.
        return "error", r["stderr"]
    return ("present" if r["stdout"].strip() else "absent"), ""


# ------------------------------------------------------------------------------
# Nettoyage des manifestes (équivalent automatisé des étapes 3 du document)
# ------------------------------------------------------------------------------
def _strip_meta(meta):
    for k in ("uid", "resourceVersion", "creationTimestamp", "generation",
              "managedFields", "selfLink"):
        meta.pop(k, None)
    ann = meta.get("annotations")
    if isinstance(ann, dict):
        for k in ("kubectl.kubernetes.io/last-applied-configuration",
                  "pv.kubernetes.io/bind-completed",
                  "pv.kubernetes.io/bound-by-controller",
                  "volume.kubernetes.io/selected-node"):
            ann.pop(k, None)
        if not ann:
            meta.pop("annotations", None)
    return meta


def clean_pv(pv):
    """Nettoie un PersistentVolume : ne garde que ce qui est nécessaire à réappliquer."""
    pv.pop("status", None)
    meta = pv.get("metadata", {})
    _strip_meta(meta)
    meta.pop("finalizers", None)
    spec = pv.get("spec", {})
    cr = spec.get("claimRef")
    if isinstance(cr, dict):
        if CONFIG.get("strip_claimref"):
            # Option : retirer claimRef et laisser le PVC recréé rebinder.
            spec.pop("claimRef", None)
        else:
            # On garde claimRef (name+namespace) pour pré-binder le bon PVC,
            # mais on retire uid/resourceVersion (sinon PV bloqué en Released).
            cr.pop("uid", None)
            cr.pop("resourceVersion", None)
    return pv


def clean_pvc(pvc):
    """Nettoie un PersistentVolumeClaim."""
    pvc.pop("status", None)
    meta = pvc.get("metadata", {})
    _strip_meta(meta)
    meta.pop("finalizers", None)
    return pvc


# ------------------------------------------------------------------------------
# Cœur métier : reconnexion d'un VG restauré/cloné (étapes 7 du document)
# ------------------------------------------------------------------------------
def split_volume_handle(vh):
    """Sépare un volumeHandle en (préfixe, uuid). Le préfixe est tout ce qui
    précède l'UUID — ce qui rend l'outil indépendant du driver CSI."""
    m = UUID_RE.search(vh or "")
    if not m:
        return (vh or "", None)
    return (vh[:m.start()], m.group(0))


def derive_volume_handle(new_ref, old_volume_handle=None):
    """À partir d'une RÉFÉRENCE du VG cloné/restauré, renvoie le volumeHandle.
    `new_ref` peut être :
      - l'UUID nu du VG (cas NKP moderne : VG attaché à la VM, pas d'IQN) ;
      - un volumeHandle complet 'NutanixVolumes-<uuid>' ;
      - un IQN (clusters iSCSI hérités : 'iqn.…:cible-<uuid>-…-tgt0').
    Dans tous les cas, on extrait l'UUID 8-4-4-4-12 (le bloc horodaté éventuel
    d'un IQN est ignoré). Le PRÉFIXE est repris du PV existant (auto-détection
    multi-clients), sinon de la config, sinon 'NutanixVolumes-' par défaut."""
    m = UUID_RE.search(new_ref or "")
    if not m:
        return None
    new_uuid = m.group(0)
    prefix, _ = split_volume_handle(old_volume_handle or "")
    if not prefix:
        prefix = CONFIG.get("volume_handle_prefix") or "NutanixVolumes-"
    return prefix + new_uuid


def analyse_pv(pv_dict):
    """Repère, dans un PV, l'IQN, le volumeHandle et le préfixe de handle actuels
    (recherche textuelle, robuste aux variations de schéma du driver CSI)."""
    text = json.dumps(pv_dict)
    iqn = IQN_RE.search(text)
    vh = None
    csi = (pv_dict.get("spec") or {}).get("csi")
    if isinstance(csi, dict) and isinstance(csi.get("volumeHandle"), str):
        vh = csi["volumeHandle"]
    if vh is None:
        # Repli pour PV iSCSI hérité (sans spec.csi.volumeHandle) : l'IDENTITÉ du VG est
        # l'UUID porté par l'IQN (« iqn.…:…ntnx-k8s-<uuid-du-VG>… »). On la prend de
        # l'IQN — JAMAIS du repli textuel générique, qui matcherait d'abord le NOM du PV
        # « pvc-<uuid-du-PVC> » (metadata sérialisée avant spec) et figerait le mauvais
        # UUID, laissant le nouveau PV pointer vers le VG SOURCE.
        iqn_uuid = UUID_RE.search(iqn.group(0)) if iqn else None
        if iqn_uuid:
            prefix = CONFIG.get("volume_handle_prefix") or "NutanixVolumes-"
            vh = prefix + iqn_uuid.group(0)
        else:
            m = re.search(r"[A-Za-z0-9_]+-" + UUID_RE.pattern, text)
            vh = m.group(0) if m else None
    prefix, _ = split_volume_handle(vh or "")
    return {
        "name": (pv_dict.get("metadata") or {}).get("name"),
        "old_iqn": iqn.group(0) if iqn else None,
        "old_volume_handle": vh,
        "handle_prefix": prefix,
    }


def _replace_in_leaves(node, pairs, exact_pairs=None):
    """Édition structurelle : on n'opère que sur des feuilles chaîne du manifeste.
    - 'pairs'       : remplacement de sous-chaîne (old -> new) — pour IQN/handle ;
    - 'exact_pairs' : remplacement uniquement si la feuille EST EXACTEMENT 'old'
                      (-> new) — pour un UUID 'nu' (clé volumeID/uuid d'un
                      volumeAttributes). On n'utilise jamais le sous-chaîne pour un
                      UUID : 36 caractères pourraient corrompre l'IQN/volumeHandle.
    Aucun risque de fusionner du texte hors champ (corrige le remplacement aveugle)."""
    exact_pairs = exact_pairs or []
    if isinstance(node, dict):
        return {k: _replace_in_leaves(v, pairs, exact_pairs) for k, v in node.items()}
    if isinstance(node, list):
        return [_replace_in_leaves(v, pairs, exact_pairs) for v in node]
    if isinstance(node, str):
        for old, new in exact_pairs:
            if old and new and node == old:
                return new
        s = node
        for old, new in pairs:
            if old and new and old in s:
                s = s.replace(old, new)
        return s
    return node


def build_new_pv(old_pv, new_ref, new_name, mode):
    """Construit le nouveau manifeste de PV à appliquer pour pointer le VG cloné/restauré.
    `new_ref` = référence du nouveau VG : UUID nu (NKP moderne), volumeHandle, ou IQN (legacy).
    - volumeHandle réécrit explicitement dans spec.csi (source de vérité) ;
    - l'UUID du VG est remplacé dans TOUTES les feuilles (couvre volumeHandle,
      préfixe de cible iSCSI, IQN résiduel, attribut UUID 'nu') ; un IQN complet
      fourni en legacy est en plus échangé en entier ;
    - les attributs RUNTIME du VG source (disque attaché, identité du provisioner)
      sont purgés en clone pour que le driver les repeuple à l'attachement ;
    - nom mis à jour en mode clone.
    mode = 'clone' (nom change) ou 'inplace' (nom inchangé)."""
    info = analyse_pv(old_pv)
    new_vh = derive_volume_handle(new_ref, info["old_volume_handle"])
    if not new_vh:
        return None, ("Référence de volume invalide : impossible d'en extraire l'UUID du Volume Group. "
                      "Collez l'UUID du VG (8-4-4-4-12), un volumeHandle « NutanixVolumes-<uuid> », "
                      "ou (clusters iSCSI hérités) l'IQN complet du VG cloné.")

    new_pv = json.loads(json.dumps(old_pv))  # copie profonde
    replacements = []

    # 1) volumeHandle : réécriture structurelle dans spec.csi (emplacement officiel).
    csi = (new_pv.get("spec") or {}).get("csi")
    if isinstance(csi, dict) and isinstance(csi.get("volumeHandle"), str):
        if csi["volumeHandle"] != new_vh:
            replacements.append(("volumeHandle", csi["volumeHandle"], new_vh))
            csi["volumeHandle"] = new_vh

    # 2) Remplacements de sous-chaîne dans toutes les feuilles.
    #    L'UUID du VG est l'identité unique du volume : le remplacer partout met à
    #    jour le volumeHandle (idempotent), le préfixe de cible iSCSI « ntnx-k8s-<uuid> »,
    #    un IQN résiduel « …-<uuid>-… » et tout attribut « nu » égal à l'UUID source.
    #    Un UUID 8-4-4-4-12 est assez spécifique pour un remplacement de sous-chaîne sûr.
    pairs = []
    new_iqn = new_ref.strip() if (new_ref and IQN_RE.fullmatch(new_ref.strip())) else None
    if info["old_iqn"] and new_iqn and info["old_iqn"] != new_iqn:
        pairs.append((info["old_iqn"], new_iqn))      # legacy : échange d'IQN complet
        replacements.append(("IQN", info["old_iqn"], new_iqn))
    if info["old_volume_handle"] and info["old_volume_handle"] != new_vh:
        pairs.append((info["old_volume_handle"], new_vh))

    old_uuid = split_volume_handle(info["old_volume_handle"] or "")[1]
    new_uuid = split_volume_handle(new_vh)[1]
    if old_uuid and new_uuid and old_uuid != new_uuid:
        pairs.append((old_uuid, new_uuid))
        replacements.append(("UUID du VG", old_uuid, new_uuid))

    if pairs:
        new_pv = _replace_in_leaves(new_pv, pairs)

    # 2b) Retirer le hypervisorAttachedDiskUUIDs SOURCE (clone uniquement).
    #     = extId du disque du VG SOURCE (≠ UUID du VG, non couvert par 2). Le garder
    #     ferait pointer le PV cloné vers le DISQUE SOURCE. On le retire ici ; il est
    #     ensuite RÉÉCRIT avec le disque du VG cloné (_set_clone_disk_uuids, via Nutanix).
    #     csiProvisionerIdentity est CONSERVÉ (présent sur le PV source qui s'attache OK).
    stripped = []
    if mode == "clone" and CONFIG.get("clone_strip_runtime_attrs", True):
        # NB : _replace_in_leaves a reconstruit new_pv -> re-cibler le csi COURANT.
        csi_now = (new_pv.get("spec") or {}).get("csi")
        va = csi_now.get("volumeAttributes") if isinstance(csi_now, dict) else None
        if isinstance(va, dict) and "hypervisorAttachedDiskUUIDs" in va:
            va.pop("hypervisorAttachedDiskUUIDs", None)
            stripped.append("hypervisorAttachedDiskUUIDs")

    # 3) Nom du PV (mode clone uniquement).
    old_name = (new_pv.get("metadata") or {}).get("name")
    if mode == "clone" and new_name and new_name != old_name:
        if not K8S_NAME_RE.match(new_name):
            return None, "Nom de PV invalide : '%s' (RFC 1123 attendu)." % new_name
        new_pv.setdefault("metadata", {})["name"] = new_name
        replacements.append(("nom du PV", old_name, new_name))
    else:
        new_name = old_name  # inplace : on garde le nom

    same_uuid = bool(old_uuid and new_uuid and old_uuid == new_uuid)
    # Garde anti-confusion : le NOM du VG côté Nutanix est « pvc-<uuid-du-PVC> » — un
    # UUID DIFFÉRENT de l'UUID du VG. Si la réf saisie correspond à l'UUID du nom du PV,
    # l'utilisateur a probablement collé le NOM du VG au lieu de son UUID.
    # NB : on lit le nom ORIGINAL (old_pv), pas new_pv déjà passé par _replace_in_leaves,
    # sinon un nom réécrit fausserait le diagnostic.
    orig_pv_name = (old_pv.get("metadata") or {}).get("name")
    pvc_uuid = split_volume_handle(orig_pv_name or "")[1]
    looks_like_vg_name = bool(new_uuid and pvc_uuid and new_uuid == pvc_uuid)
    return {"manifest": new_pv, "new_name": new_name, "new_volume_handle": new_vh,
            "old_volume_handle": info["old_volume_handle"], "old_iqn": info["old_iqn"],
            "replacements": replacements, "no_change": not replacements,
            "stripped": stripped, "looks_like_vg_name": looks_like_vg_name,
            "same_uuid": same_uuid}, None


# ------------------------------------------------------------------------------
# Stockage des sauvegardes
# ------------------------------------------------------------------------------
def backup_dir(ns, root=None):
    ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f")  # microsec anti-collision
    d = os.path.join(root or CONFIG["backup_root"], ns, ts)
    os.makedirs(d, exist_ok=True)
    return d


def _resolve_backup_dest(dest):
    """Résout le dossier de destination choisi par l'utilisateur pour une sauvegarde.
    Vide -> dossier par défaut (backup_root). Sinon : chemin absolu (expanduser), créé
    si besoin. Renvoie (root, erreur). Note : c'est un outil localhost mono-opérateur,
    la destination est volontairement choisie par l'utilisateur sur SA machine."""
    dest = (dest or "").strip()
    if not dest:
        return CONFIG["backup_root"], None
    root = os.path.abspath(os.path.expanduser(dest))
    try:
        os.makedirs(root, exist_ok=True)
    except OSError as e:
        return None, "Dossier de destination inutilisable (%s) : %s" % (root, e)
    if not os.path.isdir(root):
        return None, "Le chemin de destination n'est pas un dossier : %s" % root
    return root, None


def _safe_backup_path(p, extra_root=None):
    """Valide qu'un backup_path fourni par l'UI reste sous backup_root — ou sous un
    dossier personnalisé EXPLICITEMENT choisi par l'utilisateur (extra_root). Défense en
    profondeur contre une lecture hors zone ; la zone personnalisée n'est ouverte que si
    l'utilisateur la désigne (outil localhost mono-opérateur)."""
    if not p:
        return None
    full = os.path.realpath(p)
    roots = [os.path.realpath(CONFIG["backup_root"])]
    extra = (extra_root or "").strip()
    if extra:
        er = os.path.realpath(os.path.expanduser(extra))
        if os.path.isdir(er):
            roots.append(er)
    for root in roots:
        if full == root or full.startswith(root + os.sep):
            return full
    return None


def list_backups(ns, root=None):
    """Liste les sauvegardes d'un namespace sous backup_root, ou sous un dossier
    personnalisé `root` (chemin contenant <namespace>/<horodatage>/index.json)."""
    root = os.path.expanduser(root.strip()) if (root and root.strip()) else CONFIG["backup_root"]
    base = os.path.join(root, ns)
    if not os.path.isdir(base):
        return []
    out = []
    for ts in sorted(os.listdir(base), reverse=True):
        idx = os.path.join(base, ts, "index.json")
        if os.path.isfile(idx):
            try:
                with open(idx, encoding="utf-8") as f:
                    out.append({"timestamp": ts, "path": os.path.join(base, ts),
                                "index": json.load(f)})
            except Exception:
                pass
    return out


# ------------------------------------------------------------------------------
# Actions exposées à l'interface
# ------------------------------------------------------------------------------
def _kubectl_hint(err):
    e = (err or "").lower()
    if "introuvable" in e or "not found" in e or "installé" in e or "no such file" in e:
        return "kubectl_missing"
    if "current-context" in e or "not set" in e:
        return "no_context"
    if "no configuration" in e or "kubeconfig" in e:
        return "no_kubeconfig"
    return "other"


def action_contexts(kubeconfig=None):
    """Liste les contextes disponibles dans le kubeconfig (ciblé ou par défaut)."""
    kc = (kubeconfig if kubeconfig is not None else (CONFIG.get("kubeconfig_path") or "")).strip()
    cmd = CONFIG["kubectl_path"].split()
    if kc:
        cmd += ["--kubeconfig", kc]
    cmd += ["config", "get-contexts", "-o", "name"]
    r = run(cmd)
    if not r["ok"]:
        return {"ok": False, "error": r["stderr"], "hint": _kubectl_hint(r["stderr"]), "contexts": []}
    ctxs = [l.strip() for l in r["stdout"].splitlines() if l.strip()]
    return {"ok": True, "contexts": ctxs, "selected": CONFIG.get("kube_context") or "",
            "kubeconfig_path": kc}


def action_context():
    allowed = CONFIG.get("allowed_contexts") or []
    selected = (CONFIG.get("kube_context") or "").strip()
    if selected:
        # Contexte choisi explicitement : on vérifie qu'il existe dans le kubeconfig.
        lst = action_contexts()
        if lst["ok"] and selected in lst["contexts"]:
            ctx, err, kubectl_ok, hint = selected, None, True, None
        elif lst["ok"]:
            ctx, err, kubectl_ok, hint = None, ("Contexte « %s » introuvable dans le kubeconfig." % selected), False, "no_context"
        else:
            ctx, err, kubectl_ok, hint = None, lst.get("error"), False, lst.get("hint")
    else:
        r = kubectl(["config", "current-context"])
        ctx = r["stdout"] if (r["ok"] and r["stdout"]) else None
        err = None if r["ok"] else r["stderr"]
        kubectl_ok = ctx is not None
        hint = None if kubectl_ok else _kubectl_hint(err)
    return {"context": ctx, "error": err,
            "allowed": allowed,
            "context_ok": (not allowed) or (ctx in allowed),
            "kubectl_ok": kubectl_ok, "kubectl_hint": hint,
            "selected_context": selected,
            "require_confirm": bool(CONFIG.get("require_context_confirm"))}


def _namespace_allowed(ns):
    flt = CONFIG.get("namespace_filter") or []
    return (not flt) or (ns in flt)


def action_namespaces():
    data, err = kubectl_json(["get", "ns"])
    if err:
        return {"ok": False, "namespaces": [], "error": err}
    names = sorted(i["metadata"]["name"] for i in data.get("items", []))
    flt = CONFIG.get("namespace_filter") or []
    if flt:
        names = [n for n in names if n in flt]
    return {"ok": True, "namespaces": names, "error": None}


def action_ns_filter():
    """Liste TOUTES les namespaces du cluster (non filtrées) + le filtre courant,
    pour l'éditeur de filtre."""
    data, err = kubectl_json(["get", "ns"])
    flt = CONFIG.get("namespace_filter") or []
    if err:
        return {"ok": False, "error": err, "all": [], "filter": flt}
    names = sorted(i["metadata"]["name"] for i in data.get("items", []))
    return {"ok": True, "all": names, "filter": flt, "error": None}


def action_set_ns_filter(payload):
    """Enregistre le filtre de namespaces. Liste vide = toutes (aucun filtre)."""
    flt = payload.get("filter")
    if not isinstance(flt, list):
        flt = []
    flt = sorted({str(x).strip() for x in flt if str(x).strip()})
    save_config({"namespace_filter": flt})
    audit("ns_filter_set", count=len(flt), filter=flt)
    return {"ok": True, "filter": flt}


def action_pvcs(ns):
    """Liste les PVC d'un namespace avec leur PV et leur état."""
    if not _namespace_allowed(ns):
        return {"ok": False, "pvcs": [], "error": "Namespace '%s' non autorisé par la configuration." % ns}
    data, err = kubectl_json(["get", "pvc", "-n", ns])
    if err:
        return {"ok": False, "pvcs": [], "error": err}
    pvcs = []
    for i in data.get("items", []):
        spec = i.get("spec", {})
        pvcs.append({
            "name": i["metadata"]["name"],
            "pv": spec.get("volumeName"),
            "phase": i.get("status", {}).get("phase"),
            "storage": spec.get("resources", {}).get("requests", {}).get("storage"),
            "storageClass": spec.get("storageClassName"),
        })
    return {"ok": True, "pvcs": pvcs, "error": None}


def action_backup(ns, dest=None):
    """Exporte + nettoie tous les PV/PVC du namespace (étapes 1-3 du document).
    `dest` (optionnel) = dossier de destination choisi par l'utilisateur (vide = défaut)."""
    if not _namespace_allowed(ns):
        return {"ok": False, "error": "Namespace '%s' non autorisé par la configuration." % ns}
    root, derr = _resolve_backup_dest(dest)
    if derr:
        return {"ok": False, "error": derr}
    pvc_data, err = kubectl_json(["get", "pvc", "-n", ns])
    if err:
        return {"ok": False, "error": err}
    items = pvc_data.get("items", [])
    if not items:
        return {"ok": False, "error": "Aucun PVC trouvé dans le namespace '%s'." % ns}

    d = backup_dir(ns, root)
    index = {"namespace": ns, "created": datetime.datetime.now().isoformat(),
             "context": action_context().get("context"), "volumes": []}
    files = []
    for pvc in items:
        name = pvc["metadata"]["name"]
        pv_name = pvc.get("spec", {}).get("volumeName")
        clean_c = clean_pvc(json.loads(json.dumps(pvc)))
        pvc_path = os.path.join(d, "pvc_%s.json" % name)
        with open(pvc_path, "w", encoding="utf-8") as f:
            json.dump(clean_c, f, indent=2)
        files.append(os.path.basename(pvc_path))
        entry = {"pvc": name, "pv": pv_name, "pvc_file": os.path.basename(pvc_path)}
        if pv_name:
            pv_data, perr = kubectl_json(["get", "pv", pv_name])
            if pv_data and not perr:
                clean_v = clean_pv(json.loads(json.dumps(pv_data)))
                pv_path = os.path.join(d, "pv_%s.json" % pv_name)
                with open(pv_path, "w", encoding="utf-8") as f:
                    json.dump(clean_v, f, indent=2)
                files.append(os.path.basename(pv_path))
                entry["pv_file"] = os.path.basename(pv_path)
                entry["analysis"] = analyse_pv(clean_v)
        index["volumes"].append(entry)

    with open(os.path.join(d, "index.json"), "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2)

    audit("backup", namespace=ns, dir=d, count=len(items))
    return {"ok": True, "error": None, "dir": d, "root": root, "count": len(items),
            "files": files, "volumes": index["volumes"]}


def action_backup_all(dest=None):
    """Sauvegarde la config (PV/PVC) de TOUS les namespaces autorisés par le filtre
    courant (tous les namespaces du cluster si aucun filtre). Un namespace sans PVC est
    « ignoré » (pas une erreur). Renvoie un récapitulatif par namespace + des totaux.
    `dest` (optionnel) = dossier de destination commun (vide = défaut)."""
    info = action_namespaces()
    if not info.get("ok"):
        return {"ok": False, "error": info.get("error") or "Liste des namespaces indisponible.",
                "results": []}
    namespaces = info.get("namespaces") or []
    if not namespaces:
        return {"ok": False, "error": "Aucun namespace à sauvegarder.", "results": []}
    root, derr = _resolve_backup_dest(dest)        # valide la destination une seule fois
    if derr:
        return {"ok": False, "error": derr, "results": []}
    results, backed_up, vol_total = [], 0, 0
    for ns in namespaces:
        b = action_backup(ns, root)
        if b.get("ok"):
            backed_up += 1
            vol_total += b.get("count", 0)
            results.append({"ns": ns, "ok": True, "count": b.get("count", 0), "dir": b.get("dir")})
        else:
            err = b.get("error") or ""
            results.append({"ns": ns, "ok": False, "skipped": "Aucun PVC" in err,
                            "count": 0, "error": err})
    audit("backup_all", namespaces=len(namespaces), backed_up=backed_up, volumes=vol_total, root=root)
    return {"ok": True, "error": None, "results": results, "root": root,
            "namespaces": len(namespaces), "backed_up": backed_up, "volumes": vol_total,
            "filtered": bool(CONFIG.get("namespace_filter"))}


# ------------------------------------------------------------------------------
# Workloads (scale down/up) et attente active
# ------------------------------------------------------------------------------
def _scan_workloads(ns):
    """Réplicas COURANTS des Deployments et StatefulSets (0 inclus)."""
    captured = []
    for kind in ("deployment", "statefulset"):
        data, _ = kubectl_json(["get", kind, "-n", ns])
        if data:
            for i in data.get("items", []):
                captured.append({"kind": kind, "name": i["metadata"]["name"],
                                 "replicas": i.get("spec", {}).get("replicas", 1) or 0})
    return captured


def _replica_state_path(ns):
    return os.path.join(CONFIG["backup_root"], ns, "_replica_state.json")


def _load_replica_state(ns):
    try:
        with open(_replica_state_path(ns), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_replica_state(ns, desired_map):
    try:
        os.makedirs(os.path.dirname(_replica_state_path(ns)), exist_ok=True)
        with open(_replica_state_path(ns), "w", encoding="utf-8") as f:
            json.dump(desired_map, f, indent=2)
    except Exception:
        pass


# --- Transaction de restauration (reprise idempotente après interruption) ---
def _txn_path(ns):
    return os.path.join(CONFIG["backup_root"], ns, "_restore_txn.json")


def _load_txn(ns):
    """Transaction de restauration en cours pour ce namespace, ou None (fail-safe)."""
    try:
        with open(_txn_path(ns), encoding="utf-8") as f:
            t = json.load(f)
        return t if t.get("status") == "in_progress" else None
    except Exception:
        return None


def _save_txn(ns, data):
    try:
        os.makedirs(os.path.dirname(_txn_path(ns)), exist_ok=True)
        with open(_txn_path(ns), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def _clear_txn(ns):
    try:
        os.remove(_txn_path(ns))
    except OSError:
        pass


def _resolve_workloads(ns):
    """Renvoie (courants, cible). 'cible' = nombre de réplicas à RESTAURER pour
    chaque workload : la valeur courante si > 0, sinon la dernière valeur non
    nulle mémorisée (corrige le piège : après un échec l'app est à 0 ; un nouveau
    run ne doit JAMAIS 'restaurer' 0 réplica et croire avoir réussi)."""
    current = _scan_workloads(ns)
    prev = _load_replica_state(ns)  # {"kind/name": n}
    desired_map = dict(prev)
    for w in current:
        key = "%s/%s" % (w["kind"], w["name"])
        if w["replicas"] > 0:
            desired_map[key] = w["replicas"]   # la réalité courante non nulle fait foi
    # On ne mémorise que des valeurs strictement positives.
    desired_map = {k: v for k, v in desired_map.items() if isinstance(v, int) and v > 0}
    _save_replica_state(ns, desired_map)
    desired = []
    for w in current:
        key = "%s/%s" % (w["kind"], w["name"])
        if key in desired_map:
            desired.append({"kind": w["kind"], "name": w["name"], "replicas": desired_map[key]})
    return current, desired


def _stop_workloads(current, ns, dry, log):
    """Scale-down à 0 des workloads en cours. Renvoie (ok, detail_échec)."""
    for w in current:
        if w["replicas"] > 0:                       # n'arrêter que ce qui tourne
            r = kubectl(["scale", w["kind"], w["name"], "-n", ns, "--replicas=0"],
                        dry=dry, label="Arrêt %s/%s" % (w["kind"], w["name"]))
            log.append(r)
            if not (r["ok"] or r["dry"]):
                return False, "arrêt de %s/%s" % (w["kind"], w["name"])
    return True, ""


def _restart_workloads(desired, ns, dry, log):
    """Scale-up des workloads à leur nombre de réplicas d'origine."""
    for w in desired:
        log.append(kubectl(["scale", w["kind"], w["name"], "-n", ns, "--replicas=%s" % w["replicas"]],
                           dry=dry, label="Redémarrage %s/%s -> %s" % (w["kind"], w["name"], w["replicas"])))


def _pods_using_pvcs(ns, pvc_names):
    """Renvoie la liste des pods du namespace qui montent l'un des PVC visés."""
    data, _ = kubectl_json(["get", "pods", "-n", ns])
    using = []
    if not data:
        return using
    wanted = set(pvc_names)
    for pod in data.get("items", []):
        for vol in pod.get("spec", {}).get("volumes", []) or []:
            claim = (vol.get("persistentVolumeClaim") or {}).get("claimName")
            if claim in wanted:
                using.append(pod["metadata"]["name"])
                break
    return using


def _unmanaged_pods_using_pvcs(ns, pvc_names):
    """Pods montant les PVC ciblés dont le contrôleur racine N'EST PAS un
    Deployment (via ReplicaSet) ni un StatefulSet — donc NON arrêtés par le
    scale-down : DaemonSet, Job, pod nu, Operator/CRD. Renvoie [(pod, owner_kind)]."""
    data, _ = kubectl_json(["get", "pods", "-n", ns])
    out = []
    if not data:
        return out
    wanted = set(pvc_names)
    for pod in data.get("items", []):
        claims = [(v.get("persistentVolumeClaim") or {}).get("claimName")
                  for v in (pod.get("spec", {}).get("volumes") or [])]
        if not any(c in wanted for c in claims):
            continue
        kinds = {o.get("kind") for o in (pod.get("metadata", {}).get("ownerReferences") or [])}
        if not (kinds & {"ReplicaSet", "StatefulSet"}):
            out.append((pod["metadata"]["name"],
                        ", ".join(sorted(k for k in kinds if k)) or "aucun contrôleur"))
    return out


def _wait_pods_gone(ns, pvc_names, timeout, log):
    """Attend activement que plus aucun pod ne monte les PVC visés (corrige la
    course où l'on supprime le PVC alors qu'un pod le tient encore)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        using = _pods_using_pvcs(ns, pvc_names)
        if not using:
            log.append({"ok": True, "dry": False, "label": "Pods arrêtés",
                        "cmd": "(attente) pods montant les PVC", "stdout": "aucun pod ne monte les volumes ciblés", "stderr": "", "rc": 0})
            return True
        time.sleep(2)
    using = _pods_using_pvcs(ns, pvc_names)
    log.append({"ok": False, "dry": False, "label": "Pods encore présents",
                "cmd": "(attente) pods montant les PVC",
                "stdout": "", "stderr": "Délai dépassé, pods encore actifs : " + ", ".join(using), "rc": -1})
    return False


def _delete_and_unblock(kind, name, ns, log):
    """Supprime une ressource puis attend sa disparition ; si elle reste bloquée
    en Terminating (finalizer), retire les finalizers et re-vérifie.
    S'applique aussi bien au PV qu'au PVC (corrige le PVC laissé Terminating).
    Renvoie True si la ressource est bien absente à la fin."""
    state, _ = resource_state(kind, name, ns)
    if state == "absent":
        log.append({"ok": True, "dry": False, "label": "%s %s déjà absent" % (kind.upper(), name),
                    "cmd": "", "stdout": "rien à supprimer", "stderr": "", "rc": 0})
        return True

    args = ["delete", kind, name, "--wait=false", "--ignore-not-found"]
    if ns:
        args += ["-n", ns]
    log.append(kubectl(args, dry=False, label="Suppression %s %s" % (kind.upper(), name)))

    # Attente bornée de la suppression.
    wargs = ["wait", "--for=delete", "%s/%s" % (kind, name), "--timeout=%ss" % CONFIG["wait_timeout"]]
    if ns:
        wargs += ["-n", ns]
    kubectl(wargs, dry=False, label="Attente suppression %s %s" % (kind.upper(), name))

    state, detail = resource_state(kind, name, ns)
    if state == "present":
        # bloqué en Terminating -> on retire les finalizers
        pargs = ["patch", kind, name, "-p", '{"metadata":{"finalizers":null}}', "--type=merge"]
        if ns:
            pargs += ["-n", ns]
        log.append(kubectl(pargs, dry=False, label="Déblocage finalizer %s %s" % (kind.upper(), name)))
        time.sleep(1)
        state, detail = resource_state(kind, name, ns)

    if state == "absent":
        return True
    log.append({"ok": False, "dry": False, "label": "%s %s non supprimé" % (kind.upper(), name),
                "cmd": "", "stdout": "", "stderr": "État : %s (%s)" % (state, detail), "rc": -1})
    return False


def _apply_manifest(manifest, basename, dry, label):
    """Écrit le manifeste dans un fichier temporaire unique, kubectl apply -f, puis
    nettoie le fichier. En simulation, n'écrit rien sur disque."""
    if dry:
        return {"ok": True, "dry": True, "cmd": "kubectl apply -f <%s>.json" % basename,
                "stdout": "", "stderr": "", "rc": None, "label": label}
    tmp = os.path.join(CONFIG["backup_root"], "_apply")
    os.makedirs(tmp, exist_ok=True)
    path = os.path.join(tmp, "%s_%s.json" % (basename, secrets.token_hex(4)))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    try:
        return kubectl(["apply", "-f", path], dry=False, label=label)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def _wait_pvc_bound(name, ns, log):
    """Attend que le PVC soit Bound (vérification déterministe de fin)."""
    wargs = ["wait", "--for=jsonpath={.status.phase}=Bound",
             "pvc/%s" % name, "-n", ns, "--timeout=%ss" % CONFIG["wait_timeout"]]
    r = kubectl(wargs, dry=False, label="Attente PVC %s lié (Bound)" % name)
    log.append(r)
    return r["ok"]


# ------------------------------------------------------------------------------
# Récupération du PV de référence (sauvegarde ou live)
# ------------------------------------------------------------------------------
def _load_old_pv(ns, pvc_name, backup_path, backup_root=None):
    """Renvoie (old_pv, pv_name) depuis la sauvegarde si fournie, sinon en live."""
    bp = _safe_backup_path(backup_path, backup_root)
    if bp:
        idx_path = os.path.join(bp, "index.json")
        if os.path.isfile(idx_path):
            with open(idx_path, encoding="utf-8") as f:
                idx = json.load(f)
            for v in idx.get("volumes", []):
                if v["pvc"] == pvc_name and v.get("pv_file"):
                    with open(os.path.join(bp, v["pv_file"]), encoding="utf-8") as f:
                        return json.load(f), v.get("pv")
    # repli : lecture live
    live = action_pvcs(ns)
    pv_name = None
    for p in live.get("pvcs", []):
        if p["name"] == pvc_name:
            pv_name = p["pv"]
            break
    if pv_name:
        pv_data, _ = kubectl_json(["get", "pv", pv_name])
        if pv_data:
            return clean_pv(json.loads(json.dumps(pv_data))), pv_name
    return None, pv_name


def _load_backup_pvc(backup_path, pvc_name, backup_root=None):
    bp = _safe_backup_path(backup_path, backup_root)
    if not bp:
        return None
    idx_path = os.path.join(bp, "index.json")
    if not os.path.isfile(idx_path):
        return None
    with open(idx_path, encoding="utf-8") as f:
        idx = json.load(f)
    for v in idx.get("volumes", []):
        if v["pvc"] == pvc_name and v.get("pvc_file"):
            with open(os.path.join(bp, v["pvc_file"]), encoding="utf-8") as f:
                return json.load(f)
    return None


def _load_old_pvc(ns, pvc_name, backup_path, backup_root=None):
    """Manifeste du PVC depuis la sauvegarde si fournie, sinon en LIVE (nettoyé).
    Permet de recréer le PVC même sans export préalable (étape 1), tant que le PVC
    existe encore dans le cluster au moment de la préparation."""
    b = _load_backup_pvc(backup_path, pvc_name, backup_root)
    if b is not None:
        return b
    live, _ = kubectl_json(["get", "pvc", pvc_name, "-n", ns])
    if live:
        return clean_pvc(json.loads(json.dumps(live)))
    return None


# ------------------------------------------------------------------------------
# Préparation (aperçu) — multi-PVC
# ------------------------------------------------------------------------------
def _prepare_one(ns, item, mode, backup_path, backup_root=None):
    """Construit l'aperçu pour UN volume. item = {pvc, new_ref|new_iqn, new_name}.
    `new_ref` = UUID du VG (NKP), volumeHandle, ou IQN (legacy)."""
    pvc_name = item.get("pvc")
    new_ref = (item.get("new_ref") or item.get("new_iqn") or "").strip()
    suggested = (item.get("new_name") or "").strip()

    if not pvc_name:
        return {"ok": False, "pvc": pvc_name, "error": "PVC manquant."}
    if not new_ref:
        return {"ok": False, "pvc": pvc_name,
                "error": "Indiquez la référence du Volume Group cloné/restauré pour « %s » "
                         "(UUID du VG, volumeHandle, ou IQN)." % pvc_name}
    # La référence doit contenir un UUID 8-4-4-4-12 (et rien de plus si c'est un IQN :
    # on rejette un IQN mal collé, mais on accepte un UUID nu ou un volumeHandle).
    if not UUID_RE.search(new_ref):
        return {"ok": False, "pvc": pvc_name,
                "error": "Référence invalide pour « %s » : aucun UUID détecté. Collez l'UUID du VG "
                         "(8-4-4-4-12), un volumeHandle « NutanixVolumes-<uuid> », ou l'IQN complet." % pvc_name}

    old_pv, pv_name = _load_old_pv(ns, pvc_name, backup_path, backup_root)
    if old_pv is None:
        return {"ok": False, "pvc": pvc_name,
                "error": "Manifeste du PV introuvable pour « %s ». Sauvegardez d'abord ce namespace, "
                         "ou vérifiez que le PV existe encore." % pvc_name}

    built, err = build_new_pv(old_pv, new_ref, suggested, mode)
    if err:
        return {"ok": False, "pvc": pvc_name, "error": err}

    warn = None
    if built["looks_like_vg_name"]:
        warn = ("L'UUID fourni correspond au NOM du VG (« pvc-<uuid> », = UUID du PVC) et non à l'UUID "
                "du Volume Group. Vous avez probablement saisi le nom du VG au lieu de son UUID — "
                "utilisez « Rechercher le VG dans Prism » ou copiez l'UUID du VG (suffixe de NutanixVolumes-… / ntnx-k8s-…).")
    elif mode == "clone" and built["same_uuid"]:
        warn = ("L'UUID est identique à l'ancien : le clone n'a peut-être pas produit de nouveau VG "
                "(UUID du VG source saisi au lieu du VG cloné ?).")
    elif built["no_change"]:
        warn = ("Aucun changement détecté dans le manifeste : en restauration sur place avec le même VG, "
                "un simple redémarrage des pods suffit à remonter les données restaurées.")

    # Capturer le PVC MAINTENANT (avant toute suppression), sauvegarde ou live, pour
    # pouvoir le recréer même sans export préalable (étape 1). None s'il est introuvable.
    pvc_manifest = _load_old_pvc(ns, pvc_name, backup_path, backup_root)
    return {"ok": True, "pvc": pvc_name, "old_pv_name": pv_name,
            "new_pv_name": built["new_name"], "new_volume_handle": built["new_volume_handle"],
            "old_volume_handle": built["old_volume_handle"], "old_iqn": built["old_iqn"],
            "replacements": built["replacements"], "no_change": built["no_change"],
            "stripped": built["stripped"], "warn": warn,
            "pvc_captured": pvc_manifest is not None, "pvc_manifest": pvc_manifest,
            "manifest_preview": json.dumps(built["manifest"], indent=2),
            "manifest": built["manifest"]}


def action_prepare_restore(payload):
    """Aperçu du restore SANS rien exécuter, pour un ou plusieurs PVC."""
    ns = payload.get("namespace")
    if not _namespace_allowed(ns):
        return {"ok": False, "error": "Namespace '%s' non autorisé par la configuration." % ns}
    mode = payload.get("mode", "clone")
    backup_path = payload.get("backup_path")
    backup_root = payload.get("backup_root")
    items = payload.get("items")
    if not items:  # compat : ancien format mono-PVC
        items = [{"pvc": payload.get("pvc"),
                  "new_ref": payload.get("new_ref") or payload.get("new_iqn"),
                  "new_name": payload.get("new_name")}]

    results = [_prepare_one(ns, it, mode, backup_path, backup_root) for it in items]
    ok = all(r["ok"] for r in results)
    plan = _plan_steps(ns, [r for r in results if r.get("ok")], mode)
    return {"ok": ok, "error": None if ok else "Un ou plusieurs volumes n'ont pas pu être préparés.",
            "results": results, "planned_steps": plan, "namespace": ns, "mode": mode}


def _plan_steps(ns, prepared, mode):
    """Plan textuel de la séquence transactionnelle multi-PVC."""
    steps = ["Arrêter l'application (tous les Deployments/StatefulSets du namespace -> 0 réplica)",
             "Attendre l'arrêt effectif des pods qui montent les volumes ciblés"]
    for r in prepared:
        steps.append("Supprimer l'ancien PVC « %s » (+ déblocage finalizer si nécessaire)" % r["pvc"])
        if r.get("old_pv_name"):
            steps.append("Supprimer l'ancien PV « %s » (+ déblocage finalizer si nécessaire)" % r["old_pv_name"])
        steps.append("Créer le nouveau PV « %s » (volumeHandle %s)" % (r["new_pv_name"], r["new_volume_handle"]))
        steps.append("Recréer le PVC « %s » et le lier au nouveau PV, attendre l'état Bound" % r["pvc"])
    steps.append("Redémarrer l'application (réplicas d'origine restaurés)")
    steps.append("Vérifier : tous les PVC liés (Bound) et pods démarrés")
    if mode == "clone":
        steps.append("APRÈS : re-protéger le(s) nouveau(x) Volume Group(s) dans HYCU "
                     "(politique / catégorie Prism) — non automatisé par cet outil")
    return steps


# ------------------------------------------------------------------------------
# Exécution transactionnelle du restore (multi-PVC, arrêt sur échec)
# ------------------------------------------------------------------------------
def _context_guard(payload):
    """Garde contexte (mode réel) commune aux trois orchestrateurs destructifs :
    refuse un contexte kubectl hors `allowed_contexts`, ou non reconfirmé quand
    `require_context_confirm` est actif. Le frontend n'étant que consultatif, cette
    vérification côté serveur est la vraie frontière. Renvoie un dict d'erreur prêt à
    retourner, ou None si le contexte est autorisé et confirmé."""
    cinfo = action_context()
    if not cinfo["context_ok"]:
        return {"ok": False, "error": "Contexte kubectl « %s » non autorisé par la configuration "
                "(allowed_contexts)." % cinfo.get("context"), "log": []}
    if cinfo["require_confirm"] and payload.get("confirm_context") != cinfo.get("context"):
        return {"ok": False, "error": "Confirmation du contexte requise : retapez le nom du contexte ciblé "
                "(« %s ») pour confirmer." % cinfo.get("context"), "log": []}
    return None


def action_execute_restore(payload, log=None):
    """Exécute la séquence de restore pour un ou plusieurs PVC en une transaction.
    - un seul scale-down / scale-up encadrant tous les volumes ;
    - arrêt immédiat (pas de scale-up aveugle) si une étape critique échoue ;
    - respecte le mode simulation et exige un jeton/contexte côté serveur.
    `log` (optionnel) = liste partagée pour la progression live (/api/op_status)."""
    try:
        with action_lock():
            return _execute_restore_locked(payload, log=log)
    except _Busy as e:
        return _err(str(e), log=log if log is not None else [])


def _execute_restore_locked(payload, log=None):
    ns = payload.get("namespace")
    dry = bool(payload.get("dry", True))
    if log is None:
        log = []

    if not _namespace_allowed(ns):
        return {"ok": False, "error": "Namespace '%s' non autorisé par la configuration." % ns, "log": []}

    # Garde contexte : en mode réel, refuser si le contexte n'est pas confirmé/autorisé.
    if not dry:
        guard = _context_guard(payload)
        if guard:
            return guard

    # Reprise idempotente : charger une éventuelle transaction en cours AVANT la
    # préparation. En reprise, le PVC/PV source a déjà été supprimé du cluster — les
    # manifestes doivent être relus depuis la sauvegarde de sécurité initiale
    # (txn["backup_dir"]), sinon _prepare_one ne retrouve rien en live et la reprise
    # échoue définitivement (app laissée à 0 réplica, PV/PVC absents).
    txn = _load_txn(ns) if not dry else None
    backup_path = payload.get("backup_path") or (txn or {}).get("backup_dir")

    prep = action_prepare_restore({**payload, "backup_path": backup_path, "dry": dry})
    if not prep.get("ok"):
        return {"ok": False, "error": prep.get("error"), "log": [],
                "results": prep.get("results")}

    prepared = [r for r in prep["results"] if r.get("ok")]
    aborted = False
    abort_detail = ""

    audit("restore_start", namespace=ns, dry=dry, mode=payload.get("mode"),
          volumes=[{"pvc": r["pvc"], "new_pv": r["new_pv_name"],
                    "new_volume_handle": r["new_volume_handle"]} for r in prepared])

    # 0. Filet de sécurité + transaction (reprise idempotente). En réel : on sauvegarde
    #    les manifestes AVANT toute destruction. Si une transaction précédente est en
    #    cours (restauration interrompue), c'est une REPRISE : on réutilise la sauvegarde
    #    initiale (ne pas re-sauvegarder un état à moitié restauré) — les étapes sont
    #    idempotentes (delete d'un absent = ok, apply = upsert).
    if not dry:
        if txn:
            log.append(logentry("Reprise d'une restauration interrompue",
                                stdout="Démarrée %s (mode %s). Sauvegarde de sécurité initiale réutilisée ; "
                                       "les étapes déjà faites sont rejouées sans dommage."
                                       % (txn.get("started"), txn.get("mode"))))
        backup_dir = (txn or {}).get("backup_dir")
        if not txn and CONFIG.get("backup_before_restore", True):
            b = action_backup(ns)
            log.append(logentry("Sauvegarde de sécurité du namespace avant restauration",
                                ok=bool(b.get("ok")), rc=0 if b.get("ok") else -1,
                                stdout=("Manifestes : %s" % b.get("dir")) if b.get("dir") else "",
                                stderr="" if b.get("ok") else (b.get("error") or "")))
            if not b.get("ok"):
                return _err("Sauvegarde de sécurité impossible (%s) — restauration annulée pour ne pas "
                            "détruire sans filet. Corrigez puis relancez." % b.get("error"), log=log)
            backup_dir = b.get("dir")
        _save_txn(ns, {"status": "in_progress",
                       "started": (txn.get("started") if txn else datetime.datetime.now().isoformat()),
                       "mode": payload.get("mode", "clone"), "backup_dir": backup_dir,
                       "volumes": [{"pvc": r["pvc"], "new_pv": r["new_pv_name"]} for r in prepared]})

    # 1. Résoudre les réplicas (courants + cibles à restaurer) puis arrêter l'app.
    #    La cible n'est JAMAIS 0 : si l'app est déjà à 0 (reprise après échec), on
    #    récupère le compte d'origine mémorisé pour ne pas 'restaurer' un arrêt.
    current, desired = _resolve_workloads(ns)
    log.append({"ok": True, "dry": dry, "label": "Réplicas mémorisés", "rc": 0, "stderr": "",
                "cmd": "(lecture) réplicas cibles",
                "stdout": ", ".join("%s/%s=%s" % (w["kind"], w["name"], w["replicas"]) for w in desired) or "aucun"})

    # Avertir si un pod montant un volume ciblé n'est PAS géré par un Deployment/
    # StatefulSet : le scale-down ne l'arrêtera pas et il pourrait recréer le pod /
    # tenir le PVC pendant la suppression.
    unmanaged = _unmanaged_pods_using_pvcs(ns, [r["pvc"] for r in prepared])
    if unmanaged:
        log.append(logentry("⚠ Pod(s) NON géré(s) par un Deployment/StatefulSet montant les volumes ciblés",
                            stdout="; ".join("%s (contrôleur : %s)" % (p, k) for p, k in unmanaged)
                                   + ". Le scale-down ne les arrêtera pas — arrêtez-les manuellement "
                                     "(DaemonSet/Job/Operator/pod nu) avant de continuer."))

    ok_stop, detail_stop = _stop_workloads(current, ns, dry, log)
    if not ok_stop:
        aborted = True
        abort_detail = detail_stop

    pvc_names = [r["pvc"] for r in prepared]

    # 2. Attendre l'arrêt effectif des pods (réel uniquement).
    if not dry and not aborted:
        if not _wait_pods_gone(ns, pvc_names, CONFIG["wait_timeout"], log):
            aborted = True
            abort_detail = "attente de l'arrêt des pods"

    # 3. Pour chaque volume : delete PVC -> delete PV -> apply PV -> apply PVC -> Bound.
    for r in prepared:
        if aborted:
            break
        pvc_name = r["pvc"]
        pv_old = r.get("old_pv_name")
        new_name = r["new_pv_name"]
        retain = bool(CONFIG.get("retain_source_pv", True))

        # Réécrire hypervisorAttachedDiskUUIDs avec le disque du VG cloné (clone) AVANT
        # l'apply : sans lui, le CSI tente l'attach iSCSI et l'attachement échoue.
        if payload.get("mode", "clone") == "clone":
            disk_ok = _set_clone_disk_uuids(r.get("manifest"), r.get("new_volume_handle"), dry, log)
            if not disk_ok and not dry and CONFIG.get("clone_require_disk_uuids", True):
                aborted = True
                abort_detail = ("disque du VG cloné introuvable pour %s (Prism Central requis) — "
                                "PV non recréé pour éviter un volume non attachable" % pvc_name)
                break

        if dry:
            if pv_old and retain:
                log.append({"ok": True, "dry": True, "label": "Protection du VG source : PV %s -> Retain" % pv_old,
                            "cmd": 'kubectl patch pv %s -p \'{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}\'' % pv_old,
                            "stdout": "Évite que la suppression du PV/PVC ne supprime le Volume Group Nutanix "
                                      "(reclaimPolicy=Delete par défaut).", "stderr": "", "rc": None})
            log.append({"ok": True, "dry": True, "label": "Suppression PVC %s" % pvc_name,
                        "cmd": "kubectl delete pvc %s -n %s (+ finalizer si besoin)" % (pvc_name, ns),
                        "stdout": "", "stderr": "", "rc": None})
            if pv_old:
                log.append({"ok": True, "dry": True, "label": "Suppression PV %s" % pv_old,
                            "cmd": "kubectl delete pv %s (+ finalizer si besoin)" % pv_old,
                            "stdout": "", "stderr": "", "rc": None})
            log.append(_apply_manifest(r["manifest"], "pv_%s" % new_name, True,
                                       "Création du nouveau PV %s" % new_name))
        else:
            # 0) Protéger le VG source : passer l'ANCIEN PV en Retain AVANT toute
            #    suppression. Avec reclaimPolicy=Delete (défaut Nutanix), supprimer le
            #    PVC/PV déclenche la suppression du Volume Group côté CSI — destruction
            #    du volume (source du clone, et/ou volume re-pointé si même VG).
            if pv_old and retain:
                st_pv, _ = resource_state("pv", pv_old)
                if st_pv == "present":
                    pr = kubectl(["patch", "pv", pv_old, "--type=merge",
                                  "-p", '{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}'],
                                 dry=False, label="Protection du VG source : PV %s -> Retain" % pv_old)
                    log.append(pr)
                    if not pr["ok"]:
                        aborted = True
                        abort_detail = "protection (Retain) du PV source %s — suppression annulée pour " \
                                       "ne pas risquer la perte du Volume Group" % pv_old
                        break
            if not _delete_and_unblock("pvc", pvc_name, ns, log):
                aborted = True
                abort_detail = "suppression du PVC %s" % pvc_name
                break
            if pv_old and not _delete_and_unblock("pv", pv_old, None, log):
                aborted = True
                abort_detail = "suppression du PV %s (volume %s)" % (pv_old, pvc_name)
                break
            ra = _apply_manifest(r["manifest"], "pv_%s" % new_name, False,
                                 "Création du nouveau PV %s" % new_name)
            log.append(ra)
            if not ra["ok"]:
                aborted = True
                abort_detail = "création du nouveau PV %s (volume %s)" % (new_name, pvc_name)
                break

        # Recréer le PVC à partir du manifeste CAPTURÉ à la préparation (sauvegarde ou
        # live), pointé vers le nouveau PV. Disponible même sans export préalable.
        pvc_manifest = r.get("pvc_manifest")
        if pvc_manifest is not None:
            pvc_manifest = json.loads(json.dumps(pvc_manifest))   # copie défensive
            pvc_manifest.setdefault("spec", {})["volumeName"] = new_name
            ra = _apply_manifest(pvc_manifest, "pvc_%s" % pvc_name, dry,
                                 "Recréation du PVC %s -> %s" % (pvc_name, new_name))
            log.append(ra)
            if not (ra["ok"] or ra["dry"]):
                aborted = True
                abort_detail = "recréation du PVC %s" % pvc_name
                break
            if not dry and not _wait_pvc_bound(pvc_name, ns, log):
                aborted = True
                abort_detail = "liaison (Bound) du PVC %s" % pvc_name
                break
        else:
            log.append({"ok": True, "dry": dry, "label": "PVC %s non recréé" % pvc_name, "rc": 0,
                        "cmd": "", "stderr": "",
                        "stdout": "Manifeste du PVC introuvable (ni sauvegarde ni live) : le PVC sera recréé "
                                  "par votre déploiement applicatif (vérifiez ensuite qu'il devient Bound)."})

    # 4. Redémarrer l'application — UNIQUEMENT si rien n'a échoué.
    if not aborted:
        _restart_workloads(desired, ns, dry, log)
    else:
        log.append({"ok": False, "dry": dry, "label": "SÉQUENCE INTERROMPUE", "rc": -1, "stdout": "",
                    "cmd": "", "stderr": ("Échec à l'étape : %s. " % (abort_detail or "inconnue")) +
                    "L'application reste ARRÊTÉE (réplicas à 0) pour éviter de redémarrer sur des "
                    "volumes incohérents. Corrigez la cause, puis relancez la restauration (les "
                    "réplicas d'origine sont mémorisés), ou redémarrez manuellement : " +
                    "; ".join("kubectl scale %s %s -n %s --replicas=%s" % (w["kind"], w["name"], ns, w["replicas"]) for w in desired)})

    # 5. Vérification finale (réelle si non-dry) — dont contrôle anti mauvais-volume :
    #    le PVC doit être lié au PV portant le volumeHandle ATTENDU (VG cible).
    if not dry and not aborted:
        v = action_verify(ns)
        vh_by_pvc = {p["name"]: p.get("volume_handle") for p in v.get("pvcs", [])}
        mism = []
        for r in prepared:
            got, exp = vh_by_pvc.get(r["pvc"]), r["new_volume_handle"]
            if got and exp and got != exp:
                mism.append("%s lié à %s au lieu de %s" % (r["pvc"], got, exp))
        if mism:
            log.append(logentry("⚠ volumeHandle INATTENDU — vérifiez le volume réellement monté",
                                stdout="Incohérence(s) : " + " ; ".join(mism)
                                       + ". Le pod tourne peut-être sur le mauvais Volume Group."))
        else:
            log.append(logentry("volumeHandle conforme au VG attendu pour tous les volumes"))
        log.append(logentry("Vérification finale", cmd="kubectl get pvc/pv/pods",
                            stdout=json.dumps(v, indent=2)))

    ok_all = (not aborted) and all(r["ok"] or r.get("dry") for r in log)
    # Transaction : effacée si la restauration s'est terminée sans interruption (réel).
    # Si interrompue, le marqueur reste -> le prochain run est traité comme une reprise.
    if not dry and not aborted:
        _clear_txn(ns)
    # Rappel : un VG CLONÉ tout neuf n'est pas protégé dans HYCU -> le signaler.
    reprotect = []
    if payload.get("mode", "clone") == "clone" and not dry and not aborted:
        reprotect = [{"pvc": r["pvc"], "new_pv_name": r["new_pv_name"],
                      "new_volume_handle": r["new_volume_handle"]} for r in prepared]
    audit("restore_end", namespace=ns, dry=dry, ok=ok_all, aborted=aborted)
    return {"ok": ok_all, "error": None, "dry": dry, "aborted": aborted, "log": log,
            "reprotect": reprotect}


def action_verify(ns):
    """État des PVC et des pods du namespace."""
    out = {"ok": True, "namespace": ns, "pvcs": [], "pods": [], "error": None}
    if not _namespace_allowed(ns):
        out["ok"] = False
        out["error"] = "Namespace '%s' non autorisé par la configuration." % ns
        return out
    pvc_data, err = kubectl_json(["get", "pvc", "-n", ns])
    if err:
        out["ok"] = False
        out["error"] = err
        return out
    # volumeHandle réellement lié par PV (preuve du volume monté, pas juste "Bound").
    pv_handle = {}
    pv_all, _ = kubectl_json(["get", "pv"])
    for pv in (pv_all or {}).get("items", []):
        h = (((pv.get("spec") or {}).get("csi") or {}).get("volumeHandle"))
        if h:
            pv_handle[pv["metadata"]["name"]] = h
    for i in pvc_data.get("items", []):
        pvn = i.get("spec", {}).get("volumeName")
        out["pvcs"].append({"name": i["metadata"]["name"],
                            "phase": i.get("status", {}).get("phase"),
                            "pv": pvn,
                            "volume_handle": pv_handle.get(pvn)})
    pod_data, _ = kubectl_json(["get", "pods", "-n", ns])
    if pod_data:
        for i in pod_data.get("items", []):
            cs = i.get("status", {}).get("containerStatuses", []) or []
            ready = sum(1 for c in cs if c.get("ready"))
            out["pods"].append({"name": i["metadata"]["name"],
                                "phase": i.get("status", {}).get("phase"),
                                "ready": "%d/%d" % (ready, len(cs))})
    return out


def action_get_config():
    return {"config": CONFIG, "defaults": DEFAULT_CONFIG,
            "exists": os.path.isfile(CONFIG_PATH)}


def action_set_config(payload):
    ok, err = save_config(payload.get("config") or {})
    return {"ok": ok, "error": err, "config": CONFIG}


# ------------------------------------------------------------------------------
# Connecteurs HYCU / Nutanix (REST, stdlib uniquement, identifiants en RAM)
# ------------------------------------------------------------------------------
def _ssl_ctx(verify):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _auth_header(auth):
    """En-tête Authorization selon le mode : Basic (user/mot de passe) ou clé API
    (HYCU 5.x : Bearer). 'auth' = {"mode":"basic","user","password"} ou
    {"mode":"apikey","key"}."""
    if not auth:
        return None
    if auth.get("mode") == "apikey":
        return "Bearer " + (auth.get("key") or "")
    token = base64.b64encode(("%s:%s" % (auth.get("user", ""), auth.get("password", ""))).encode("utf-8")).decode("ascii")
    return "Basic " + token


class _NoCredLeakRedirect(urllib.request.HTTPRedirectHandler):
    """Suit les redirections HTTP mais RETIRE l'en-tête Authorization si l'hôte cible
    change : évite de réémettre les identifiants HYCU/Nutanix (Basic/Bearer) vers un
    hôte tiers si une appliance compromise — ou un MITM (TLS souvent désactivé) —
    renvoie un 30x cross-host."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        newreq = urllib.request.HTTPRedirectHandler.redirect_request(
            self, req, fp, code, msg, headers, newurl)
        if newreq is not None:
            try:
                same = (urllib.parse.urlsplit(req.full_url).netloc
                        == urllib.parse.urlsplit(newurl).netloc)
            except Exception:
                same = False
            if not same:
                newreq.headers.pop("Authorization", None)
                newreq.unredirected_hdrs.pop("Authorization", None)
        return newreq


def _http_json(method, url, auth, verify, body=None, timeout=30):
    """Appel REST générique (Basic Auth ou clé API + JSON). Renvoie un dict de
    résultat homogène, sans jamais lever d'exception vers l'appelant."""
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in ("https", "http"):
        return {"ok": False, "status": None,
                "error": "Schéma d'URL refusé (%s) : seuls http/https sont autorisés." % (scheme or "—")}
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    h = _auth_header(auth)
    if h:
        req.add_header("Authorization", h)
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        opener = urllib.request.build_opener(
            _NoCredLeakRedirect(),
            urllib.request.HTTPSHandler(context=_ssl_ctx(verify)))
        with opener.open(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "ignore")
            parsed = None
            if raw:
                try:
                    parsed = json.loads(raw)
                except json.JSONDecodeError:
                    parsed = None
            return {"ok": True, "status": getattr(r, "status", 200), "json": parsed, "raw": raw}
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "ignore")[:300]
        except Exception:
            pass
        return {"ok": False, "status": e.code, "error": "HTTP %s" % e.code, "raw": detail}
    except urllib.error.URLError as e:
        return {"ok": False, "status": None, "error": "Connexion impossible : %s" % e.reason}
    except ssl.SSLError as e:
        return {"ok": False, "status": None, "error": "Erreur TLS : %s" % e}
    except Exception as e:  # pragma: no cover
        return {"ok": False, "status": None, "error": str(e)}


def _system_cfg(system):
    return (CONFIG.get("%s_url" % system, "").rstrip("/"),
            CONFIG.get("%s_api_base" % system, ""),
            bool(CONFIG.get("%s_verify_tls" % system, False)))


def _rest(system, method, path, body=None, timeout=30):
    """Appel REST avec les identifiants de session (hycu/nutanix)."""
    base, api, verify = _system_cfg(system)
    if not base:
        return {"ok": False, "error": "URL %s non configurée (onglet Réglages)." % system.upper()}
    creds = SESSION_CREDS.get(system)
    if not creds:
        return {"ok": False, "error": "Non connecté à %s." % system.upper()}
    return _http_json(method, base + api + path, creds, verify, body, timeout)


def _rest_raw(system, method, raw_path, body=None, timeout=30):
    """Comme _rest mais avec un chemin ABSOLU (on ignore le api_base configuré) —
    pour atteindre une AUTRE API du même appareil (ex. Prism Central v4 Volumes,
    `/api/volumes/v4.0.b1/...`, celle qu'utilise réellement le CSI Nutanix)."""
    base, _, verify = _system_cfg(system)
    if not base:
        return {"ok": False, "error": "URL %s non configurée (onglet Réglages)." % system.upper()}
    creds = SESSION_CREDS.get(system)
    if not creds:
        return {"ok": False, "error": "Non connecté à %s." % system.upper()}
    return _http_json(method, base + raw_path, creds, verify, body, timeout)


NTX_LABEL = {"nutanix": "Prism Element", "prismcentral": "Prism Central",
             "pe": "Prism Element", "pc": "Prism Central"}


def _nutanix_identity(base, auth, verify):
    """Détecte Prism Element vs Prism Central via la FONCTION du cluster
    (cluster_functions de l'API v2 /cluster, servie par les deux) :
      'NDFS'        -> Prism Element (cluster AOS de stockage)
      'MULTICLUSTER'-> Prism Central
    Renvoie 'pe' | 'pc' | 'unknown'.
    NB : l'API v3 (/api/nutanix/v3) est servie par PE ET PC -> inutilisable comme
    discriminant (c'était la cause d'un faux positif « c'est un Prism Central »)."""
    b = (base or "").rstrip("/")
    r = _http_json("GET", b + "/PrismGateway/services/rest/v2.0/cluster", auth, verify, timeout=15)
    if r["ok"] and isinstance(r.get("json"), dict):
        cf = r["json"].get("cluster_functions") or r["json"].get("clusterFunctions") or []
        cf = [str(x).upper() for x in cf] if isinstance(cf, list) else [str(cf).upper()]
        if "MULTICLUSTER" in cf:
            return "pc"
        if "NDFS" in cf:
            return "pe"
    return "unknown"


def action_connect(payload):
    """Mémorise les identifiants EN RAM après un test de connexion.
    Modes : Basic (user/mot de passe) ou clé API (HYCU 5.x avec 2FA)."""
    system = payload.get("system")
    if system not in ("hycu", "nutanix", "prismcentral"):
        return {"ok": False, "error": "Système inconnu."}
    base, api, verify = _system_cfg(system)
    if not base:
        return {"ok": False, "error": "URL %s non configurée (onglet Réglages)." % system.upper()}

    mode = payload.get("auth_mode", "basic")
    if mode == "apikey":
        key = (payload.get("api_key") or "").strip()
        if not key:
            return {"ok": False, "error": "Clé API requise."}
        auth = {"mode": "apikey", "key": key}
    else:
        user = (payload.get("user") or "").strip()
        pwd = payload.get("password") or ""
        if not user or not pwd:
            return {"ok": False, "error": "Identifiant et mot de passe requis."}
        auth = {"mode": "basic", "user": user, "password": pwd}

    test_path = {"nutanix": "/cluster", "prismcentral": "/users/me"}.get(
        system, CONFIG.get("hycu_test_path") or "/vms")
    r = _http_json("GET", base + api + test_path, auth, verify)
    warning = None
    if not r["ok"]:
        st = r.get("status")
        if st in (401, 403):
            return {"ok": False, "error": "Authentification %s refusée (HTTP %s). "
                    "Vérifiez les identifiants%s." % (system.upper(), st,
                    " ou utilisez une clé API si le 2FA est activé" if system == "hycu" else "")}
        if st == 404 and system in ("hycu", "prismcentral"):
            # Serveur joignable, auth franchie, mais le chemin de test n'existe pas
            # sur cette version : on connecte quand même avec un avertissement.
            where = "Aide → REST API Explorer" if system == "hycu" else "la version de l'API v3/v4"
            warning = ("Connecté, mais l'endpoint de test « %s » est introuvable (HTTP 404). "
                       "Les chemins REST dépendent de la version : vérifiez %s et ajustez si besoin."
                       % (test_path, where))
        elif system not in ("nutanix", "prismcentral"):
            return {"ok": False, "error": "Échec de connexion %s : %s" % (
                system.upper(), r.get("error") or ("HTTP %s" % st))}

    # Prism Element vs Prism Central : empêcher d'inverser les deux ou de mettre
    # deux fois la même URL. On vérifie quel Prism répond réellement derrière l'URL.
    if system in ("nutanix", "prismcentral"):
        other = "prismcentral" if system == "nutanix" else "nutanix"
        other_url = (CONFIG.get(other + "_url") or "").rstrip("/")
        if other_url and other_url == base:
            return {"ok": False, "error": "Cette URL est identique à celle de %s. "
                    "Prism Element et Prism Central doivent pointer vers des hôtes différents."
                    % NTX_LABEL[other]}
        identity = _nutanix_identity(base, auth, verify)
        expected = "pe" if system == "nutanix" else "pc"
        if identity == "unknown" and not r["ok"]:
            return {"ok": False, "error": "Échec de connexion %s : %s" % (
                system.upper(), r.get("error") or ("HTTP %s" % r.get("status")))}
        if identity != "unknown" and identity != expected:
            note = ("Attention : cette URL semble être un %s, pas un %s — vérifiez de ne pas avoir "
                    "inversé les deux connecteurs. La connexion est tout de même établie."
                    % (NTX_LABEL[identity], NTX_LABEL[expected]))
            warning = (warning + " " + note) if warning else note

    if not verify:
        tls_note = ("Certificat TLS NON vérifié — les identifiants transitent vers un hôte non "
                    "authentifié. N'utilisez ce mode que sur un réseau de gestion de confiance.")
        warning = (warning + " " + tls_note) if warning else tls_note
    with CRED_LOCK:
        SESSION_CREDS[system] = auth
    audit("connect", system=system, url=base, mode=mode, verify_tls=verify)
    return {"ok": True, "system": system, "connected": True, "warning": warning,
            "tls_insecure": not verify}


def action_disconnect(payload):
    system = payload.get("system")
    with CRED_LOCK:
        if system in SESSION_CREDS:
            SESSION_CREDS[system] = None
    return {"ok": True, "system": system, "connected": False}


def action_conn_status():
    out = {}
    for s in ("hycu", "nutanix", "prismcentral"):
        base, api, verify = _system_cfg(s)
        out[s] = {"configured": bool(base), "url": base, "api_base": api,
                  "verify_tls": verify, "connected": SESSION_CREDS.get(s) is not None}
    out["vault"] = {"present": os.path.isfile(SECRETS_PATH)}
    return out


# ------------------------------------------------------------------------------
# Coffre d'identifiants chiffré (optionnel) — phrase secrète maîtresse, stdlib pure
#
# NB : MD5 (ou tout hachage) est À SENS UNIQUE et ne permettrait PAS de récupérer
# le mot de passe pour se reconnecter. On utilise donc un chiffrement RÉVERSIBLE :
# clé dérivée de la phrase par PBKDF2-HMAC-SHA256, flux de chiffrement HMAC-SHA256
# en mode compteur (XOR), et scellé HMAC (chiffrer-puis-MAC) pour l'intégrité et la
# détection d'une mauvaise phrase. La phrase n'est jamais stockée.
# ------------------------------------------------------------------------------
def _derive_keys(passphrase, salt):
    iters = int(CONFIG.get("pbkdf2_iterations") or 200000)
    dk = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iters, dklen=64)
    return dk[:32], dk[32:]   # (clé de chiffrement, clé MAC)


def _keystream(enc_key, nonce, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hmac.new(enc_key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest())
        counter += 1
    return bytes(out[:length])


def _xor(data, ks):
    return bytes(a ^ b for a, b in zip(data, ks))


def encrypt_secret(plaintext, passphrase):
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    enc_key, mac_key = _derive_keys(passphrase, salt)
    ct = _xor(plaintext, _keystream(enc_key, nonce, len(plaintext)))
    tag = hmac.new(mac_key, salt + nonce + ct, hashlib.sha256).digest()
    return base64.b64encode(salt + nonce + ct + tag).decode("ascii")


def decrypt_secret(blob_b64, passphrase):
    try:
        raw = base64.b64decode(blob_b64)
        if len(raw) < 64:
            return None
        salt, nonce, body = raw[:16], raw[16:32], raw[32:]
        ct, tag = body[:-32], body[-32:]
        enc_key, mac_key = _derive_keys(passphrase, salt)
        expected = hmac.new(mac_key, salt + nonce + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, tag):
            return None   # mauvaise phrase secrète ou fichier altéré
        return _xor(ct, _keystream(enc_key, nonce, len(ct)))
    except Exception:
        return None


def action_save_credentials(payload):
    """Chiffre les identifiants de session courants dans hycu_secrets.enc."""
    pw = payload.get("passphrase") or ""
    if len(pw) < 8:
        return {"ok": False, "error": "Choisissez une phrase secrète d'au moins 8 caractères."}
    with CRED_LOCK:
        creds = {k: v for k, v in SESSION_CREDS.items() if v}
    if not creds:
        return {"ok": False, "error": "Connectez-vous d'abord à au moins un système."}
    try:
        blob = encrypt_secret(json.dumps(creds).encode("utf-8"), pw)
        with open(SECRETS_PATH, "w", encoding="utf-8") as f:
            f.write(blob)
        try:
            os.chmod(SECRETS_PATH, 0o600)   # coffre lisible/écrit par le seul propriétaire
        except OSError:
            pass                            # best-effort (Windows / FS sans POSIX perms)
    except Exception as e:
        return {"ok": False, "error": "Écriture du coffre impossible : %s" % e}
    save_config({"remember_credentials": True})
    audit("creds_saved", systems=list(creds.keys()))
    return {"ok": True, "saved": sorted(creds.keys())}


def action_load_credentials(payload):
    """Déchiffre le coffre et charge les identifiants en mémoire de session."""
    pw = payload.get("passphrase") or ""
    if not os.path.isfile(SECRETS_PATH):
        return {"ok": False, "error": "Aucune connexion mémorisée."}
    try:
        with open(SECRETS_PATH, encoding="utf-8") as f:
            blob = f.read()
    except Exception as e:
        return {"ok": False, "error": "Lecture du coffre impossible : %s" % e}
    data = decrypt_secret(blob, pw)
    if data is None:
        return {"ok": False, "error": "Phrase secrète incorrecte (ou fichier altéré)."}
    try:
        creds = json.loads(data.decode("utf-8"))
    except Exception:
        return {"ok": False, "error": "Données déchiffrées illisibles."}
    loaded = []
    with CRED_LOCK:
        for k, v in creds.items():
            if k in SESSION_CREDS and isinstance(v, dict):
                SESSION_CREDS[k] = v
                loaded.append(k)
    audit("creds_loaded", systems=loaded)
    return {"ok": True, "loaded": sorted(loaded)}


def action_forget_credentials():
    """Supprime le coffre chiffré du disque."""
    try:
        if os.path.isfile(SECRETS_PATH):
            os.remove(SECRETS_PATH)
    except OSError as e:
        return {"ok": False, "error": "Suppression impossible : %s" % e}
    save_config({"remember_credentials": False})
    audit("creds_forgotten")
    return {"ok": True}


def _extract_iqn(obj):
    """Extrait un IQN d'un objet JSON par recherche textuelle (robuste aux
    variations de schéma entre versions Prism)."""
    m = IQN_RE.search(json.dumps(obj))
    return m.group(0) if m else None


def _nutanix_source():
    """Choisit la source Nutanix connectée : Prism Element en priorité, sinon
    Prism Central. Renvoie le nom de système ou None."""
    if SESSION_CREDS.get("nutanix"):
        return "nutanix"
    if SESSION_CREDS.get("prismcentral"):
        return "prismcentral"
    return None


def action_nutanix_vgs(query=""):
    """Liste les Volume Groups (IQN extrait si présent), filtrés. Source = Prism
    Element (REST v2, GET) ou Prism Central (API v3, POST .../list)."""
    sysname = _nutanix_source()
    if not sysname:
        return {"ok": False, "error": "Aucune connexion Nutanix (Prism Element ou Central).", "vgs": []}
    q = (query or "").lower()
    vgs, seen = [], set()

    def keep(vg):
        """Renvoie True si le VG a un uuid NOUVEAU (dédup anti-pagination), qu'il
        passe ou non le filtre de recherche."""
        name = vg.get("name") or (vg.get("spec") or {}).get("name") or (vg.get("status") or {}).get("name") or ""
        uuid = vg.get("uuid") or (vg.get("metadata") or {}).get("uuid") or ""
        key = uuid or name
        if key in seen:
            return False
        seen.add(key)
        if not q or q in name.lower() or q in uuid.lower():
            vgs.append({"name": name, "uuid": uuid, "iqn": _extract_iqn(vg)})
        return True

    guard, page_size = 0, 500
    if sysname == "nutanix":                    # Prism Element v2 : count/page
        page = 1
        while guard < 80:
            guard += 1
            r = _rest("nutanix", "GET", "/volume_groups?count=%d&page=%d" % (page_size, page))
            if not r["ok"]:
                return {"ok": False, "error": r.get("error") or "Erreur Nutanix.", "vgs": vgs}
            data = r.get("json") or {}
            items = data.get("entities") or data.get("items") or []
            fresh = sum(1 for vg in items if keep(vg))
            meta = data.get("metadata") or {}
            total = meta.get("grand_total_entities") or meta.get("total_entities")
            if not items or len(items) < page_size or fresh == 0:
                break
            if total is not None and page * page_size >= total:
                break
            page += 1
    else:                                       # Prism Central v3 : offset/length
        offset = 0
        while guard < 80:
            guard += 1
            r = _rest("prismcentral", "POST", "/volume_groups/list",
                      body={"kind": "volume_group", "length": page_size, "offset": offset})
            if not r["ok"]:
                return {"ok": False, "error": r.get("error") or "Erreur Nutanix.", "vgs": vgs}
            data = r.get("json") or {}
            items = data.get("entities") or []
            fresh = sum(1 for vg in items if keep(vg))
            meta = data.get("metadata") or {}
            total = meta.get("total_matches")
            if not items or len(items) < page_size or fresh == 0:
                break
            if total is not None and offset + page_size >= total:
                break
            offset += page_size
    return {"ok": True, "vgs": vgs, "source": sysname}


def action_nutanix_iqn(uuid):
    """Détail d'un VG : renvoie sa RÉFÉRENCE de volume (l'UUID du VG, qui suffit au
    CSI Nutanix moderne) et l'IQN s'il est exposé (clusters iSCSI hérités).
    L'UUID du VG = ce qu'il faut pour reconstruire le volumeHandle « <préfixe><uuid> »."""
    if not uuid:
        return {"ok": False, "error": "UUID de Volume Group manquant."}
    sysname = _nutanix_source()
    if not sysname:
        return {"ok": False, "error": "Aucune connexion Nutanix (Prism Element ou Central)."}
    r = _rest(sysname, "GET", "/volume_groups/%s" % urllib.parse.quote(str(uuid)))
    if not r["ok"]:
        return {"ok": False, "error": r.get("error")}
    j = r.get("json") or {}
    vg_uuid = j.get("uuid") or (j.get("metadata") or {}).get("uuid") or str(uuid)
    iqn = _extract_iqn(j)
    # `ref` = ce qu'on injecte dans le PV (UUID du VG). `iqn` reste informatif/legacy.
    return {"ok": bool(vg_uuid), "ref": vg_uuid, "uuid": vg_uuid, "iqn": iqn,
            "error": None if vg_uuid else "UUID introuvable dans la réponse Nutanix pour ce VG."}


def action_nutanix_detach_vg(vg_uuid):
    """Détache un Volume Group de TOUTES ses VM/initiateurs (Prism Element v2), pour
    que le CSI Nutanix puisse l'attacher au nœud. Indispensable après un clone HYCU :
    HYCU crée le VG cloné déjà attaché à la VM worker -> le CSI échoue à l'attacher
    (AttachIscsiClient ... task failed) et les pods restent bloqués."""
    if not vg_uuid:
        return {"ok": False, "error": "UUID de Volume Group manquant.", "detached": []}
    if _nutanix_source() != "nutanix":
        return {"ok": False, "detached": [],
                "error": "Le détachement automatique requiert Prism Element (API v2). "
                         "Connectez Prism Element, ou détachez le VG de sa VM dans Prism."}
    enc = urllib.parse.quote(str(vg_uuid))
    r = _rest("nutanix", "GET", "/volume_groups/%s" % enc)
    if not r["ok"]:
        return {"ok": False, "error": r.get("error"), "detached": []}
    attachments = (r.get("json") or {}).get("attachment_list") or []
    detached, errors = [], []
    for a in attachments:
        vm = a.get("vm_uuid")
        initiator = a.get("iscsi_initiator_name") or a.get("client_uuid")
        body = {"operation": "DETACH"}
        if vm:
            body["vm_uuid"] = vm
        elif initiator:
            body["iscsi_initiator_name"] = initiator
        else:
            continue
        dr = _rest("nutanix", "POST", "/volume_groups/%s/detach" % enc, body=body)
        (detached.append(vm or initiator) if dr["ok"]
         else errors.append("%s: %s" % (vm or initiator, dr.get("error"))))
    return {"ok": not errors, "detached": detached, "errors": errors,
            "already_free": not attachments}


def action_nutanix_vg_v4(uuid):
    """DIAGNOSTIC : config v4 d'un Volume Group + ses attachements iSCSI externes +
    ses disques, via Prism Central (API `v4.0.b1 Volumes`, celle que le CSI appelle).
    Sert à COMPARER un VG source qui s'attache à un VG cloné HYCU qui échoue, pour
    isoler le réglage qui diffère (accès client externe, CHAP, cible iSCSI, etc.)."""
    if not uuid:
        return {"ok": False, "error": "UUID de Volume Group manquant."}
    if not SESSION_CREDS.get("prismcentral"):
        return {"ok": False, "error": "Connectez Prism Central : l'API v4 Volumes (et le CSI) y sont servies."}
    enc = urllib.parse.quote(str(uuid))
    b = "/api/volumes/v4.0.b1/config/volume-groups/"
    vg = _rest_raw("prismcentral", "GET", b + enc)
    att = _rest_raw("prismcentral", "GET", b + enc + "/external-iscsi-attachments?$limit=50&$page=0")
    vmatt = _rest_raw("prismcentral", "GET", b + enc + "/vm-attachments?$limit=50&$page=0")
    disks = _rest_raw("prismcentral", "GET", b + enc + "/disks?$limit=50&$page=0")

    def part(r):
        return r.get("json") if r.get("ok") else {"error": r.get("error"), "raw": (r.get("raw") or "")[:400]}
    return {"ok": bool(vg.get("ok")), "uuid": uuid,
            "volume_group": part(vg),
            "external_iscsi_attachments": part(att),
            "vm_attachments": part(vmatt),
            "disks": part(disks),
            "error": None if vg.get("ok") else vg.get("error")}


def _clone_vg_disk_uuids(vg_uuid):
    """extId(s) du/des disque(s) d'un VG, via Prism Central v4 (la valeur attendue dans
    `volumeAttributes.hypervisorAttachedDiskUUIDs`). Renvoie une chaîne (jointe par ',')
    ou None."""
    enc = urllib.parse.quote(str(vg_uuid))
    r = _rest_raw("prismcentral", "GET",
                  "/api/volumes/v4.0.b1/config/volume-groups/%s/disks?$limit=50&$page=0" % enc)
    if not r.get("ok"):
        return None
    data = (r.get("json") or {}).get("data") or []
    # Tri pour un ordre canonique : l'API v4 ne garantit pas l'ordre des extId ; sans
    # tri, un VG multi-disques paraîtrait « changé » sur un simple ré-ordonnancement.
    ids = sorted(d.get("extId") for d in data if d.get("extId"))
    return ",".join(ids) if ids else None


def _set_clone_disk_uuids(pv_manifest, new_volume_handle, dry, log):
    """Réécrit `volumeAttributes.hypervisorAttachedDiskUUIDs` du PV cloné avec l'extId
    du disque du VG CLONÉ (lu via Prism Central v4). C'est ce champ qui fait choisir au
    CSI l'attach par hyperviseur (qui marche) plutôt que l'attach iSCSI (qui échoue).
    À appeler AVANT l'apply du PV.
    Renvoie True s'il faut/peut continuer, False si l'info est INTROUVABLE en mode réel
    (l'appelant décidera d'abandonner selon `clone_require_disk_uuids`)."""
    if not CONFIG.get("clone_fix_disk_uuids", True):
        return True
    vg_uuid = split_volume_handle(new_volume_handle or "")[1]
    csi = (pv_manifest.get("spec") or {}).get("csi") if isinstance(pv_manifest, dict) else None
    if not vg_uuid or not isinstance(csi, dict):
        return True
    if dry:
        log.append(logentry("Renseigner hypervisorAttachedDiskUUIDs (disque du VG cloné %s)" % vg_uuid,
                            dry=True, rc=None,
                            stdout="Lu via Prism Central v4 ; sans lui le CSI tente l'attach iSCSI (échec)."))
        return True
    if not SESSION_CREDS.get("prismcentral"):
        log.append(logentry("hypervisorAttachedDiskUUIDs NON renseigné (Prism Central non connecté)",
                            ok=False, rc=-1,
                            stderr="Le CSI tentera l'attach iSCSI et l'attachement échouera. Connectez Prism Central."))
        return False
    uuids = _clone_vg_disk_uuids(vg_uuid)
    if uuids:
        csi.setdefault("volumeAttributes", {})["hypervisorAttachedDiskUUIDs"] = uuids
        log.append(logentry("hypervisorAttachedDiskUUIDs renseigné depuis le VG cloné",
                            stdout="Disque(s) du VG cloné : %s" % uuids))
        return True
    log.append(logentry("hypervisorAttachedDiskUUIDs NON renseigné (disque introuvable)",
                        ok=False, rc=-1, stderr="Aucun disque lu pour le VG %s" % vg_uuid,
                        stdout="Le CSI tentera l'attach iSCSI ; vérifiez le VG cloné dans Prism."))
    return False


# NB : `action_nutanix_detach_vg` (ci-dessus) reste exposé pour un détachement MANUEL
# de VG via l'endpoint /api/nutanix/detach_vg, mais n'est plus appelé dans le flux clone
# (le bon correctif est `_set_clone_disk_uuids` : on garde l'attach-VM, qui est nécessaire).


def _refresh_pv_disk(ns, pvc_name, dry, log):
    """Après un restore IN-PLACE HYCU, le VG peut avoir un NOUVEAU disque (extId) : le
    `hypervisorAttachedDiskUUIDs` du PV devient périmé -> NodeStage échoue
    («failed to get symlink for disk …»). `spec.csi.volumeAttributes` étant IMMUABLE,
    on RECRÉE le PV (même volumeHandle/nom) avec le disque à jour, et le PVC. À appeler
    APP ARRÊTÉE. Renvoie (ok, detail_échec). No-op si disque inchangé ou conf désactivée."""
    if not CONFIG.get("inplace_refresh_pv_disk", True):
        return True, ""
    pvc_live, _ = kubectl_json(["get", "pvc", pvc_name, "-n", ns])
    pv_name = (pvc_live.get("spec") or {}).get("volumeName") if pvc_live else None
    if not pv_name:
        return True, ""
    pv_live, _ = kubectl_json(["get", "pv", pv_name])
    csi = ((pv_live or {}).get("spec") or {}).get("csi") or {}
    vh = csi.get("volumeHandle")
    old_disk = (csi.get("volumeAttributes") or {}).get("hypervisorAttachedDiskUUIDs")
    vg_uuid = split_volume_handle(vh or "")[1]
    if not vg_uuid:
        return True, ""
    if not SESSION_CREDS.get("prismcentral"):
        log.append(logentry("Disque du PV %s non vérifié (Prism Central non connecté)" % pv_name,
                            ok=False, rc=-1,
                            stderr="Si le pod reste en FailedMount («failed to get symlink»), connectez "
                                   "Prism Central et relancez la restauration sur place."))
        return True, ""                                  # non bloquant (HYCU n'a peut-être pas changé le disque)
    new_disk = _clone_vg_disk_uuids(vg_uuid)
    # Comparaison indépendante de l'ordre : un VG multi-disques ne doit pas être vu
    # comme « changé » sur un simple ré-ordonnancement des extId renvoyés par l'API v4.
    def _disk_set(s):
        return frozenset(x for x in (s or "").split(",") if x)
    if not new_disk or _disk_set(new_disk) == _disk_set(old_disk):
        return True, ""                                  # disque inchangé -> rien à faire
    log.append(logentry("Disque du VG remplacé par le restore in-place — rafraîchissement du PV %s" % pv_name,
                        stdout="hypervisorAttachedDiskUUIDs : %s -> %s" % (old_disk, new_disk)))
    if dry:
        log.append(logentry("Recréer le PV %s avec le disque à jour (Retain -> delete -> apply)" % pv_name,
                            dry=True, rc=None))
        return True, ""
    new_pv = clean_pv(json.loads(json.dumps(pv_live)))
    new_pv.setdefault("spec", {}).setdefault("csi", {}).setdefault("volumeAttributes", {})[
        "hypervisorAttachedDiskUUIDs"] = new_disk
    # Filet de sécurité : le PV recréé est forcé en Retain pour qu'une suppression
    # ULTÉRIEURE (autre échec, nettoyage opérateur, teardown de namespace) ne détruise
    # PAS le Volume Group restauré (reclaimPolicy=Delete par défaut côté Nutanix). Sans
    # cela, new_pv hériterait de la politique d'origine du PV live (souvent Delete).
    new_pv.setdefault("spec", {})["persistentVolumeReclaimPolicy"] = "Retain"
    pvc_manifest = clean_pvc(json.loads(json.dumps(pvc_live)))
    # Retain AVANT suppression : on ne supprime le PV QUE si son état est CERTAIN.
    # resource_state ne renvoie jamais "present" sur erreur kubectl transitoire (RBAC,
    # réseau, timeout API-server) ; dans le doute on AVORTE plutôt que de supprimer un
    # PV peut-être en politique Delete (sinon le CSI supprimerait le VG -> perte du
    # volume tout juste restauré in-place).
    st_pv, st_err = resource_state("pv", pv_name)
    if st_pv != "present":
        log.append(logentry("Rafraîchissement du PV %s annulé : état du PV indéterminé (%s)" % (pv_name, st_pv),
                            ok=False, rc=-1,
                            stderr=(st_err or "") + " — suppression refusée pour ne pas risquer la perte du "
                                   "Volume Group. Vérifiez l'accès kubectl puis relancez."))
        return False, "vérification de l'état du PV %s avant suppression" % pv_name
    pr = kubectl(["patch", "pv", pv_name, "--type=merge",
                  "-p", '{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}'],
                 dry=False, label="Protection du VG : PV %s -> Retain" % pv_name)
    log.append(pr)
    if not pr["ok"]:
        return False, "protection (Retain) du PV %s" % pv_name
    if not _delete_and_unblock("pvc", pvc_name, ns, log):
        return False, "suppression du PVC %s" % pvc_name
    if not _delete_and_unblock("pv", pv_name, None, log):
        return False, "suppression du PV %s" % pv_name
    ra = _apply_manifest(new_pv, "pv_%s" % pv_name, False, "Recréation du PV %s (disque rafraîchi)" % pv_name)
    log.append(ra)
    if not ra["ok"]:
        return False, "recréation du PV %s" % pv_name
    pvc_manifest.setdefault("spec", {})["volumeName"] = pv_name
    ra2 = _apply_manifest(pvc_manifest, "pvc_%s" % pvc_name, False, "Recréation du PVC %s" % pvc_name)
    log.append(ra2)
    if not ra2["ok"]:
        return False, "recréation du PVC %s" % pvc_name
    if not _wait_pvc_bound(pvc_name, ns, log):
        return False, "liaison (Bound) du PVC %s" % pvc_name
    return True, ""


# ----- HYCU : Volume Groups / points de restauration + déclenchement (API 5.2 vérifiée) -----
# Endpoints relevés et testés sur HYCU R-Cloud 5.2 (Swagger /rest/v1.0/api-docs) :
#   GET  /volumegroups                       -> liste des VG protégés
#   GET  /volumegroups/{vgUuid}/backups      -> points de restauration (backups) d'un VG
#   POST /volumegroups/vgrestore             -> déclenche le restore/clone (body RestoreSpecDTO)
#   GET  /jobs/{jobUuid}                      -> état du job
def _hycu_items(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("entities") or data.get("items") or []
    return []


def _hycu_first(j):
    """Premier OBJET (dict) utile d'une réponse HYCU : `entities[0]` si c'est un dict,
    sinon le dict `j`. Renvoie TOUJOURS un dict : certains endpoints renvoient des
    `entities` = listes de chaînes (UUID), qu'on ne déréférence pas par clé."""
    if isinstance(j, dict):
        ents = j.get("entities")
        if isinstance(ents, list):
            for e in ents:
                if isinstance(e, dict):
                    return e
        return j
    return {}


def _hycu_job_id(j):
    """Identifiant de job/tâche d'une réponse HYCU (format variable selon l'endpoint).
    Tolère : une réponse = chaîne (UUID nu), ou `entities`/racine = liste de chaînes
    (ex. /schedules/backupVolumeGroup renvoie des UUID de tâches), ou un objet dict."""
    if isinstance(j, str):
        return j or None
    seq = j.get("entities") if isinstance(j, dict) else (j if isinstance(j, list) else None)
    for e in (seq or []):
        if isinstance(e, str) and e:                 # entities = liste d'UUID (chaînes)
            return e
    o = _hycu_first(j)                                # entities = liste d'objets
    return (o.get("uuid") or o.get("jobUuid") or o.get("restoreManagedTaskUuid")
            or (o.get("metadata") or {}).get("jobUuid"))


def _hycu_list_vgs():
    """Parcourt TOUTES les pages de /volumegroups (HYCU pagine à 100 par défaut)
    et renvoie (items_bruts, erreur). Chaque item garde ses champs (uuid, name,
    externalId, hasBackups…)."""
    out, seen = [], set()
    page, page_size, total, guard = 1, 500, None, 0
    while guard < 80:                       # garde-fou : 80 * 500 = 40000 VG
        guard += 1
        r = _rest("hycu", "GET", "/volumegroups?pageSize=%d&pageNumber=%d" % (page_size, page))
        if not r["ok"]:
            return None, r.get("error")
        data = r.get("json") or {}
        items = _hycu_items(data)
        fresh = 0                           # dédup par uuid : robuste si l'API ignore l'offset
        for it in items:
            if not isinstance(it, dict):    # certains endpoints renvoient des entités = chaînes
                continue
            uid = it.get("uuid") or it.get("externalId") or it.get("name")
            if uid in seen:
                continue
            seen.add(uid); out.append(it); fresh += 1
        meta = data.get("metadata") or {}
        total = meta.get("totalEntityCount", total)
        if not items or len(items) < page_size or fresh == 0:  # fresh==0 -> page qui ne progresse plus
            break
        if total is not None and page * page_size >= total:
            break
        page += 1
    return out, None


def action_hycu_sources(query=""):
    """Liste TOUS les Volume Groups protégés par HYCU (lecture seule)."""
    items, err = _hycu_list_vgs()
    if err is not None:
        return {"ok": False, "error": err, "sources": []}
    q = (query or "").lower()
    out = []
    for it in items:
        name = it.get("name") or ""
        if q and q not in str(name).lower():
            continue
        out.append({"name": name, "uuid": it.get("uuid") or "",
                    "has_backups": bool(it.get("hasBackups"))})
    return {"ok": True, "sources": out, "total": len(items)}


def action_hycu_restore_points(source_uuid):
    """Liste les points de restauration (backups) d'un Volume Group HYCU."""
    if not source_uuid:
        return {"ok": False, "error": "Volume Group requis.", "points": []}
    r = _rest("hycu", "GET", "/volumegroups/%s/backups?pageSize=500&pageNumber=1"
              % urllib.parse.quote(str(source_uuid)))
    if not r["ok"]:
        return {"ok": False, "error": r.get("error"), "points": []}
    out = []
    for it in _hycu_items(r.get("json")):
        ms = it.get("restorePointInMillis")
        when = ""
        if ms:
            try:
                when = datetime.datetime.fromtimestamp(int(ms) / 1000.0).strftime("%Y-%m-%d %H:%M")
            except (ValueError, TypeError, OSError):
                when = str(ms)
        out.append({"id": it.get("uuid"), "time": when,
                    "status": it.get("status"),
                    "restorable": it.get("restoreAvailable", True)})
    return {"ok": True, "points": out}


def action_hycu_restore(payload):
    """Déclenche un restore/clone de Volume Group HYCU (POST /volumegroups/vgrestore).
    dry-run par défaut : montre l'appel exact (méthode + URL + corps) AVANT tout envoi."""
    dry = bool(payload.get("dry", True))
    rp = payload.get("restore_point_id")            # = backupUuid (point de restauration)
    if not rp:
        return {"ok": False, "error": "Point de restauration requis."}
    mode = payload.get("mode", "clone")
    new_name = (payload.get("new_name") or "").strip()
    src = payload.get("source_uuid")
    ns = payload.get("namespace")
    # Garde anti-stale : si un namespace est fourni, le VG source doit appartenir à
    # sa correspondance courante (recalculée serveur), comme pour action_hycu_protect.
    if ns and src:
        stale = _reject_stale_vgs(ns, [src])
        if stale:
            return _err(stale)
    base, api, _ = _system_cfg("hycu")
    path = "/volumegroups/vgrestore"
    body = {
        "backupUuid": rp,
        "restoreSource": payload.get("restore_source", "AUTO"),
        "createVolumeGroup": mode == "clone",       # clone = nouveau VG ; sinon restore sur place
        "startVgRestore": True,
    }
    if mode == "clone" and new_name:
        body["vgName"] = new_name
    if dry:
        return {"ok": True, "dry": True,
                "planned": {"method": "POST", "url": base + api + path, "body": body},
                "message": "Simulation : aucun appel HYCU envoyé. Vérifiez l'appel ci-dessus, "
                           "puis désactivez la simulation pour lancer réellement."}
    try:
        with action_lock():
            r = _rest("hycu", "POST", path, body=body)
            if not r["ok"]:
                return {"ok": False, "error": r.get("error"), "raw": (r.get("raw") or "")[:500]}
            job_id = _hycu_job_id(r.get("json") or {})
            audit("hycu_restore", restore_point=rp, mode=mode, vg_name=new_name, namespace=ns, job=job_id)
            return {"ok": True, "dry": False, "job_id": job_id, "raw": (r.get("raw") or "")[:500]}
    except _Busy as e:
        return _err(str(e))


def action_hycu_job(job_id):
    if not job_id:
        return {"ok": False, "error": "Identifiant de job manquant."}
    r = _rest("hycu", "GET", "/jobs/%s" % urllib.parse.quote(str(job_id)))
    if not r["ok"]:
        return {"ok": False, "error": r.get("error")}
    job = _hycu_first(r.get("json") or {})
    pct = job.get("completitionPct")   # fraction 0..1 sur HYCU 5.2 (faute de frappe de l'API, à NE PAS corriger)
    progress = round(pct * 100) if isinstance(pct, (int, float)) else None
    return {"ok": True, "status": job.get("status") or job.get("statusLocalized"),
            "progress": progress}


# ----- HYCU : protéger réellement les données (assigner politique + sauvegarder) -----
def action_hycu_policies():
    """Liste les politiques de protection HYCU."""
    r = _rest("hycu", "GET", "/policies")
    if not r["ok"]:
        return {"ok": False, "error": r.get("error"), "policies": []}
    out = []
    for it in _hycu_items(r.get("json")):
        out.append({"uuid": it.get("uuid"), "name": it.get("name")})
    return {"ok": True, "policies": out}


def _namespace_nutanix_vgs(ns):
    """Pour chaque PVC du namespace, déduit l'UUID du Volume Group Nutanix
    (depuis le volumeHandle du PV) et le nom du PV."""
    pvc_data, err = kubectl_json(["get", "pvc", "-n", ns])
    if err:
        return None, err
    out = []
    for pvc in pvc_data.get("items", []):
        name = pvc["metadata"]["name"]
        pv_name = pvc.get("spec", {}).get("volumeName")
        nutanix_uuid = None
        if pv_name:
            pv_data, _ = kubectl_json(["get", "pv", pv_name])
            if pv_data:
                info = analyse_pv(pv_data)
                if info["old_volume_handle"]:
                    nutanix_uuid = split_volume_handle(info["old_volume_handle"])[1]
        out.append({"pvc": name, "pv": pv_name, "nutanix_uuid": nutanix_uuid})
    return out, None


def action_hycu_match(ns):
    """Associe chaque PVC du namespace à son Volume Group HYCU.
    Pivot FIABLE = égalité EXACTE de l'UUID : l'externalId d'un VG Nutanix est
    l'UUID du Volume Group, identique à celui du volumeHandle du PV. Le match par
    NOM (nom du VG = nom du PV côté CSI) n'est qu'une SUGGESTION à confirmer, jamais
    auto-protégée. Toute ambiguïté (plusieurs VG pour un même UUID/nom) n'est jamais
    tranchée au hasard : le PVC est marqué 'ambiguous'."""
    if not _namespace_allowed(ns):
        return {"ok": False, "error": "Namespace '%s' non autorisé." % ns, "matches": []}
    vols, err = _namespace_nutanix_vgs(ns)
    if err:
        return {"ok": False, "error": err, "matches": []}
    items, herr = _hycu_list_vgs()
    if herr is not None:
        return {"ok": False, "error": herr, "matches": []}
    # Index sensibles aux collisions (listes), UUID normalisé via UUID_RE.
    by_ext, by_name = {}, {}
    for vg in items:
        if not isinstance(vg, dict):
            continue
        m = UUID_RE.search(vg.get("externalId") or "")
        if m:
            by_ext.setdefault(m.group(0).lower(), []).append(vg)
        nm = (vg.get("name") or "").strip().lower()
        if nm:
            by_name.setdefault(nm, []).append(vg)
    matches = []
    for v in vols:
        nu = (v.get("nutanix_uuid") or "").lower()
        pv = (v.get("pv") or "").strip().lower()
        ext_c = by_ext.get(nu, []) if nu else []
        name_c = by_name.get(pv, []) if pv else []
        hy, kind = None, "none"
        if len(ext_c) == 1:
            hy, kind = ext_c[0], "exact"
        elif len(ext_c) > 1:
            kind = "ambiguous"
        elif len(name_c) == 1:
            hy, kind = name_c[0], "name"        # suggestion -> à confirmer
        elif len(name_c) > 1:
            kind = "ambiguous"
        matches.append({
            "pvc": v["pvc"], "pv": v.get("pv"), "nutanix_uuid": v.get("nutanix_uuid"),
            "hycu_vg_uuid": hy.get("uuid") if hy else None,
            "hycu_vg_name": hy.get("name") if hy else None,
            "hycu_external_id": (hy.get("externalId") if hy else None),
            "match_kind": kind,                 # 'exact' | 'name' | 'ambiguous' | 'none'
            "trusted": kind == "exact",         # seul l'exact est auto-protégeable
            "matched": hy is not None,
            # État de protection HYCU (issu de l'objet VG, sans appel supplémentaire)
            "protected": hy.get("status") if hy else None,            # PROTECTED / UNPROTECTED / …
            "compliancy": hy.get("compliancyStatus") if hy else None,  # GREEN / GREY / RED
            "policy": hy.get("protectionGroupName") if hy else None,
            "has_backups": bool(hy.get("hasBackups")) if hy else False,
        })
    return {"ok": True, "namespace": ns, "matches": matches}


def _reject_stale_vgs(ns, uuids):
    """Re-vérifie côté serveur que tous les `uuids` (VG HYCU) appartiennent à la
    correspondance COURANTE du namespace (anti-stale / anti mauvais-volume). Renvoie
    un message d'erreur si l'un est hors-correspondance, sinon None."""
    if not ns:
        return None
    match = action_hycu_match(ns)
    if not match.get("ok"):
        return "Re-vérification de la correspondance impossible : %s" % match.get("error")
    allowed = {m["hycu_vg_uuid"] for m in match.get("matches", [])
               if m.get("matched") and m.get("hycu_vg_uuid")}
    bad = [u for u in uuids if u and u not in allowed]
    if bad:
        return ("Volume Group(s) hors de la correspondance actuelle du namespace « %s » : %s. "
                "Relancez l'analyse." % (ns, ", ".join(bad)))
    return None


def action_hycu_protect(payload):
    """Assigne (optionnellement) une politique HYCU aux Volume Groups, puis
    déclenche une sauvegarde à la demande. dry-run par défaut : montre les appels.
    Garde-fou : si 'namespace' est fourni, on RE-CALCULE la correspondance côté
    serveur et on REFUSE tout VG hors de ce match courant (anti-état périmé /
    anti-mauvaise cible)."""
    dry = bool(payload.get("dry", True))
    ns = payload.get("namespace")
    vg_uuids = sorted({u for u in (payload.get("vg_uuids") or []) if u})
    policy_uuid = (payload.get("policy_uuid") or "").strip()
    force_full = bool(payload.get("force_full"))
    if not vg_uuids:
        return {"ok": False, "error": "Aucun Volume Group HYCU à protéger "
                "(correspondance introuvable — voir l'analyse)."}

    if ns:
        stale = _reject_stale_vgs(ns, vg_uuids)
        if stale:
            return _err(stale)

    acquired = False
    if not dry:
        if not ACTION_LOCK.acquire(blocking=False):
            return _err("Une autre opération est déjà en cours. Réessayez.")
        acquired = True
    try:
        base, api, _ = _system_cfg("hycu")
        steps = []
        if policy_uuid:
            path = "/policies/%s/assign" % urllib.parse.quote(policy_uuid)
            body = {"volumeGroupUuidList": vg_uuids, "includeDependencies": False}
            if dry:
                steps.append({"label": "Assigner la politique", "ok": True, "dry": True,
                              "planned": {"method": "POST", "url": base + api + path, "body": body}})
            else:
                r = _rest("hycu", "POST", path, body=body)
                steps.append({"label": "Assigner la politique", "ok": r["ok"],
                              "error": r.get("error"), "raw": (r.get("raw") or "")[:300]})
                if not r["ok"]:
                    audit("hycu_protect", ok=False, step="assign", namespace=ns,
                          policy=policy_uuid, vgs=vg_uuids)
                    return {"ok": False, "error": "Échec de l'assignation de politique : %s" % r.get("error"),
                            "steps": steps, "dry": False}

        path = "/schedules/backupVolumeGroup"
        body = {"uuidList": vg_uuids, "forceFull": force_full}
        if dry:
            steps.append({"label": "Lancer la sauvegarde maintenant", "ok": True, "dry": True,
                          "planned": {"method": "POST", "url": base + api + path, "body": body}})
            return {"ok": True, "dry": True, "steps": steps}
        r = _rest("hycu", "POST", path, body=body)
        job_id = _hycu_job_id(r.get("json") or {})
        steps.append({"label": "Lancer la sauvegarde maintenant", "ok": r["ok"],
                      "error": r.get("error"), "job_id": job_id, "raw": (r.get("raw") or "")[:300]})
        audit("hycu_protect", ok=r["ok"], policy=policy_uuid or None, force_full=force_full,
              namespace=ns, vgs=vg_uuids, job=job_id)
        return {"ok": r["ok"], "dry": False, "steps": steps, "job_id": job_id}
    finally:
        if acquired:
            ACTION_LOCK.release()


def _wait_hycu_job(job_id, log, timeout=1800, label="Job HYCU"):
    """Attend la fin d'un job HYCU (poll /jobs/{uuid}). Renvoie True si succès."""
    if not job_id:
        log.append({"ok": False, "dry": False, "label": label, "rc": -1, "stdout": "",
                    "stderr": "Job HYCU non identifié — fin non confirmable."})
        return False
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = _rest("hycu", "GET", "/jobs/%s" % urllib.parse.quote(str(job_id)))
        if r["ok"]:
            job = _hycu_first(r.get("json") or {})
            status = str((job or {}).get("status") or "").upper()
            if status in ("OK", "DONE", "SUCCESS", "COMPLETED", "COMPLETE"):
                log.append({"ok": True, "dry": False, "label": "%s terminé" % label, "rc": 0,
                            "stdout": status, "stderr": ""})
                return True
            if status in ("FAILED", "ERROR", "FATAL", "ABORTED", "ABORT"):
                log.append({"ok": False, "dry": False, "label": "%s en échec" % label, "rc": -1,
                            "stdout": "", "stderr": status})
                return False
        time.sleep(3)
    log.append({"ok": False, "dry": False, "label": label, "rc": -1, "stdout": "",
                "stderr": "Délai dépassé (%ss) — le job continue côté HYCU." % timeout})
    return False


def action_orchestrate_inplace(payload, log=None):
    """Restauration SUR PLACE entièrement orchestrée, sans recréation de PV/PVC
    (l'identité du volume ne change pas) : arrêt de l'app -> attente du détachement
    -> restore in-place HYCU -> attente du job -> redémarrage -> vérification.
    payload : { namespace, items:[{pvc, source_vg_uuid, restore_point_id}], dry }.
    `log` (optionnel) = liste partagée pour la progression live."""
    ns = payload.get("namespace")
    dry = bool(payload.get("dry", True))
    if log is None:
        log = []
    if not _namespace_allowed(ns):
        return {"ok": False, "error": "Namespace '%s' non autorisé." % ns, "log": []}
    if not SESSION_CREDS.get("hycu"):
        return {"ok": False, "error": "Connectez-vous à HYCU pour orchestrer la restauration sur place.", "log": []}
    items = [it for it in (payload.get("items") or [])
             if it.get("source_vg_uuid") and it.get("restore_point_id")]
    if not items:
        return {"ok": False, "error": "Aucun volume avec un point de restauration sélectionné.", "log": []}

    # Garde anti-stale : les VG source doivent appartenir à la correspondance courante.
    stale = _reject_stale_vgs(ns, [it["source_vg_uuid"] for it in items])
    if stale:
        return _err(stale, log=[])

    # Garde contexte (mode réel) : ne pas déclencher un vgrestore in-place destructif
    # (qui ÉCRASE les données du volume live) sur un contexte non autorisé/non reconfirmé.
    if not dry:
        guard = _context_guard(payload)
        if guard:
            return guard

    acquired = False
    if not dry:
        if not ACTION_LOCK.acquire(blocking=False):
            return {"ok": False, "error": "Une autre opération est déjà en cours. Réessayez.", "log": []}
        acquired = True
    try:
        aborted = False
        pvc_names = [it["pvc"] for it in items]
        base, api, _ = _system_cfg("hycu")

        current, desired = _resolve_workloads(ns)
        log.append({"ok": True, "dry": dry, "label": "Réplicas mémorisés", "rc": 0, "stderr": "", "cmd": "(lecture)",
                    "stdout": ", ".join("%s/%s=%s" % (w["kind"], w["name"], w["replicas"]) for w in desired) or "aucun"})
        if not _stop_workloads(current, ns, dry, log)[0]:
            aborted = True

        if not dry and not aborted:
            if not _wait_pods_gone(ns, pvc_names, CONFIG["wait_timeout"], log):
                aborted = True

        for it in items:
            if aborted:
                break
            body = {"backupUuid": it["restore_point_id"], "restoreSource": "AUTO",
                    "createVolumeGroup": False, "startVgRestore": True}
            if dry:
                log.append({"ok": True, "dry": True, "label": "Restore in-place HYCU (%s)" % it["pvc"],
                            "planned": {"method": "POST", "url": base + api + "/volumegroups/vgrestore", "body": body}})
                continue
            r = _rest("hycu", "POST", "/volumegroups/vgrestore", body=body)
            jid = _hycu_job_id(r.get("json") or {})
            log.append({"ok": r["ok"], "dry": False, "label": "Restore in-place HYCU (%s)" % it["pvc"],
                        "job_id": jid, "rc": 0 if r["ok"] else -1, "stdout": "", "stderr": r.get("error") or ""})
            if not r["ok"]:
                aborted = True
                break
            if not _wait_hycu_job(jid, log, label="Restore HYCU %s" % it["pvc"]):
                aborted = True
                break

        # Après le restore in-place, HYCU a pu remplacer le disque du VG -> rafraîchir le
        # PV (recréation avec le bon hypervisorAttachedDiskUUIDs) sinon NodeStage échoue.
        if not aborted:
            for it in items:
                ok_ref, detail_ref = _refresh_pv_disk(ns, it["pvc"], dry, log)
                if not ok_ref:
                    aborted = True
                    log.append(logentry("Rafraîchissement du PV interrompu : %s" % detail_ref, ok=False, rc=-1))
                    break

        if not aborted:
            _restart_workloads(desired, ns, dry, log)
        else:
            log.append({"ok": False, "dry": dry, "label": "SÉQUENCE INTERROMPUE", "rc": -1, "stdout": "", "cmd": "",
                        "stderr": "Une étape a échoué. L'application reste ARRÊTÉE pour éviter de redémarrer sur "
                        "des données incohérentes. Corrigez puis relancez, ou redémarrez : " +
                        "; ".join("kubectl scale %s %s -n %s --replicas=%s" % (w["kind"], w["name"], ns, w["replicas"]) for w in desired)})

        if not dry:
            v = action_verify(ns)
            log.append({"ok": True, "dry": False, "label": "Vérification finale", "rc": 0, "stderr": "",
                        "cmd": "kubectl get pvc/pods", "stdout": json.dumps(v, indent=2)})

        ok_all = (not aborted) and all(x["ok"] or x.get("dry") for x in log)
        audit("orchestrate_inplace", namespace=ns, dry=dry, ok=ok_all, aborted=aborted,
              volumes=[it["pvc"] for it in items])
        return {"ok": ok_all, "error": None, "dry": dry, "aborted": aborted, "log": log}
    finally:
        if acquired:
            ACTION_LOCK.release()


# ------------------------------------------------------------------------------
# Clone d'application : copie de l'app sur le volume cloné (app d'origine intacte)
# ------------------------------------------------------------------------------
def _find_workloads_using_pvcs(ns, pvc_names):
    """Deployments/StatefulSets du namespace qui montent l'un des PVC visés."""
    wanted = set(pvc_names)
    out = []
    for kind in ("deployment", "statefulset"):
        data, _ = kubectl_json(["get", kind, "-n", ns])
        if not data:
            continue
        for w in data.get("items", []):
            vols = ((w.get("spec") or {}).get("template", {}).get("spec", {}).get("volumes")) or []
            used = [(v.get("persistentVolumeClaim") or {}).get("claimName") for v in vols]
            if any(c in wanted for c in used):
                w.setdefault("kind", "Deployment" if kind == "deployment" else "StatefulSet")
                out.append(w)
    return out


CLONE_LABEL = "app.kubernetes.io/managed-by"
CLONE_LABEL_VAL = "hycu-clone"


def _clone_pvc_manifest(src_pvc, target_ns, same_ns, suffix, new_pv_name):
    """Copie d'un PVC : renommé (même ns) ou re-namespacé, lié au nouveau PV."""
    p = clean_pvc(json.loads(json.dumps(src_pvc)))
    meta = p.setdefault("metadata", {})
    old = meta.get("name", "")
    new = (old + suffix) if same_ns else old
    meta["name"] = new
    meta["namespace"] = target_ns
    meta.setdefault("labels", {})[CLONE_LABEL] = CLONE_LABEL_VAL
    p.setdefault("spec", {})["volumeName"] = new_pv_name
    return new, p


def _clone_workload_manifest(w, target_ns, same_ns, suffix, pvc_rename):
    """Copie d'un workload : nouveau nom + labels isolés (même ns) ou nouveau
    namespace, et repointage des claimName via pvc_rename {ancien: nouveau}."""
    w = json.loads(json.dumps(w))
    w.pop("status", None)
    meta = w.setdefault("metadata", {})
    _strip_meta(meta)
    meta.pop("ownerReferences", None)
    meta.setdefault("labels", {})[CLONE_LABEL] = CLONE_LABEL_VAL
    if same_ns:
        meta["name"] = meta.get("name", "") + suffix
        spec = w.setdefault("spec", {})
        sel = (spec.setdefault("selector", {})).setdefault("matchLabels", {})
        tmpl_labels = spec.setdefault("template", {}).setdefault("metadata", {}).setdefault("labels", {})
        # Isole le sélecteur : suffixe les valeurs des matchLabels ET des labels du
        # template, PLUS un label d'isolation unique (qu'aucun Service/contrôleur
        # d'origine ne sélectionne) -> le clone n'adopte jamais les pods d'origine.
        iso = (suffix.lstrip("-") or "clone")
        for k in list(sel.keys()):
            sel[k] = str(sel[k]) + suffix
            if k in tmpl_labels:
                tmpl_labels[k] = str(tmpl_labels[k]) + suffix
        sel["hycu-clone"] = iso
        tmpl_labels["hycu-clone"] = iso
    else:
        meta["namespace"] = target_ns
    vols = ((w.get("spec") or {}).get("template", {}).get("spec", {}).get("volumes")) or []
    for v in vols:
        ref = v.get("persistentVolumeClaim")
        if ref and ref.get("claimName") in pvc_rename:
            ref["claimName"] = pvc_rename[ref["claimName"]]
    return w


def _referenced_objects(w):
    """Objets namespacés référencés par le pod template du workload :
    Secrets, ConfigMaps et ServiceAccount (≠ default). Sert au clone cross-namespace
    pour recréer ces dépendances dans le namespace cible (sans elles, les pods ne
    démarrent pas : montage de secret/cm manquant, SA introuvable)."""
    ts = ((w.get("spec") or {}).get("template", {}).get("spec")) or {}
    secrets, configmaps = set(), set()
    sa = ts.get("serviceAccountName") or ts.get("serviceAccount")
    sa = sa if (sa and sa != "default") else None
    for ips in (ts.get("imagePullSecrets") or []):
        if ips.get("name"):
            secrets.add(ips["name"])
    for v in (ts.get("volumes") or []):
        if (v.get("secret") or {}).get("secretName"):
            secrets.add(v["secret"]["secretName"])
        if (v.get("configMap") or {}).get("name"):
            configmaps.add(v["configMap"]["name"])
        for src in ((v.get("projected") or {}).get("sources") or []):  # volumes projetés
            if (src.get("secret") or {}).get("name"):
                secrets.add(src["secret"]["name"])
            if (src.get("configMap") or {}).get("name"):
                configmaps.add(src["configMap"]["name"])
    for cnt in (ts.get("containers") or []) + (ts.get("initContainers") or []):
        for ef in (cnt.get("envFrom") or []):
            if (ef.get("secretRef") or {}).get("name"):
                secrets.add(ef["secretRef"]["name"])
            if (ef.get("configMapRef") or {}).get("name"):
                configmaps.add(ef["configMapRef"]["name"])
        for e in (cnt.get("env") or []):
            vf = e.get("valueFrom") or {}
            if (vf.get("secretKeyRef") or {}).get("name"):
                secrets.add(vf["secretKeyRef"]["name"])
            if (vf.get("configMapKeyRef") or {}).get("name"):
                configmaps.add(vf["configMapKeyRef"]["name"])
    return {"secrets": secrets, "configmaps": configmaps, "serviceaccount": sa}


def _prepare_cloned_object(obj, target_ns):
    """Nettoie un objet namespacé (Secret/ConfigMap/ServiceAccount/Service) pour le
    recréer dans target_ns : retire l'identité runtime, re-namespace, marque le clone,
    et neutralise les champs alloués par le cluster (clusterIP, nodePort, token SA)."""
    o = json.loads(json.dumps(obj))
    o.pop("status", None)
    meta = o.setdefault("metadata", {})
    _strip_meta(meta)
    meta.pop("ownerReferences", None)
    meta["namespace"] = target_ns
    meta.setdefault("labels", {})[CLONE_LABEL] = CLONE_LABEL_VAL
    kind = o.get("kind")
    if kind == "Service":
        spec = o.setdefault("spec", {})
        for k in ("clusterIP", "clusterIPs", "externalIPs", "loadBalancerIP", "healthCheckNodePort"):
            spec.pop(k, None)
        for p in (spec.get("ports") or []):
            p.pop("nodePort", None)        # laisser le cluster réattribuer
    elif kind == "ServiceAccount":
        o.pop("secrets", None)             # tokens auto-générés par le cluster
    return o


def _fetch_for_clone(kind, name, src_ns, target_ns):
    """Récupère un objet du namespace source et le prépare pour le clone.
    Renvoie le manifeste, ou None si absent / non clonable (token de SA)."""
    data, _ = kubectl_json(["get", kind, name, "-n", src_ns])
    if not data:
        return None
    if kind == "secret" and data.get("type") == "kubernetes.io/service-account.token":
        return None  # géré automatiquement par le cluster, ne pas cloner
    return _prepare_cloned_object(data, target_ns)


def _services_for_workloads(src_ns, cloned_workloads, target_ns):
    """Services du namespace source dont le sélecteur cible les pods des workloads
    clonés (labels identiques en cross-namespace) -> à cloner pour la connectivité
    intra-app (ex. WordPress -> Service mariadb). Prêts pour apply dans target_ns."""
    data, _ = kubectl_json(["get", "svc", "-n", src_ns])
    if not data:
        return []
    pod_label_sets = []
    for w in cloned_workloads:
        lbls = (((w.get("spec") or {}).get("template") or {}).get("metadata") or {}).get("labels") or {}
        if lbls:
            pod_label_sets.append(lbls)
    out = []
    for svc in data.get("items", []):
        sel = (svc.get("spec") or {}).get("selector") or {}
        if not sel:
            continue  # headless sans sélecteur / ExternalName -> ignorer
        if any(all(pl.get(k) == v for k, v in sel.items()) for pl in pod_label_sets):
            out.append(_prepare_cloned_object(svc, target_ns))
    return out


def action_clone_app(payload, log=None):
    """Crée une COPIE de l'application sur le(s) volume(s) cloné(s), SANS toucher à
    l'app d'origine. Cible : même namespace (avec suffixe) ou autre namespace.
    payload : { namespace, target_namespace (vide=même), suffix, backup_path,
                items:[{pvc, new_ref|new_iqn, new_name}], dry }.
    new_ref = UUID du VG cloné (NKP), volumeHandle, ou IQN (legacy).
    `log` (optionnel) = liste partagée pour la progression live."""
    ns = payload.get("namespace")
    dry = bool(payload.get("dry", True))
    if log is None:
        log = []
    target_ns = (payload.get("target_namespace") or "").strip() or ns
    suffix = (payload.get("suffix") or "").strip()
    same_ns = (target_ns == ns)
    backup_path = payload.get("backup_path")
    backup_root = payload.get("backup_root")
    items = payload.get("items") or []
    if not _namespace_allowed(ns):
        return {"ok": False, "error": "Namespace '%s' non autorisé." % ns, "log": []}
    # NB : le namespace CIBLE d'un clone est une destination de COPIE (créée par l'outil),
    # pas une source : on ne le restreint donc PAS au namespace_filter (qui borne les
    # sources). On valide seulement son nom (RFC 1123) ; il est créé s'il n'existe pas.
    if same_ns and not suffix:
        return {"ok": False, "error": "Un suffixe est requis pour cloner dans le même namespace.", "log": []}
    if not K8S_NAME_RE.match(target_ns):
        return {"ok": False, "error": "Nom de namespace cible invalide : '%s'." % target_ns, "log": []}
    if not items:
        return {"ok": False, "error": "Aucun volume sélectionné.", "log": []}
    # Garde contexte (mode réel) : appliquer des manifestes (PV/PVC/workloads/Secrets)
    # sur le cluster courant exige un contexte autorisé/reconfirmé, comme la restauration.
    if not dry:
        guard = _context_guard(payload)
        if guard:
            return guard

    prepared, pvc_rename = [], {}
    for it in items:
        pvc_name = it.get("pvc")
        new_ref = (it.get("new_ref") or it.get("new_iqn") or "").strip()
        if not new_ref or not UUID_RE.search(new_ref):
            return {"ok": False, "error": "Référence du VG cloné manquante/invalide pour « %s » "
                    "(UUID du VG, volumeHandle, ou IQN)." % pvc_name, "log": []}
        old_pv, _ = _load_old_pv(ns, pvc_name, backup_path, backup_root)
        if old_pv is None:
            return {"ok": False, "error": "Manifeste du PV introuvable pour « %s »." % pvc_name, "log": []}
        built, err = build_new_pv(old_pv, new_ref, (it.get("new_name") or "").strip(), "clone")
        if err:
            return {"ok": False, "error": "%s : %s" % (pvc_name, err), "log": []}
        # Garde anti-confusion (comme la prévisualisation du restore) : refuser si la réf
        # est l'UUID du VG SOURCE (le clone pointerait vers le MÊME disque que l'app
        # d'origine -> multi-attach/corruption) ou le NOM du VG au lieu de son UUID.
        if built.get("same_uuid"):
            return {"ok": False, "error": "« %s » : la référence est identique au volume SOURCE — le clone "
                    "pointerait vers le même disque Nutanix que l'application d'origine (risque de "
                    "multi-attach/corruption). Collez l'UUID du VG CLONÉ." % pvc_name, "log": []}
        if built.get("looks_like_vg_name"):
            return {"ok": False, "error": "« %s » : la référence correspond au NOM du Volume Group "
                    "(« pvc-<uuid-du-PVC> ») et non à son UUID. Collez l'UUID du VG cloné." % pvc_name, "log": []}
        src_pvc = _load_backup_pvc(backup_path, pvc_name, backup_root)
        if src_pvc is None:
            live, _ = kubectl_json(["get", "pvc", pvc_name, "-n", ns])
            src_pvc = clean_pvc(json.loads(json.dumps(live))) if live else None
        if src_pvc is None:
            return {"ok": False, "error": "Manifeste du PVC introuvable pour « %s »." % pvc_name, "log": []}
        # Nom de PV cloné TOUJOURS distinct de l'original (les PV sont cluster-scoped ;
        # l'app d'origine garde le sien). Sinon on viserait à muter le PV de production.
        orig_pv_name = (old_pv.get("metadata") or {}).get("name") or ""
        clone_pv_name = built["new_name"]
        if not clone_pv_name or clone_pv_name == orig_pv_name:
            clone_pv_name = (orig_pv_name or "pvc-clone") + (suffix or "-clone")
        if clone_pv_name == orig_pv_name:
            return {"ok": False, "error": "Le nom du PV cloné doit différer de l'original « %s »." % orig_pv_name, "log": []}
        pv = built["manifest"]
        pv.setdefault("metadata", {})["name"] = clone_pv_name
        new_pvc_name, pvc_manifest = _clone_pvc_manifest(src_pvc, target_ns, same_ns, suffix, clone_pv_name)
        cr = (pv.get("spec") or {}).get("claimRef")
        if isinstance(cr, dict):
            cr["name"] = new_pvc_name
            cr["namespace"] = target_ns
        pvc_rename[pvc_name] = new_pvc_name
        prepared.append({"pvc": pvc_name, "pv": pv, "pvc_manifest": pvc_manifest,
                         "new_pv_name": clone_pv_name, "new_pvc_name": new_pvc_name,
                         "orig_pv_name": orig_pv_name})

    workloads = _find_workloads_using_pvcs(ns, [it["pvc"] for it in items])
    warnings = []
    for w in workloads:
        wname = w["metadata"]["name"]
        # Le workload ne doit monter QUE des PVC sélectionnés : sinon son clone
        # référencerait le volume d'ORIGINE (multi-attach RWO / partage RWX prod,
        # ou claimName inexistant en autre namespace).
        vols = ((w.get("spec") or {}).get("template", {}).get("spec", {}).get("volumes")) or []
        claims = [(v.get("persistentVolumeClaim") or {}).get("claimName") for v in vols if v.get("persistentVolumeClaim")]
        missing = sorted({c for c in claims if c and c not in pvc_rename})
        if missing:
            return {"ok": False, "error": "Le workload « %s » monte aussi le(s) PVC %s non sélectionné(s) : "
                    "sélectionnez TOUS les volumes de cette application pour la cloner." % (wname, ", ".join(missing)),
                    "log": []}
        # Clone même-namespace : un sélecteur matchExpressions ne peut pas être isolé
        # par simple suffixe -> refuser (utiliser un autre namespace).
        if same_ns and ((w.get("spec") or {}).get("selector") or {}).get("matchExpressions"):
            return {"ok": False, "error": "Le workload « %s » utilise un sélecteur matchExpressions : le clone dans "
                    "le même namespace n'est pas supporté (risque de collision de pods). Choisissez « Autre namespace »." % wname,
                    "log": []}
        if w.get("kind") == "StatefulSet" and (w.get("spec") or {}).get("volumeClaimTemplates"):
            warnings.append("StatefulSet « %s » utilise des volumeClaimTemplates : son clone provisionnera de "
                            "NOUVEAUX volumes (pas le VG cloné). À adapter manuellement." % wname)
    cloned_workloads = [_clone_workload_manifest(w, target_ns, same_ns, suffix, pvc_rename) for w in workloads]

    # Dépendances namespacées : en clone CROSS-namespace, recréer dans le namespace
    # cible les Secrets / ConfigMaps / ServiceAccount référencés + les Services qui
    # ciblent les pods clonés (sinon les pods ne démarrent pas / l'app ne se joint pas).
    clone_refs = payload.get("clone_refs", True)
    dep_manifests, dep_summary, dep_missing = [], [], []
    if not same_ns and workloads and clone_refs:
        want_secrets, want_cms, want_sas = set(), set(), set()
        for w in workloads:
            r = _referenced_objects(w)
            want_secrets |= r["secrets"]
            want_cms |= r["configmaps"]
            if r["serviceaccount"]:
                want_sas.add(r["serviceaccount"])
        for sa in sorted(want_sas):
            o = _fetch_for_clone("serviceaccount", sa, ns, target_ns)
            (dep_manifests.append(o) or dep_summary.append("ServiceAccount " + sa)) if o else dep_missing.append("ServiceAccount " + sa)
        for cm in sorted(want_cms):
            o = _fetch_for_clone("configmap", cm, ns, target_ns)
            (dep_manifests.append(o) or dep_summary.append("ConfigMap " + cm)) if o else dep_missing.append("ConfigMap " + cm)
        for sec in sorted(want_secrets):
            o = _fetch_for_clone("secret", sec, ns, target_ns)
            (dep_manifests.append(o) or dep_summary.append("Secret " + sec)) if o else dep_missing.append("Secret " + sec)
        for s in _services_for_workloads(ns, cloned_workloads, target_ns):
            dep_manifests.append(s)
            dep_summary.append("Service " + s["metadata"]["name"])
        if dep_summary:
            warnings.append("Dépendances clonées automatiquement vers « %s » : %s." % (target_ns, ", ".join(dep_summary)))
        if dep_missing:
            warnings.append("Référencé(s) par l'app mais INTROUVABLE(S) dans « %s » — à créer à la main : %s."
                            % (ns, ", ".join(dep_missing)))
        warnings.append("Non clonés automatiquement : Ingress, NetworkPolicies et les liaisons RBAC "
                        "(RoleBindings) des ServiceAccounts — à recréer si l'app en dépend.")
    elif not same_ns and workloads and not clone_refs:
        allrefs = set()
        for w in workloads:
            r = _referenced_objects(w)
            allrefs |= {"Secret " + s for s in r["secrets"]} | {"ConfigMap " + c for c in r["configmaps"]}
            if r["serviceaccount"]:
                allrefs.add("ServiceAccount " + r["serviceaccount"])
        if allrefs:
            warnings.append("Clone des dépendances DÉSACTIVÉ : à recréer manuellement dans « %s » : %s."
                            % (target_ns, ", ".join(sorted(allrefs))))
    if same_ns and workloads:
        warnings.append("Same-namespace : les Services / Ingress / NetworkPolicies de l'app NE sont PAS clonés et "
                        "peuvent router vers les pods d'origine (labels hors-sélecteur conservés). À cloner/éditer séparément.")
    if not workloads:
        warnings.append("Aucun Deployment/StatefulSet ne monte ces PVC : seuls le PV et le PVC clonés seront "
                        "créés (déployez votre application dessus).")

    preview = {"target_namespace": target_ns, "same_namespace": same_ns,
               "pvs": [p["new_pv_name"] for p in prepared],
               "pvcs": [p["new_pvc_name"] for p in prepared],
               "workloads": ["%s/%s" % (w["kind"], w["metadata"]["name"]) for w in cloned_workloads],
               "dependencies": dep_summary}

    acquired = False
    if not dry:
        if not ACTION_LOCK.acquire(blocking=False):
            return {"ok": False, "error": "Une autre opération est déjà en cours. Réessayez.", "log": []}
        acquired = True
    try:
        # (log partagé pour la progression live, ou créé en tête de fonction)
        # Pré-vol (réel) : refuser si un objet cible existe déjà (collision de nom /
        # re-run), pour ne pas écraser une vraie app ou un PV de production.
        if not dry:
            coll = []
            for p in prepared:
                st, _ = resource_state("pv", p["new_pv_name"])
                if st != "absent":
                    coll.append("PV %s%s" % (p["new_pv_name"], " (injoignable)" if st == "error" else ""))
                st, _ = resource_state("pvc", p["new_pvc_name"], target_ns)
                if st != "absent":
                    coll.append("PVC %s/%s" % (target_ns, p["new_pvc_name"]))
            for w in cloned_workloads:
                st, _ = resource_state((w.get("kind") or "Deployment").lower(), w["metadata"]["name"], target_ns)
                if st != "absent":
                    coll.append("%s %s/%s" % (w.get("kind"), target_ns, w["metadata"]["name"]))
            if coll:
                return {"ok": False, "error": "Objet(s) déjà présent(s) — refus pour ne rien écraser : %s. "
                        "Changez le suffixe ou le namespace cible." % ", ".join(coll), "log": []}
        # Pré-résoudre le disque de CHAQUE VG cloné (renseigne hypervisorAttachedDiskUUIDs)
        # AVANT toute création : si introuvable en réel, on abandonne sans rien créer.
        for p in prepared:
            handle = ((p["pv"].get("spec") or {}).get("csi") or {}).get("volumeHandle")
            if not _set_clone_disk_uuids(p["pv"], handle, dry, log) and not dry and CONFIG.get("clone_require_disk_uuids", True):
                return {"ok": False, "log": log, "warnings": warnings, "preview": preview,
                        "error": "Disque du VG cloné introuvable pour « %s » (Prism Central requis) — "
                                 "rien n'a été créé." % p["new_pvc_name"]}
        if not same_ns:
            log.append(_apply_manifest({"apiVersion": "v1", "kind": "Namespace",
                                        "metadata": {"name": target_ns}},
                                       "ns_%s" % target_ns, dry, "Namespace cible « %s »" % target_ns))
        # Dépendances (Secrets/ConfigMaps/SA/Services) AVANT les workloads. On NE
        # remplace PAS une dépendance déjà présente dans la cible (ne rien écraser).
        for o in dep_manifests:
            k = (o.get("kind") or "").lower()
            nm = o["metadata"]["name"]
            if not dry:
                st, _ = resource_state(k, nm, target_ns)
                if st == "present":
                    log.append({"ok": True, "dry": False, "rc": 0, "cmd": "", "stderr": "",
                                "label": "%s %s déjà présent — conservé" % (o.get("kind"), nm),
                                "stdout": "Non écrasé (la version existante de « %s » est gardée)." % target_ns})
                    continue
            log.append(_apply_manifest(o, "clonedep_%s_%s" % (k, nm), dry,
                                       "Dépendance clonée %s %s/%s" % (o.get("kind"), target_ns, nm)))
        for p in prepared:  # hypervisorAttachedDiskUUIDs déjà renseigné dans la pré-passe ci-dessus
            log.append(_apply_manifest(p["pv"], "clonepv_%s" % p["new_pv_name"], dry,
                                       "PV cloné %s" % p["new_pv_name"]))
            log.append(_apply_manifest(p["pvc_manifest"], "clonepvc_%s" % p["new_pvc_name"], dry,
                                       "PVC cloné %s (ns %s)" % (p["new_pvc_name"], target_ns)))
        for w in cloned_workloads:
            log.append(_apply_manifest(w, "clonewl_%s" % w["metadata"]["name"], dry,
                                       "Application clonée %s/%s (ns %s)" % (w["kind"], w["metadata"]["name"], target_ns)))
        ok_all = all(x["ok"] or x.get("dry") for x in log)
        audit("clone_app", namespace=ns, target_namespace=target_ns, dry=dry, ok=ok_all,
              items=[it["pvc"] for it in items])
        return {"ok": ok_all, "error": None, "dry": dry, "log": log, "warnings": warnings,
                "preview": preview,
                "manifests_preview": json.dumps(cloned_workloads, indent=2) if dry else None}
    finally:
        if acquired:
            ACTION_LOCK.release()


# ------------------------------------------------------------------------------
# Serveur HTTP minimal — durci (Host/Origin + jeton anti-CSRF + erreurs génériques)
# ------------------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _send(self, code, body, ctype="application/json", extra_headers=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        # charset uniquement pour le texte ; surtout pas pour un binaire (zip…).
        ct = ctype if (";" in ctype or "zip" in ctype or "octet-stream" in ctype) else ctype + "; charset=utf-8"
        try:
            self.send_response(code)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            # Empêche le navigateur de servir une ancienne version en cache.
            self.send_header("Cache-Control", "no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()           # flush des en-têtes (écrit sur le socket)
            self.wfile.write(data)        # corps de la réponse
        except ConnectionError:
            # Le client a fermé la connexion avant la fin de la réponse (rafraîchissement,
            # navigation, requête annulée par le navigateur/une extension…). Il n'y a plus
            # rien à envoyer : on ignore proprement, au lieu de laisser un traceback
            # ConnectionAbortedError [WinError 10053] / BrokenPipe / ConnectionReset polluer
            # la console (sans incidence sur le serveur, qui continue de tourner).
            pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj))

    def _download_backup(self, raw_path, root):
        """Empaquette un dossier de sauvegarde en .zip et le renvoie en téléchargement.
        Sert à SORTIR une sauvegarde du conteneur/Pod vers le poste de l'opérateur via le
        navigateur (le serveur ne peut pas écrire sur le disque du client). Le chemin est
        validé par _safe_backup_path (anti-traversée : reste sous backup_root ou un dossier
        personnalisé explicitement désigné)."""
        full = _safe_backup_path(raw_path, root)
        if not full or not os.path.isdir(full):
            return self._send(404, "Sauvegarde introuvable.", "text/plain")
        # Nom lisible : <ns>_<horodatage>.zip pour une sauvegarde, sinon le nom du dossier.
        top = os.path.basename(full.rstrip("/\\")) or "backups"
        if os.path.isfile(os.path.join(full, "index.json")):
            top = "%s_%s" % (os.path.basename(os.path.dirname(full)), top)
        fname = re.sub(r"[^A-Za-z0-9._-]+", "_", top) + ".zip"
        buf, total = io.BytesIO(), 0
        try:
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                for dirpath, _dirs, fnames in os.walk(full):
                    for n in sorted(fnames):
                        fp = os.path.join(dirpath, n)
                        if not os.path.isfile(fp):
                            continue
                        total += os.path.getsize(fp)
                        if total > 512 * 1024 * 1024:   # garde-fou : 512 Mo décompressés
                            return self._send(413, "Sauvegarde trop volumineuse pour un téléchargement direct.", "text/plain")
                        z.write(fp, os.path.join(top, os.path.relpath(fp, full)))
        except OSError as e:
            print("Erreur zip sauvegarde %s : %s" % (full, e))
            return self._send(500, "Erreur lors de la création de l'archive.", "text/plain")
        return self._send(200, buf.getvalue(), "application/zip",
                          {"Content-Disposition": 'attachment; filename="%s"' % fname})

    def _origin_ok(self, require_origin=False):
        """Anti-DNS-rebinding : l'en-tête Host doit pointer vers la boucle locale ;
        si Origin/Referer est présent, il doit aussi être local. Sur les requêtes
        mutatrices (POST), au moins l'un des deux doit être présent ET local."""
        if not _host_is_local(self.headers.get("Host")):
            return False
        seen = False
        for h in ("Origin", "Referer"):
            val = self.headers.get(h)
            if val:
                seen = True
                try:
                    name = urllib.parse.urlparse(val).hostname
                except Exception:
                    return False
                if name not in ALLOWED_HOSTS:
                    return False
        if require_origin and not seen:
            return False
        return True

    def do_GET(self):
        if not self._origin_ok():
            return self._send(403, "Forbidden", "text/plain")
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        if path == "/":
            return self._send(200, HTML.replace("__CSRF_TOKEN__", CSRF_TOKEN)
                              .replace("__VERSION__", VERSION).replace("__LOGO__", _logo_markup()), "text/html")
        try:
            if path == "/api/context":
                return self._json(action_context())
            if path == "/api/contexts":
                return self._json(action_contexts(qs.get("kubeconfig")))
            if path == "/api/namespaces":
                return self._json(action_namespaces())
            if path == "/api/ns_filter":
                return self._json(action_ns_filter())
            if path == "/api/pvcs":
                return self._json(action_pvcs(qs.get("ns", "")))
            if path == "/api/backups":
                return self._json({"backups": list_backups(qs.get("ns", ""), qs.get("root"))})
            if path == "/api/backup/download":
                return self._download_backup(qs.get("path", ""), qs.get("root"))
            if path == "/api/verify":
                return self._json(action_verify(qs.get("ns", "")))
            if path == "/api/config":
                return self._json(action_get_config())
            if path == "/api/conn_status":
                return self._json(action_conn_status())
            if path == "/api/op_status":
                return self._json(action_op_status(qs.get("id", "")))
            if path == "/api/nutanix/vgs":
                return self._json(action_nutanix_vgs(qs.get("q", "")))
            if path == "/api/nutanix/vg_v4":
                return self._json(action_nutanix_vg_v4(qs.get("uuid", "")))
            if path == "/api/hycu/sources":
                return self._json(action_hycu_sources(qs.get("q", "")))
            if path == "/api/hycu/restorepoints":
                return self._json(action_hycu_restore_points(qs.get("source", "")))
            if path == "/api/hycu/policies":
                return self._json(action_hycu_policies())
            if path == "/api/hycu/match":
                return self._json(action_hycu_match(qs.get("ns", "")))
        except Exception as e:
            print("Erreur GET %s : %s" % (path, e))
            return self._json({"error": "Erreur interne."}, 500)
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        if not self._origin_ok(require_origin=True):
            return self._send(403, "Forbidden", "text/plain")
        if self.headers.get("X-CSRF-Token") != CSRF_TOKEN:
            return self._json({"error": "Jeton anti-CSRF invalide ou absent."}, 403)
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > 5 * 1024 * 1024:
            return self._json({"error": "Charge trop volumineuse."}, 413)
        try:
            raw = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
            payload = json.loads(raw or "{}")
        except (ValueError, json.JSONDecodeError):
            return self._json({"error": "JSON invalide"}, 400)
        path = urllib.parse.urlparse(self.path).path
        try:
            if path == "/api/backup":
                return self._json(action_backup(payload.get("ns", ""), payload.get("dest")))
            if path == "/api/backup_all":
                return self._json(action_backup_all(payload.get("dest")))
            if path == "/api/prepare_restore":
                return self._json(action_prepare_restore(payload))
            if path == "/api/execute_restore":
                return self._json(_run_async(action_execute_restore, payload))
            if path == "/api/config":
                return self._json(action_set_config(payload))
            if path == "/api/connect":
                return self._json(action_connect(payload))
            if path == "/api/disconnect":
                return self._json(action_disconnect(payload))
            if path == "/api/nutanix/iqn":
                return self._json(action_nutanix_iqn(payload.get("uuid")))
            if path == "/api/nutanix/detach_vg":
                return self._json(action_nutanix_detach_vg(payload.get("uuid")))
            if path == "/api/hycu/restore":
                return self._json(action_hycu_restore(payload))
            if path == "/api/hycu/job":
                return self._json(action_hycu_job(payload.get("job_id")))
            if path == "/api/creds/save":
                return self._json(action_save_credentials(payload))
            if path == "/api/creds/load":
                return self._json(action_load_credentials(payload))
            if path == "/api/creds/forget":
                return self._json(action_forget_credentials())
            if path == "/api/ns_filter":
                return self._json(action_set_ns_filter(payload))
            if path == "/api/hycu/protect":
                return self._json(action_hycu_protect(payload))
            if path == "/api/orchestrate/inplace":
                return self._json(_run_async(action_orchestrate_inplace, payload))
            if path == "/api/clone_app":
                return self._json(_run_async(action_clone_app, payload))
        except Exception as e:
            print("Erreur POST %s : %s" % (path, e))
            return self._json({"ok": False, "error": "Erreur interne."}, 500)
        return self._json({"error": "not found"}, 404)


# ------------------------------------------------------------------------------
# Logo embarqué (offline / site isolé) : si un fichier hycu_logo.* est présent à
# côté du programme (ou via CONFIG["logo_path"]), il est INLINÉ en data-URI base64
# dans la page — aucune requête réseau (fonctionne en dark site). À défaut, un repère
# neutre est affiché (ce N'EST PAS le logo officiel HYCU : déposez votre fichier).
# ------------------------------------------------------------------------------
LOGO_BASENAMES = ("hycu_logo.svg", "hycu_logo.png", "hycu_logo.webp",
                  "hycu_logo.jpg", "hycu_logo.jpeg", "hycu_logo.gif")
LOGO_MIME = {".svg": "image/svg+xml", ".png": "image/png", ".webp": "image/webp",
             ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif"}
LOGO_MAX_BYTES = 512 * 1024

# Repère neutre par défaut (générique, pas la marque officielle).
LOGO_PLACEHOLDER = (
    '<svg class="logo" width="38" height="38" viewBox="0 0 38 38" role="img" aria-label="HYCU">'
    '<rect x="1" y="1" width="36" height="36" rx="9" fill="#43128E"></rect>'
    '<path d="M19 8 L28 11 V19 C28 24.5 24 28.5 19 30.5 C14 28.5 10 24.5 10 19 V11 Z" fill="#ADFF00"></path>'
    '<path d="M14.7 18.6 l3 3 l6.6 -7.6" fill="none" stroke="#1B0C33" stroke-width="2.6"'
    ' stroke-linecap="round" stroke-linejoin="round"></path>'
    '</svg>')


def _scan_brand_logo(d):
    """Repère un asset de marque déposé tel quel dans `d` (ex.
    « HYCU_Logomark_HYCUPurple_RGB.svg ») : fichier image dont le nom commence par
    « hycu » et contient « logo »/« logomark ». Priorité au vectoriel (.svg) puis au
    nom le plus court. Renvoie un chemin ou None."""
    try:
        names = os.listdir(d)
    except Exception:
        return None
    cands = []
    for n in names:
        ext = os.path.splitext(n)[1].lower()
        low = n.lower()
        if ext in LOGO_MIME and low.startswith("hycu") and ("logo" in low):
            cands.append(n)
    cands.sort(key=lambda n: (0 if n.lower().endswith(".svg") else 1, len(n), n.lower()))
    return os.path.join(d, cands[0]) if cands else None


def _find_logo_file():
    """Localise un fichier logo local : 1) CONFIG['logo_path'] explicite ; 2) hycu_logo.*
    ; 3) un asset de marque déposé tel quel (HYCU…logo….svg/png). Cherche dans le
    répertoire courant puis à côté du script. Renvoie un chemin ou None."""
    cfg = (CONFIG.get("logo_path") or "").strip()
    if cfg and os.path.isfile(cfg):
        return cfg
    here = os.path.dirname(os.path.abspath(__file__))
    dirs = [os.getcwd(), here]
    for d in dirs:                                   # 2) noms explicites hycu_logo.*
        for base in LOGO_BASENAMES:
            p = os.path.join(d, base)
            try:
                if os.path.isfile(p):
                    return p
            except Exception:
                pass
    for d in dirs:                                   # 3) asset de marque officiel
        p = _scan_brand_logo(d)
        if p:
            return p
    return None


def _logo_markup():
    """Markup du logo pour l'en-tête : <img> en data-URI base64 si un fichier local
    existe (embarqué -> hors-ligne), sinon le repère neutre par défaut."""
    p = _find_logo_file()
    if not p:
        return LOGO_PLACEHOLDER
    try:
        if os.path.getsize(p) > LOGO_MAX_BYTES:
            return LOGO_PLACEHOLDER                       # garde-fou : logo déraisonnable
        with open(p, "rb") as f:
            raw = f.read()
        mime = LOGO_MIME.get(os.path.splitext(p)[1].lower(), "application/octet-stream")
        uri = "data:%s;base64,%s" % (mime, base64.b64encode(raw).decode("ascii"))
        return '<img class="logo" src="%s" alt="HYCU" />' % uri
    except Exception:
        return LOGO_PLACEHOLDER


# ------------------------------------------------------------------------------
# Interface (HTML + CSS + JS, un seul bloc, vanilla)
# ------------------------------------------------------------------------------
HTML = r"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf-token" content="__CSRF_TOKEN__">
<title>HYCU · Kubernetes sur Nutanix</title>
<style>
  :root{
    /* Palette officielle HYCU : violet (marque), gris (neutres), chartreuse (accent) */
    --ink:#1B0C33;        /* HP0 Black Purple */
    --paper:#F2F4F8;      /* HG11 Ghost Gray */
    --line:#DDE1E6;       /* HG10 Lighter Gray */
    --teal:#721EF2;       /* HP4 Solid Purple (action principale) */
    --teal-d:#43128E;     /* HP2 HYCU Purple (survol / accents) */
    --accent:#ADFF00;     /* HC8 Chartreuse (énergie / surlignage) */
    --amber:#c46b18; --red:#9c2b22;
    --muted:#565C63;      /* gris assombri pour contraste AA (≥4.5:1 sur fond clair) */
    --card:#FFFFFF; --good:#5c7a00; --warn:#c46b18;
  }
  *{box-sizing:border-box}
  body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
       background:var(--paper);color:var(--ink);line-height:1.5}
  .mono,code,pre,textarea,.tag{font-family:"SF Mono",ui-monospace,Menlo,Consolas,monospace}
  header{background:var(--ink);color:#fff;padding:18px 22px;
         display:flex;flex-wrap:wrap;gap:14px;align-items:center;justify-content:space-between}
  header h1{margin:0;font-size:19px;font-weight:700;letter-spacing:.2px}
  header h1 small{display:block;font-size:11px;color:#B8B4FC;font-weight:400;
                  text-transform:uppercase;letter-spacing:1.5px;margin-top:3px}
  .brand{display:flex;align-items:center;gap:13px}
  .logo{flex:none;display:block;height:38px;width:auto;max-width:180px}
  .wm{color:var(--accent);font-weight:800;letter-spacing:2px;margin-right:8px}
  .ctx{font-size:12px;color:#E9E6FF;font-weight:600}
  .ver{font-family:ui-monospace,Consolas,monospace;font-size:11px;color:#C9C4FF;font-weight:600;opacity:.85}
  /* Focus clavier visible partout (accessibilité). */
  button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible,[tabindex]:focus-visible{
    outline:3px solid var(--accent);outline-offset:2px;border-radius:4px}
  /* Stepper (fil conducteur du parcours Restaurer). */
  .stepper{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}
  .stepper .st{font-size:12px;font-weight:600;color:var(--muted);background:#EEF0F6;border-radius:20px;padding:5px 12px}
  .stepper .st.on{background:var(--teal);color:#fff}
  .stepper .st.done{background:#E6F0CC;color:var(--good)}
  .ctx b{color:#fff}
  .ctx .bad{color:#f3b0a8}
  .wrap{max-width:980px;margin:0 auto;padding:22px}
  .dry{display:flex;align-items:center;gap:10px;background:#F3F2FF;border:1px solid #D0CEFB;
       border-radius:8px;padding:10px 14px;font-size:13px;margin-bottom:18px;color:#43128E;
       position:sticky;top:0;z-index:40}
  .dry.live{background:#fbe9e7;border-color:#e3a9a2;color:#7a221b}
  /* Mode réel : bandeau rouge fixe en haut de fenêtre, visible même en scrollant. */
  .realbar{position:fixed;top:0;left:0;right:0;height:5px;background:var(--red);z-index:200;display:none}
  body.realmode .realbar{display:block}
  body.realmode header{box-shadow:inset 0 -3px 0 var(--red)}
  /* Modale de confirmation des actions destructives. */
  .modal-bg{position:fixed;inset:0;background:rgba(20,12,40,.55);display:flex;align-items:center;
            justify-content:center;z-index:300;padding:16px}
  .modal{background:#fff;border-radius:12px;max-width:540px;width:100%;padding:22px;
         box-shadow:0 24px 70px rgba(0,0,0,.4)}
  .modal h3{margin:0 0 10px;color:var(--red);font-size:17px}
  .modal .dm-line{font-size:13px;margin:5px 0;line-height:1.5}
  .modal .dm-need{margin-top:14px}
  .modal-actions{margin-top:18px;display:flex;gap:10px;justify-content:flex-end}
  .switch{position:relative;width:46px;height:26px;flex:none}
  .switch input{opacity:0;width:0;height:0}
  .slider{position:absolute;inset:0;background:var(--teal);border-radius:26px;cursor:pointer;transition:.2s}
  .slider:before{content:"";position:absolute;height:20px;width:20px;left:3px;top:3px;
                 background:#fff;border-radius:50%;transition:.2s}
  input:checked + .slider{background:var(--red)}
  input:checked + .slider:before{transform:translateX(20px)}
  nav{display:flex;gap:4px;border-bottom:2px solid var(--line);margin-bottom:22px;flex-wrap:wrap}
  nav button{background:none;border:none;padding:11px 18px;font-size:14px;cursor:pointer;
             color:var(--muted);border-bottom:3px solid transparent;margin-bottom:-2px}
  nav button.on{color:var(--teal-d);border-bottom-color:var(--teal);font-weight:700}
  .step-no{display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;
           border-radius:50%;background:var(--teal);color:#fff;font-size:13px;font-weight:700;
           margin-right:8px;flex:none}
  .card{background:var(--card);border:1px solid var(--line);border-radius:10px;
        padding:18px 20px;margin-bottom:16px}
  .card h3{margin:0 0 4px;font-size:16px;display:flex;align-items:center}
  .card p.sub{margin:0 0 14px;color:var(--muted);font-size:13px}
  label.fld{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.8px;
            color:var(--muted);margin:12px 0 5px}
  select,input[type=text],input[type=password],textarea{width:100%;padding:9px 11px;border:1px solid var(--line);
        border-radius:7px;background:#fff;font-size:13px;color:var(--ink)}
  select:focus,input[type=text]:focus,input[type=password]:focus,textarea:focus{outline:none;border-color:var(--teal);
        box-shadow:0 0 0 3px rgba(114,30,242,.15)}
  .conn-dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:#c9ccd1;margin-right:6px;vertical-align:0}
  .conn-dot.on{background:var(--accent);box-shadow:0 0 0 3px rgba(173,255,0,.25)}
  textarea{resize:vertical;min-height:46px}
  .row{display:flex;gap:12px;flex-wrap:wrap}
  .row > div{flex:1;min-width:180px}
  .btn{background:var(--teal);color:#fff;border:none;border-radius:7px;padding:10px 18px;
       font-size:13px;cursor:pointer;font-weight:700;letter-spacing:.3px}
  .btn:hover{background:var(--teal-d)}
  .btn:disabled{opacity:.45;cursor:not-allowed}
  .btn.ghost{background:#fff;color:var(--teal-d);border:1px solid var(--teal)}
  .btn.danger{background:var(--red)}
  .btn.danger:hover{background:#7a221b}
  .seg{display:inline-flex;border:1px solid var(--line);border-radius:7px;overflow:hidden}
  .seg button{background:#fff;border:none;padding:8px 14px;font-size:12px;cursor:pointer;color:var(--muted)}
  .seg button.on{background:var(--teal-d);color:#fff}
  .pvc-list{list-style:none;padding:0;margin:0}
  .pvc-list li{display:flex;align-items:center;gap:12px;padding:10px 12px;border:1px solid var(--line);
               border-radius:8px;margin-bottom:8px;background:#fff}
  .pvc-list li.sel{border-color:var(--teal);background:#F3F2FF;box-shadow:inset 3px 0 0 var(--accent)}
  .pvc-list .nm{font-weight:600;font-size:13px}
  .pvc-list .meta{font-size:11px;color:var(--muted)}
  .vol-cfg{border:1px solid var(--line);border-radius:8px;padding:12px;margin:8px 0;background:#fff}
  .vol-cfg.disabled{opacity:.5}
  .rsAdv{margin-top:8px;border:1px solid var(--line);border-radius:8px;background:#faf9fc;padding:6px 10px}
  .rsAdvSum{cursor:pointer;font-weight:600;font-size:13px;color:#5a4b86;user-select:none}
  .rsAdv[open] .rsAdvSum{margin-bottom:8px}
  .rsManualPlain{border:none;background:none;padding:0}
  .rsManualPlain > .rsAdvSum{display:none}
  .rsGuide{margin:0 0 10px;padding:8px 12px;border-left:3px solid var(--accent);background:#f3f0fb;border-radius:6px;font-size:13px}
  .badge{font-size:10px;padding:2px 8px;border-radius:20px;text-transform:uppercase;letter-spacing:.5px}
  .b-bound{background:#eefcc4;color:#4f6b00} .b-lost{background:#fbe9e7;color:var(--red)}
  .b-pending{background:#fff7e8;color:var(--amber)} .b-na{background:#eee;color:#777}
  pre.box{background:#1B0C33;color:#E2E0FD;border-radius:8px;padding:14px;font-size:12px;
          overflow:auto;max-height:340px;white-space:pre-wrap;word-break:break-word}
  .repl{font-size:12px;border:1px dashed var(--line);border-radius:8px;padding:10px;margin:10px 0;background:#fff}
  .repl div{margin:4px 0} .repl .k{color:var(--teal-d);font-weight:600}
  .repl .old{color:var(--red);text-decoration:line-through} .repl .new{color:var(--teal-d)}
  ol.plan{margin:6px 0 0;padding-left:20px;font-size:13px}
  ol.plan li{margin:3px 0}
  .logline{display:flex;gap:8px;font-size:12px;padding:6px 0;border-bottom:1px solid var(--line)}
  .logline .ic{flex:none;width:18px;text-align:center}
  .ok{color:var(--good)} .ko{color:var(--red)} .sim{color:var(--amber)}
  .hint{font-size:12px;color:var(--muted);margin-top:8px}
  .note{background:#F3F2FF;border-left:3px solid var(--teal);padding:10px 14px;border-radius:0 8px 8px 0;
        font-size:13px;margin-top:14px;color:#2F0F61}
  .warnbox{background:#fff7e8;border-left:3px solid var(--amber);padding:10px 14px;border-radius:0 8px 8px 0;
        font-size:13px;margin-top:10px;color:#7a4a10}
  .err{background:#fbe9e7;border-left:3px solid var(--red);padding:10px 14px;border-radius:0 8px 8px 0;
       font-size:13px;color:#7a221b;margin-top:10px}
  .spin{display:inline-block;width:14px;height:14px;border:2px solid #ffffff80;border-top-color:#fff;
        border-radius:50%;animation:sp .7s linear infinite;vertical-align:-2px;margin-right:6px}
  @keyframes sp{to{transform:rotate(360deg)}}
  .jbar{height:8px;background:#E2E0FD;border-radius:6px;overflow:hidden;margin-top:6px}
  .jbar span{display:block;height:100%;width:0;background:var(--teal);transition:width .4s}
  /* ----- Assistant de configuration (premier lancement) ----- */
  .wiz{position:fixed;inset:0;background:rgba(27,12,51,.6);backdrop-filter:blur(3px);
       display:flex;align-items:center;justify-content:center;z-index:1000;padding:18px}
  .wiz-card{background:#fff;border-radius:16px;max-width:580px;width:100%;
            box-shadow:0 24px 70px rgba(0,0,0,.35);display:flex;flex-direction:column;max-height:94vh}
  .wiz-head{background:var(--ink);color:#fff;padding:22px 26px;border-radius:16px 16px 0 0}
  .wiz-brand{font-weight:800;letter-spacing:4px;font-size:13px;color:var(--accent)}
  .wiz-head h2{margin:6px 0 14px;font-size:21px}
  .wiz-bar{height:5px;background:#3a2a5e;border-radius:5px;overflow:hidden}
  .wiz-bar span{display:block;height:100%;width:0;background:var(--accent);transition:width .3s}
  .wiz-body{padding:24px 26px;overflow:auto}
  .wiz-body h3{margin:0 0 6px;font-size:17px}
  .wiz-body p.q{color:var(--muted);font-size:13px;margin:0 0 16px}
  .wiz-foot{display:flex;align-items:center;justify-content:space-between;gap:12px;
            padding:14px 26px;border-top:1px solid var(--line)}
  .wiz-opt{display:block;border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:8px 0;cursor:pointer}
  .wiz-opt.sel{border-color:var(--teal);background:#F3F2FF;box-shadow:inset 3px 0 0 var(--accent)}
  .wiz-opt b{font-size:14px} .wiz-opt .d{font-size:12px;color:var(--muted);margin-top:2px}
  .chip{display:inline-block;border:1px solid var(--line);border-radius:20px;padding:6px 13px;margin:4px 6px 4px 0;
        font-size:12px;cursor:pointer;background:#fff}
  .chip.sel{background:var(--teal);color:#fff;border-color:var(--teal)}
  .wiz-recap{background:#1B0C33;color:#E2E0FD;border-radius:8px;padding:14px;font-size:12px;white-space:pre-wrap;
             font-family:"SF Mono",ui-monospace,Menlo,Consolas,monospace}
  @media(max-width:560px){.wrap{padding:14px}header{padding:14px}}
</style>
</head>
<body>
<div class="realbar"></div>
<!-- ===================== MODALE DE CONFIRMATION (actions destructives) ===================== -->
<div id="dangerModal" class="modal-bg" style="display:none">
  <div class="modal">
    <h3 id="dmTitle">Confirmer l'action réelle</h3>
    <div id="dmBody"></div>
    <div id="dmConfirmWrap" class="dm-need" style="display:none">
      <label class="fld">Pour confirmer, retapez <b id="dmWord"></b></label>
      <input type="text" id="dmInput" autocomplete="off">
    </div>
    <div class="modal-actions">
      <button class="btn ghost" id="dmCancel">Annuler</button>
      <button class="btn danger" id="dmOk">Confirmer en mode réel</button>
    </div>
  </div>
</div>
<!-- ===================== ASSISTANT (1er lancement) ===================== -->
<div id="wizard" class="wiz" style="display:none">
  <div class="wiz-card">
    <div class="wiz-head">
      <div class="wiz-brand"><svg width="22" height="22" viewBox="0 0 38 38" aria-hidden="true" style="vertical-align:-5px;margin-right:8px">
        <rect x="1" y="1" width="36" height="36" rx="9" fill="#5B18C0"></rect>
        <path d="M19 8 L28 11 V19 C28 24.5 24 28.5 19 30.5 C14 28.5 10 24.5 10 19 V11 Z" fill="#ADFF00"></path>
        <path d="M14.7 18.6 l3 3 l6.6 -7.6" fill="none" stroke="#1B0C33" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"></path>
      </svg>HYCU</div>
      <h2 id="wizTitle">Configuration initiale</h2>
      <div class="wiz-bar"><span id="wizBar"></span></div>
    </div>
    <div class="wiz-body" id="wizBody"></div>
    <div class="wiz-foot">
      <button class="btn ghost" id="wizBack">Précédent</button>
      <span class="hint" id="wizStep" style="margin:0"></span>
      <button class="btn" id="wizNext">Suivant</button>
    </div>
  </div>
</div>

<!-- ===================== DÉVERROUILLAGE (coffre présent) ===================== -->
<div id="unlock" class="wiz" style="display:none">
  <div class="wiz-card">
    <div class="wiz-head">
      <div class="wiz-brand"><svg width="22" height="22" viewBox="0 0 38 38" aria-hidden="true" style="vertical-align:-5px;margin-right:8px">
        <rect x="1" y="1" width="36" height="36" rx="9" fill="#5B18C0"></rect>
        <path d="M19 8 L28 11 V19 C28 24.5 24 28.5 19 30.5 C14 28.5 10 24.5 10 19 V11 Z" fill="#ADFF00"></path>
        <path d="M14.7 18.6 l3 3 l6.6 -7.6" fill="none" stroke="#1B0C33" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"></path>
      </svg>HYCU</div>
      <h2>Déverrouiller les connexions</h2>
    </div>
    <div class="wiz-body">
      <p class="q">Un coffre d'identifiants chiffré a été trouvé. Saisissez la phrase secrète maîtresse
        pour reconnecter automatiquement HYCU / Nutanix.</p>
      <label class="fld">Phrase secrète</label>
      <input type="password" id="unlockPass" autocomplete="off">
      <div id="unlockErr"></div>
    </div>
    <div class="wiz-foot">
      <button class="btn ghost" id="unlockSkip">Plus tard</button>
      <button class="btn" id="unlockGo">Déverrouiller</button>
    </div>
  </div>
</div>

<!-- ===================== FILTRE DES NAMESPACES ===================== -->
<div id="nsFilter" class="wiz" style="display:none">
  <div class="wiz-card">
    <div class="wiz-head">
      <div class="wiz-brand">HYCU</div>
      <h2>Filtrer les namespaces</h2>
    </div>
    <div class="wiz-body">
      <label class="wiz-opt" id="nsAllOpt" style="cursor:pointer">
        <input type="checkbox" id="nsAll" style="width:auto;margin-right:8px">
        <b>Toutes les namespaces (aucun filtre)</b>
        <div class="d">Affiche toutes les namespaces, y compris celles créées plus tard.</div>
      </label>
      <div id="nsPick">
        <input type="text" id="nsSearch" placeholder="rechercher une namespace…">
        <div style="display:flex;gap:8px;margin:8px 0">
          <button class="btn ghost" id="nsCheckAll" type="button">Tout cocher (visibles)</button>
          <button class="btn ghost" id="nsUncheckAll" type="button">Tout décocher (visibles)</button>
        </div>
        <div id="nsList" style="max-height:260px;overflow:auto"></div>
      </div>
      <div id="nsFilterErr"></div>
    </div>
    <div class="wiz-foot">
      <button class="btn ghost" id="nsCancel">Annuler</button>
      <span class="hint" id="nsCount" style="margin:0"></span>
      <button class="btn" id="nsSave">Enregistrer le filtre</button>
    </div>
  </div>
</div>

<header>
  <div class="brand">
    __LOGO__
    <h1><span class="wm">HYCU</span>Protection Kubernetes sur Nutanix<small>Sauvegarde &amp; restauration guidées · Nutanix</small></h1>
  </div>
  <div class="ctx">Contexte kubectl : <b id="ctx">…</b><span id="ctxWarn"></span> · <span class="ver" title="Version de la build">v:__VERSION__</span></div>
</header>

<div class="wrap">
  <div id="kubeBanner"></div>
  <div class="dry" id="dryBar">
    <label class="switch"><input type="checkbox" id="dry" checked><span class="slider"></span></label>
    <div><b id="dryLabel">Mode simulation activé</b> — aucune commande destructive n'est exécutée.
      Désactivez-le seulement quand vous êtes prêt à agir réellement.</div>
  </div>

  <nav role="tablist" aria-label="Sections de l'outil">
    <button class="on" role="tab" aria-selected="true" data-tab="backup">1 · Sauvegarder</button>
    <button role="tab" aria-selected="false" data-tab="restore">2 · Restaurer</button>
    <button role="tab" aria-selected="false" data-tab="verify">3 · Vérifier</button>
    <button role="tab" aria-selected="false" data-tab="connect">Connexions</button>
    <button role="tab" aria-selected="false" data-tab="settings">⚙ Réglages</button>
  </nav>

  <!-- ===================== SAUVEGARDE ===================== -->
  <section id="tab-backup">
    <div class="card">
      <h3><span class="step-no">1</span>Sauvegarder les volumes d'un namespace</h3>
      <p class="sub">Exporte et nettoie automatiquement tous les PV et PVC du namespace.
        Équivaut aux boucles kubectl + nettoyage manuel des manifestes.</p>
      <label class="fld">Namespace</label>
      <div class="row">
        <div><select id="bkNs"></select></div>
        <div style="flex:none"><button class="btn ghost nsEdit" title="Filtrer la liste des namespaces">✎ Filtrer</button></div>
        <div style="flex:none"><button class="btn" id="bkRun">Sauvegarder ce namespace</button></div>
        <div style="flex:none"><button class="btn ghost" id="bkRunAll" title="Sauvegarder tous les namespaces autorisés par le filtre (tous si aucun filtre)">Sauvegarder tous (filtrés)</button></div>
      </div>
      <label class="fld" style="margin-top:10px">Dossier de destination (optionnel)</label>
      <input type="text" id="bkDest" placeholder="Vide = hycu-backups/ (à côté du programme). Ex. D:\sauvegardes\hycu  ou  /mnt/backups">
      <div class="hint" style="margin-top:4px">Chemin sur la machine qui exécute l'outil. Le sous-dossier &lt;namespace&gt;/&lt;horodatage&gt; est créé automatiquement.</div>
      <div id="bkOut"></div>
    </div>

    <div class="card" id="bkProtectCard">
      <h3><span class="step-no">2</span>Protéger les données dans HYCU</h3>
      <p class="sub">L'export ci-dessus ne sauvegarde que les <b>manifestes</b> (la « recette » du restore).
        Les <b>données</b> vivent dans les Volume Groups Nutanix : seul HYCU les sauvegarde réellement.
        Ici, on associe les PVC du namespace aux Volume Groups HYCU, on assigne une politique, et on lance
        une sauvegarde.</p>
      <div id="bkProtectOff" class="warnbox">Connectez-vous à HYCU (onglet <b>Connexions</b>) pour activer cette section.</div>
      <div id="bkProtectOn" style="display:none">
        <button class="btn ghost" id="bkMatch">Analyser la correspondance PVC ↔ Volume Group HYCU</button>
        <div id="bkMatchOut"></div>
        <div id="bkProtectForm" style="display:none">
          <label class="fld">Politique HYCU à assigner (optionnel)</label>
          <select id="bkPolicy"></select>
          <label class="fld" style="margin-top:10px"><input type="checkbox" id="bkForceFull" style="width:auto"> Sauvegarde complète (forceFull)</label>
          <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
            <button class="btn" id="bkProtect">Assigner + sauvegarder maintenant</button>
            <span class="hint" id="bkProtectHint" style="margin:0"></span>
          </div>
          <div id="bkProtectLog"></div>
        </div>
      </div>
    </div>
  </section>

  <!-- ===================== RESTAURATION ===================== -->
  <section id="tab-restore" style="display:none">
    <div class="stepper" id="rsStepper">
      <span class="st on" data-st="1">1 · Volumes</span>
      <span class="st" data-st="2">2 · Configurer</span>
      <span class="st" data-st="3">3 · Lancer</span>
    </div>
    <div class="card">
      <h3><span class="step-no">1</span>Choisir le namespace et les volumes</h3>
      <p class="sub">Cochez le(s) PVC à restaurer. Plusieurs volumes d'une même application sont
        restaurés en une seule transaction (arrêt unique, redémarrage unique).</p>
      <label class="fld">Namespace</label>
      <div class="row">
        <div><select id="rsNs"></select></div>
        <div style="flex:none;align-self:flex-end"><button class="btn ghost nsEdit" title="Filtrer la liste des namespaces">✎ Filtrer</button></div>
      </div>
      <label class="fld" style="margin-top:8px"><input type="checkbox" id="rsCustomDir" style="width:auto"> Lire les sauvegardes depuis un dossier personnalisé</label>
      <div id="rsCustomDirWrap" style="display:none;margin-top:4px">
        <input type="text" id="rsBackupRoot" placeholder="Ex. D:\sauvegardes\hycu  ou  /mnt/backups  (dossier contenant &lt;namespace&gt;/&lt;horodatage&gt;/)">
        <div class="hint" style="margin-top:4px">Les sauvegardes lues (et utilisées pour la restauration) seront cherchées ici, au lieu de <code>hycu-backups/</code>.</div>
      </div>
      <div id="rsBackupSelWrap" style="display:none;margin-top:8px">
        <label class="fld">Sauvegarde de configuration à restaurer</label>
        <select id="rsBackupSel"></select>
        <div class="hint" style="margin-top:4px">Manifestes PV/PVC utilisés (le « squelette »). Indépendant du point de restauration HYCU des <b>données</b>. Par défaut : la plus récente.<a id="rsBackupDl" href="#" download style="display:none;margin-left:6px;text-decoration:none">⬇ Télécharger (.zip)</a></div>
      </div>
      <label class="fld">Type d'opération HYCU (pour tout le lot)</label>
      <div class="seg" id="rsMode">
        <button class="on" data-mode="clone">Clone (nouveau VG)</button>
        <button data-mode="inplace">Restauration sur place</button>
      </div>
      <div id="rsCloneSubWrap">
        <label class="fld">Que faire du clone ?</label>
        <div class="seg" id="rsCloneSub">
          <button class="on" data-sub="reattach">Rattacher à l'app existante</button>
          <button data-sub="cloneapp">Cloner l'application</button>
        </div>
        <div id="rsCloneAppWrap" style="display:none">
          <label class="fld">Cible du clone d'application</label>
          <div class="seg" id="rsCloneNsMode">
            <button class="on" data-nsmode="same">Même namespace (suffixe)</button>
            <button data-nsmode="other">Autre namespace</button>
          </div>
          <div class="row" style="margin-top:6px">
            <div id="rsCloneSuffixWrap"><label class="fld">Suffixe appliqué aux copies</label><input type="text" id="rsCloneSuffix" value="-clone"></div>
            <div id="rsCloneTargetWrap" style="display:none"><label class="fld">Namespace cible</label><input type="text" id="rsCloneTargetNs" placeholder="bo-dev-restore"></div>
          </div>
          <label class="fld" id="rsCloneRefsWrap" style="margin-top:8px;display:none"><input type="checkbox" id="rsCloneRefs" checked style="width:auto">
            Cloner aussi les dépendances (Secrets, ConfigMaps, ServiceAccount, Services qui ciblent l'app)
            <span class="hint">— nécessaire pour que les pods démarrent dans l'autre namespace</span></label>
        </div>
      </div>
      <ul class="pvc-list" id="rsPvcs" style="margin-top:12px"></ul>
    </div>

    <div class="card" id="rsConfig" style="display:none">
      <h3><span class="step-no">2</span>Indiquer le(s) Volume Group(s) restauré(s)</h3>
      <div id="rsFlowGuide" class="rsGuide"></div>
      <div id="rsVolCfgs"></div>
      <div id="rsInplaceRunWrap" style="display:none;margin-top:14px;border-top:1px solid var(--line);padding-top:12px">
        <b style="font-size:13px">Restauration sur place orchestrée</b>
        <p class="sub" style="margin:4px 0 8px">Choisissez un point de restauration HYCU par volume (bouton « Point de restauration HYCU » ci-dessus),
          puis lancez : <b>arrêt → restore in-place → redémarrage</b>. Aucune référence à saisir ni recréation de PV/PVC.</p>
        <button class="btn" id="rsInplaceRun" disabled>Lancer la restauration sur place</button>
        <span class="hint" id="rsInplaceHint" style="margin:0"></span>
        <div id="rsInplaceLog"></div>
      </div>
      <details id="rsManualAdv" class="rsAdv rsManualPlain" open style="margin-top:14px">
        <summary class="rsAdvSum">Flux manuel (avancé) — si vous avez déjà restauré/cloné le VG dans HYCU vous-même</summary>
        <div style="margin-top:8px">
          <button class="btn ghost" id="rsPreview">Prévisualiser le plan <span class="hint">(réf. VG)</span></button>
        </div>
      </details>
      <div id="rsErr"></div>
    </div>

    <div class="card" id="rsPlan" style="display:none">
      <h3><span class="step-no">3</span>Vérifier puis lancer</h3>
      <p class="sub">Vérifiez les remplacements dérivés et la séquence, puis lancez.</p>
      <div id="rsRepl"></div>
      <div><b style="font-size:13px">Séquence prévue</b><ol class="plan" id="rsSteps"></ol></div>
      <div id="rsCtxConfirm" style="display:none;margin-top:14px">
        <label class="fld">Confirmation du contexte cible (mode réel)</label>
        <input type="text" id="rsCtxInput" placeholder="retapez le nom du contexte kubectl">
      </div>
      <div style="margin-top:16px;display:flex;gap:10px;flex-wrap:wrap;align-items:center">
        <button class="btn" id="rsGo">Lancer la restauration</button>
        <span class="hint" id="rsGoHint"></span>
      </div>
      <div id="rsLog"></div>
    </div>
  </section>

  <!-- ===================== VÉRIFICATION ===================== -->
  <section id="tab-verify" style="display:none">
    <div class="card">
      <h3><span class="step-no">3</span>Vérifier l'état d'un namespace</h3>
      <p class="sub">Confirme que les PVC sont liés (Bound) et que les pods tournent.</p>
      <label class="fld">Namespace</label>
      <div class="row">
        <div><select id="vfNs"></select></div>
        <div style="flex:none"><button class="btn ghost nsEdit" title="Filtrer la liste des namespaces">✎ Filtrer</button></div>
        <div style="flex:none"><button class="btn" id="vfRun">Vérifier</button></div>
        <div style="flex:none"><button class="btn ghost" id="vfAuto" title="Rafraîchit la vérification toutes les ~3 s (jusqu'à 10 fois) et s'arrête dès que tous les PVC sont Bound et les pods Running">Rafraîchir auto (~30 s)</button></div>
      </div>
      <div id="vfOut"></div>
    </div>
  </section>

  <!-- ===================== CONNEXIONS ===================== -->
  <section id="tab-connect" style="display:none">
    <div class="card">
      <h3><span class="step-no">H</span>HYCU — connexion</h3>
      <p class="sub">Pour lister les points de restauration et orchestrer le clone/restore d'un Volume Group
        depuis l'onglet <b>Restaurer</b>. Les identifiants restent <b>en mémoire</b> le temps de la session — jamais écrits sur disque.</p>
      <label class="fld">URL HYCU (port 8443)</label>
      <input type="text" id="hyUrl" placeholder="https://hycu.exemple.com:8443">
      <label class="fld">Authentification</label>
      <div class="seg" id="hyAuthMode">
        <button class="on" data-mode="basic">Basic (utilisateur)</button>
        <button data-mode="apikey">Clé API (2FA)</button>
      </div>
      <div id="hyBasicFields" class="row">
        <div><label class="fld">Identifiant</label><input type="text" id="hyUser" autocomplete="off"></div>
        <div><label class="fld">Mot de passe</label><input type="password" id="hyPass" autocomplete="off"></div>
      </div>
      <div id="hyApiField" style="display:none">
        <label class="fld">Clé API <span class="hint">(HYCU : Aide → API Keys)</span></label>
        <input type="password" id="hyApiKey" autocomplete="off">
      </div>
      <label class="fld" style="margin-top:10px"><input type="checkbox" id="hyTls" style="width:auto"> Vérifier le certificat TLS (décoché = certificat auto-signé accepté)</label>
      <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <button class="btn" id="hyConnect">Tester &amp; connecter</button>
        <button class="btn ghost" id="hyDisconnect">Déconnecter</button>
        <span class="hint" id="hyStatus" style="margin:0"><span class="conn-dot"></span>non connecté</span>
      </div>
      <div id="hyErr"></div>
    </div>

    <div class="card">
      <h3><span class="step-no">N</span>Nutanix Prism Element — connexion</h3>
      <p class="sub">Récupère automatiquement la référence (UUID) du Volume Group cloné (lecture seule, API v2)
        dans l'onglet Restaurer. Identifiants en mémoire de session uniquement.</p>
      <label class="fld">URL Prism Element</label>
      <input type="text" id="ntUrl" placeholder="https://prism-element.exemple.com:9440">
      <div class="row">
        <div><label class="fld">Identifiant</label><input type="text" id="ntUser" autocomplete="off"></div>
        <div><label class="fld">Mot de passe</label><input type="password" id="ntPass" autocomplete="off"></div>
      </div>
      <label class="fld" style="margin-top:10px"><input type="checkbox" id="ntTls" style="width:auto"> Vérifier le certificat TLS</label>
      <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <button class="btn" id="ntConnect">Tester &amp; connecter</button>
        <button class="btn ghost" id="ntDisconnect">Déconnecter</button>
        <span class="hint" id="ntStatus" style="margin:0"><span class="conn-dot"></span>non connecté</span>
      </div>
      <div id="ntErr"></div>
    </div>

    <div class="card">
      <h3><span class="step-no">PC</span>Nutanix Prism Central — connexion</h3>
      <p class="sub">Alternative multi-cluster (API v3). Sert aussi à récupérer la référence (UUID) du Volume Group
        cloné si vous n'utilisez pas Prism Element. Identifiants en mémoire de session uniquement.</p>
      <label class="fld">URL Prism Central</label>
      <input type="text" id="pcUrl" placeholder="https://prism-central.exemple.com:9440">
      <div class="row">
        <div><label class="fld">Identifiant</label><input type="text" id="pcUser" autocomplete="off"></div>
        <div><label class="fld">Mot de passe</label><input type="password" id="pcPass" autocomplete="off"></div>
      </div>
      <label class="fld" style="margin-top:10px"><input type="checkbox" id="pcTls" style="width:auto"> Vérifier le certificat TLS</label>
      <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <button class="btn" id="pcConnect">Tester &amp; connecter</button>
        <button class="btn ghost" id="pcDisconnect">Déconnecter</button>
        <span class="hint" id="pcStatus" style="margin:0"><span class="conn-dot"></span>non connecté</span>
      </div>
      <div id="pcErr"></div>
    </div>

    <div class="card">
      <h3><span class="step-no">🔒</span>Mémoriser les connexions (chiffré)</h3>
      <p class="sub">Option : enregistrer les identifiants saisis ci-dessus dans un coffre <b>chiffré</b>
        (<code>hycu_secrets.enc</code>), protégé par une <b>phrase secrète maîtresse</b> — jamais stockée.
        Par défaut, rien n'est écrit (RAM seulement), le choix le plus sûr.</p>
      <label class="fld">Phrase secrète (≥ 8 caractères)</label>
      <input type="password" id="vaultPass" autocomplete="off">
      <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <button class="btn" id="vaultSave">Enregistrer (chiffrer)</button>
        <button class="btn ghost" id="vaultLoad">Charger (déchiffrer)</button>
        <button class="btn danger" id="vaultForget">Oublier</button>
        <span class="hint" id="vaultStatus" style="margin:0"><span class="conn-dot"></span>aucun coffre</span>
      </div>
      <div class="hint" style="margin-top:8px">MD5 n'étant pas réversible, le coffre utilise un chiffrement
        par phrase secrète (PBKDF2-HMAC-SHA256 + scellé d'intégrité).</div>
      <div id="vaultErr"></div>
    </div>
  </section>

  <!-- ===================== RÉGLAGES ===================== -->
  <section id="tab-settings" style="display:none">
    <div class="card">
      <h3><span class="step-no">⎈</span>Cluster cible (contexte kubectl)</h3>
      <p class="sub">Choisissez explicitement le cluster, au lieu de suivre le contexte courant.
        L'outil ajoute <code>--context</code> (et <code>--kubeconfig</code>) à chaque commande kubectl.</p>
      <label class="fld">Fichier kubeconfig (vide = défaut ~/.kube/config)</label>
      <input type="text" id="cfgKubeconfig" placeholder="%USERPROFILE%\.kube\config">
      <div class="row" style="margin-top:6px">
        <div><label class="fld">Contexte</label><select id="cfgContext"></select></div>
        <div style="flex:none;align-self:flex-end"><button class="btn ghost" id="ctxList">Lister les contextes</button></div>
      </div>
      <div style="margin-top:12px"><button class="btn" id="ctxApply">Utiliser ce contexte</button>
        <span class="hint" id="ctxMsg" style="margin:0"></span></div>
    </div>

    <div class="card">
      <h3><span class="step-no">⚙</span>Réglages (adaptation par client)</h3>
      <p class="sub">Ces réglages sont enregistrés dans <code>hycu_config.json</code> à côté du programme.
        Laissez vide ce que vous ne voulez pas contraindre.</p>
      <div class="row">
        <div><label class="fld">Binaire kubectl</label><input type="text" id="cfgKubectl" placeholder="kubectl"></div>
        <div><label class="fld">Préfixe volumeHandle (vide = auto)</label><input type="text" id="cfgVhPrefix" placeholder="auto-détecté"></div>
      </div>
      <div class="row">
        <div><label class="fld">Contextes autorisés (séparés par des virgules ; vide = tous)</label><input type="text" id="cfgCtx" placeholder="prod-cluster, dr-cluster"></div>
        <div><label class="fld">Namespaces autorisés (vide = tous)</label><input type="text" id="cfgNs" placeholder="wordpress, bo-dev"></div>
      </div>
      <div class="row">
        <div><label class="fld">Timeout d'attente (s)</label><input type="text" id="cfgWait" placeholder="120"></div>
        <div><label class="fld">Suffixe de nom de clone</label><input type="text" id="cfgSuffix" placeholder="0000"></div>
      </div>
      <label class="fld" style="margin-top:14px"><input type="checkbox" id="cfgConfirm" style="width:auto"> Exiger la confirmation du contexte avant toute action réelle</label>
      <label class="fld"><input type="checkbox" id="cfgStrip" style="width:auto"> Retirer entièrement claimRef du PV (laisser le PVC rebinder)</label>
      <div style="margin-top:14px"><button class="btn" id="cfgSave">Enregistrer les réglages</button> <span class="hint" id="cfgMsg"></span></div>
    </div>
  </section>
</div>

<script>
const $ = s => document.querySelector(s);
const CSRF = document.querySelector('meta[name=csrf-token]').content;
const dry = () => $("#dry").checked;
let state = {selected:{}, mode:"clone", cloneSub:"reattach", cloneNsMode:"same", backup_path:null, backup_root:null, preview:null, ns:null};
let ctxInfo = {};
function isCloneApp(){ return state.mode==="clone" && state.cloneSub==="cloneapp"; }

function badge(phase){
  const p=(phase||"").toLowerCase();
  const c = p==="bound"?"b-bound":p==="lost"?"b-lost":p==="pending"?"b-pending":"b-na";
  return `<span class="badge ${c}">${phase||"—"}</span>`;
}
function esc(s){return (s==null?"":String(s)).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
async function get(u){const r=await fetch(u);return r.json();}
async function post(u,b){const r=await fetch(u,{method:"POST",
  headers:{"Content-Type":"application/json","X-CSRF-Token":CSRF},
  body:JSON.stringify(b)});return r.json();}

// Erreurs actionnables : reconnaît les causes courantes (HYCU/Nutanix/kubectl/HTTP)
// et préfixe un conseil concret, en gardant le détail brut en dessous.
function errHint(raw){
  const e=(raw||"").toLowerCase();
  if(/401|unauthorized|identifiant|mot de passe|invalid cred/.test(e)) return "Identifiants refusés — vérifiez l'utilisateur/mot de passe, ou la clé API HYCU (Aide → API Keys, requise si 2FA).";
  if(/\b403\b|forbidden|interdit|rbac/.test(e)) return "Accès refusé — droits insuffisants (RBAC / rôle sur l'API).";
  if(/\b404\b|not found|api-docs/.test(e)) return "Endpoint introuvable — vérifiez l'URL de base et la version d'API (⚙ Réglages).";
  if(/certificat|certificate|ssl|tls|self.?signed/.test(e)) return "Certificat TLS — cochez/décochez « Vérifier le certificat TLS » dans Connexions selon votre PKI.";
  if(/timeout|timed out|délai|connexion impossible|refused|unreachable|injoignable|getaddrinfo|name or service|errno|10061|10060/.test(e)) return "Hôte injoignable — vérifiez l'URL:port (HYCU 8443, Prism 9440), le réseau et le pare-feu.";
  if(/non connecté|connectez-vous|not connected/.test(e)) return "Connectez-vous d'abord dans l'onglet Connexions.";
  if(/namespace.*(non autorisé|autorisé)|(non autorisé).*namespace/.test(e)) return "Namespace hors liste autorisée — voir ⚙ Réglages → namespaces autorisés.";
  if(/contexte.*non autorisé|allowed_contexts/.test(e)) return "Contexte kubectl hors liste autorisée — voir ⚙ Réglages.";
  if(/confirmation du contexte/.test(e)) return "Retapez le nom exact du contexte cible pour confirmer (mode réel).";
  if(/jeton anti-csrf/.test(e)) return "Rechargez la page (Ctrl+Shift+R) : le jeton de sécurité a expiré.";
  return "";
}
function errBox(raw){
  const h=errHint(raw);
  return `<div class="err">${h?`<b>${esc(h)}</b><div class="hint" style="margin-top:4px">${esc(raw||"")}</div>`:esc(raw||"erreur")}</div>`;
}

// Onglets
// Namespace GLOBAL synchronisé entre les 3 onglets (fluidité : un seul choix).
function applyGlobalNs(){ if(!state.ns) return; ["#bkNs","#rsNs","#vfNs"].forEach(id=>{ const e=$(id); if(e && e.value!==state.ns) e.value=state.ns; }); }
// Stepper du parcours Restaurer : surligne l'étape courante (1 Volumes, 2 Configurer, 3 Lancer).
function setRsStep(n){ document.querySelectorAll("#rsStepper .st").forEach(e=>{ const k=+e.dataset.st;
  e.classList.toggle("on",k===n); e.classList.toggle("done",k<n); }); }
const navBtns=[...document.querySelectorAll("nav button")];
navBtns.forEach(b=>b.onclick=()=>{
  navBtns.forEach(x=>{ x.classList.remove("on"); x.setAttribute("aria-selected","false"); });
  b.classList.add("on"); b.setAttribute("aria-selected","true");
  const tab=b.dataset.tab;
  ["backup","restore","verify","connect","settings"].forEach(t=>$("#tab-"+t).style.display="none");
  $("#tab-"+tab).style.display="block";
  applyGlobalNs();                                   // l'onglet ouvert reflète le namespace courant
  if(tab==="restore" && state.ns && state.pvcNs!==state.ns) loadPvcs();   // recharger si le ns a changé ailleurs
  if(tab==="backup" && bkMatchNs && bkMatchNs!==state.ns) clearBkProtect();
});
// Navigation clavier des onglets (flèches gauche/droite + Home/Fin).
document.querySelector("nav").addEventListener("keydown",e=>{
  const i=navBtns.indexOf(document.activeElement); if(i<0) return;
  let j=-1;
  if(e.key==="ArrowRight") j=(i+1)%navBtns.length;
  else if(e.key==="ArrowLeft") j=(i-1+navBtns.length)%navBtns.length;
  else if(e.key==="Home") j=0;
  else if(e.key==="End") j=navBtns.length-1;
  if(j>=0){ e.preventDefault(); navBtns[j].focus(); navBtns[j].click(); }
});

// Bandeau simulation (source de vérité unique : #dry)
function refreshDry(){
  const live=!dry();
  $("#dryBar").classList.toggle("live",live);
  document.body.classList.toggle("realmode",live);   // barre rouge fixe + en-tête souligné
  $("#dryLabel").textContent = live? "MODE RÉEL — les commandes seront exécutées" : "Mode simulation activé";
}
$("#dry").onchange=refreshDry;

// Modale de confirmation pour les actions destructives. Renvoie une Promise :
//  - false si annulé ;  - true (ou le texte retapé) si confirmé.
// opts = { title, lines:[html…], requireText:(string|null) }
function confirmDanger(opts){
  return new Promise(resolve=>{
    const bg=$("#dangerModal"), ok=$("#dmOk"), cancel=$("#dmCancel"), inp=$("#dmInput");
    $("#dmTitle").textContent=opts.title||"Confirmer l'action réelle";
    $("#dmBody").innerHTML=(opts.lines||[]).map(l=>`<div class="dm-line">${l}</div>`).join("");
    const need=opts.requireText||"";
    $("#dmConfirmWrap").style.display=need?"block":"none";
    $("#dmWord").textContent=need; inp.value="";
    function sync(){ ok.disabled = need ? (inp.value.trim()!==need) : false; }
    sync(); inp.oninput=sync;
    bg.style.display="flex"; if(need) setTimeout(()=>inp.focus(),30);
    function close(val){ bg.style.display="none"; inp.oninput=null; ok.onclick=null; cancel.onclick=null; resolve(val); }
    ok.onclick=()=>close(need?inp.value.trim():true);
    cancel.onclick=()=>close(false);
  });
}

function sleep(ms){ return new Promise(r=>setTimeout(r,ms)); }

// Rendu HTML d'un log d'étapes (UNIFIE les 4 rendus dupliqués : restore, in-place,
// clone-app, protect). Une entrée = {ok,dry,label,cmd,stdout,stderr,planned,job_id}.
function renderLog(log){
  return (log||[]).map(l=>{
    const ic = l.dry? '<span class="ic sim">○</span>' : (l.ok?'<span class="ic ok">✓</span>':'<span class="ic ko">✕</span>');
    const planned = l.planned? ` <code style="font-size:11px;color:#888">${esc(JSON.stringify(l.planned.body||l.planned))}</code>`:'';
    const cmd = l.cmd? ` <code style="font-size:11px;color:#888">${esc(l.cmd)}</code>`:'';
    const detail = (l.stderr&&!l.ok)? ` — <span class="ko">${esc(l.stderr)}</span>` :
       (l.stdout? ` <span class="hint">${esc(l.stdout.length>200?l.stdout.slice(0,200)+'…':l.stdout)}</span>`:'');
    return `<div class="logline">${ic}<span><b>${esc(l.label||'')}</b>${l.job_id?(' · job '+esc(l.job_id)):''}${cmd}${planned}${detail}</span></div>`;
  }).join("");
}

// Lance une opération longue côté serveur et suit sa progression (polling), en
// rafraîchissant l'affichage à chaque tick. Renvoie le résultat final.
async function runOp(url, body, onProgress){
  const start = await post(url, body);
  if(!start || !start.op_id){ return start || {ok:false, error:"Démarrage de l'opération impossible."}; }
  for(let i=0;i<6000;i++){            // garde-fou : ~90 min à 0,9 s
    const st = await get("/api/op_status?id="+encodeURIComponent(start.op_id));
    if(!st.ok){ return {ok:false, error:st.error||"Suivi de l'opération interrompu."}; }
    if(onProgress) onProgress(st.log||[], st.done);
    if(st.done) return st.result || {ok:false, error:"Opération terminée sans résultat."};
    await sleep(900);
  }
  return {ok:false, error:"Délai de suivi dépassé (l'opération continue peut-être côté serveur)."};
}

// Init : contexte + namespaces + config
async function initApp(){
  ctxInfo = await get("/api/context");
  $("#ctx").textContent = ctxInfo.context || "indisponible";
  $("#ctxWarn").innerHTML = (ctxInfo.context && ctxInfo.allowed && ctxInfo.allowed.length && !ctxInfo.context_ok)
    ? ' <span class="bad">⚠ hors liste autorisée</span>' : '';
  renderKubeBanner();
  const n=await get("/api/namespaces");
  const opts = (n.namespaces||[]).map(x=>`<option>${esc(x)}</option>`).join("");
  ["#bkNs","#rsNs","#vfNs"].forEach(id=>$(id).innerHTML = opts || "<option>—</option>");
  if(n.error){["#bkNs","#rsNs","#vfNs"].forEach(id=>$(id).innerHTML="<option>kubectl ?</option>");}
  loadConfig();
  await loadConnStatus();                     // ATTENDRE que `conn` soit prêt (sinon la popup
  loadPvcs();                                 // de déverrouillage ne s'affichait jamais)
  maybePromptUnlock();                        // coffre présent + rien de connecté -> déverrouillage
}
(async()=>{
  const cfg = await get("/api/config");
  ctxInfo = await get("/api/context");      // utilisé comme suggestion par l'assistant
  if(cfg && cfg.exists===false){ startWizard(); }
  await initApp();
})();
function maybePromptUnlock(){
  if(!conn || !conn.vault || !conn.vault.present) return;           // pas de coffre -> rien
  const anyConn = conn.hycu.connected || conn.nutanix.connected || conn.prismcentral.connected;
  if(anyConn) return;                                               // déjà connecté -> inutile
  if($("#wizard") && $("#wizard").style.display!=="none") return;   // l'assistant 1er lancement prime
  $("#unlock").style.display="flex";
  setTimeout(()=>$("#unlockPass").focus(),60);
}
$("#unlockSkip").onclick=()=>{ $("#unlock").style.display="none"; };
$("#unlockPass").onkeydown=(e)=>{ if(e.key==="Enter") $("#unlockGo").click(); };
$("#unlockGo").onclick=async()=>{
  $("#unlockErr").innerHTML="";
  const b=$("#unlockGo"); b.disabled=true; b.innerHTML='<span class="spin"></span>…';
  const r=await post("/api/creds/load",{passphrase:$("#unlockPass").value});
  $("#unlockPass").value=""; b.disabled=false; b.textContent="Déverrouiller";
  if(!r.ok){ $("#unlockErr").innerHTML=errBox(r.error);
    setTimeout(()=>$("#unlockPass").focus(),30); return; }
  const names={hycu:"HYCU", nutanix:"Prism Element", prismcentral:"Prism Central"};
  const lst=(r.loaded||[]).map(s=>names[s]||s).join(", ");
  $("#unlockErr").innerHTML=`<div class="note">Connexions rechargées : ${esc(lst||"aucune")}.</div>`;
  await loadConnStatus();
  setTimeout(()=>{ $("#unlock").style.display="none"; $("#unlockErr").innerHTML=""; }, 900);
};

// ----- Assistant de configuration (affiché si hycu_config.json est absent) -----
const wcfg = {kubectl_path:"kubectl", allowed_contexts:[], namespace_filter:[],
  require_context_confirm:true, wait_timeout:120, clone_name_suffix:"0000", volume_handle_prefix:""};
let wizStep=0, wizSteps=[];

function wizFinalConfig(){
  return {kubectl_path:wcfg.kubectl_path, allowed_contexts:wcfg.allowed_contexts,
    namespace_filter:wcfg.namespace_filter, require_context_confirm:wcfg.require_context_confirm,
    wait_timeout:wcfg.wait_timeout, clone_name_suffix:wcfg.clone_name_suffix,
    volume_handle_prefix:wcfg.volume_handle_prefix};
}
function buildWizSteps(){
  const ctx = ctxInfo.context || "";
  wizSteps = [
    {render:()=>`<h3>Première configuration</h3>
      <p class="q">Aucun fichier <code>hycu_config.json</code> n'a été trouvé. Quelques questions
      pour le générer — vous pourrez tout modifier ensuite dans l'onglet ⚙ Réglages.</p>
      <div class="note" style="margin-top:0">Contexte kubectl détecté : <b>${esc(ctx||"indisponible")}</b></div>`,
     commit:()=>{}},

    {render:()=>`<h3>Quel binaire kubectl utiliser ?</h3>
      <p class="q">Choisissez la distribution, ou saisissez une commande / un chemin personnalisé.</p>
      <div id="wKChips">${["kubectl","microk8s kubectl","k3s kubectl"].map(v=>
        `<span class="chip ${wcfg.kubectl_path===v?'sel':''}" data-v="${v}">${v}</span>`).join("")}</div>
      <label class="fld">Commande kubectl</label>
      <input type="text" id="wK" value="${esc(wcfg.kubectl_path)}">`,
     enter:()=>{document.querySelectorAll("#wKChips .chip").forEach(c=>c.onclick=()=>{
        $("#wK").value=c.dataset.v;
        document.querySelectorAll("#wKChips .chip").forEach(x=>x.classList.remove("sel")); c.classList.add("sel");});},
     commit:()=>{ wcfg.kubectl_path=($("#wK").value.trim()||"kubectl"); }},

    {render:()=>{const r=wcfg.allowed_contexts.length>0;
      return `<h3>Verrouiller le(s) cluster(s) ?</h3>
      <p class="q">Restreindre l'outil à des contextes kubectl précis évite d'agir par erreur sur le mauvais cluster.</p>
      <div class="wiz-opt ${!r?'sel':''}" data-mode="all"><b>Tous les contextes</b><div class="d">Aucune restriction.</div></div>
      <div class="wiz-opt ${r?'sel':''}" data-mode="restrict"><b>Restreindre</b><div class="d">N'autoriser que les contextes listés.</div></div>
      <div id="wCtxWrap" style="${r?'':'display:none'}"><label class="fld">Contextes autorisés (virgules)</label>
        <input type="text" id="wCtx" value="${esc(wcfg.allowed_contexts.join(', ')||ctx)}"></div>`;},
     enter:()=>{document.querySelectorAll('.wiz-opt[data-mode]').forEach(o=>o.onclick=()=>{
        document.querySelectorAll('.wiz-opt[data-mode]').forEach(x=>x.classList.remove('sel')); o.classList.add('sel');
        $("#wCtxWrap").style.display=o.dataset.mode==='restrict'?'block':'none';});},
     commit:()=>{ wcfg.allowed_contexts = document.querySelector('.wiz-opt[data-mode=restrict].sel')? csv($("#wCtx").value):[]; }},

    {render:()=>{const r=wcfg.namespace_filter.length>0;
      return `<h3>Limiter aux namespaces concernés ?</h3>
      <p class="q">Vous pouvez n'exposer que les namespaces applicatifs protégés par HYCU.</p>
      <div class="wiz-opt ${!r?'sel':''}" data-mode="all"><b>Tous les namespaces</b><div class="d">Lister tous les namespaces du cluster.</div></div>
      <div class="wiz-opt ${r?'sel':''}" data-mode="restrict"><b>Restreindre</b><div class="d">N'afficher que les namespaces listés.</div></div>
      <div id="wNsWrap" style="${r?'':'display:none'}"><label class="fld">Namespaces autorisés (virgules)</label>
        <input type="text" id="wNs" value="${esc(wcfg.namespace_filter.join(', '))}" placeholder="wordpress, bo-dev"></div>`;},
     enter:()=>{document.querySelectorAll('.wiz-opt[data-mode]').forEach(o=>o.onclick=()=>{
        document.querySelectorAll('.wiz-opt[data-mode]').forEach(x=>x.classList.remove('sel')); o.classList.add('sel');
        $("#wNsWrap").style.display=o.dataset.mode==='restrict'?'block':'none';});},
     commit:()=>{ wcfg.namespace_filter = document.querySelector('.wiz-opt[data-mode=restrict].sel')? csv($("#wNs").value):[]; }},

    {render:()=>`<h3>Garde-fou avant action réelle</h3>
      <p class="q">Recommandé : exiger de retaper le nom du contexte avant toute restauration réelle.</p>
      <label class="wiz-opt ${wcfg.require_context_confirm?'sel':''}" id="wConfirmOpt">
        <input type="checkbox" id="wConfirm" ${wcfg.require_context_confirm?'checked':''} style="width:auto;margin-right:8px">
        <b>Exiger la confirmation du contexte</b><div class="d">L'opérateur retape le contexte cible avant d'agir.</div></label>`,
     enter:()=>{ $("#wConfirm").onchange=()=>$("#wConfirmOpt").classList.toggle('sel',$("#wConfirm").checked); },
     commit:()=>{ wcfg.require_context_confirm=$("#wConfirm").checked; }},

    {render:()=>`<h3>Réglages avancés (facultatif)</h3>
      <p class="q">Les valeurs par défaut conviennent à la plupart des environnements.</p>
      <div class="row">
        <div><label class="fld">Timeout d'attente (s)</label><input type="text" id="wWait" value="${wcfg.wait_timeout}"></div>
        <div><label class="fld">Suffixe nom de clone</label><input type="text" id="wSuf" value="${esc(wcfg.clone_name_suffix)}"></div>
      </div>
      <label class="fld">Préfixe volumeHandle (vide = auto-détecté)</label>
      <input type="text" id="wVh" value="${esc(wcfg.volume_handle_prefix)}" placeholder="auto-détecté depuis le PV existant">`,
     commit:()=>{ wcfg.wait_timeout=parseInt($("#wWait").value)||120;
        wcfg.clone_name_suffix=$("#wSuf").value.trim()||"0000"; wcfg.volume_handle_prefix=$("#wVh").value.trim(); }},

    {final:true, render:()=>`<h3>Créer la configuration</h3>
      <p class="q">Vérifiez puis créez <code>hycu_config.json</code> (modifiable ensuite dans ⚙ Réglages).</p>
      <div class="wiz-recap">${esc(JSON.stringify(wizFinalConfig(),null,2))}</div>`,
     commit:()=>{}},
  ];
}
function startWizard(){ buildWizSteps(); wizStep=0; $("#wizard").style.display="flex"; renderWiz(); }
function renderWiz(){
  const s=wizSteps[wizStep];
  $("#wizBody").innerHTML=s.render();
  if(s.enter) s.enter();
  $("#wizBar").style.width=Math.round(wizStep/(wizSteps.length-1)*100)+"%";
  $("#wizStep").textContent=`Étape ${wizStep+1} / ${wizSteps.length}`;
  $("#wizBack").style.visibility=wizStep===0?"hidden":"visible";
  $("#wizNext").textContent=s.final?"Créer la configuration":"Suivant";
}
$("#wizBack").onclick=()=>{ if(wizStep>0){ wizSteps[wizStep].commit&&wizSteps[wizStep].commit(); wizStep--; renderWiz(); } };
$("#wizNext").onclick=async()=>{
  const s=wizSteps[wizStep]; if(s.commit) s.commit();
  if(s.final){
    const b=$("#wizNext"); b.disabled=true; b.innerHTML='<span class="spin"></span>Création…';
    const r=await post("/api/config",{config:wizFinalConfig()});
    b.disabled=false; b.textContent="Créer la configuration";
    if(!r.ok){ $("#wizBody").innerHTML+=`<div class="err">Échec : ${esc(r.error||'')}</div>`; return; }
    $("#wizard").style.display="none"; initApp(); return;
  }
  if(wizStep<wizSteps.length-1){ wizStep++; renderWiz(); }
};

// --------- Sauvegarde ---------
// Lien de téléchargement (.zip) d'un dossier de sauvegarde — permet de SORTIR une
// sauvegarde du conteneur/Pod vers le poste de l'opérateur (indispensable en Docker/K8s,
// où le serveur ne peut pas écrire sur le disque du client).
function dlBackupLink(dir, root, label){
  if(!dir) return "";
  const u="/api/backup/download?path="+encodeURIComponent(dir)+(root?("&root="+encodeURIComponent(root)):"");
  return `<a class="btn ghost" href="${u}" download style="padding:2px 8px;font-size:12px;text-decoration:none;margin-left:6px">⬇ ${esc(label||'Télécharger (.zip)')}</a>`;
}
$("#bkRun").onclick=async()=>{
  const ns=$("#bkNs").value, b=$("#bkRun"), dest=$("#bkDest").value.trim();
  b.disabled=true; b.innerHTML='<span class="spin"></span>Sauvegarde…';
  const r=await post("/api/backup",{ns, dest});
  b.disabled=false; b.textContent="Sauvegarder ce namespace";
  if(!r.ok){$("#bkOut").innerHTML=errBox(r.error);return;}
  const rows=r.volumes.map(v=>{
    const vh=v.analysis&&v.analysis.old_volume_handle;
    const vgUuid=vh?(String(vh).match(/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/)||[null])[0]:null;
    const tag=vgUuid?`<span class="hint">(VG ${esc(vgUuid)})</span>`:(v.analysis&&v.analysis.old_iqn?'<span class="hint">(IQN détecté)</span>':'');
    return `<li class="logline"><span class="ic ok">✓</span>
     <span><b>${esc(v.pvc)}</b> → PV ${esc(v.pv||"—")} ${tag}</span></li>`;
  }).join("");
  $("#bkOut").innerHTML=`<div class="note">${r.count} volume(s) sauvegardé(s) dans
     <code>${esc(r.dir)}</code>${dlBackupLink(r.dir, r.root)}</div><ul class="pvc-list" style="margin-top:10px">${rows}</ul>
     <div class="warnbox">⚠ Récupérez cette sauvegarde <b>hors du cluster</b> via ⬇ Télécharger (.zip) — ou copiez le dossier vers un autre stockage : c'est votre filet de sécurité en cas de sinistre.</div>`;
};
$("#bkRunAll").onclick=async()=>{
  const b=$("#bkRunAll"), dest=$("#bkDest").value.trim();
  b.disabled=true; b.innerHTML='<span class="spin"></span>Sauvegarde…';
  const r=await post("/api/backup_all",{dest});
  b.disabled=false; b.textContent="Sauvegarder tous (filtrés)";
  if(!r.ok){$("#bkOut").innerHTML=errBox(r.error);return;}
  const rows=(r.results||[]).map(x=>{
    if(x.ok) return `<li class="logline"><span class="ic ok">✓</span><span><b>${esc(x.ns)}</b> — ${x.count} volume(s) → <code>${esc(x.dir)}</code>${dlBackupLink(x.dir, r.root, 'Télécharger')}</span></li>`;
    if(x.skipped) return `<li class="logline"><span class="ic sim">○</span><span><b>${esc(x.ns)}</b> — aucun PVC (ignoré)</span></li>`;
    return `<li class="logline"><span class="ic ko">✕</span><span><b>${esc(x.ns)}</b> — ${esc(x.error||'échec')}</span></li>`;
  }).join("");
  const scope = r.filtered? "namespaces du filtre" : "tous les namespaces du cluster";
  $("#bkOut").innerHTML=`<div class="note">${r.backed_up}/${r.namespaces} namespace(s) sauvegardé(s) · ${r.volumes} volume(s) au total <span class="hint">(${scope})</span>.${dlBackupLink(r.root, r.root, 'Tout télécharger (.zip)')}</div>
     <ul class="pvc-list" style="margin-top:10px">${rows}</ul>
     <div class="warnbox">⚠ Récupérez ces sauvegardes <b>hors du cluster</b> via ⬇ Télécharger — ou copiez les dossiers vers un autre stockage : c'est votre filet de sécurité en cas de sinistre.</div>`;
};

// --------- Protection HYCU (assigner politique + sauvegarder) ---------
let bkMatches=[], bkMatchNs=null;
function clearBkProtect(){ bkMatches=[]; bkMatchNs=null; $("#bkMatchOut").innerHTML=""; $("#bkProtectForm").style.display="none"; $("#bkProtectLog").innerHTML=""; }

// Re-protection HYCU après un clone : bascule sur l'onglet Sauvegarder, cible le bon
// namespace et lance l'analyse de correspondance (puis l'utilisateur choisit la politique).
function goReprotect(ns){
  const tab=document.querySelector('nav button[data-tab="backup"]'); if(tab) tab.click();
  if(ns){ $("#bkNs").value=ns; }
  clearBkProtect();
  window.scrollTo({top:0, behavior:"smooth"});
  setTimeout(()=>$("#bkMatch").click(), 50);   // lance l'analyse + affiche le formulaire de protection
}
$("#bkNs").onchange=()=>{ state.ns=$("#bkNs").value; applyGlobalNs(); clearBkProtect(); };  // ns global + invalide l'analyse
$("#vfNs").onchange=()=>{ state.ns=$("#vfNs").value; applyGlobalNs(); };
$("#bkMatch").onclick=async()=>{
  const ns=$("#bkNs").value; clearBkProtect();
  $("#bkMatchOut").innerHTML='<div class="hint">Analyse en cours…</div>';
  const r=await get("/api/hycu/match?ns="+encodeURIComponent(ns));
  if(!r.ok){ $("#bkMatchOut").innerHTML=errBox(r.error); return; }
  bkMatches=r.matches||[]; bkMatchNs=r.namespace||ns;
  const rows=bkMatches.map(m=>{
    let chk="", label="";
    if(m.match_kind==="exact"){
      chk=`<input type="checkbox" class="bkMchk" data-uuid="${esc(m.hycu_vg_uuid)}" data-name="${esc(m.hycu_vg_name||'')}" data-ext="${esc(m.hycu_external_id||'')}" checked style="width:auto;margin-right:8px">`;
      label=`→ VG <b>${esc(m.hycu_vg_name||m.hycu_vg_uuid)}</b> <span class="hint">(externalId ${esc(m.hycu_external_id||'')})</span>`;
    } else if(m.match_kind==="name"){
      chk=`<input type="checkbox" class="bkMchk" data-uuid="${esc(m.hycu_vg_uuid)}" data-name="${esc(m.hycu_vg_name||'')}" data-ext="${esc(m.hycu_external_id||'')}" style="width:auto;margin-right:8px">`;
      label=`→ VG <b>${esc(m.hycu_vg_name||m.hycu_vg_uuid)}</b> <span class="sim">par nom — à confirmer</span>`;
    } else if(m.match_kind==="ambiguous"){
      chk=`<span class="ic ko" style="width:18px;display:inline-block;text-align:center;margin-right:8px">⚠</span>`;
      label=`<span class="ko">ambigu : plusieurs Volume Groups correspondent — vérifiez dans HYCU</span>`;
    } else {
      chk=`<span class="ic ko" style="width:18px;display:inline-block;text-align:center;margin-right:8px">✕</span>`;
      label=`<span class="ko">aucun Volume Group HYCU trouvé</span>`;
    }
    let prot="";
    if(m.matched){
      const cs=(m.compliancy||"").toUpperCase();
      const cb = cs==="GREEN"? '<span class="badge b-bound">conforme</span>'
               : cs==="RED"? '<span class="badge b-lost">non conforme</span>'
               : '<span class="badge b-pending">à sauvegarder</span>';
      const unp = (m.protected && m.protected!=="PROTECTED")? ' <span class="badge b-pending">non protégé</span>':'';
      prot=`<div class="meta">${cb}${unp} · politique : <b>${esc(m.policy||'aucune')}</b> · backups : ${m.has_backups?'oui':'non'}</div>`;
    }
    return `<li class="logline">${chk}<span style="flex:1"><b>${esc(m.pvc)}</b> ${label}${prot}</span></li>`;
  }).join("") || '<div class="hint">Aucun PVC dans ce namespace.</div>';
  const nx=bkMatches.filter(m=>m.match_kind==="exact").length, nn=bkMatches.filter(m=>m.match_kind==="name").length,
        na=bkMatches.filter(m=>m.match_kind==="ambiguous").length, n0=bkMatches.filter(m=>m.match_kind==="none").length;
  $("#bkMatchOut").innerHTML=`<ul class="pvc-list" style="margin-top:10px">${rows}</ul>
     <div class="hint">${nx} exact(s) · ${nn} par nom (à confirmer) · ${na} ambigu(s) · ${n0} non trouvé(s)</div>`;
  if(nx+nn>0){ $("#bkProtectForm").style.display="block"; loadPolicies(); updateBkHint(); }
};
async function loadPolicies(){
  const r=await get("/api/hycu/policies");
  $("#bkPolicy").innerHTML=`<option value="">(ne pas changer la politique)</option>`+
    (r.ok? (r.policies||[]).map(p=>`<option value="${esc(p.uuid)}">${esc(p.name||p.uuid)}</option>`).join("") : "");
}
function updateBkHint(){ $("#bkProtectHint").textContent = dry()? "Mode simulation (bandeau du haut) : montre les appels HYCU." : "Mode réel : exécute sur HYCU."; }
$("#dry").addEventListener("change",()=>{ if($("#bkProtectForm").style.display!=="none") updateBkHint(); });
$("#bkProtect").onclick=async()=>{
  const sel=[...document.querySelectorAll(".bkMchk:checked")];
  const vg_uuids=sel.map(c=>c.dataset.uuid);
  if(!vg_uuids.length){ $("#bkProtectLog").innerHTML='<div class="err">Cochez au moins un Volume Group (les correspondances « par nom » doivent être confirmées).</div>'; return; }
  const live=!dry(), pol=$("#bkPolicy").value;
  const names=sel.map(c=>"• "+(c.dataset.name||c.dataset.uuid)+(c.dataset.ext?(" ("+c.dataset.ext+")"):""));
  if(live && !(await confirmDanger({title:"Protection HYCU RÉELLE", lines:[
     (pol?"Assigner la politique puis <b>sauvegarder</b>":"<b>Sauvegarder</b>")+" ces Volume Groups :",
     "<b>"+names.map(esc).join("</b>, <b>")+"</b>"]}))) return;
  const b=$("#bkProtect"); b.disabled=true; b.innerHTML='<span class="spin"></span>…';
  const r=await post("/api/hycu/protect",{namespace:bkMatchNs, vg_uuids, policy_uuid:pol, force_full:$("#bkForceFull").checked, dry:dry()});
  b.disabled=false; b.textContent="Assigner + sauvegarder maintenant";
  if(!r.ok && !(r.steps&&r.steps.length)){ $("#bkProtectLog").innerHTML=errBox(r.error); return; }
  const lines=(r.steps||[]).map(s=> s.dry
    ? `<div class="logline"><span class="ic sim">○</span><span><b>${esc(s.label)}</b><pre class="box" style="margin-top:4px">${esc(JSON.stringify(s.planned,null,2))}</pre></span></div>`
    : `<div class="logline"><span class="ic ${s.ok?'ok':'ko'}">${s.ok?'✓':'✕'}</span><span><b>${esc(s.label)}</b>${s.job_id?(' · job '+esc(s.job_id)):''}${(s.error&&!s.ok)?(' — <span class="ko">'+esc(s.error)+'</span>'):''}</span></div>`
  ).join("");
  const head = r.dry? '<div class="warnbox">Simulation — appels qui seraient envoyés à HYCU :</div>'
     : (r.ok? '<div class="note">Politique assignée / sauvegarde HYCU déclenchée.</div>' : '<div class="err">Échec — voir le détail.</div>');
  $("#bkProtectLog").innerHTML=head+lines;
  if(!r.dry && r.ok && r.job_id){ $("#bkProtectLog").innerHTML+='<div id="bkJobProgress"></div>'; pollJobBar(r.job_id,"#bkJobProgress"); }
};

// --------- Restauration ---------
$("#rsNs").onchange=()=>{ state.ns=$("#rsNs").value; applyGlobalNs(); loadPvcs(); };
$("#rsCustomDir").onchange=()=>{ $("#rsCustomDirWrap").style.display=$("#rsCustomDir").checked?"block":"none"; if($("#rsNs").value) loadPvcs(); };
$("#rsBackupRoot").addEventListener("change",()=>{ if($("#rsCustomDir").checked && $("#rsNs").value) loadPvcs(); });
$("#rsBackupSel").onchange=applyBackupSelection;   // changer de sauvegarde de config sans re-fetch
let rsBackups = [];   // sauvegardes de config du namespace courant (la plus récente en premier)
async function loadPvcs(){
  const sel=$("#rsNs"); if(!sel.value) return;
  const ns=sel.value; state.ns=ns; state.pvcNs=ns; rsHyMatch=null; rsInplaceSel={};
  const customRoot = $("#rsCustomDir").checked ? $("#rsBackupRoot").value.trim() : "";
  state.backup_root = customRoot || null;
  const bk=await get("/api/backups?ns="+encodeURIComponent(ns)+(customRoot?("&root="+encodeURIComponent(customRoot)):""));
  rsBackups = bk.backups || [];
  const wrap=$("#rsBackupSelWrap"), selEl=$("#rsBackupSel");
  if(rsBackups.length){
    selEl.innerHTML = rsBackups.map((b,i)=>{
      const idx=b.index||{}; const n=(idx.volumes||[]).length;
      const created=((idx.created||b.timestamp||"")+"").replace("T"," ").slice(0,19);
      const ctx=idx.context?(" · ctx "+idx.context):"";
      return `<option value="${i}">${esc(created)} — ${n} volume(s)${esc(ctx)}${i===0?" (la plus récente)":""}</option>`;
    }).join("");
    selEl.value="0"; wrap.style.display="block";
  }else{ selEl.innerHTML=""; wrap.style.display="none"; }
  await applyBackupSelection();
}
async function applyBackupSelection(){
  const ns=state.ns; state.selected={};
  const customRoot=state.backup_root, i=$("#rsBackupSel").value;
  let pvcs=[], src=customRoot?"dossier personnalisé":"cluster";
  if(rsBackups.length && i!=="" && rsBackups[i*1]){
    const b=rsBackups[i*1];
    state.backup_path=b.path;
    pvcs=((b.index||{}).volumes||[]).map(v=>({name:v.pvc,pv:v.pv,phase:"sauvegardé"}));
    src=customRoot?"sauvegarde (dossier perso)":(i==="0"?"dernière sauvegarde":"sauvegarde choisie");
    const _dl=$("#rsBackupDl"); if(_dl){ _dl.href="/api/backup/download?path="+encodeURIComponent(b.path)+(customRoot?("&root="+encodeURIComponent(customRoot)):""); _dl.style.display="inline"; }
  }else{
    state.backup_path=null;   // aucune sauvegarde -> repli live (vide si namespace détruit)
    const _dl=$("#rsBackupDl"); if(_dl) _dl.style.display="none";
    const live=await get("/api/pvcs?ns="+encodeURIComponent(ns));
    pvcs=live.pvcs||[];
  }
  renderRsPvcs(pvcs, src);
}
function renderRsPvcs(pvcs, src){
  $("#rsPvcs").innerHTML = pvcs.length? pvcs.map(p=>`
     <li><input type="checkbox" style="width:auto" class="rsChk" data-pvc="${esc(p.name)}" data-pv="${esc(p.pv||'')}">
       <div style="flex:1"><div class="nm">${esc(p.name)}</div>
       <div class="meta">PV ${esc(p.pv||'—')} · source : ${src}</div></div>${badge(p.phase)}</li>`).join("")
     : `<div class="hint">Aucun PVC. Sauvegardez d'abord ce namespace dans l'onglet 1.</div>`;
  document.querySelectorAll(".rsChk").forEach(c=>c.onchange=rebuildVolCfgs);
  $("#rsConfig").style.display="none"; $("#rsPlan").style.display="none"; setRsStep(1);
}
// Horodatage epoch en secondes (≈ `date -u +%s`) : sert de suffixe UNIQUE à chaque clone,
// pour ne JAMAIS réutiliser un nom déjà créé (sinon : « le PVC/VG …-0000 existe déjà » au
// 2ᵉ clone de la même application). L'utilisateur peut éditer le champ ensuite.
function cloneStamp(){ return Math.floor(Date.now()/1000); }
function suggestName(pv){
  if(!pv) return "";
  return pv + "-" + cloneStamp();   // suffixe horodaté -> nom toujours unique et ≠ source
}
function rebuildVolCfgs(){
  const chks=[...document.querySelectorAll(".rsChk:checked")];
  if(!chks.length){$("#rsConfig").style.display="none";setRsStep(1);return;}
  $("#rsConfig").style.display="block"; $("#rsPlan").style.display="none"; setRsStep(2);
  const ntOn = (conn.nutanix && conn.nutanix.connected) || (conn.prismcentral && conn.prismcentral.connected);
  const hyOn = conn.hycu && conn.hycu.connected;
  $("#rsVolCfgs").innerHTML = chks.map(c=>{
    const pvc=c.dataset.pvc, pv=c.dataset.pv;
    const nameRow = state.mode==="clone"
      ? `<label class="fld">Nom du nouveau PV (modifiable)</label>
         <input type="text" class="rsName" data-pvc="${esc(pvc)}" value="${esc(suggestName(pv))}">` : "";
    const ntRow = ntOn
      ? `<button class="btn ghost ntRefBtn" data-pvc="${esc(pvc)}" style="margin-top:6px">Rechercher le VG dans Prism</button>
         <div class="ntpick" data-pvc="${esc(pvc)}"></div>` : "";
    const hyRow = (hyOn && state.mode==="clone")
      ? `<button class="btn ghost hyOrchBtn" data-pvc="${esc(pvc)}" style="margin-top:6px">⚙ Orchestrer depuis HYCU (clone)</button>
         <div class="hyOrch" data-pvc="${esc(pvc)}"></div>` : "";
    const hyInpRow = (hyOn && state.mode==="inplace")
      ? `<button class="btn ghost hyInpBtn" data-pvc="${esc(pvc)}" style="margin-top:6px">Point de restauration HYCU</button>
         <div class="hyInp" data-pvc="${esc(pvc)}"></div>` : "";
    const advOpen = hyOn ? "" : "open";   // sans orchestration HYCU, la saisie manuelle est la seule voie -> volet ouvert
    const iqnRow = `<details class="rsAdv" ${advOpen}>
         <summary class="rsAdvSum">Saisie manuelle / avancé — référence du Volume Group</summary>
         <label class="fld">Référence du Volume Group restauré/cloné — UUID du VG ${state.mode==="inplace"?'<span class="hint">(uniquement pour le flux manuel)</span>':''}</label>
         <textarea class="rsRef" data-pvc="${esc(pvc)}" placeholder="5b4d284b-7109-4e82-4c71-7d0e36ecb5ab  (UUID du VG, ou NutanixVolumes-&lt;uuid&gt;, ou IQN legacy)"></textarea>${ntRow}
       </details>`;
    return `<div class="vol-cfg"><div class="nm">${esc(pvc)} <span class="hint">(PV ${esc(pv||'—')})</span></div>
      ${hyRow}${hyInpRow}${iqnRow}${nameRow}</div>`;
  }).join("");
  document.querySelectorAll(".ntRefBtn").forEach(b=>b.onclick=()=>ntFindRef(b.dataset.pvc));
  document.querySelectorAll(".hyOrchBtn").forEach(b=>b.onclick=()=>openHyOrch(b.dataset.pvc));
  document.querySelectorAll(".hyInpBtn").forEach(b=>b.onclick=()=>openHyInplace(b.dataset.pvc));
  // Bouton global d'orchestration sur place (mode inplace + HYCU)
  $("#rsInplaceRunWrap").style.display = (hyOn && state.mode==="inplace")? "block":"none";
  if(hyOn && state.mode==="inplace") updateInplaceRunBtn();

  // Flux manuel : action principale en clone (ou sur place sans HYCU) ; replié en
  // « avancé » quand l'orchestration HYCU sur place est disponible (recommandée).
  const manualAdv=$("#rsManualAdv");
  if(hyOn && state.mode==="inplace"){ manualAdv.classList.remove("rsManualPlain"); manualAdv.open=false; }
  else { manualAdv.classList.add("rsManualPlain"); manualAdv.open=true; }

  // Guide de flux adapté au choix (type de restore + HYCU connecté).
  let guide;
  if(state.mode==="inplace"){
    guide = hyOn
      ? "<b>Restauration sur place (recommandé) :</b> sur chaque volume, cliquez « Point de restauration HYCU » et choisissez le point, puis « <b>Lancer la restauration sur place</b> » ci-dessous. <span class='hint'>Aucune référence à saisir.</span>"
      : "<b>Restauration sur place — flux manuel :</b> restaurez le VG dans HYCU, renseignez la référence du VG (UUID) par volume, puis « <b>Prévisualiser le plan</b> ». <span class='hint'>Connectez HYCU pour le flux orchestré.</span>";
  } else if(isCloneApp()){
    guide = hyOn
      ? "<b>Clone d'application — 2 étapes :</b> <b>(A)</b> sur chaque volume, « ⚙ Orchestrer depuis HYCU (clone) » → crée le VG cloné et récupère sa référence. <b>(B)</b> quand tous les volumes ont leur référence, « <b>Prévisualiser le plan</b> » puis « <b>Lancer le clone de l'application</b> » crée la copie (namespace, PV/PVC, workloads, dépendances)."
      : "<b>Clone d'application — flux manuel :</b> <b>(A)</b> clonez le VG de chaque volume dans HYCU et collez sa référence (UUID). <b>(B)</b> « <b>Prévisualiser le plan</b> » puis « <b>Lancer le clone de l'application</b> ». <span class='hint'>Connectez HYCU pour cloner et récupérer la référence automatiquement.</span>";
  } else {
    guide = hyOn
      ? "<b>Clone (rattacher à l'app existante) :</b> sur chaque volume, « ⚙ Orchestrer depuis HYCU (clone) » → VG cloné + référence, puis « <b>Prévisualiser le plan</b> » → « <b>Lancer le clone</b> »."
      : "<b>Clone (rattacher) — flux manuel :</b> clonez le VG dans HYCU, collez la référence (UUID) par volume, puis « <b>Prévisualiser le plan</b> » → « <b>Lancer le clone</b> ». <span class='hint'>Connectez HYCU pour automatiser.</span>";
  }
  $("#rsFlowGuide").innerHTML = guide;
}
let rsHyMatch=null;   // cache de la correspondance PVC↔VG HYCU pour le namespace courant
async function openHyOrch(pvc){
  const box=document.querySelector(`.hyOrch[data-pvc="${CSS.escape(pvc)}"]`);
  if(box.dataset.open==="1"){ box.dataset.open=""; box.innerHTML=""; return; }
  box.dataset.open="1"; box.innerHTML='<div class="hint">Recherche du Volume Group HYCU…</div>';
  const ns=$("#rsNs").value;
  if(!rsHyMatch || rsHyMatch.ns!==ns){
    const r=await get("/api/hycu/match?ns="+encodeURIComponent(ns));
    if(!r.ok){ box.innerHTML=errBox(r.error); return; }
    rsHyMatch={ns, matches:r.matches||[]};
  }
  const m=(rsHyMatch.matches||[]).find(x=>x.pvc===pvc);
  if(!m || !m.matched){ box.innerHTML='<div class="warnbox">Aucun Volume Group HYCU associé à ce PVC. Vérifiez la connexion HYCU / la correspondance (onglet Sauvegarder).</div>'; return; }
  const rp=await get("/api/hycu/restorepoints?source="+encodeURIComponent(m.hycu_vg_uuid));
  if(!rp.ok){ box.innerHTML=errBox(rp.error); return; }
  const opts=(rp.points||[]).map(p=>`<option value="${esc(p.id)}">${esc(p.time||p.id)}${p.status?(' · '+esc(p.status)):''}</option>`).join("")||"<option value=''>aucun point</option>";
  const isClone=state.mode==="clone";
  box.innerHTML=`<div class="repl" style="margin-top:6px">
     <div>VG HYCU : <b>${esc(m.hycu_vg_name||m.hycu_vg_uuid)}</b> ${m.match_kind!=='exact'?('<span class="sim">(correspondance '+esc(m.match_kind)+' — à vérifier)</span>'):''}</div>
     <label class="fld">Point de restauration</label>
     <select class="hyRp2" data-pvc="${esc(pvc)}">${opts}</select>
     ${isClone?`<label class="fld">Nom du VG cloné</label><input type="text" class="hyVgName2" data-pvc="${esc(pvc)}" value="${esc((m.hycu_vg_name||'')+'-'+cloneStamp())}"><div class="hint" style="margin-top:2px">Suffixe horodaté = nom unique à chaque clone (modifiable).</div>`:''}
     <div style="margin-top:10px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
       <button class="btn hyGo2" data-pvc="${esc(pvc)}" data-vg="${esc(m.hycu_vg_uuid)}">${isClone?'Cloner dans HYCU':'Restaurer dans HYCU'} puis récupérer la réf. du VG</button>
     </div>
     <div class="hyOrchOut" data-pvc="${esc(pvc)}"></div></div>`;
  box.querySelector(".hyGo2").onclick=()=>hyOrchRun(pvc);
}
async function hyOrchRun(pvc){
  const box=document.querySelector(`.hyOrch[data-pvc="${CSS.escape(pvc)}"]`);
  const out=box.querySelector(".hyOrchOut");
  const vgUuid=box.querySelector(".hyGo2").dataset.vg;
  const rpSel=box.querySelector(".hyRp2"); const rp=rpSel?rpSel.value:"";
  const nameEl=box.querySelector(".hyVgName2"); const newName=nameEl?nameEl.value.trim():"";
  if(!rp){ out.innerHTML='<div class="err">Choisissez un point de restauration.</div>'; return; }
  const live=!dry();
  if(live && !(await confirmDanger({title:"Opération HYCU RÉELLE", lines:[
     "Déclencher dans HYCU le <b>"+(state.mode==="clone"?"clone":"restore sur place")+"</b> de ce Volume Group ?"]}))) return;
  const body={namespace:rsHyMatch.ns, source_uuid:vgUuid, restore_point_id:rp, mode:state.mode, new_name:newName, dry:dry()};
  const r=await post("/api/hycu/restore",body);
  if(!r.ok){ out.innerHTML=errBox(r.error); return; }
  if(r.dry){ out.innerHTML=`<div class="warnbox">Simulation — appel HYCU qui serait envoyé :</div><pre class="box">${esc(JSON.stringify(r.planned,null,2))}</pre>`; return; }
  out.innerHTML=`<div class="note">Job HYCU lancé : <code>${esc(r.job_id||'?')}</code></div><div class="hyOrchProg"></div>`;
  if(!r.job_id){ out.innerHTML+='<div class="warnbox">Job HYCU non identifié — impossible de confirmer la fin du clone. Récupérez la réf. du VG via « Rechercher le VG dans Prism » une fois le clone terminé dans HYCU.</div>'; return; }
  const ok=await pollJobBar(r.job_id, box.querySelector(".hyOrchProg"));
  if(!ok){ out.innerHTML+='<div class="err">Le job HYCU n\'a pas abouti — référence du VG non récupérée.</div>'; return; }
  await hyOrchFillRef(pvc, newName);   // clone : UUID du nouveau VG par nom EXACT côté Nutanix
}
async function hyOrchFillRef(pvc, vgName){
  const box=document.querySelector(`.hyOrch[data-pvc="${CSS.escape(pvc)}"]`);
  const out=box.querySelector(".hyOrchOut");
  if(!((conn.nutanix&&conn.nutanix.connected)||(conn.prismcentral&&conn.prismcentral.connected))){
    out.innerHTML+='<div class="warnbox">Opération HYCU terminée. Connectez Nutanix (Prism) pour récupérer la réf. du VG automatiquement, sinon utilisez « Rechercher le VG dans Prism » ou collez l\'UUID du VG.</div>'; return;
  }
  out.innerHTML+='<div class="hint">Récupération de l\'UUID du VG cloné depuis Nutanix…</div>';
  const r=await get("/api/nutanix/vgs?q="+encodeURIComponent(vgName||""));
  if(!r.ok || !(r.vgs||[]).length){ out.innerHTML+=`<div class="warnbox">VG « ${esc(vgName||'')} » introuvable côté Nutanix — récupérez la réf. manuellement via « Rechercher le VG dans Prism ».</div>`; return; }
  // Égalité EXACTE du nom : ne jamais deviner (un mauvais VG = mauvais volume attaché).
  const exact=r.vgs.filter(v=>(v.name||"")===vgName);
  if(exact.length!==1){ out.innerHTML+=`<div class="warnbox">${exact.length===0?'Aucun':'Plusieurs'} VG nommé(s) exactement « ${esc(vgName||'')} » côté Nutanix — récupérez la réf. manuellement via « Rechercher le VG dans Prism » pour choisir le bon.</div>`; return; }
  let vg=exact[0];
  // NKP moderne : l'UUID du VG est la référence (= suffixe du volumeHandle). Pas d'IQN requis.
  let ref=vg.uuid;
  if(!ref){ out.innerHTML+='<div class="warnbox">VG trouvé mais UUID non exposé — récupérez la réf. manuellement.</div>'; return; }
  const ta=document.querySelector(`.rsRef[data-pvc="${CSS.escape(pvc)}"]`);
  if(ta){ ta.value=ref; const d=ta.closest("details.rsAdv"); if(d) d.open=true; }   // déplier pour montrer la réf remplie
  out.innerHTML+=`<div class="note">Référence du VG (UUID <code>${esc(ref)}</code>) remplie automatiquement depuis « ${esc(vg.name||'')} ». Cliquez « Prévisualiser le plan ».</div>`;
}
// --------- Orchestration RESTAURATION SUR PLACE (arrêt -> restore in-place -> redémarrage) ---------
let rsInplaceSel={};   // {pvc: {source_vg_uuid, restore_point_id, vg_name}}
async function openHyInplace(pvc){
  const box=document.querySelector(`.hyInp[data-pvc="${CSS.escape(pvc)}"]`);
  if(box.dataset.open==="1"){ box.dataset.open=""; box.innerHTML=""; return; }
  box.dataset.open="1"; box.innerHTML='<div class="hint">Recherche du Volume Group HYCU…</div>';
  const ns=$("#rsNs").value;
  if(!rsHyMatch || rsHyMatch.ns!==ns){
    const r=await get("/api/hycu/match?ns="+encodeURIComponent(ns));
    if(!r.ok){ box.innerHTML=errBox(r.error); return; }
    rsHyMatch={ns, matches:r.matches||[]};
  }
  const m=(rsHyMatch.matches||[]).find(x=>x.pvc===pvc);
  if(!m||!m.matched){ box.innerHTML='<div class="warnbox">Aucun Volume Group HYCU associé à ce PVC.</div>'; return; }
  const rp=await get("/api/hycu/restorepoints?source="+encodeURIComponent(m.hycu_vg_uuid));
  if(!rp.ok){ box.innerHTML=errBox(rp.error); return; }
  const opts=(rp.points||[]).map(p=>`<option value="${esc(p.id)}">${esc(p.time||p.id)}${p.status?(' · '+esc(p.status)):''}</option>`).join("")||"<option value=''>aucun point</option>";
  box.innerHTML=`<div class="repl" style="margin-top:6px">
     <div>VG HYCU : <b>${esc(m.hycu_vg_name||m.hycu_vg_uuid)}</b> ${m.match_kind!=='exact'?('<span class="sim">(correspondance '+esc(m.match_kind)+' — à vérifier)</span>'):''}</div>
     <label class="fld">Point de restauration</label>
     <select class="hyInpRp" data-pvc="${esc(pvc)}">${opts}</select>
     <div style="margin-top:8px"><button class="btn ghost hyInpSel" data-pvc="${esc(pvc)}" data-vg="${esc(m.hycu_vg_uuid)}" data-name="${esc(m.hycu_vg_name||'')}">Sélectionner ce point</button> <span class="hint hyInpState">${rsInplaceSel[pvc]?'<span class="ok">✓ sélectionné</span>':''}</span></div>
     </div>`;
  box.querySelector(".hyInpSel").onclick=()=>{
    const sel=box.querySelector(".hyInpRp"); const rpv=sel?sel.value:"";
    if(!rpv){ return; }
    const btn=box.querySelector(".hyInpSel");
    rsInplaceSel[pvc]={source_vg_uuid:btn.dataset.vg, restore_point_id:rpv, vg_name:btn.dataset.name};
    box.querySelector(".hyInpState").innerHTML='<span class="ok">✓ sélectionné ('+esc(sel.options[sel.selectedIndex].text)+')</span>';
    updateInplaceRunBtn();
  };
}
function updateInplaceRunBtn(){
  const chosen=[...document.querySelectorAll(".rsChk:checked")].map(c=>c.dataset.pvc);
  const ready=chosen.filter(p=>rsInplaceSel[p]);
  if(!$("#rsInplaceRun")) return;
  $("#rsInplaceRun").disabled = ready.length===0;
  $("#rsInplaceHint").textContent = ready.length
    ? (ready.length+" / "+chosen.length+" volume(s) prêt(s)"+(dry()?" · simulation":" · MODE RÉEL"))
    : "Sélectionnez un point de restauration par volume.";
}
$("#dry").addEventListener("change",()=>{ if($("#rsInplaceRunWrap").style.display!=="none") updateInplaceRunBtn(); });
$("#rsInplaceRun").onclick=async()=>{
  const chosen=[...document.querySelectorAll(".rsChk:checked")].map(c=>c.dataset.pvc);
  const items=chosen.filter(p=>rsInplaceSel[p]).map(p=>({pvc:p, source_vg_uuid:rsInplaceSel[p].source_vg_uuid, restore_point_id:rsInplaceSel[p].restore_point_id}));
  if(!items.length) return;
  const live=!dry();
  let confirmedCtx="";
  if(live){
    const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||"") : null;
    const res = await confirmDanger({title:"Restauration SUR PLACE RÉELLE", requireText:needCtx, lines:[
       "Namespace : <b>"+esc((rsHyMatch?rsHyMatch.ns:$("#rsNs").value)||"?")+"</b>",
       "Contexte kubectl : <b>"+esc(ctxInfo.context||"?")+"</b>",
       "L'application sera <b>ARRÊTÉE</b>, les volumes restaurés <b>in-place</b> dans HYCU (données écrasées par le point choisi), puis l'application <b>REDÉMARRÉE</b>."]});
    if(!res) return;
    if(typeof res==="string") confirmedCtx=res;
  }
  const b=$("#rsInplaceRun"); b.disabled=true; b.innerHTML='<span class="spin"></span>Orchestration…';
  $("#rsInplaceLog").innerHTML='<div class="hint"><span class="spin"></span> Démarrage…</div>';
  const ipBody={namespace:(rsHyMatch?rsHyMatch.ns:$("#rsNs").value), items, dry:dry()};
  if(live && ctxInfo.require_confirm) ipBody.confirm_context=confirmedCtx;
  const r=await runOp("/api/orchestrate/inplace", ipBody,
    log=>{ $("#rsInplaceLog").innerHTML='<div class="hint"><span class="spin"></span> Orchestration en cours…</div>'+renderLog(log); });
  b.disabled=false; b.textContent="Lancer la restauration sur place";
  if(r.error && !(r.log&&r.log.length)){ $("#rsInplaceLog").innerHTML=errBox(r.error); return; }
  const lines=renderLog(r.log);
  const head=r.dry?'<div class="warnbox">Simulation — séquence et appels HYCU qui seraient exécutés.</div>'
    :(r.aborted?'<div class="err"><b>Séquence interrompue</b> — l\'application est restée arrêtée. Voir le détail.</div>'
      :(r.ok?'<div class="note">Restauration sur place terminée.</div>':'<div class="err">Des étapes ont échoué.</div>'));
  $("#rsInplaceLog").innerHTML=head+lines;
};
document.querySelectorAll("#rsMode button").forEach(b=>b.onclick=()=>{
  document.querySelectorAll("#rsMode button").forEach(x=>x.classList.remove("on"));
  b.classList.add("on"); state.mode=b.dataset.mode;
  $("#rsCloneSubWrap").style.display = state.mode==="clone"?"block":"none";
  rebuildVolCfgs();
});
document.querySelectorAll("#rsCloneSub button").forEach(b=>b.onclick=()=>{
  document.querySelectorAll("#rsCloneSub button").forEach(x=>x.classList.remove("on"));
  b.classList.add("on"); state.cloneSub=b.dataset.sub;
  $("#rsCloneAppWrap").style.display = state.cloneSub==="cloneapp"?"block":"none";
  $("#rsPlan").style.display="none";
});
document.querySelectorAll("#rsCloneNsMode button").forEach(b=>b.onclick=()=>{
  document.querySelectorAll("#rsCloneNsMode button").forEach(x=>x.classList.remove("on"));
  b.classList.add("on"); state.cloneNsMode=b.dataset.nsmode;
  $("#rsCloneSuffixWrap").style.display = state.cloneNsMode==="same"?"block":"none";
  $("#rsCloneTargetWrap").style.display = state.cloneNsMode==="other"?"block":"none";
  $("#rsCloneRefsWrap").style.display = state.cloneNsMode==="other"?"block":"none";
});
function cloneAppBody(){
  const same = state.cloneNsMode==="same";
  return {namespace:$("#rsNs").value, items:collectItems(), backup_path:state.backup_path, backup_root:state.backup_root,
          target_namespace: same? "" : $("#rsCloneTargetNs").value.trim(),
          suffix: same? ($("#rsCloneSuffix").value.trim()||"-clone") : "",
          clone_refs: same? false : !!($("#rsCloneRefs")&&$("#rsCloneRefs").checked)};
}
function renderCloneAppPlan(r){
  if(!r.ok && !r.preview){ $("#rsErr").innerHTML=errBox(r.error); return; }
  const p=r.preview||{};
  let html=`<div class="note">Aperçu prêt. Vérifiez ci-dessous, puis cliquez « <b>Lancer le clone de l'application (réel)</b> » en bas pour créer la copie. <span class="hint">L'application d'origine n'est pas touchée.</span></div>
     <div class="repl"><div class="nm">Clone d'application → namespace <b>${esc(p.target_namespace)}</b> ${p.same_namespace?'(même namespace, suffixe)':'(autre namespace)'}</div>
     <div><span class="k">PV créés</span> : ${esc((p.pvs||[]).join(', ')||'—')}</div>
     <div><span class="k">PVC créés</span> : ${esc((p.pvcs||[]).join(', ')||'—')}</div>
     <div><span class="k">Applications clonées</span> : ${esc((p.workloads||[]).join(', ')||'aucune')}</div>
     ${(p.dependencies&&p.dependencies.length)?`<div><span class="k">Dépendances clonées</span> : ${esc(p.dependencies.join(', '))}</div>`:''}</div>`;
  (r.warnings||[]).forEach(w=>html+=`<div class="warnbox">⚠ ${esc(w)}</div>`);
  if(r.manifests_preview){ html+=`<details style="margin-top:6px"><summary class="hint">Voir les manifestes des applications clonées</summary><pre class="box">${esc(r.manifests_preview)}</pre></details>`; }
  $("#rsRepl").innerHTML=html;
  $("#rsSteps").innerHTML='<li>Créer le namespace cible (si « autre »)</li><li>Créer les PV/PVC clonés (sur le VG cloné)</li><li>Créer les applications clonées (elles démarrent automatiquement)</li><li>L\'application d\'origine n\'est PAS modifiée ni arrêtée</li>';
  $("#rsPlan").style.display="block"; setRsStep(3);
  updateGoButton(r.ok);
}

function collectItems(){
  const items=[];
  document.querySelectorAll(".rsChk:checked").forEach(c=>{
    const pvc=c.dataset.pvc;
    const ref=(document.querySelector(`.rsRef[data-pvc="${CSS.escape(pvc)}"]`)||{}).value||"";
    const nameEl=document.querySelector(`.rsName[data-pvc="${CSS.escape(pvc)}"]`);
    items.push({pvc, new_ref:ref, new_name:nameEl?nameEl.value:""});
  });
  return items;
}

$("#rsPreview").onclick=async()=>{
  $("#rsErr").innerHTML="";
  const items=collectItems();
  if(!items.length){$("#rsErr").innerHTML='<div class="err">Cochez au moins un PVC.</div>';return;}
  if(isCloneApp()){
    if(state.cloneNsMode==="other" && !$("#rsCloneTargetNs").value.trim()){ $("#rsErr").innerHTML='<div class="err">Indiquez le namespace cible.</div>'; return; }
    const cb=cloneAppBody(); cb.dry=true;
    const r=await runOp("/api/clone_app",cb);
    state.preview={_cloneapp:true};
    renderCloneAppPlan(r);
    return;
  }
  const body={namespace:$("#rsNs").value,mode:state.mode,items,backup_path:state.backup_path,backup_root:state.backup_root,dry:dry()};
  const r=await post("/api/prepare_restore",body);
  state.preview=body;
  let html="";
  (r.results||[]).forEach(res=>{
    if(!res.ok){html+=`<div class="err"><b>${esc(res.pvc)}</b> : ${esc(res.error)}</div>`;return;}
    const repl=(res.replacements||[]).map(([k,o,n])=>`<div><span class="k">${esc(k)}</span> :
       <span class="old">${esc(o)}</span> → <span class="new">${esc(n)}</span></div>`).join("")||
       '<div class="hint">Aucun changement de chaîne.</div>';
    const warn = res.warn? `<div class="warnbox">⚠ ${esc(res.warn)}</div>` : "";
    html+=`<div class="repl"><div class="nm">${esc(res.pvc)} → PV ${esc(res.new_pv_name)}</div>${repl}
       <div><span class="k">volumeHandle dérivé</span> : <span class="new">${esc(res.new_volume_handle)}</span></div>${warn}
       <details style="margin-top:6px"><summary class="hint">Voir le manifeste complet du nouveau PV</summary>
       <pre class="box">${esc(res.manifest_preview)}</pre></details></div>`;
  });
  $("#rsRepl").innerHTML=html;
  $("#rsSteps").innerHTML=(r.planned_steps||[]).map(s=>`<li>${esc(s)}</li>`).join("");
  $("#rsPlan").style.display="block"; setRsStep(3);
  if(!r.ok){$("#rsErr").innerHTML='<div class="err">Corrigez les volumes en erreur avant de lancer.</div>';}
  updateGoButton(r.ok);
};

function updateGoButton(ready){
  refreshDry();
  const live=!dry();
  const needConfirm = live && ctxInfo.require_confirm;
  $("#rsCtxConfirm").style.display = needConfirm? "block":"none";
  $("#rsGoHint").textContent = live? "Mode réel : ces opérations seront exécutées sur le cluster."
     : "Mode simulation : rien ne sera modifié.";
  $("#rsGo").className = live? "btn danger" : "btn";
  let act;
  if(state.mode!=="clone") act = "la restauration sur place (flux manuel)";
  else if(isCloneApp()) act = "le clone de l'application";
  else act = "le clone";
  $("#rsGo").textContent = (live? "Lancer " : "Simuler ") + act + (live? " (réel)" : "");
  $("#rsGo").disabled = !ready;
}
$("#dry").addEventListener("change",()=>{ if($("#rsPlan").style.display!=="none") updateGoButton(!$("#rsGo").disabled); });

$("#rsGo").onclick=async()=>{
  const live=!dry();
  if(state.preview && state.preview._cloneapp){
    let confirmedCtxCA="";
    if(live){
      const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||"") : null;
      const res = await confirmDanger({title:"Clone d'application RÉEL", requireText:needCtx, lines:[
         "Une <b>COPIE</b> de l'application sera créée"+(state.cloneNsMode==="same"?" dans le <b>même namespace</b> (avec suffixe)":" dans le namespace cible <b>"+esc($("#rsCloneTargetNs").value||"?")+"</b>")+".",
         "Contexte kubectl : <b>"+esc(ctxInfo.context||"?")+"</b>",
         "L'application d'origine n'est <b>PAS</b> modifiée ni arrêtée."]});
      if(!res) return;
      if(typeof res==="string") confirmedCtxCA=res;
    }
    const bb=$("#rsGo"); bb.disabled=true; bb.innerHTML='<span class="spin"></span>…';
    $("#rsLog").innerHTML='<div class="hint"><span class="spin"></span> Démarrage…</div>';
    const caBody={...cloneAppBody(), dry:dry()};
    if(live && ctxInfo.require_confirm) caBody.confirm_context=confirmedCtxCA;
    const r=await runOp("/api/clone_app", caBody,
      log=>{ $("#rsLog").innerHTML='<div class="hint"><span class="spin"></span> Clonage en cours…</div>'+renderLog(log); });
    bb.disabled=false; updateGoButton(true);
    if(r.error && !(r.log&&r.log.length)){ $("#rsLog").innerHTML=errBox(r.error); return; }
    const lns=renderLog(r.log);
    const hd=r.dry?'<div class="warnbox">Simulation — ressources qui seraient créées (l\'app d\'origine reste intacte).</div>'
      :(r.ok?'<div class="note">Clone d\'application créé. L\'application d\'origine est intacte.</div>':'<div class="err">Des étapes ont échoué — voir le détail.</div>');
    $("#rsLog").innerHTML=hd+lns+((r.warnings||[]).map(w=>`<div class="warnbox">⚠ ${esc(w)}</div>`).join(""));
    return;
  }
  let confirmedCtx="";
  if(live){
    const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||"") : null;
    const res = await confirmDanger({title:"Restauration RÉELLE", requireText:needCtx, lines:[
      "Namespace : <b>"+esc($("#rsNs").value||"?")+"</b>",
      "Contexte kubectl : <b>"+esc(ctxInfo.context||"?")+"</b>",
      "L'application sera <b>arrêtée</b>, les anciens PVC/PV <b>supprimés</b> puis recréés sur le(s) Volume Group(s) restauré(s)."]});
    if(!res) return;
    if(typeof res==="string") confirmedCtx=res;
  }
  const b=$("#rsGo"); b.disabled=true; b.innerHTML='<span class="spin"></span>Exécution…';
  const body={...state.preview,dry:dry()};
  if(live && ctxInfo.require_confirm) body.confirm_context=confirmedCtx || $("#rsCtxInput").value.trim();
  $("#rsLog").innerHTML='<div class="hint"><span class="spin"></span> Démarrage…</div>';
  const r=await runOp("/api/execute_restore", body, log=>{
    $("#rsLog").innerHTML='<div class="hint"><span class="spin"></span> Exécution en cours…</div>'+renderLog(log); });
  b.disabled=false; updateGoButton(true);
  if(r.error && !(r.log&&r.log.length)){$("#rsLog").innerHTML=errBox(r.error);return;}
  const lines=renderLog(r.log);
  let head;
  if(r.dry) head='<div class="note">Simulation terminée — voici ce qui serait exécuté en mode réel.</div>';
  else if(r.aborted) head='<div class="err"><b>Séquence interrompue</b> — l\'application est restée arrêtée pour éviter un redémarrage incohérent. Voir le détail.</div>';
  else if(r.ok) head='<div class="note">Restauration terminée.</div>';
  else head='<div class="err">Des étapes ont échoué — voir ci-dessous.</div>';
  let reprot="";
  if(r.reprotect && r.reprotect.length){
    const items=r.reprotect.map(x=>`<li><b>${esc(x.new_pv_name)}</b> <span class="hint">${esc(x.new_volume_handle||'')}</span></li>`).join("");
    reprot=`<div class="warnbox">⚠ <b>Re-protection HYCU requise.</b> Le(s) Volume Group(s) cloné(s) ci-dessous
       ne sont <b>pas encore protégés</b> par HYCU (la politique de l'app pointait l'ancien VG).
       <ul class="pvc-list" style="margin-top:8px">${items}</ul>
       <button class="btn" id="rsReprotectBtn" style="margin-top:6px">Re-protéger maintenant dans HYCU</button></div>`;
  }
  $("#rsLog").innerHTML = head + lines + reprot;
  const rb=$("#rsReprotectBtn"); if(rb) rb.onclick=()=>goReprotect($("#rsNs").value);
};

// --------- Vérification ---------
async function runVerify(){
  const ns=$("#vfNs").value;
  const r=await get("/api/verify?ns="+encodeURIComponent(ns));
  if(r.error){$("#vfOut").innerHTML=errBox(r.error);return false;}
  const pvcs=r.pvcs.map(p=>`<li class="logline"><span>${badge(p.phase)} <b>${esc(p.name)}</b>
     <span class="hint">→ ${esc(p.pv||'—')}</span></span></li>`).join("")||'<div class="hint">Aucun PVC.</div>';
  let allReady=r.pods.length>0;
  const pods=r.pods.map(p=>{
    const ok=p.phase==="Running"; if(!ok) allReady=false;
    return `<li class="logline"><span class="ic ${ok?'ok':'sim'}">${ok?'✓':'○'}</span>
     <span><b>${esc(p.name)}</b> <span class="hint">${esc(p.phase)} · prêts ${esc(p.ready)}</span></span></li>`;}).join("")
     ||'<div class="hint">Aucun pod.</div>';
  $("#vfOut").innerHTML=`<div style="margin-top:12px"><b style="font-size:13px">PVC</b>
     <ul class="pvc-list">${pvcs}</ul><b style="font-size:13px">Pods</b><ul class="pvc-list">${pods}</ul></div>`;
  const allBound=r.pvcs.every(p=>(p.phase||"").toLowerCase()==="bound");
  return allBound && allReady;
}
$("#vfRun").onclick=runVerify;
$("#vfAuto").onclick=async()=>{
  const b=$("#vfAuto"); b.disabled=true;
  for(let i=0;i<10;i++){ const done=await runVerify(); if(done) break; await new Promise(r=>setTimeout(r,3000)); }
  b.disabled=false;
};

// --------- Réglages ---------
async function loadConfig(){
  const r=await get("/api/config"); const c=r.config||{};
  $("#cfgKubectl").value=c.kubectl_path||""; $("#cfgVhPrefix").value=c.volume_handle_prefix||"";
  $("#cfgCtx").value=(c.allowed_contexts||[]).join(", ");
  $("#cfgNs").value=(c.namespace_filter||[]).join(", ");
  $("#cfgWait").value=c.wait_timeout; $("#cfgSuffix").value=c.clone_name_suffix||"";
  $("#cfgConfirm").checked=!!c.require_context_confirm; $("#cfgStrip").checked=!!c.strip_claimref;
  $("#cfgKubeconfig").value=c.kubeconfig_path||"";
  $("#cfgContext").innerHTML=`<option value="${esc(c.kube_context||'')}">${esc(c.kube_context||'(contexte courant du kubeconfig)')}</option>`;
}
$("#ctxList").onclick=async()=>{
  const kc=$("#cfgKubeconfig").value.trim();
  $("#ctxMsg").textContent="…";
  const r=await get("/api/contexts"+(kc?("?kubeconfig="+encodeURIComponent(kc)):""));
  if(!r.ok){ $("#ctxMsg").innerHTML=`<span class="ko">${esc(r.error||'kubectl indisponible')}</span>`; return; }
  const cur=r.selected||"";
  $("#cfgContext").innerHTML=`<option value="">(contexte courant du kubeconfig)</option>`+
    (r.contexts||[]).map(c=>`<option value="${esc(c)}" ${c===cur?'selected':''}>${esc(c)}</option>`).join("");
  $("#ctxMsg").textContent=`${(r.contexts||[]).length} contexte(s) trouvé(s)`;
};
$("#ctxApply").onclick=async()=>{
  const cfg={kube_context:$("#cfgContext").value, kubeconfig_path:$("#cfgKubeconfig").value.trim()};
  const r=await post("/api/config",{config:cfg});
  if(!r.ok){ $("#ctxMsg").innerHTML=`<span class="ko">${esc(r.error||'erreur')}</span>`; return; }
  $("#ctxMsg").textContent = cfg.kube_context? ("Contexte « "+cfg.kube_context+" » appliqué.") : "Contexte courant utilisé.";
  await initApp();   // recharge en-tête + namespaces sur le nouveau cluster
};
function csv(s){return (s||"").split(",").map(x=>x.trim()).filter(Boolean);}
$("#cfgSave").onclick=async()=>{
  const cfg={kubectl_path:$("#cfgKubectl").value.trim()||"kubectl",
    volume_handle_prefix:$("#cfgVhPrefix").value.trim(),
    allowed_contexts:csv($("#cfgCtx").value), namespace_filter:csv($("#cfgNs").value),
    wait_timeout:parseInt($("#cfgWait").value)||120, clone_name_suffix:$("#cfgSuffix").value.trim()||"0000",
    require_context_confirm:$("#cfgConfirm").checked, strip_claimref:$("#cfgStrip").checked};
  const r=await post("/api/config",{config:cfg});
  $("#cfgMsg").textContent = r.ok? "Enregistré." : ("Erreur : "+(r.error||""));
  ctxInfo=await get("/api/context");
};

// --------- Connexions HYCU / Nutanix ---------
let conn = {hycu:{connected:false}, nutanix:{connected:false}};
function connDot(on){ return `<span class="conn-dot ${on?'on':''}"></span>`; }
async function loadConnStatus(){
  const s = await get("/api/conn_status"); conn = s;
  ntAllVgs=null;   // invalide le cache des VG Nutanix après tout (dé)connexion
  const st=(x)=>connDot(x.connected)+(x.connected?"connecté":"non connecté");
  $("#hyStatus").innerHTML=st(s.hycu); $("#ntStatus").innerHTML=st(s.nutanix); $("#pcStatus").innerHTML=st(s.prismcentral);
  if(!$("#hyUrl").value) $("#hyUrl").value = s.hycu.url||"";
  if(!$("#ntUrl").value) $("#ntUrl").value = s.nutanix.url||"";
  if(!$("#pcUrl").value) $("#pcUrl").value = s.prismcentral.url||"";
  $("#hyTls").checked=!!s.hycu.verify_tls; $("#ntTls").checked=!!s.nutanix.verify_tls; $("#pcTls").checked=!!s.prismcentral.verify_tls;
  $("#bkProtectOff").style.display = s.hycu.connected? "none":"block";
  $("#bkProtectOn").style.display = s.hycu.connected? "block":"none";
  loadVaultStatus();
}
function loadVaultStatus(){
  const present = conn && conn.vault && conn.vault.present;
  $("#vaultStatus").innerHTML = connDot(present) + (present? "coffre présent" : "aucun coffre");
  $("#vaultLoad").style.display = present? "inline-block" : "none";
  $("#vaultForget").style.display = present? "inline-block" : "none";
}
function renderKubeBanner(){
  const el=$("#kubeBanner");
  if(ctxInfo.kubectl_ok){ el.style.display="none"; el.innerHTML=""; return; }
  const tips={
    kubectl_missing:"<b>kubectl introuvable.</b> Installez kubectl et ajoutez-le au PATH, ou indiquez son binaire/chemin dans ⚙ Réglages (ex. « microk8s kubectl »).",
    no_context:"<b>Aucun contexte kubectl sélectionné.</b> Choisissez le cluster cible : <code>kubectl config use-context &lt;nom&gt;</code>, puis rechargez la page.",
    no_kubeconfig:"<b>Aucune configuration kubectl trouvée.</b> Vérifiez <code>%USERPROFILE%\\.kube\\config</code> (ou la variable <code>KUBECONFIG</code>), puis rechargez.",
    other:"<b>Cluster injoignable via kubectl.</b> Vérifiez la connectivité réseau et vos droits (RBAC) sur l'API server."
  };
  const tip=tips[ctxInfo.kubectl_hint]||tips.other;
  el.innerHTML=`<div class="warnbox" style="margin-bottom:14px">⚠ ${tip}
    <div class="hint" style="margin-top:6px">Les onglets <b>Sauvegarder</b>, <b>Restaurer</b> (séquence Kubernetes) et <b>Vérifier</b> nécessitent kubectl. Les connexions <b>HYCU / Nutanix</b> fonctionnent, elles, sans kubectl.${ctxInfo.error?`<br><code style="color:#7a221b">${esc(ctxInfo.error)}</code>`:''}</div></div>`;
  el.style.display="block";
}
async function vaultAction(url, needPass){
  $("#vaultErr").innerHTML="";
  const body = needPass? {passphrase:$("#vaultPass").value} : {};
  const r = await post(url, body);
  $("#vaultPass").value="";
  return r;
}
$("#vaultSave").onclick=async()=>{
  const r=await vaultAction("/api/creds/save", true);
  $("#vaultErr").innerHTML = r.ok? `<div class="note">Connexions chiffrées : ${esc((r.saved||[]).join(', '))}.</div>`
                                 : errBox(r.error);
  await loadConnStatus();
};
$("#vaultLoad").onclick=async()=>{
  const r=await vaultAction("/api/creds/load", true);
  $("#vaultErr").innerHTML = r.ok? `<div class="note">Connexions chargées : ${esc((r.loaded||[]).join(', '))}.</div>`
                                 : errBox(r.error);
  await loadConnStatus();
};
$("#vaultForget").onclick=async()=>{
  if(!confirm("Supprimer le coffre chiffré du disque ?")) return;
  const r=await vaultAction("/api/creds/forget", false);
  $("#vaultErr").innerHTML = r.ok? '<div class="note">Coffre supprimé.</div>' : `<div class="err">${esc(r.error||'')}</div>`;
  await loadConnStatus();
};
let hyAuthMode="basic";
document.querySelectorAll("#hyAuthMode button").forEach(b=>b.onclick=()=>{
  document.querySelectorAll("#hyAuthMode button").forEach(x=>x.classList.remove("on"));
  b.classList.add("on"); hyAuthMode=b.dataset.mode;
  $("#hyBasicFields").style.display = hyAuthMode==="basic"?"flex":"none";
  $("#hyApiField").style.display = hyAuthMode==="apikey"?"block":"none";
});
const SYS={
  hycu:        {p:'hy', urlKey:'hycu_url',         tlsKey:'hycu_verify_tls'},
  nutanix:     {p:'nt', urlKey:'nutanix_url',      tlsKey:'nutanix_verify_tls'},
  prismcentral:{p:'pc', urlKey:'prismcentral_url', tlsKey:'prismcentral_verify_tls'},
};
async function connectSystem(sys){
  const m=SYS[sys], P='#'+m.p;
  $(P+'Err').innerHTML="";
  const url=$(P+'Url').value.trim();
  if(!url){ $(P+'Err').innerHTML='<div class="err">Renseignez l\'URL.</div>'; return; }
  const cfg={}; cfg[m.urlKey]=url; cfg[m.tlsKey]=$(P+'Tls').checked;
  await post("/api/config",{config:cfg});
  let body={system:sys, auth_mode:'basic'};
  if(sys==='hycu' && hyAuthMode==='apikey'){ body.auth_mode='apikey'; body.api_key=$("#hyApiKey").value; }
  else { body.user=$(P+'User').value.trim(); body.password=$(P+'Pass').value; }
  const r=await post("/api/connect",body);
  $(P+'Pass').value=""; if(sys==='hycu') $("#hyApiKey").value="";
  if(!r.ok){ $(P+'Err').innerHTML=errBox(r.error); }
  else if(r.warning){ $(P+'Err').innerHTML=`<div class="warnbox">${esc(r.warning)}</div>`; }
  await loadConnStatus();
}
async function disconnectSystem(sys){ await post("/api/disconnect",{system:sys}); await loadConnStatus(); }
$("#hyConnect").onclick=()=>connectSystem("hycu");
$("#ntConnect").onclick=()=>connectSystem("nutanix");
$("#pcConnect").onclick=()=>connectSystem("prismcentral");
$("#hyDisconnect").onclick=()=>disconnectSystem("hycu");
$("#ntDisconnect").onclick=()=>disconnectSystem("nutanix");
$("#pcDisconnect").onclick=()=>disconnectSystem("prismcentral");

// Nutanix : recherche instantanée d'un VG et remplissage de sa RÉFÉRENCE (UUID du VG).
// Les VG sont chargés une fois (pagination serveur) puis filtrés côté navigateur.
let ntAllVgs=null;
async function ntFindRef(pvc){
  const box=document.querySelector(`.ntpick[data-pvc="${CSS.escape(pvc)}"]`);
  if(box.dataset.open==="1"){ box.dataset.open=""; box.innerHTML=""; return; }  // 2e clic = refermer
  box.dataset.open="1";
  box.innerHTML='<div class="hint">Chargement des Volume Groups…</div>';
  if(ntAllVgs===null){
    const r=await get("/api/nutanix/vgs");
    if(!r.ok){ box.innerHTML=errBox(r.error); return; }
    ntAllVgs=r.vgs||[];
  }
  box.innerHTML=`<div style="border:1px solid var(--line);border-radius:8px;padding:8px;margin-top:6px;background:#fff">
    <input type="text" class="ntSearch" placeholder="rechercher le VG cloné par nom…">
    <div class="ntResults" style="max-height:200px;overflow:auto;margin-top:6px"></div>
    <div class="hint ntCount" style="margin-top:4px"></div></div>`;
  const inp=box.querySelector(".ntSearch"), res=box.querySelector(".ntResults"), cnt=box.querySelector(".ntCount");
  function render(){
    const t=(inp.value||"").toLowerCase();
    let list=t? ntAllVgs.filter(v=>(v.name||"").toLowerCase().includes(t)) : ntAllVgs;
    const total=list.length, capped=list.length>200; list=list.slice(0,200);
    res.innerHTML=list.length? list.map(v=>`<div class="logline ntRow" data-uuid="${esc(v.uuid)}" style="cursor:pointer">
       <span><b>${esc(v.name||v.uuid)}</b> <span class="hint">UUID ${esc(v.uuid||'?')}</span></span></div>`).join("")
       : '<div class="hint">Aucun Volume Group ne correspond.</div>';
    cnt.textContent=`${total} VG${total>1?'s':''} sur ${ntAllVgs.length}`+(capped?' (200 affichés — affinez)':'');
    res.querySelectorAll(".ntRow").forEach(row=>row.onclick=()=>{
      // NKP moderne : l'UUID du VG suffit (= suffixe du volumeHandle). Pas d'appel IQN.
      const ref=row.dataset.uuid;
      if(!ref){ box.innerHTML='<div class="err">UUID du VG indisponible.</div>'; box.dataset.open=""; return; }
      const ta=document.querySelector(`.rsRef[data-pvc="${CSS.escape(pvc)}"]`); if(ta) ta.value=ref;
      box.innerHTML='<div class="note" style="margin-top:6px">Référence du VG (UUID) remplie depuis Nutanix.</div>'; box.dataset.open="";
    });
  }
  inp.oninput=render; render(); inp.focus();
}

// Suivi générique d'un job HYCU : barre de progression + polling (backup ou restore).
async function pollJobBar(id, target){
  const el=(typeof target==="string")?$(target):target; if(!el) return false;
  for(let i=0;i<240;i++){                       // ~12 min max (240 * 3s)
    const r=await post("/api/hycu/job",{job_id:id});
    if(!r.ok){ el.innerHTML=`<div class="hint">Suivi du job indisponible : ${esc(r.error||'')}</div>`; return false; }
    const pct=(r.progress!=null)?r.progress:0, status=r.status||"?";
    el.innerHTML=`<div class="hint" style="margin-top:8px">Job <code>${esc(id)}</code> — ${esc(status)}${r.progress!=null?(' · '+pct+'%'):''}</div>
       <div class="jbar"><span style="width:${pct}%"></span></div>`;
    if(/OK|DONE|SUCCESS|COMPLET/i.test(status)){ el.innerHTML+='<div class="note" style="margin-top:6px">Job terminé avec succès.</div>'; return true; }
    if(/FAIL|ERROR|FATAL|ABORT/i.test(status)){ el.innerHTML+='<div class="err" style="margin-top:6px">Job en échec — vérifiez dans HYCU.</div>'; return false; }
    await new Promise(s=>setTimeout(s,3000));
  }
  el.innerHTML+='<div class="hint">Suivi interrompu (délai) — le job continue côté HYCU.</div>';
  return false;
}

// --------- Filtre des namespaces (éditeur) ---------
async function refreshNamespaces(){
  if(typeof clearBkProtect==="function") clearBkProtect();   // l'analyse HYCU précédente n'est plus valide
  const n=await get("/api/namespaces"); const list=n.namespaces||[];
  const opts=list.map(x=>`<option>${esc(x)}</option>`).join("");
  ["#bkNs","#rsNs","#vfNs"].forEach(id=>{
    const cur=$(id).value; $(id).innerHTML=opts||"<option>—</option>";
    if(cur && list.includes(cur)){ $(id).value=cur; return; }
    // La namespace sélectionnée a disparu du nouveau filtre -> purge de l'état dépendant.
    if(id==="#bkNs"){ $("#bkOut").innerHTML=""; }
    else if(id==="#vfNs"){ $("#vfOut").innerHTML=""; }
    else if(id==="#rsNs"){ $("#rsConfig").style.display="none"; $("#rsPlan").style.display="none";
      $("#rsLog").innerHTML=""; $("#rsErr").innerHTML=""; state.preview=null; loadPvcs(); }
  });
}
let nsAllList=[], nsChecked=new Set();
function nsVisible(){ const t=($("#nsSearch").value||"").toLowerCase(); return nsAllList.filter(x=>!t||x.toLowerCase().includes(t)); }
function nsTogglePick(){ const off=$("#nsAll").checked; $("#nsPick").style.opacity=off?".45":"1"; $("#nsPick").style.pointerEvents=off?"none":"auto"; }
function nsUpdateCount(){
  if($("#nsAll").checked){ $("#nsCount").textContent="toutes"; return; }
  const allManual = nsAllList.length>0 && nsChecked.size===nsAllList.length;
  $("#nsCount").textContent = nsChecked.size+" / "+nsAllList.length+" sélectionnée(s)"
    + (allManual? " · futures namespaces exclues (cochez « Toutes »)" : "");
}
function renderNsList(){
  const vis=nsVisible();
  $("#nsList").innerHTML = vis.length? ('<ul class="pvc-list" style="margin:0">'+vis.map(n=>`<li><label style="display:flex;gap:10px;align-items:center;cursor:pointer;width:100%">
      <input type="checkbox" class="nsChk" value="${esc(n)}" ${nsChecked.has(n)?'checked':''} style="width:auto">
      <span class="nm">${esc(n)}</span></label></li>`).join("")+'</ul>')
    : '<div class="hint">Aucune namespace ne correspond.</div>';
  $("#nsList").querySelectorAll(".nsChk").forEach(c=>c.onchange=()=>{ c.checked? nsChecked.add(c.value):nsChecked.delete(c.value); nsUpdateCount(); });
  nsUpdateCount();
}
async function openNsFilter(){
  // Normalisation systématique : on repart d'un état propre à chaque ouverture,
  // et la sauvegarde reste désactivée tant que le filtre réel n'est pas chargé
  // (sinon, kubectl en panne -> on enregistrerait [] = écrasement de la whitelist).
  $("#nsFilterErr").innerHTML=""; $("#nsAll").checked=false;
  nsAllList=[]; nsChecked=new Set(); $("#nsSearch").value="";
  $("#nsSave").disabled=true;
  nsTogglePick(); renderNsList();
  $("#nsFilter").style.display="flex";
  const r=await get("/api/ns_filter");
  if(!r.ok){ $("#nsFilterErr").innerHTML=`<div class="err">${esc(r.error||'kubectl indisponible')} — impossible de charger la liste ; sauvegarde désactivée.</div>`; return; }
  nsAllList=r.all||[]; const filt=r.filter||[], noFilter=filt.length===0;
  $("#nsAll").checked=noFilter;
  nsChecked=new Set(noFilter? nsAllList : filt);
  $("#nsSave").disabled=false;
  nsTogglePick(); renderNsList();
}
document.querySelectorAll(".nsEdit").forEach(b=>b.onclick=openNsFilter);
$("#nsAll").onchange=()=>{ nsTogglePick(); nsUpdateCount(); };
$("#nsSearch").oninput=renderNsList;
$("#nsCheckAll").onclick=()=>{ nsVisible().forEach(n=>nsChecked.add(n)); renderNsList(); };
$("#nsUncheckAll").onclick=()=>{ nsVisible().forEach(n=>nsChecked.delete(n)); renderNsList(); };
$("#nsCancel").onclick=()=>{ $("#nsFilter").style.display="none"; };
$("#nsSave").onclick=async()=>{
  const filter = $("#nsAll").checked? [] : [...nsChecked];
  const r=await post("/api/ns_filter",{filter});
  if(!r.ok){ $("#nsFilterErr").innerHTML=`<div class="err">${esc(r.error||'erreur')}</div>`; return; }
  $("#nsFilter").style.display="none";
  await refreshNamespaces();
  $("#cfgNs").value=(r.filter||[]).join(", ");   // garder l'onglet Réglages cohérent
};
refreshDry();
</script>
</body>
</html>
"""

# Édition assistée en dev : si un fichier `ui.html` est présent à côté du programme,
# il REMPLACE l'UI embarquée (coloration/lint/autocomplétion dans l'éditeur). Le `.py`
# reste 100 % autonome : sans `ui.html`, l'UI embarquée ci-dessus est utilisée.
# (Pour créer le point de départ : dumper la constante HTML dans ui.html.)
_UI_PATH = os.path.join(os.getcwd(), "ui.html")
if os.path.isfile(_UI_PATH):
    try:
        with open(_UI_PATH, encoding="utf-8") as _f:
            HTML = _f.read()
        print("UI chargée depuis ui.html (mode développement).")
    except Exception as _e:                      # pragma: no cover
        print("ui.html illisible (%s) : UI embarquée utilisée." % _e)


# ------------------------------------------------------------------------------
# Lancement
# ------------------------------------------------------------------------------
def _port_in_use(host, port):
    """Détecte si un serveur écoute déjà sur (host, port). Sur Windows,
    allow_reuse_address autorise deux serveurs sur le même port : c'est alors
    l'ANCIENNE instance qui peut répondre au navigateur (et afficher l'ancienne
    page). On refuse donc de démarrer en double."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)
    try:
        return s.connect_ex((host, port)) == 0
    except OSError:
        return False
    finally:
        s.close()


def main():
    load_config()
    os.makedirs(CONFIG["backup_root"], exist_ok=True)
    host, port = CONFIG["host"], CONFIG["port"]
    url = "http://%s:%d" % (host, port)

    if _port_in_use(host, port):
        print("=" * 64)
        print("  ⚠ Un serveur répond DÉJÀ sur %s" % url)
        print("  C'est très probablement une ANCIENNE instance encore ouverte :")
        print("  le navigateur lui parle et affiche l'ancienne page.")
        print("  -> Fermez-la d'abord, puis relancez ce programme :")
        print("       Windows  : taskkill /F /IM python.exe  (ou fermez l'autre fenêtre)")
        print("       Linux/Mac: pkill -f hycu_k8s_nutanix.py")
        print("=" * 64)
        return

    print("=" * 64)
    print("  Outil HYCU / Kubernetes / Nutanix (v2)  ·  version v:%s" % VERSION)
    print("  Ouvrez votre navigateur sur : %s" % url)
    print("  (Ctrl+C pour arrêter)")
    print("  Sauvegardes & audit écrits dans : %s" % CONFIG["backup_root"])
    print("  Configuration : %s" % CONFIG_PATH)
    print("  Astuce : au 1er affichage, faites Ctrl+Shift+R pour vider le cache.")
    print("=" * 64)
    if CONFIG.get("open_browser"):
        try:
            threading.Timer(1.0, lambda: webbrowser.open(url)).start()
        except Exception:
            pass
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    try:
        with socketserver.ThreadingTCPServer((host, port), Handler) as httpd:
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\nArrêt.")
    except OSError as e:
        print("Impossible de démarrer le serveur sur %s : %s" % (url, e))
        print("Le port est peut-être déjà utilisé. Fermez l'autre instance et relancez.")


if __name__ == "__main__":
    main()
