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
    D'autres clusters peuvent être ajoutés depuis l'interface (⚙ Sources : kubeconfig
    importé, ou découverte des workspaces NKP) ; le cluster ACTIF se choisit dans
    la barre du haut et les sauvegardes sont rangées par cluster.

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
import shutil
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
import atexit
import tempfile
import concurrent.futures
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

# Types de ressources namespacées exportées par la sauvegarde de configuration
# ÉTENDUE (au-delà des PV/PVC). Liste volontairement restreinte aux objets utiles à
# reconstruire une application ; les objets éphémères/gérés (pods, replicasets) sont exclus.
CONFIG_BACKUP_KINDS_DEFAULT = [
    "deployment", "statefulset", "daemonset", "cronjob", "job",
    "service", "ingress", "configmap", "secret", "serviceaccount",
    "role", "rolebinding", "networkpolicy", "poddisruptionbudget",
    "horizontalpodautoscaler",
]

DEFAULT_CONFIG = {
    "host": "127.0.0.1",            # jamais exposé hors machine locale
    "port": 8765,
    "kubectl_path": "kubectl",      # chemin/binaire kubectl (ex. "microk8s kubectl")
    "kube_context": "",             # contexte ciblé (vide = contexte courant du kubeconfig)
    "kubeconfig_path": "",          # fichier kubeconfig (vide = résolution par défaut)
    "backup_root": os.path.join(os.getcwd(), "hycu-backups"),
    "allowed_contexts": [],         # [] = tout contexte (mais confirmation demandée)
    "namespace_filter": [],         # [] = tous les namespaces ; sinon liste blanche
    # Filtres de namespaces des clusters AJOUTÉS depuis l'interface (⚙ Sources) :
    # { "<nom du cluster>": ["ns1", "ns2"] }. Le cluster local utilise namespace_filter.
    "cluster_namespace_filters": {},
    # Contrôle périodique de santé des clusters (lecture seule : liste des namespaces,
    # 10 s max par cluster). Pastille dans ⚙ Sources ; 0 = désactivé.
    "cluster_health_minutes": 5,
    # Rétention du journal d'audit (et donc de l'historique des Tâches) : les entrées
    # plus anciennes que N jours sont purgées une fois par jour (compaction atomique).
    # 0 = conserver indéfiniment. Évite qu'audit.log grossisse sans limite.
    "audit_retention_days": 31,
    # GARDE-FOUS DU STOCKAGE des sauvegardes :
    #  - storage_min_free_mb : PLANCHER d'espace libre — une sauvegarde est REFUSÉE
    #    (erreur claire) si le disque passerait sous ce seuil. Jamais de disque plein.
    #  - storage_quota_gb : QUOTA global (Go) du dossier de sauvegardes (0 = illimité) —
    #    au-delà, les sauvegardes LES PLUS ANCIENNES sont purgées (la plus récente de
    #    chaque namespace/cluster et la sauvegarde d'une restauration en cours sont
    #    toujours conservées).
    "storage_min_free_mb": 500,
    "storage_quota_gb": 0,
    # MODE DISASTER RECOVERY : False (défaut sûr) = la restauration inter-cluster /
    # inter-contexte reste refusée. True = elle devient possible, mais UNIQUEMENT via
    # une demande explicite « restauration DR » (avertissement, sources lues depuis la
    # SEULE sauvegarde, audit dédié). À activer le temps d'un exercice ou d'un sinistre.
    "allow_dr_restore": False,
    # Sélecteur d'étiquettes Kubernetes appliqué à la LISTE des namespaces (en plus du
    # filtre par noms) : ex. "hycu.io/backup=true" ou "env in (prod,preprod)". Vide =
    # inactif. Les équipes applicatives peuvent ainsi s'inclure via leurs manifestes.
    "namespace_label_selector": "",
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
    # Sauvegarde de configuration ÉTENDUE : en plus des PV/PVC, exporter aussi les
    # autres ressources du namespace (Deployments, Services, ConfigMaps, Secrets...).
    # LECTURE SEULE ; c'est un INSTANTANÉ de config (référence / restore manuel), NON
    # utilisé par la restauration automatique (qui reste centrée PV/PVC). True = activé.
    "config_backup_full": True,
    # « Contrat de restauration » : à chaque sauvegarde, collecter (best-effort, sans
    # jamais échouer le backup) ce qui rend la RESTAURATION sans saisie manuelle —
    # UUID/nom du Volume Group côté HYCU/Nutanix, disque(s), Prism Element, dernier
    # point de restauration HYCU. Requiert HYCU/Prism connectés ; sinon ignoré.
    "backup_collect_restore_contract": True,
    # Récupération d'une application supprimée : si son Volume Group d'origine n'existe
    # plus sur le cluster (reclaimPolicy=Delete) mais reste « Protected deleted » dans
    # HYCU, restaurer/cloner automatiquement le VG via HYCU et découvrir son nouvel UUID
    # — en un seul clic « Restaurer ». Requiert HYCU + Prism connectés.
    "recover_restore_deleted_vg": True,
    # Mode de récupération d'un VG supprimé : "restore" = restauration IN-PLACE via HYCU
    # (le VG revient à son UUID d'origine, on réutilise le PV tel quel — le plus simple) ;
    # "clone" = HYCU crée un nouveau VG (nouvel UUID) et l'outil le découvre.
    "recover_deleted_vg_mode": "restore",
    "config_backup_kinds": list(CONFIG_BACKUP_KINDS_DEFAULT),   # types namespacés exportés
    # False (défaut sûr) = les DONNÉES des Secrets sont MASQUÉES sur disque (structure
    # conservée, valeurs remplacées par « __REDACTED__ »). True = secrets en clair dans
    # la sauvegarde (à n'activer que si le dossier de sauvegarde est lui-même protégé).
    "config_backup_include_secret_data": False,
    # Données des Secrets dans la sauvegarde — indispensables pour recréer une application
    # (récupération, DR, bulk restore) : "auto" (défaut) = CHIFFRÉES avec la phrase du
    # coffre si elle est disponible (coffre déverrouillé, ou HYCU_VAULT_PASSPHRASE[_FILE]),
    # sinon en clair avec avertissement ; "encrypted" = chiffrées, sinon masquées ;
    # "clear" = en clair ; "redacted" = masquées (ancien comportement).
    "backup_secrets": "auto",
    # Sauvegarde AUTOMATIQUE planifiée : tant que l'outil tourne, sauvegarde la config
    # PV/PVC de tous les namespaces autorisés par namespace_filter, à intervalle régulier.
    "auto_backup_enabled": False,
    "auto_backup_interval_hours": 24,
    "auto_backup_dest": "",         # vide = backup_root ; sinon dossier commun dédié
    "auto_backup_keep": 15,         # rétention « compteur » : versions conservées par namespace
    # Grands clusters (centaines / milliers de namespaces) :
    "apps_fallback_max": 50,        # repli « 1 appel par namespace » (liste cluster-wide refusée) : au-delà, on renonce
    "apps_cache_ttl_s": 45,         # cache de l'inventaire Applications (tableau de bord + page), secondes
    "backup_parallel": 4,           # namespaces sauvegardés en parallèle lors d'un passage « tous »
    "backup_pv_prefetch_min": 20,   # à partir de N namespaces, les PV sont lus UNE fois par passage
    # Rétention : "count" = garder N versions (auto_backup_keep) ; "gfs" = grand-père/
    # père/fils — garder la plus récente de chaque JOUR sur D jours, de chaque SEMAINE
    # sur W semaines, de chaque MOIS sur M mois (comme les produits de sauvegarde
    # d'entreprise ; la plus récente est toujours conservée).
    "auto_backup_retention": "count",
    "auto_backup_keep_daily": 7,
    "auto_backup_keep_weekly": 4,
    "auto_backup_keep_monthly": 12,
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
    # ---- Export des sauvegardes vers un stockage objet S3 (OPTIONNEL, désactivé) ----
    # Compatible S3 : Nutanix Objects, MinIO, AWS S3… Identifiants (access/secret key)
    # saisis dans ⚙ Sources (RAM / coffre chiffré), JAMAIS ici.
    "s3_url": "",                         # endpoint, ex. https://objects.exemple.com ou https://s3.eu-west-1.amazonaws.com
    "s3_bucket": "",
    "s3_region": "us-east-1",             # région SigV4 (souvent ignorée par Objects/MinIO mais requise pour signer)
    "s3_prefix": "hycu-backups",          # préfixe des clés d'objets
    "s3_verify_tls": False,               # appliances souvent en certificat auto-signé
    "s3_path_style": True,                # True = https://endpoint/bucket/clé (Objects/MinIO) ; False = bucket en sous-domaine
    "s3_auto_upload": False,              # True = chaque sauvegarde réussie est AUSSI envoyée en .zip vers le bucket
    # OPTION : chiffrer les exports S3 (même schéma que le coffre : PBKDF2 + flux HMAC
    # + scellé). La phrase de chiffrement est saisie dans ⚙ Sources (RAM/coffre, jamais
    # ici). Déchiffrement : python3 hycu_k8s_nutanix.py --decrypt <fichier>.zip.enc
    "s3_encrypt": False,
}

CONFIG = dict(DEFAULT_CONFIG)
# Sérialise mutation de CONFIG + écriture du fichier : save_config est appelé depuis
# plusieurs threads (UI, clone asynchrone qui auto-ajoute un namespace au filtre).
CONFIG_LOCK = threading.RLock()


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
    # backup_root vide (ex. laissé "" dans le fichier d'exemple) -> défaut, sinon
    # os.makedirs("") planterait au démarrage.
    if not (CONFIG.get("backup_root") or "").strip():
        CONFIG["backup_root"] = DEFAULT_CONFIG["backup_root"]
    _apply_env_overrides()
    return CONFIG


def save_config(updates):
    """Met à jour et persiste la configuration (uniquement les clés connues).
    Sous verrou (écritures concurrentes UI / threads asynchrones) et via un fichier
    temporaire + os.replace : un arrêt brutal ne laisse jamais un hycu_config.json
    tronqué (qui serait silencieusement remplacé par les défauts au redémarrage)."""
    global CONFIG
    with CONFIG_LOCK:
        for k, v in (updates or {}).items():
            if k in DEFAULT_CONFIG:
                CONFIG[k] = v
        try:
            tmp = CONFIG_PATH + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(CONFIG, f, indent=2, ensure_ascii=False)
            os.replace(tmp, CONFIG_PATH)
            return True, None
        except Exception as e:
            return False, str(e)


# Version horodatée de la build (format AAAAMMJJ-HHMM). À incrémenter à chaque
# changement notable du programme ; affichée dans l'en-tête de l'interface.
VERSION = "20260928-1900"

# Jeton anti-CSRF généré au démarrage, injecté dans la page et exigé sur les POST.
CSRF_TOKEN = secrets.token_urlsafe(32)

# Identifiants HYCU/Nutanix gardés UNIQUEMENT en mémoire, le temps de la session
# du serveur. Jamais écrits sur disque. Effacés à l'arrêt et sur déconnexion.
SESSION_CREDS = {"hycu": None, "nutanix": None, "prismcentral": None, "s3": None}   # creds en RAM par système
CRED_LOCK = threading.Lock()

# Session de NAVIGATEUR courante (cookie de session « hycu_sess », sans expiration :
# il meurt avec le navigateur). Les identifiants HYCU/Nutanix sont liés à UNE session
# de navigateur : charger la page sans le cookie de la session courante (navigateur
# relancé, autre navigateur, fenêtre privée) VERROUILLE les connexions — identifiants
# effacés, phrase secrète / mots de passe redemandés. Sans cela, un serveur qui tourne
# longtemps (mode conteneur) garderait les connexions ouvertes pour quiconque rouvre
# la page. Un simple rechargement (F5) dans le même navigateur conserve la session.
UI_SESSION = {"id": None}

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
AUDIT_LOCK = threading.Lock()          # append et compaction ne se marchent jamais dessus
_AUDIT_COMPACT = {"last": 0.0}


def _audit_path():
    return os.path.join(CONFIG["backup_root"], "audit.log")


def _audit_compact(now=None):
    """Purge du journal d'audit : réécrit audit.log en ne gardant que les entrées
    plus récentes que `audit_retention_days` jours (0 = illimité, aucune purge).
    Atomique (fichier temporaire + os.replace) et sous verrou : aucune écriture
    concurrente perdue. Les lignes illisibles ou sans horodatage sont CONSERVÉES
    (fail-safe : ne jamais détruire ce qu'on ne sait pas dater).
    Renvoie le nombre de lignes supprimées."""
    try:
        days = float(CONFIG.get("audit_retention_days") or 0)
    except (TypeError, ValueError):
        days = 31.0
    if days <= 0:
        return 0
    now = time.time() if now is None else now
    cutoff = datetime.datetime.fromtimestamp(now - days * 86400.0).isoformat()
    path = _audit_path()
    removed = 0
    with AUDIT_LOCK:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            return 0
        kept = []
        for line in lines:
            try:
                ts = json.loads(line).get("ts")
            except ValueError:
                ts = None
            if ts and str(ts) < cutoff:
                removed += 1
            else:
                kept.append(line)
        if removed:
            tmp = path + ".tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as f:
                    f.writelines(kept)
                os.replace(tmp, path)
            except OSError as e:
                print("Compaction du journal d'audit impossible : %s" % e)
                return 0
    _AUDIT_COMPACT["last"] = now
    return removed


def audit(event, **fields):
    """Écrit une ligne JSON horodatée dans backup_root/audit.log."""
    try:
        os.makedirs(CONFIG["backup_root"], exist_ok=True)
        rec = {"ts": datetime.datetime.now().isoformat(), "event": event}
        if "cluster" not in fields:             # cluster ciblé (multi-cluster)
            try:
                rec["cluster"] = _cluster_label()
            except Exception:
                pass
        rec.update(fields)
        with AUDIT_LOCK:
            with open(_audit_path(), "a", encoding="utf-8") as f:
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
    cid = _current_cid()            # l'opération reste sur le cluster de la requête
    with OP_LOCK:
        # purge : ne garder qu'un historique borné d'opérations terminées
        done_ids = [k for k, v in OPERATIONS.items() if v["done"]]
        for k in done_ids[:-20]:
            OPERATIONS.pop(k, None)
        OPERATIONS[op_id] = {"log": shared, "done": False, "result": None}

    def worker():
        try:
            with use_cluster(cid):
                res = fn(payload, log=shared)
        except Exception as e:  # filet : ne jamais laisser un thread mourir sans verdict
            res = {"ok": False, "error": "Erreur interne : %s" % e, "log": shared}
        with OP_LOCK:
            OPERATIONS[op_id]["result"] = res
            OPERATIONS[op_id]["done"] = True
        _apps_cache_clear()                      # l'opération a pu créer/modifier des applications

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
def run(cmd, dry=False, label=None, timeout=None, input_text=None):
    """Exécute une commande (liste d'arguments). Renvoie un dict de résultat.
    Si dry=True, ne lance rien et renvoie la commande qui aurait été exécutée.
    `input_text` : contenu passé sur stdin (ex. manifeste pour `kubectl apply -f -`,
    afin qu'aucun Secret ne transite par un fichier sur disque).
    Le timeout subprocess est volontairement supérieur au timeout 'kubectl wait'
    pour ne pas tuer la commande avant son propre verdict."""
    if cmd and cmd[0] == _NO_CLUSTER:
        # Cluster actif inconnu (retiré / session verrouillée) : on n'exécute RIEN, et
        # surtout on ne se rabat jamais silencieusement sur le cluster local.
        return {"ok": False, "dry": bool(dry), "cmd": "", "stdout": "", "rc": -1,
                "stderr": _NO_CLUSTER_MSG % (cmd[1] if len(cmd) > 1 else "?"),
                "label": label or "kubectl"}
    pretty = " ".join(_redact_cmd(cmd))
    if dry:
        return {"ok": True, "dry": True, "cmd": pretty, "stdout": "", "stderr": "",
                "rc": None, "label": label or pretty}
    if timeout is None:
        timeout = CONFIG["wait_timeout"] + CONFIG["subprocess_margin"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           input=input_text)
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


# ------------------------------------------------------------------------------
# Multi-cluster : kubeconfigs chargés depuis l'interface (⚙ Sources)
#
# Le cluster « local » est celui de la configuration (kubeconfig_path / kube_context,
# ou la résolution kubectl par défaut) : comportement historique inchangé. Des
# clusters SUPPLÉMENTAIRES peuvent être ajoutés depuis l'interface (kubeconfig collé
# ou importé, ou découvert depuis un cluster de management NKP). Leur kubeconfig est
# un SECRET : gardé en mémoire + dans un fichier temporaire 0600 (dossier 0700, en
# RAM /dev/shm si disponible), effacé au retrait, au verrouillage de session et à
# l'arrêt. Il n'est persisté que dans le coffre chiffré, sur demande.
#
# Routage : chaque requête HTTP porte l'en-tête « X-HYCU-Cluster » (cluster actif
# choisi dans la barre du haut) ; il est posé dans un contexte PAR THREAD, lu par
# _kubectl_base(). Les opérations longues (_run_async) héritent du cluster de la
# requête qui les a lancées. Un cluster inconnu n'exécute RIEN (pas de repli local).
# ------------------------------------------------------------------------------
LOCAL_CID = "local"
CLUSTERS = {}                       # cid -> {id, name, context, server, kc_path, kubeconfig, auth…}
CLUSTERS_LOCK = threading.Lock()
_CL_TL = threading.local()
_KC_DIR = {"path": None}
_NO_CLUSTER = "__HYCU_NO_CLUSTER__"
_NO_CLUSTER_MSG = ("Cluster « %s » inconnu (retiré, ou session verrouillée) : sélectionnez un cluster "
                   "dans la barre du haut. Aucune commande n'a été exécutée.")
KUBECONFIG_MAX_BYTES = 1024 * 1024
_LOCAL_CTX = {"name": None, "at": 0.0}


def _current_cid():
    return getattr(_CL_TL, "cid", None) or LOCAL_CID


@contextlib.contextmanager
def use_cluster(cid, req_timeout=None):
    """Exécute le bloc sur le cluster `cid` (thread courant uniquement)."""
    prev = (getattr(_CL_TL, "cid", None), getattr(_CL_TL, "req_timeout", None))
    _CL_TL.cid = cid or LOCAL_CID
    _CL_TL.req_timeout = req_timeout
    try:
        yield
    finally:
        _CL_TL.cid, _CL_TL.req_timeout = prev


def _get_cluster(cid):
    with CLUSTERS_LOCK:
        c = CLUSTERS.get(cid)
        return dict(c) if c else None


def _cluster_ids():
    """Clusters connus : le local d'abord, puis les clusters ajoutés (ordre d'ajout)."""
    with CLUSTERS_LOCK:
        return [LOCAL_CID] + list(CLUSTERS.keys())


def _local_context_name(max_age=15.0):
    """Nom du contexte du cluster local (mis en cache quelques secondes)."""
    now = time.time()
    if _LOCAL_CTX["at"] and now - _LOCAL_CTX["at"] < max_age:
        return _LOCAL_CTX["name"]
    sel = (CONFIG.get("kube_context") or "").strip()
    name = sel
    if not sel:
        with use_cluster(LOCAL_CID):
            r = kubectl(["config", "current-context"])
        name = r["stdout"].strip() if (r["ok"] and r["stdout"]) else None
    # Un échec transitoire de kubectl n'est JAMAIS mis en cache : sinon, pendant 15 s,
    # les sauvegardes seraient rangées sans contexte (disposition « legacy »), visibles
    # et purgeables depuis n'importe quel autre contexte.
    _LOCAL_CTX.update({"name": name, "at": now if name else 0.0})
    return name


def _cluster_label(cid=None):
    """Nom lisible d'un cluster (journal d'audit, confirmations, tâches)."""
    cid = cid or _current_cid()
    if cid == LOCAL_CID:
        return _local_context_name() or "local"
    c = _get_cluster(cid)
    return c["name"] if c else cid


def _cluster_root(root):
    """Dossier de sauvegarde PROPRE au cluster actif, sous `root` — une vraie
    hiérarchie par cluster/contexte, car deux clusters (ex. prod et dev) portent
    souvent LES MÊMES namespaces :
      - clusters ajoutés  : <root>/_clusters/<id>/<ns>/<horodatage>
      - cluster local     : <root>/_contexts/<contexte>/<ns>/<horodatage>
        (par CONTEXTE kubectl : basculer kube_context ne mélange jamais les
        sauvegardes ; contexte inconnu -> disposition historique <root>/<ns>).
    « _clusters »/« _contexts » ne peuvent pas entrer en collision avec un
    namespace (le « _ » est interdit par K8s). Les ANCIENNES sauvegardes locales
    (<root>/<ns>) restent lisibles via list_backups (filtrées par contexte)."""
    cid = _current_cid()
    if cid == LOCAL_CID:
        ctx = _local_context_name()
        if ctx:
            return os.path.join(root, "_contexts", _cluster_slug(ctx))
        return root
    return os.path.join(root, "_clusters", cid)


def _ns_filter():
    """Filtre de namespaces du cluster actif ([] = tous)."""
    cid = _current_cid()
    if cid == LOCAL_CID:
        return list(CONFIG.get("namespace_filter") or [])
    c = _get_cluster(cid)
    flts = CONFIG.get("cluster_namespace_filters") or {}
    return list(flts.get(c["name"]) or []) if (c and isinstance(flts, dict)) else []


def _save_ns_filter(flt):
    cid = _current_cid()
    if cid == LOCAL_CID:
        return save_config({"namespace_filter": flt})
    c = _get_cluster(cid)
    if not c:
        return False, "Cluster inconnu."
    flts = dict(CONFIG.get("cluster_namespace_filters") or {})
    if flt:
        flts[c["name"]] = flt
    else:
        flts.pop(c["name"], None)
    return save_config({"cluster_namespace_filters": flts})


def _kc_dir():
    """Dossier privé (0700) des kubeconfigs temporaires ; en RAM (/dev/shm) si possible."""
    if _KC_DIR["path"] and os.path.isdir(_KC_DIR["path"]):
        return _KC_DIR["path"]
    parent = "/dev/shm" if (os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK)) else None
    d = tempfile.mkdtemp(prefix="hycu-kc-", dir=parent)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    _KC_DIR["path"] = d
    return d


def _write_kc_file(text):
    fd, path = tempfile.mkstemp(prefix="kc-", suffix=".json", dir=_kc_dir())
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def _rm_quiet(path):
    try:
        if path:
            os.remove(path)
    except OSError:
        pass


@atexit.register
def _cleanup_kc_dir():
    d = _KC_DIR.get("path")
    if d:
        shutil.rmtree(d, ignore_errors=True)


def _redact_cmd(cmd):
    """Masque le chemin du kubeconfig temporaire d'un cluster ajouté dans les logs."""
    d = _KC_DIR.get("path")
    if not d:
        return cmd
    return ["<kubeconfig>" if (isinstance(a, str) and a.startswith(d)) else a for a in cmd]


def _kubectl_base():
    """Binaire kubectl (« kubectl », « microk8s kubectl »…) + ciblage explicite du
    cluster ACTIF : --kubeconfig et --context sont ajoutés à TOUTES les commandes,
    pour viser le bon cluster sans dépendre du contexte courant."""
    base = CONFIG["kubectl_path"].split()
    cid = _current_cid()
    if cid == LOCAL_CID:
        kc = (CONFIG.get("kubeconfig_path") or "").strip()
        if kc:
            base += ["--kubeconfig", kc]
        ctx = (CONFIG.get("kube_context") or "").strip()
        if ctx:
            base += ["--context", ctx]
    else:
        c = _get_cluster(cid)
        if not c:
            return [_NO_CLUSTER, cid]
        base += ["--kubeconfig", c["kc_path"], "--context", c["context"]]
    rt = getattr(_CL_TL, "req_timeout", None)
    if rt:
        base.append("--request-timeout=%ds" % int(rt))
    return base


# --- Analyse d'un kubeconfig (sans parseur YAML : `kubectl config view -o json`) ---
def _b64url_json(seg):
    try:
        pad = "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg + pad).decode("utf-8"))
    except Exception:
        return None


def _kc_auth_info(user, cluster, now=None):
    """Type d'authentification d'une entrée « user » + avertissements utiles.
    level : ok | warn | error. Ne renvoie jamais de secret."""
    now = time.time() if now is None else now
    user, cluster = user or {}, cluster or {}
    warnings, level, typ, exp = [], "ok", "unknown", None

    def warn(msg, lvl="warn"):
        nonlocal level
        warnings.append(msg)
        if lvl == "error" or level == "ok":
            level = lvl
    if user.get("exec"):
        cmd = (user["exec"] or {}).get("command") or "?"
        typ = "exec"
        warn("Authentification par plugin exec (« %s ») : cette commande doit être installée là où "
             "tourne l'outil (absente de l'image conteneur par défaut) ; elle peut aussi ouvrir un "
             "navigateur (OIDC) que l'outil ne peut pas piloter." % os.path.basename(str(cmd)))
    elif user.get("auth-provider"):
        typ = "auth-provider"
        warn("Authentification « auth-provider » (%s) : mécanisme déprécié, jeton OIDC à durée de vie "
             "courte — prévoyez un jeton de ServiceAccount pour un usage durable."
             % ((user["auth-provider"] or {}).get("name") or "oidc"))
    elif user.get("token") or user.get("tokenFile"):
        typ = "token"
        if user.get("tokenFile"):
            warn("Le jeton est lu depuis un fichier local (%s) : il doit exister là où tourne l'outil."
                 % user.get("tokenFile"))
        parts = str(user.get("token") or "").split(".")
        claims = _b64url_json(parts[1]) if len(parts) == 3 else None
        if isinstance(claims, dict) and claims.get("exp"):
            try:
                exp = float(claims["exp"])
            except (TypeError, ValueError):
                exp = None
            if exp and exp <= now:
                warn("Le jeton a EXPIRÉ (%s) : régénérez le kubeconfig."
                     % datetime.datetime.fromtimestamp(exp).strftime("%Y-%m-%d %H:%M"), "error")
            elif exp and exp - now < 24 * 3600:
                warn("Le jeton expire dans moins de 24 h (%s) : les sauvegardes planifiées échoueront ensuite."
                     % datetime.datetime.fromtimestamp(exp).strftime("%Y-%m-%d %H:%M"))
    elif user.get("client-certificate-data") or user.get("client-certificate"):
        typ = "client-certificate"
        if user.get("client-certificate") and not user.get("client-certificate-data"):
            warn("Le certificat client est un fichier local (%s) : il doit exister là où tourne l'outil."
                 % user.get("client-certificate"))
    elif user.get("username"):
        typ = "basic"
        warn("Authentification par identifiant/mot de passe (basic) : désactivée sur la plupart des clusters récents.")
    else:
        warn("Aucune information d'authentification reconnue pour ce contexte.")
    if cluster.get("insecure-skip-tls-verify"):
        warn("Vérification TLS du serveur DÉSACTIVÉE (insecure-skip-tls-verify).")
    if cluster.get("certificate-authority") and not cluster.get("certificate-authority-data"):
        warn("L'autorité de certification est un fichier local (%s) : il doit exister là où tourne l'outil."
             % cluster.get("certificate-authority"))
    return {"type": typ, "warnings": warnings, "level": level, "expires": exp}


def _kc_view(path):
    """Kubeconfig -> dict JSON via kubectl (résout aussi le format YAML). (data, err)."""
    r = run(CONFIG["kubectl_path"].split() + ["--kubeconfig", path, "config", "view", "--raw", "-o", "json"],
            timeout=30)
    if not r["ok"]:
        return None, (r["stderr"] or "kubectl config view a échoué").replace(path, "<kubeconfig>")
    try:
        return json.loads(r["stdout"] or "{}"), None
    except ValueError as e:
        return None, "Kubeconfig illisible : %s" % e


def _kc_contexts(view):
    """[{name, cluster, user, server, auth}] + contexte courant, depuis `config view`."""
    by = lambda key: {e.get("name"): (e.get(key[:-1]) or {}) for e in (view.get(key) or [])}
    clusters, users = by("clusters"), by("users")
    out = []
    for e in view.get("contexts") or []:
        ctx = e.get("context") or {}
        cl = clusters.get(ctx.get("cluster")) or {}
        out.append({"name": e.get("name"), "cluster": ctx.get("cluster"), "user": ctx.get("user"),
                    "namespace": ctx.get("namespace") or "", "server": cl.get("server") or "",
                    "auth": _kc_auth_info(users.get(ctx.get("user")), cl)})
    return out, view.get("current-context") or ""


def _load_kubeconfig_text(text):
    """Écrit le kubeconfig dans un fichier privé et l'analyse.
    Renvoie (path, contexts, current, err) — path supprimé en cas d'erreur."""
    if not isinstance(text, str) or not text.strip():
        return None, [], "", "Kubeconfig vide."
    if len(text.encode("utf-8")) > KUBECONFIG_MAX_BYTES:
        return None, [], "", "Kubeconfig trop volumineux (1 Mo max)."
    path = _write_kc_file(text)
    view, err = _kc_view(path)
    if err:
        _rm_quiet(path)
        return None, [], "", "Kubeconfig invalide : %s" % err
    ctxs, cur = _kc_contexts(view)
    if not ctxs:
        _rm_quiet(path)
        return None, [], "", "Aucun contexte dans ce kubeconfig."
    return path, ctxs, cur, None


def _cluster_slug(name):
    return re.sub(r"[^a-z0-9._-]+", "-", (name or "").strip().lower()).strip("-._")[:63]


def action_clusters_inspect(payload):
    """Analyse un kubeconfig SANS l'enregistrer : contextes, serveur, type d'auth."""
    path, ctxs, cur, err = _load_kubeconfig_text(payload.get("kubeconfig"))
    _rm_quiet(path)
    if err:
        return _err(err)
    return _ok(contexts=ctxs, current=cur or ctxs[0]["name"])


def _test_cluster(path, context):
    """Test de connectivité (lecture seule, 10 s max). Renvoie (ok, avertissement|erreur)."""
    r = run(CONFIG["kubectl_path"].split() + ["--kubeconfig", path, "--context", context,
            "--request-timeout=10s", "get", "ns", "-o", "name"], timeout=25)
    if r["ok"]:
        return True, None
    msg = (r["stderr"] or "").replace(path, "<kubeconfig>")
    if "forbidden" in msg.lower():
        return True, ("Connexion établie, mais la liste des namespaces est refusée (RBAC) : l'outil "
                      "ne verra que les namespaces explicitement autorisés.")
    return False, msg or "Cluster injoignable."


def _register_cluster(name, text, context=None, workspace="", source="upload", nkp_ref="",
                      management="", test=True, allow_exec=True):
    """Enregistre un cluster supplémentaire. Renvoie _ok(cluster=…) ou _err(...).
    allow_exec=False : refuse un contexte authentifié par plugin « exec » (kubectl
    exécuterait alors une commande arbitraire décrite DANS le kubeconfig — inacceptable
    pour un kubeconfig qui ne vient pas directement de l'opérateur, ex. Secret NKP)."""
    name = (name or "").strip()
    cid = _cluster_slug(name)
    if not name or not cid or len(name) > 63:
        return _err("Nom de cluster invalide (1 à 63 caractères, lettres/chiffres/-/./_).")
    if cid == LOCAL_CID or name == (_local_context_name() or ""):
        return _err("Ce nom est réservé au cluster local : choisissez-en un autre.")
    with CLUSTERS_LOCK:
        if cid in CLUSTERS or any(c["name"] == name for c in CLUSTERS.values()):
            return _err("Un cluster nommé « %s » est déjà enregistré." % name)
    path, ctxs, cur, err = _load_kubeconfig_text(text)
    if err:
        return _err(err)
    names = [c["name"] for c in ctxs]
    context = (context or "").strip() or (cur if cur in names else "") or (names[0] if len(names) == 1 else "")
    if not context:
        _rm_quiet(path)
        return _err("Ce kubeconfig contient plusieurs contextes : choisissez-en un.",
                    need_context=True, contexts=ctxs)
    if context not in names:
        _rm_quiet(path)
        return _err("Contexte « %s » introuvable dans ce kubeconfig." % context, contexts=ctxs)
    info = next(c for c in ctxs if c["name"] == context)
    if not allow_exec and info["auth"].get("type") == "exec":
        _rm_quiet(path)
        return _err("Kubeconfig refusé : authentification par plugin exec (commande externe) non "
                    "autorisée pour un kubeconfig importé automatiquement.")
    note = None
    if test:
        ok, note = _test_cluster(path, context)
        if not ok:
            _rm_quiet(path)
            return _err("Connexion au cluster impossible : %s" % note)
    entry = {"id": cid, "name": name, "context": context, "server": info["server"],
             "kc_path": path, "kubeconfig": text, "auth": info["auth"], "user": info["user"],
             "workspace": workspace or "", "source": source, "nkp_ref": nkp_ref or "",
             "management": management or "", "added": time.time(), "note": note}
    with CLUSTERS_LOCK:
        if cid in CLUSTERS:                     # course : ajouté entre-temps
            _rm_quiet(path)
            return _err("Un cluster nommé « %s » est déjà enregistré." % name)
        CLUSTERS[cid] = entry
    return _ok(cluster=_cluster_public(entry))


def _cluster_public(c):
    """Vue publique d'un cluster (jamais le kubeconfig ni le chemin du fichier)."""
    auth = dict(c.get("auth") or {})
    if auth.get("expires"):                     # ré-évaluer l'expiration à chaque lecture
        exp = auth["expires"]
        if exp <= time.time() and auth.get("level") != "error":
            auth["level"] = "error"
            auth["warnings"] = list(auth.get("warnings") or []) + ["Le jeton a EXPIRÉ : régénérez le kubeconfig."]
    return {"id": c["id"], "name": c["name"], "context": c["context"], "server": c["server"],
            "auth": auth, "workspace": c.get("workspace") or "", "source": c.get("source") or "upload",
            "nkp_ref": c.get("nkp_ref") or "", "management": c.get("management") or "",
            "warning": c.get("note")}


def action_clusters():
    """Liste des clusters : le local (configuration) + les clusters ajoutés."""
    local_ctx = _local_context_name()
    out = [{"id": LOCAL_CID, "name": local_ctx or "local", "context": local_ctx or "",
            "server": "", "local": True, "configured": bool(local_ctx),
            "kubeconfig_path": (CONFIG.get("kubeconfig_path") or "").strip(),
            "auth": None, "workspace": "", "source": "config"}]
    with CLUSTERS_LOCK:
        extra = [_cluster_public(c) for c in CLUSTERS.values()]
    for c in out + extra:
        c["health"] = CLUSTER_HEALTH.get(c["id"])
    return _ok(clusters=out + extra, active=_current_cid())


def action_clusters_add(payload):
    r = _register_cluster(payload.get("name"), payload.get("kubeconfig"), payload.get("context"),
                          workspace=(payload.get("workspace") or "").strip())
    if r.get("ok"):
        audit("cluster_add", cluster=r["cluster"]["name"], context=r["cluster"]["context"],
              server=r["cluster"]["server"], auth=r["cluster"]["auth"].get("type"))
    return r


def _unregister_cluster(cid):
    with CLUSTERS_LOCK:
        c = CLUSTERS.pop(cid, None)
    if c:
        _rm_quiet(c.get("kc_path"))
    return c


def action_clusters_remove(payload):
    cid = payload.get("id") or ""
    if cid == LOCAL_CID:
        return _err("Le cluster local (configuration) ne peut pas être retiré ici : voir Réglages.")
    c = _unregister_cluster(cid)
    if not c:
        return _err("Cluster inconnu.")
    # Purge du filtre de namespaces persistant : sans cela, un AUTRE cluster ajouté
    # plus tard sous le même nom hériterait silencieusement de cette liste blanche.
    flts = dict(CONFIG.get("cluster_namespace_filters") or {})
    if c["name"] in flts:
        flts.pop(c["name"])
        save_config({"cluster_namespace_filters": flts})
    audit("cluster_remove", cluster=c["name"])
    return _ok(removed=c["name"])


# Santé des clusters : {cid: {"ok": bool, "error": str|None, "at": epoch}} — rempli
# par le thread de contrôle périodique (et par _cluster_health_run dans les tests).
CLUSTER_HEALTH = {}
_HEALTH_STATE = {"last": 0.0}


def _cluster_health_run(now=None):
    """Un passage de contrôle : teste chaque cluster connu en lecture seule.
    Un cluster local non configuré est retiré du tableau (pas un échec)."""
    now = time.time() if now is None else now
    for cid in _cluster_ids():
        with use_cluster(cid, req_timeout=10):
            if cid == LOCAL_CID and not _local_context_name():
                CLUSTER_HEALTH.pop(cid, None)            # local non configuré : sans objet
                continue
            r = kubectl(["get", "ns", "-o", "name"], timeout=25)
            ok = bool(r["ok"])
            err = None if ok else (r["stderr"] or "cluster injoignable")
            if not ok and "forbidden" in (err or "").lower():
                ok, err = True, None                     # joignable, RBAC restreint : sain
            prev = CLUSTER_HEALTH.get(cid)
            CLUSTER_HEALTH[cid] = {"ok": ok, "error": err, "at": now}
            if prev is not None and bool(prev.get("ok")) != ok:
                audit("cluster_health", cluster=_cluster_label(cid), ok=ok, error=err)
    # purge des clusters retirés
    known = set(_cluster_ids())
    for cid in [c for c in CLUSTER_HEALTH if c not in known]:
        CLUSTER_HEALTH.pop(cid, None)
    _HEALTH_STATE["last"] = now


def _cluster_health_loop():
    """Thread démon : contrôle la santé des clusters toutes les
    `cluster_health_minutes` minutes (0 = désactivé ; modifiable sans redémarrer)."""
    while True:
        time.sleep(30)
        try:
            mins = float(CONFIG.get("cluster_health_minutes") or 0)
        except (TypeError, ValueError):
            mins = 0
        if mins <= 0:
            continue
        try:
            if time.time() - _HEALTH_STATE["last"] >= max(1.0, mins) * 60.0:
                _cluster_health_run()
        except Exception as e:
            print("Contrôle de santé des clusters : erreur inattendue : %s" % e)


def _wipe_clusters():
    """Oublie tous les clusters ajoutés (verrouillage de session). Renvoie leurs noms."""
    with CLUSTERS_LOCK:
        gone = list(CLUSTERS.values())
        CLUSTERS.clear()
    for c in gone:
        _rm_quiet(c.get("kc_path"))
    return [c["name"] for c in gone]


# --- Découverte NKP (optionnelle) depuis le cluster de MANAGEMENT ---
# NKP (Kommander) : Workspace (cluster-scoped, workspaces.kommander.mesosphere.io) ->
# un namespace par workspace (status.namespaceRef.name) -> KommanderCluster
# (kommander.mesosphere.io, namespacé dans le namespace du workspace) dont
# spec.kubeconfigRef.name désigne le Secret contenant le kubeconfig du cluster.
NKP_WS_RES = "workspaces.kommander.mesosphere.io"
NKP_KC_RES = "kommanderclusters.kommander.mesosphere.io"
NKP_DISPLAY_ANN = "kommander.mesosphere.io/display-name"


def action_nkp_discover():
    """Liste les workspaces NKP et leurs clusters, vus depuis le cluster ACTIF (qui
    doit être le cluster de management). Lecture seule, n'enregistre rien."""
    wsd, err = kubectl_json(["get", NKP_WS_RES])
    if err:
        return _err("Le cluster actif ne semble pas être un cluster de management NKP (ressource "
                    "Workspace introuvable ou accès refusé) : %s" % err)
    ns2ws, workspaces = {}, []
    for w in wsd.get("items") or []:
        md = w.get("metadata") or {}
        name = md.get("name") or ""
        disp = (md.get("annotations") or {}).get(NKP_DISPLAY_ANN) or name
        wns = (((w.get("status") or {}).get("namespaceRef") or {}).get("name")
               or (w.get("spec") or {}).get("namespaceName") or name)
        ns2ws[wns] = disp
        workspaces.append({"name": name, "display": disp, "namespace": wns, "clusters": 0})
    kcd, err = kubectl_json(["get", NKP_KC_RES, "-A"])
    if err:
        return _err("Liste des clusters NKP (KommanderCluster) indisponible : %s" % err)
    with CLUSTERS_LOCK:
        known = {c.get("nkp_ref"): c["name"] for c in CLUSTERS.values() if c.get("nkp_ref")}
    clusters = []
    for k in kcd.get("items") or []:
        md = k.get("metadata") or {}
        ns, name = md.get("namespace") or "", md.get("name") or ""
        ref = ((k.get("spec") or {}).get("kubeconfigRef") or {}).get("name") or ""
        host = (name == "host-cluster") or (not ref and ns == "kommander")
        st = k.get("status") or {}
        ws = ns2ws.get(ns) or ns
        for w in workspaces:
            if w["namespace"] == ns:
                w["clusters"] += 1
        clusters.append({"name": name, "namespace": ns, "workspace": ws,
                         "secret": ref or ("%s-kubeconfig" % name),
                         "phase": st.get("phase") or "", "host": bool(host),
                         "registered": known.get("%s/%s" % (ns, name))})
    clusters.sort(key=lambda c: (c["workspace"].lower(), c["name"].lower()))
    return _ok(workspaces=workspaces, clusters=clusters, management=_cluster_label())


def _kubeconfig_from_secret(sec):
    """Texte du kubeconfig contenu dans un Secret (clés usuelles, sinon heuristique)."""
    data = sec.get("data") or {}
    keys = [k for k in ("value", "kubeconfig", "admin.conf", "config") if k in data] + sorted(data)
    for k in keys:
        try:
            txt = base64.b64decode(data[k]).decode("utf-8")
        except Exception:
            continue
        if "clusters" in txt and "contexts" in txt:
            return txt
    return None


def action_nkp_import(payload):
    """Importe des clusters NKP découverts : lit le Secret kubeconfig de chacun (sur
    le cluster de management ACTIF), l'enregistre et le teste. Opt-in explicite :
    exige payload.ack=True (lecture de Secrets = droits élevés sur le management)."""
    if not payload.get("ack"):
        return _err("Confirmez d'abord l'avertissement sur les privilèges requis.")
    mgmt = _cluster_label()
    results = []
    for it in payload.get("items") or []:
        ns, name = (it.get("namespace") or "").strip(), (it.get("name") or "").strip()
        secret = (it.get("secret") or "").strip() or ("%s-kubeconfig" % name)
        label = "%s/%s" % (ns, name)
        if not all(K8S_NAME_RE.match(x or "") for x in (ns, name, secret)):
            results.append({"cluster": label, "ok": False, "error": "Nom invalide."})
            continue
        sec, err = kubectl_json(["get", "secret", secret, "-n", ns])
        if err:
            results.append({"cluster": label, "ok": False,
                            "error": "Secret « %s » illisible : %s" % (secret, err)})
            continue
        text = _kubeconfig_from_secret(sec)
        if not text:
            results.append({"cluster": label, "ok": False,
                            "error": "Aucun kubeconfig trouvé dans le Secret « %s »." % secret})
            continue
        ws = (it.get("workspace") or "").strip()
        cname = name
        with CLUSTERS_LOCK:
            taken = {c["name"] for c in CLUSTERS.values()}
        if cname in taken and ws:
            cname = "%s-%s" % (name, _cluster_slug(ws))
        r = _register_cluster(cname, text, None, workspace=ws, source="nkp", nkp_ref=label,
                              management=mgmt, test=bool(payload.get("test", True)), allow_exec=False)
        if r.get("ok"):
            audit("nkp_import", cluster=cname, workspace=ws, management=mgmt, secret=secret)
            results.append({"cluster": label, "ok": True, "name": cname, "warning": r["cluster"].get("warning"),
                            "auth": r["cluster"]["auth"]})
        else:
            results.append({"cluster": label, "ok": False, "error": r.get("error")})
    n = sum(1 for r in results if r["ok"])
    return {"ok": n > 0 or not results, "error": None if n or not results else "Aucun cluster importé.",
            "results": results, "imported": n}


def kubectl(args, dry=False, label=None, timeout=None, input_text=None):
    return run(_kubectl_base() + args, dry=dry, label=label, timeout=timeout,
               input_text=input_text)


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


def _clean_resource(obj, include_secret_data=False):
    """Nettoie un manifeste namespacé quelconque pour un instantané de config :
    retire `status` et les métadonnées runtime. Cas particuliers :
      - ServiceAccount : on retire la liste `secrets` (tokens auto-générés) ;
      - Secret : par défaut, les DONNÉES sont MASQUÉES (pas de secret en clair sur
        disque) ; la structure (clés, type) est conservée."""
    kind = (obj.get("kind") or "").lower()
    obj.pop("status", None)
    meta = obj.get("metadata", {})
    _strip_meta(meta)
    meta.pop("finalizers", None)
    if kind == "serviceaccount":
        obj.pop("secrets", None)
    if kind == "secret" and not include_secret_data:
        if isinstance(obj.get("data"), dict):
            obj["data"] = {k: "__REDACTED__" for k in obj["data"]}
        obj.pop("stringData", None)
        ann = meta.setdefault("annotations", {})
        ann["hycu.backup/secret-data"] = "redacted"
    return obj


def _backup_namespace_resources(ns, d):
    """Sauvegarde de configuration ÉTENDUE (lecture seule) : exporte les ressources du
    namespace au-delà des PV/PVC (Deployments, Services, ConfigMaps, Secrets...). Écrit
    `resources.json` dans le dossier de sauvegarde `d`.

    Robuste : un type refusé (RBAC) ou inconnu est IGNORÉ, jamais une erreur — la
    sauvegarde PV/PVC ne doit jamais échouer à cause de cet extra. Renvoie
    (nombre d'objets, liste des types ignorés)."""
    kinds = CONFIG.get("config_backup_kinds") or CONFIG_BACKUP_KINDS_DEFAULT
    # Secrets : chiffrés (secrets.enc, phrase du coffre), en clair, ou masqués — voir
    # _secrets_mode. Dans resources.json, un Secret chiffré reste MASQUÉ (structure
    # conservée) avec l'annotation hycu.backup/secret-data=encrypted ; la lecture
    # (_load_backup_resources) le recompose quand la phrase est disponible.
    mode = _secrets_mode()
    pw = _backup_secret_passphrase() if mode in ("auto", "encrypted") else ""
    if mode == "auto":
        eff = "encrypted" if pw else "clear"
    elif mode == "encrypted":
        eff = "encrypted" if pw else "redacted"
    else:
        eff = mode
    include_secret = (eff == "clear")
    out, skipped, secret_objs = [], [], []

    def take(data):
        for item in (data or {}).get("items", []):
            try:
                raw = json.loads(json.dumps(item))
                if eff == "encrypted" and (raw.get("kind") or "").lower() == "secret":
                    secret_objs.append(_clean_resource(json.loads(json.dumps(raw)), True))
                    red = _clean_resource(raw, False)
                    red.setdefault("metadata", {}).setdefault("annotations", {})["hycu.backup/secret-data"] = "encrypted"
                    out.append(red)
                else:
                    out.append(_clean_resource(raw, include_secret))
            except Exception:
                pass

    # UN seul appel pour tous les types (15 fois moins d'appels kubectl par namespace) ;
    # kubectl échoue (rc 1) dès qu'un type est inconnu ou refusé -> repli type par type,
    # qui IGNORE les types en erreur comme avant.
    data, err = kubectl_json(["get", ",".join(kinds), "-n", ns]) if len(kinds) > 1 else (None, "un seul type")
    if not err and data:
        take(data)
    else:
        for kind in kinds:
            data, err = kubectl_json(["get", kind, "-n", ns])
            if err or not data:
                skipped.append(kind)
                continue
            take(data)
    if eff == "encrypted" and secret_objs:
        sp = os.path.join(d, SECRETS_FILE)
        with open(sp, "wb") as f:
            f.write(encrypt_bytes(json.dumps(secret_objs).encode("utf-8"), pw))
        try:
            os.chmod(sp, 0o600)
        except OSError:
            pass
    with open(os.path.join(d, "resources.json"), "w", encoding="utf-8") as f:
        json.dump({"namespace": ns, "kinds": kinds, "secret_data_included": include_secret,
                   "secrets": eff, "items": out}, f, indent=2)
    return len(out), skipped, out, eff


SECRETS_FILE = "secrets.enc"      # Secrets chiffrés d'une sauvegarde (format HV2B, phrase du coffre)
_VAULT_PW = ""                    # phrase du coffre en MÉMOIRE de session — jamais sur disque


def _backup_secret_passphrase():
    """Phrase secrète servant à chiffrer/déchiffrer les Secrets sauvegardés : celle du
    coffre, déverrouillé dans l'interface (mémoire) ou fournie par l'environnement
    (HYCU_VAULT_PASSPHRASE[_FILE], déploiement Kubernetes). Vide = indisponible."""
    return _VAULT_PW or _vault_env_passphrase() or ""


def _secrets_mode():
    """Mode de sauvegarde des données des Secrets (réglage backup_secrets) :
    auto | encrypted | clear | redacted. L'ancien réglage
    config_backup_include_secret_data=true équivaut à « clear »."""
    m = str(CONFIG.get("backup_secrets") or "auto").strip().lower()
    if m not in ("auto", "encrypted", "clear", "redacted"):
        m = "auto"
    if m == "auto" and CONFIG.get("config_backup_include_secret_data"):
        m = "clear"
    return m


def _obj_secret_encrypted(obj):
    """Secret dont les données sont dans secrets.enc (chiffrées) et pas encore recomposées."""
    if (obj.get("kind") or "").lower() != "secret":
        return False
    ann = (obj.get("metadata") or {}).get("annotations") or {}
    return ann.get("hycu.backup/secret-data") == "encrypted" and _obj_is_redacted(obj)


def _merge_backup_secrets(bp, items):
    """Recompose les Secrets chiffrés de la sauvegarde `bp` dans `items` quand la phrase
    du coffre est disponible ; sinon ils restent masqués (non restaurables) et l'appelant
    peut le signaler. Renvoie (items, état) — état : merged | locked | none."""
    sp = os.path.join(bp, SECRETS_FILE)
    if not os.path.isfile(sp) or not any(_obj_secret_encrypted(o) for o in items):
        return items, "none"
    pw = _backup_secret_passphrase()
    if not pw:
        return items, "locked"
    try:
        with open(sp, "rb") as f:
            data = decrypt_bytes(f.read(), pw)
    except OSError:
        data = None
    if data is None:
        return items, "locked"                      # mauvaise phrase / fichier altéré
    try:
        full = {(o.get("metadata") or {}).get("name"): o
                for o in json.loads(data.decode("utf-8")) if isinstance(o, dict)}
    except ValueError:
        return items, "locked"
    out = []
    for o in items:
        if _obj_secret_encrypted(o) and (o.get("metadata") or {}).get("name") in full:
            out.append(json.loads(json.dumps(full[o["metadata"]["name"]])))
        else:
            out.append(o)
    return out, "merged"


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
def _storage_floor_error(root):
    """Erreur si l'espace libre du disque de `root` est sous le plancher
    storage_min_free_mb (0 = garde désactivée). Fail-open si le disque est
    illisible (mieux vaut sauvegarder que bloquer sur une erreur de mesure)."""
    try:
        floor = max(0, int(CONFIG.get("storage_min_free_mb") or 0)) * 1024 * 1024
    except (TypeError, ValueError):
        floor = 500 * 1024 * 1024
    if not floor:
        return None
    try:
        free = shutil.disk_usage(root).free
    except OSError:
        return None
    if free < floor:
        return ("Espace disque insuffisant sous %s : %d Mo libres (plancher : %d Mo). "
                "Sauvegarde REFUSÉE pour ne pas saturer le stockage — libérez de la place, "
                "réduisez la rétention (Politiques) ou l'historique des tâches (Réglages)."
                % (root, free // 1024 // 1024, floor // 1024 // 1024))
    return None


def _all_backup_dirs(root):
    """Tous les dossiers de sauvegarde sous `root` (index.json présent), tous
    namespaces et clusters confondus : [(chemin, epoch, taille, ns_clé)] — depuis le
    catalogue (un index illisible n'y figure pas : jamais purgé d'office)."""
    out = []
    for base in _catalog_bases(root):
        for ns, vs in _catalog_all(base).items():
            for v in vs:
                key = "%s|%s" % (v.get("cluster_id") or "local", v.get("namespace") or ns)
                out.append((_catalog_backup_path(base, ns, v), v.get("epoch") or 0, v.get("size") or 0, key))
    return out


def enforce_storage_quota(root=None):
    """QUOTA global du dossier de sauvegardes (storage_quota_gb ; 0 = illimité) :
    purge les sauvegardes LES PLUS ANCIENNES (tous namespaces/clusters) jusqu'à
    repasser sous le quota. Toujours conservées : la plus récente de chaque
    namespace×cluster, et la sauvegarde d'une transaction de restauration en cours.
    Renvoie (nb supprimé, octets libérés)."""
    try:
        quota = float(CONFIG.get("storage_quota_gb") or 0) * 1024 ** 3
    except (TypeError, ValueError):
        quota = 0
    if quota <= 0:
        return 0, 0
    root = root or CONFIG["backup_root"]
    backups = _all_backup_dirs(root)
    total = sum(b[2] for b in backups)
    if total <= quota:
        return 0, 0
    # protéger la plus récente de chaque namespace×cluster + les sauvegardes de txn
    latest = {}
    for path, ts, size, key in backups:
        if key not in latest or ts > latest[key][1]:
            latest[key] = (path, ts)
    protected = {os.path.realpath(p) for p, _t in latest.values()}
    # Protéger aussi tout dossier référencé par une transaction de restauration en
    # cours (_restore_txn.json), quel que soit le cluster.
    for dirpath, dirs, fnames in os.walk(root):
        if "_restore_txn.json" in fnames:
            try:
                with open(os.path.join(dirpath, "_restore_txn.json"), encoding="utf-8") as f:
                    t = json.load(f)
                if t.get("status") == "in_progress" and t.get("backup_dir"):
                    protected.add(os.path.realpath(t["backup_dir"]))
            except (OSError, ValueError):
                pass
    removed, freed = 0, 0
    for path, ts, size, key in sorted(backups, key=lambda b: b[1]):   # plus anciennes d'abord
        if total - freed <= quota:
            break
        if os.path.realpath(path) in protected:
            continue
        try:
            shutil.rmtree(path)
            removed += 1
            freed += size
            _catalog_forget_path(path)
        except OSError as e:
            print("Quota de stockage : suppression impossible de %s : %s" % (path, e))
    if removed:
        audit("storage_quota_prune", root=root, removed=removed, freed_mb=freed // 1024 // 1024,
              quota_gb=CONFIG.get("storage_quota_gb"))
    return removed, freed


def backup_dir(ns, root=None):
    ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f")  # microsec anti-collision
    d = os.path.join(_cluster_root(root or CONFIG["backup_root"]), ns, ts)
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


def _scan_backup_dir(base):
    out = []
    if not os.path.isdir(base):
        return out
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


def list_backups(ns, root=None):
    """Liste les sauvegardes d'un namespace pour le CLUSTER ACTIF. Pour le cluster
    local, les sauvegardes de l'ancienne disposition (<root>/<ns>, antérieure à la
    hiérarchie par contexte) sont incluses SI leur index porte le contexte courant
    (ou aucun contexte). Triées plus récentes d'abord."""
    root = os.path.expanduser(root.strip()) if (root and root.strip()) else CONFIG["backup_root"]
    croot = _cluster_root(root)
    out = _scan_backup_dir(os.path.join(croot, ns))
    if _current_cid() == LOCAL_CID and croot != root:
        ctx = _local_context_name()
        for b in _scan_backup_dir(os.path.join(root, ns)):
            bctx = (b.get("index") or {}).get("context")
            if bctx in (None, "", ctx):
                out.append(b)
        out.sort(key=lambda b: b["timestamp"], reverse=True)
    return out


# ------------------------------------------------------------------------------
# CATALOGUE des sauvegardes — « base » en fichier plat JSON, DÉRIVÉE et reconstructible.
# Pourquoi : à 1 000 namespaces × 15 versions, relire 15 000 index.json à chaque
# affichage (page Applications, tableau de bord toutes les 30 s, inventaire DR, quota,
# tuile Stockage) coûte des secondes à des minutes. Le catalogue (<base>/_catalog.json ;
# une base = un dossier de cluster/contexte, la disposition historique ou un dossier
# d'import S3) mémorise, par namespace et par version, le RÉSUMÉ consommé par ces écrans
# (horodatage, volumes, identités des VG, applications, taille…).
# Il n'est JAMAIS la source de vérité d'une restauration : celle-ci lit toujours
# index.json et les manifestes (list_backups, _safe_backup_path, _backup_cluster_error).
# Invalidation : date de modification + nombre d'entrées du dossier du namespace, et
# OUBLI EXPLICITE après chaque écriture de l'outil (sauvegarde, rétention, quota, import
# S3). Un catalogue supprimé ou corrompu est simplement reconstruit au prochain accès.
# ------------------------------------------------------------------------------
CATALOG_FILE = "_catalog.json"
CATALOG_VERSION = 1
_CATALOG_LOCK = threading.RLock()
_CATALOGS = {}            # base (chemin absolu) -> {"ns": {ns: {"key", "versions", "pending"}}, "dirty"}


def _catalog_summary(path, idx):
    """Résumé d'UNE version (index.json déjà lu) : uniquement les champs consommés par
    l'inventaire, la page Applications, la DR et le quota — jamais les manifestes."""
    vols, vol_refs, vol_hycu, vol_names = [], {}, {}, {}
    for v in (idx.get("volumes") or []):
        pvc = v.get("pvc")
        if not pvc:
            continue
        vols.append(pvc)
        m = UUID_RE.search(((v.get("analysis") or {}).get("old_volume_handle")) or "")
        if m:
            vol_refs[pvc] = m.group(0)
        hy = ((v.get("restore_contract") or {}).get("hycu_uuid")) or ""
        if hy:
            vol_hycu[pvc] = hy
        nm = ((v.get("restore_contract") or {}).get("vg_name")) or v.get("pv") or ""
        if nm:
            vol_names[pvc] = nm
    size, files = _dir_size(path)
    return {"ts": os.path.basename(path), "created": idx.get("created") or "",
            "epoch": _backup_epoch({"path": path, "index": idx}) or 0,
            "namespace": idx.get("namespace") or "", "context": idx.get("context") or "",
            "cluster": idx.get("cluster") or "", "cluster_id": idx.get("cluster_id") or "",
            "volumes": vols, "vol_refs": vol_refs, "vol_hycu": vol_hycu, "vol_names": vol_names,
            "resources_count": idx.get("resources_count"),
            "has_resources": os.path.isfile(os.path.join(path, "resources.json")),
            "partial": bool(idx.get("partial")), "apps": idx.get("apps") or [],
            "secrets": idx.get("secrets"), "size": size, "files": files}


def _catalog_load(base):
    base = os.path.abspath(base)
    with _CATALOG_LOCK:
        cat = _CATALOGS.get(base)
        if cat is None:
            cat = {"ns": {}, "dirty": False}
            try:
                with open(os.path.join(base, CATALOG_FILE), encoding="utf-8") as f:
                    doc = json.load(f)
                if isinstance(doc, dict) and doc.get("v") == CATALOG_VERSION and isinstance(doc.get("ns"), dict):
                    cat["ns"] = doc["ns"]
            except (OSError, ValueError):
                pass                              # absent / corrompu : reconstruit
            _CATALOGS[base] = cat
        return cat


def _catalog_save(base):
    """Écriture atomique du catalogue s'il a changé (jamais bloquant)."""
    base = os.path.abspath(base)
    with _CATALOG_LOCK:
        cat = _CATALOGS.get(base)
        if not cat or not cat["dirty"]:
            return
        cat["dirty"] = False
        if not os.path.isdir(base):
            return
        tmp = os.path.join(base, CATALOG_FILE + ".tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"v": CATALOG_VERSION, "ns": cat["ns"]}, f)
            os.replace(tmp, os.path.join(base, CATALOG_FILE))
        except OSError as e:
            print("Catalogue des sauvegardes non écrit (%s) : %s" % (base, e))


def _catalog_forget(base, ns=None):
    """Oubli explicite (après une écriture de l'outil) : le namespace — ou toute la
    base — sera rescanné au prochain accès."""
    if not base:
        return
    base = os.path.abspath(base)
    with _CATALOG_LOCK:
        cat = _CATALOGS.get(base)
        if not cat:
            return
        if ns is None:
            cat["ns"].clear()
        else:
            cat["ns"].pop(ns, None)
        cat["dirty"] = True
    _catalog_save(base)


def _catalog_forget_path(backup_dir):
    """Oubli depuis le chemin d'UNE sauvegarde (<base>/<ns>/<horodatage>)."""
    try:
        nsdir = os.path.dirname(os.path.abspath(backup_dir))
        _catalog_forget(os.path.dirname(nsdir), os.path.basename(nsdir))
    except Exception:
        pass


def _catalog_ns(base, ns, save=True):
    """Résumés des versions de `ns` sous `base` (<base>/<ns>/<horodatage>/index.json),
    plus récentes d'abord. Réutilise le catalogue si le dossier du namespace n'a pas
    changé ; sinon ne relit que les versions nouvelles. Les dossiers vus SANS index.json
    (sauvegarde en cours d'écriture) sont revérifiés à chaque appel."""
    base = os.path.abspath(base)
    nsdir = os.path.join(base, ns)
    try:
        st = os.stat(nsdir)
        names = os.listdir(nsdir)
    except OSError:
        with _CATALOG_LOCK:
            cat = _catalog_load(base)
            if ns in cat["ns"]:
                cat["ns"].pop(ns, None)
                cat["dirty"] = True
        if save:
            _catalog_save(base)
        return []
    key = [st.st_mtime_ns, len(names)]
    with _CATALOG_LOCK:
        cat = _catalog_load(base)
        ent = cat["ns"].get(ns)
        if ent and ent.get("key") == key and not any(
                os.path.isfile(os.path.join(nsdir, t, "index.json")) for t in (ent.get("pending") or [])):
            return list(ent.get("versions") or [])
        old = {v["ts"]: v for v in ((ent or {}).get("versions") or []) if v.get("ts")}
        versions, pending = [], []
        for ts in names:
            p = os.path.join(nsdir, ts)
            prev = old.get(ts)
            if prev is not None:
                versions.append(prev)
                continue
            ip = os.path.join(p, "index.json")
            if not os.path.isfile(ip):
                if os.path.isdir(p):
                    pending.append(ts)
                continue
            try:
                with open(ip, encoding="utf-8") as f:
                    idx = json.load(f)
            except (OSError, ValueError):
                continue
            versions.append(_catalog_summary(p, idx))
        versions.sort(key=lambda v: v["ts"], reverse=True)
        cat["ns"][ns] = {"key": key, "versions": versions, "pending": pending}
        cat["dirty"] = True
    if save:
        _catalog_save(base)
    return list(versions)


def _catalog_all(base):
    """{ns: [versions]} pour toute une base : un listdir + un stat par namespace, seuls
    les namespaces modifiés sont rescannés ; le catalogue est écrit une fois."""
    base = os.path.abspath(base)
    out = {}
    if not os.path.isdir(base):
        return out
    try:
        entries = sorted(os.listdir(base))
    except OSError:
        return out
    for ns in entries:
        if ns.startswith("_") or not K8S_NAME_RE.match(ns):
            continue
        vs = _catalog_ns(base, ns, save=False)
        if vs:
            out[ns] = vs
    with _CATALOG_LOCK:
        cat = _catalog_load(base)
        for gone in [n for n in cat["ns"] if n not in entries]:
            cat["ns"].pop(gone, None)
            cat["dirty"] = True
    _catalog_save(base)
    return out


def _catalog_bases(root):
    """Toutes les bases sous `root` : disposition historique (<root>/<ns>), puis
    _contexts/*, _clusters/* et _imports/*."""
    root = os.path.abspath(root)
    bases = [root]
    for sub in ("_contexts", "_clusters", "_imports"):
        d = os.path.join(root, sub)
        try:
            for n in sorted(os.listdir(d)):
                p = os.path.join(d, n)
                if os.path.isdir(p):
                    bases.append(p)
        except OSError:
            pass
    return bases


def _catalog_backup_path(base, ns, v):
    return os.path.join(os.path.abspath(base), ns, v["ts"])


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
    cid = _current_cid()
    if cid != LOCAL_CID:
        # Cluster ajouté depuis l'interface : « contexte » affiché/confirmé = nom du
        # cluster ; autorisé si son nom OU son contexte kubeconfig est dans allowed_contexts.
        c = _get_cluster(cid)
        base = {"allowed": allowed, "require_confirm": bool(CONFIG.get("require_context_confirm")),
                "cluster_id": cid}
        if not c:
            return {**base, "context": None, "error": _NO_CLUSTER_MSG % cid, "context_ok": False,
                    "kubectl_ok": False, "kubectl_hint": "no_cluster", "selected_context": "",
                    "cluster_name": None}
        pub = _cluster_public(c)
        return {**base, "context": c["name"], "error": None,
                "context_ok": (not allowed) or (c["name"] in allowed) or (c["context"] in allowed),
                "kubectl_ok": True, "kubectl_hint": None, "selected_context": c["context"],
                "cluster_name": c["name"], "kube_context": c["context"], "server": c["server"],
                "workspace": pub["workspace"], "auth": pub["auth"]}
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
    _LOCAL_CTX.update({"name": ctx, "at": time.time()})
    return {"context": ctx, "error": err, "cluster_id": LOCAL_CID, "cluster_name": ctx or "local",
            "allowed": allowed,
            "context_ok": (not allowed) or (ctx in allowed),
            "kubectl_ok": kubectl_ok, "kubectl_hint": hint,
            "selected_context": selected,
            "require_confirm": bool(CONFIG.get("require_context_confirm"))}


def _namespace_allowed(ns):
    flt = _ns_filter()
    if flt and ns not in flt:
        return False
    return _ns_selector_ok(ns)


def _allow_namespace(ns, log=None):
    """Ajoute ns à la liste blanche namespace_filter (si un filtre est actif).

    Un namespace CRÉÉ PAR L'OUTIL (clone d'application vers un nouveau namespace)
    doit rester utilisable ensuite : sans cet ajout, Vérifier/Restaurer/Sauvegarder
    refuseraient le namespace fraîchement créé (« Namespace non autorisé »)."""
    flt = _ns_filter()
    if not flt or ns in flt:
        return
    _save_ns_filter(flt + [ns])
    audit("namespace_filter_auto_add", namespace=ns)
    if log is not None:
        log.append(logentry("Namespace « %s » ajouté aux namespaces autorisés" % ns, ok=True,
                            stdout="Filtre mis à jour (⚙ Réglages) pour que Vérifier/Restaurer acceptent ce namespace."))


def _ns_label_selector():
    return (CONFIG.get("namespace_label_selector") or "").strip()


def _ns_selector_ok(ns):
    """Vrai si `ns` satisfait le sélecteur d'étiquettes (ou s'il n'y en a pas).
    Une ERREUR kubectl vaut refus (fail-safe : ne pas ouvrir plus large en panne)."""
    sel = _ns_label_selector()
    if not sel:
        return True
    r = kubectl(["get", "ns", ns, "-l", sel, "-o", "name", "--ignore-not-found"])
    return bool(r["ok"] and r["stdout"].strip())


def action_namespaces():
    sel = _ns_label_selector()
    data, err = kubectl_json(["get", "ns"] + (["-l", sel] if sel else []))
    if err:
        return {"ok": False, "namespaces": [], "error": err}
    names = sorted(i["metadata"]["name"] for i in data.get("items", []))
    flt = _ns_filter()
    if flt:
        names = [n for n in names if n in flt]
    return {"ok": True, "namespaces": names, "error": None}


def action_ns_filter():
    """Liste TOUTES les namespaces du cluster (non filtrées par nom — mais restreintes
    au sélecteur d'étiquettes s'il est actif) + le filtre courant, pour l'éditeur."""
    sel = _ns_label_selector()
    data, err = kubectl_json(["get", "ns"] + (["-l", sel] if sel else []))
    flt = _ns_filter()
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
    _save_ns_filter(flt)
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


def action_backup(ns, dest=None, protect=None, pv_cache=None, defer_quota=False):
    """Exporte + nettoie tous les PV/PVC du namespace (étapes 1-3 du document).
    `dest` (optionnel) = dossier de destination choisi par l'utilisateur (vide = défaut).
    `protect` = chemins de sauvegarde à ne jamais purger par la rétention (ex. la
    sauvegarde SOURCE d'une restauration en cours).
    `pv_cache` = {nom: manifeste PV} lu UNE fois par passage (sauvegarde de tous les
    namespaces) ; un PV absent du cache est relu individuellement. `defer_quota` : le
    quota global est appliqué par l'appelant en fin de passage (pas par namespace)."""
    if not _namespace_allowed(ns):
        return {"ok": False, "error": "Namespace '%s' non autorisé par la configuration." % ns}
    root, derr = _resolve_backup_dest(dest)
    if derr:
        return {"ok": False, "error": derr}
    ferr = _storage_floor_error(root)
    if ferr:
        # Donner d'abord sa chance à la rétention/au quota de libérer de la place :
        # sinon le plancher bloque la seule purge capable de le lever (verrou).
        try:
            _prune_backups(root, ns, CONFIG.get("auto_backup_keep", 15), protect=protect)
            enforce_storage_quota(root)
        except Exception as e:
            print("Rétention avant sauvegarde : %s" % e)
        ferr = _storage_floor_error(root)
    if ferr:
        audit("backup_refused_storage", namespace=ns, root=root)
        return {"ok": False, "error": ferr}
    pvc_data, err = kubectl_json(["get", "pvc", "-n", ns])
    if err:
        return {"ok": False, "error": err}
    items = pvc_data.get("items", [])
    # Namespace sans PVC : sauvegardable quand même (application STATELESS — sa
    # configuration se restaure depuis l'instantané resources.json), à condition que
    # l'instantané soit activé et qu'il contienne au moins un workload (voir plus bas).
    if not items and not CONFIG.get("config_backup_full", True):
        return {"ok": False, "skipped": True, "error": "Aucun PVC trouvé dans le namespace '%s'." % ns}

    d = backup_dir(ns, root)
    index = {"namespace": ns, "created": datetime.datetime.now().isoformat(),
             "context": action_context().get("context"),
             "cluster": _cluster_label(), "cluster_id": _current_cid(), "volumes": []}
    files = []
    pv_errors = []                    # PV attendus mais illisibles -> sauvegarde PARTIELLE
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
            if pv_cache is not None and pv_name in pv_cache:
                pv_data, perr = pv_cache[pv_name], None
            else:
                pv_data, perr = kubectl_json(["get", "pv", pv_name])
            if pv_data and not perr:
                clean_v = clean_pv(json.loads(json.dumps(pv_data)))
                pv_path = os.path.join(d, "pv_%s.json" % pv_name)
                with open(pv_path, "w", encoding="utf-8") as f:
                    json.dump(clean_v, f, indent=2)
                files.append(os.path.basename(pv_path))
                entry["pv_file"] = os.path.basename(pv_path)
                entry["analysis"] = analyse_pv(clean_v)
            else:
                # Ne JAMAIS avaler l'échec : sans le manifeste du PV, ce volume n'est pas
                # restaurable ; la sauvegarde est marquée PARTIELLE et n'entraîne aucune
                # purge des versions précédentes (complètes).
                entry["pv_error"] = perr or "PV introuvable"
                pv_errors.append("%s (PV %s) : %s" % (name, pv_name, entry["pv_error"]))
        index["volumes"].append(entry)
    if pv_errors:
        index["partial"] = True
        index["pv_errors"] = pv_errors

    # Instantané de configuration ÉTENDUE (Deployments, Services, Secrets…) — lecture
    # seule, additif, n'échoue jamais la sauvegarde PV/PVC (voir _backup_namespace_resources).
    resources_count = None
    res_items = []
    secrets_mode = None
    if CONFIG.get("config_backup_full", True):
        try:
            resources_count, _skipped, res_items, secrets_mode = _backup_namespace_resources(ns, d)
            index["resources_count"] = resources_count
            index["secrets"] = secrets_mode
            files.append("resources.json")
            if os.path.isfile(os.path.join(d, SECRETS_FILE)):
                files.append(SECRETS_FILE)
        except Exception as e:
            print("Sauvegarde de config étendue (%s) ignorée : %s" % (ns, e))
    # Secrets en clair faute de phrase de coffre (mode auto) : dit explicitement, pas caché.
    secrets_warning = None
    if secrets_mode == "clear" and _secrets_mode() == "auto":
        secrets_warning = ("Secrets sauvegardés EN CLAIR (aucune phrase de coffre disponible) : "
                           "déverrouillez le coffre (⚙ → Sources) ou fournissez HYCU_VAULT_PASSPHRASE "
                           "pour les chiffrer.")
    # Applications du namespace (workloads regroupés, PVC montés, stateful/stateless) :
    # mémorisées dans l'index pour cibler la restauration — y compris quand le
    # namespace n'existera plus (récupération).
    try:
        index["apps"] = [{k: a[k] for k in ("name", "workloads", "pvcs", "type", "unassigned", "whole_ns") if a.get(k)}
                         for a in _apps_from_workloads(ns, res_items, [p["metadata"]["name"] for p in items])]
    except Exception as e:
        print("Applications de %s non indexées : %s" % (ns, e))
    if not items and not any(o.get("kind") in APP_WORKLOAD_KINDS for o in res_items):
        # Ni PVC ni workload : rien à protéger (namespace vide ou purement système).
        shutil.rmtree(d, ignore_errors=True)
        try:
            os.rmdir(os.path.dirname(d))          # dossier du namespace, s'il est resté vide
        except OSError:
            pass
        return {"ok": False, "skipped": True,
                "error": "Aucun PVC ni workload dans le namespace '%s' : rien à sauvegarder." % ns}

    # Contrat de restauration (best-effort) : de quoi restaurer plus tard SANS saisie
    # d'UUID (nom/UUID du VG côté HYCU, disques, Prism Element, dernier point HYCU).
    # N'échoue jamais la sauvegarde ; ignoré si HYCU/Prism non connectés.
    if CONFIG.get("backup_collect_restore_contract", True):
        try:
            systems = _collect_restore_contract(ns, index["volumes"])
            if systems:
                index["systems"] = systems
        except Exception as e:
            print("Contrat de restauration (%s) ignoré : %s" % (ns, e))

    # Écriture ATOMIQUE de l'index : un arrêt brutal ne laisse jamais un index tronqué
    # (dossier invisible, non purgeable, non compté).
    idx_tmp = os.path.join(d, "index.json.tmp")
    with open(idx_tmp, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2)
    os.replace(idx_tmp, os.path.join(d, "index.json"))
    _catalog_forget_path(d)                   # le catalogue rescanne ce namespace

    if pv_errors:
        audit("backup", namespace=ns, dir=d, count=len(items), resources=resources_count,
              partial=True, pv_errors=len(pv_errors))
        return {"ok": False, "partial": True, "dir": d, "root": root, "count": len(items),
                "files": files, "volumes": index["volumes"], "resources_count": resources_count,
                "error": "Sauvegarde PARTIELLE de « %s » : manifeste de PV illisible pour %s. Les "
                         "versions précédentes sont conservées (aucune purge)." % (ns, " ; ".join(pv_errors))}
    audit("backup", namespace=ns, dir=d, count=len(items), resources=resources_count, secrets=secrets_mode)
    # Garde-fous stockage : la rétention par namespace s'applique aussi aux sauvegardes
    # MANUELLES (sinon elles s'accumulent sans limite), puis le quota global éventuel.
    pruned = 0
    try:
        pruned = _prune_backups(root, ns, CONFIG.get("auto_backup_keep", 15), protect=protect)
        if not defer_quota:
            enforce_storage_quota(root)
    except Exception as e:
        print("Garde-fou stockage après sauvegarde : %s" % e)
    return _s3_after_backup(
        {"ok": True, "error": None, "dir": d, "root": root, "count": len(items), "pruned": pruned,
         "files": files, "volumes": index["volumes"], "resources_count": resources_count,
         "secrets": secrets_mode, "secrets_warning": secrets_warning})


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
    # Grands clusters : les PV sont cluster-scoped -> lus UNE fois pour tout le passage
    # (au lieu d'un appel par volume) ; échec -> lecture individuelle comme avant.
    pv_cache = None
    try:
        prefetch_min = int(CONFIG.get("backup_pv_prefetch_min", 20))
    except (TypeError, ValueError):
        prefetch_min = 20
    if len(namespaces) >= max(prefetch_min, 1):
        pvs, perr = kubectl_json(["get", "pv"])
        if not perr and pvs:
            pv_cache = {(p.get("metadata") or {}).get("name"): p for p in (pvs.get("items") or [])
                        if (p.get("metadata") or {}).get("name")}
    try:
        workers = max(1, int(CONFIG.get("backup_parallel", 4)))
    except (TypeError, ValueError):
        workers = 4
    cid, rto = _current_cid(), getattr(_CL_TL, "req_timeout", None)

    def one(ns):
        with use_cluster(cid, req_timeout=rto):          # threads : cluster de l'appelant
            # Namespace avec une restauration interrompue (transaction en cours) : son état
            # est à moitié restauré — le sauvegarder polluerait « la sauvegarde la plus
            # récente » proposée ensuite. Ignoré (repassera une fois la reprise terminée).
            if _load_txn(ns):
                return {"ns": ns, "ok": False, "skipped": True, "count": 0,
                        "error": "Restauration en cours (transaction) : sauvegarde différée."}
            try:
                b = action_backup(ns, root, pv_cache=pv_cache, defer_quota=True)
            except Exception as e:                      # un namespace en erreur n'arrête pas le passage
                b = {"ok": False, "error": "Erreur interne : %s" % e}
            if b.get("ok"):
                return {"ns": ns, "ok": True, "count": b.get("count", 0), "dir": b.get("dir"),
                        "pruned": int(b.get("pruned") or 0)}
            err = b.get("error") or ""
            return {"ns": ns, "ok": False, "skipped": bool(b.get("skipped")) or "Aucun PVC" in err,
                    "count": 0, "error": err}

    if workers > 1 and len(namespaces) > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(namespaces))) as ex:
            results = list(ex.map(one, namespaces))     # ordre des namespaces conservé
    else:
        results = [one(ns) for ns in namespaces]
    backed_up = sum(1 for r in results if r["ok"])
    vol_total = sum(r["count"] for r in results if r["ok"])
    try:
        enforce_storage_quota(root)                     # une fois par passage, pas par namespace
    except Exception as e:
        print("Quota de stockage en fin de passage : %s" % e)
    audit("backup_all", namespaces=len(namespaces), backed_up=backed_up, volumes=vol_total, root=root)
    return {"ok": True, "error": None, "results": results, "root": root,
            "namespaces": len(namespaces), "backed_up": backed_up, "volumes": vol_total,
            "filtered": bool(_ns_filter())}


# ------------------------------------------------------------------------------
# Sauvegarde AUTOMATIQUE planifiée — tant que l'outil tourne, sauvegarde à
# intervalle régulier la config PV/PVC des namespaces autorisés par le filtre
# (= action_backup_all, en lecture seule côté cluster). Le dernier passage est
# persisté sur disque : l'intervalle est respecté même après un redémarrage.
# ------------------------------------------------------------------------------
AUTO_BACKUP = {"last_run": 0.0, "last_ok": None, "last_summary": "", "running": False}


def _auto_backup_state_path():
    return os.path.join(CONFIG["backup_root"], ".auto_backup_state.json")


def _load_auto_backup_state():
    try:
        with open(_auto_backup_state_path(), encoding="utf-8") as f:
            st = json.load(f)
        for k in ("last_run", "last_ok", "last_summary"):
            if k in st:
                AUTO_BACKUP[k] = st[k]
    except Exception:
        pass                        # pas d'état = jamais exécutée


def _save_auto_backup_state():
    try:
        with open(_auto_backup_state_path(), "w", encoding="utf-8") as f:
            json.dump({k: AUTO_BACKUP[k] for k in ("last_run", "last_ok", "last_summary")}, f)
    except OSError:
        pass                        # best-effort : l'état vit en mémoire de toute façon


def _auto_backup_interval_s():
    try:
        h = float(CONFIG.get("auto_backup_interval_hours") or 24)
    except (TypeError, ValueError):
        h = 24.0
    return max(0.25, h) * 3600.0    # plancher 15 min (garde-fou anti-boucle)


def _auto_backup_due(now):
    if not CONFIG.get("auto_backup_enabled"):
        return False
    last = float(AUTO_BACKUP.get("last_run") or 0)
    if not last:
        return True                 # jamais exécutée -> première sauvegarde immédiate
    return (now - last) >= _auto_backup_interval_s()


def _gfs_keep_paths(backups, daily, weekly, monthly):
    """Sélection GFS : pour chaque jour (D plus récents), chaque semaine ISO (W) et
    chaque mois (M), garder la sauvegarde LA PLUS RÉCENTE. `backups` est trié
    plus récentes d'abord. Renvoie l'ensemble des chemins à conserver."""
    keep = set()
    seen_d, seen_w, seen_m = [], [], []
    for b in backups:
        ts = _backup_epoch(b)
        if not ts:
            keep.add(b["path"])                 # horodatage illisible : ne jamais supprimer
            continue
        dt = datetime.datetime.fromtimestamp(ts)
        iso = dt.isocalendar()
        d, w, m = dt.strftime("%Y-%m-%d"), "%d-W%02d" % (iso[0], iso[1]), dt.strftime("%Y-%m")
        if d not in seen_d and len(seen_d) < max(0, daily):
            seen_d.append(d); keep.add(b["path"])
        if w not in seen_w and len(seen_w) < max(0, weekly):
            seen_w.append(w); keep.add(b["path"])
        if m not in seen_m and len(seen_m) < max(0, monthly):
            seen_m.append(m); keep.add(b["path"])
    if backups:
        keep.add(backups[0]["path"])            # la plus récente, toujours
    return keep


def _prune_backups(root, ns, keep, protect=None):
    """Rétention : mode « count » (garder les `keep` plus récentes ; 0 = pas de
    rétention compteur, comme les autres réglages où 0 = illimité) ou « gfs »
    (quotidiennes/hebdomadaires/mensuelles — auto_backup_retention). Ne supprime QUE
    des dossiers de sauvegarde de l'outil (index.json présent) — jamais autre chose.
    `protect` : chemins supplémentaires à ne jamais supprimer (ex. la sauvegarde SOURCE
    d'une restauration en cours). Renvoie le nombre supprimé (audité s'il est > 0)."""
    try:
        keep = int(keep)
    except (TypeError, ValueError):
        keep = 15
    mode = (CONFIG.get("auto_backup_retention") or "count")
    if mode != "gfs" and keep <= 0:
        return 0
    # Ne JAMAIS supprimer la sauvegarde de sécurité d'une transaction de restauration
    # en cours (seule source des manifestes pour la reprise), ni les chemins protégés.
    txn = _load_txn(ns)
    protected = set()
    if txn and txn.get("backup_dir"):
        protected.add(os.path.realpath(txn["backup_dir"]))
    for p in (protect or []):
        if p:
            protected.add(os.path.realpath(p))
    backups = list_backups(ns, root)             # liste triée : plus récentes d'abord
    if mode == "gfs":
        def _n(key, dflt):
            try:
                return max(0, int(CONFIG.get(key)))
            except (TypeError, ValueError):
                return dflt
        keep_paths = _gfs_keep_paths(backups, _n("auto_backup_keep_daily", 7),
                                     _n("auto_backup_keep_weekly", 4),
                                     _n("auto_backup_keep_monthly", 12))
        doomed = [b for b in backups if b["path"] not in keep_paths]
    else:
        doomed = backups[keep:]
    removed = 0
    for b in doomed:
        if os.path.realpath(b["path"]) in protected:
            continue
        try:
            shutil.rmtree(b["path"])
            removed += 1
            _catalog_forget_path(b["path"])
        except OSError as e:
            print("Rétention sauvegarde auto : suppression impossible de %s : %s" % (b["path"], e))
    if removed:
        audit("backup_prune", namespace=ns, removed=removed, mode=mode,
              keep=(keep if mode != "gfs" else None))
    return removed


def _auto_backup_run(now=None, runner=None):
    """Une exécution de sauvegarde auto (scheduler ou tests). Enregistre le résultat
    puis applique la rétention (auto_backup_keep versions par namespace)."""
    now = time.time() if now is None else now
    dest = CONFIG.get("auto_backup_dest") or None
    # Exclusion mutuelle réelle avec les restaurations : le test « ACTION_LOCK non
    # pris » de la boucle est une course (une restauration peut démarrer juste
    # après) ; on ACQUIERT le verrou pour la durée de la sauvegarde. Occupé ->
    # passage sauté, retentera au tick suivant.
    if BULK["running"]:
        return None                              # restauration en masse : passage sauté (retentera)
    if not ACTION_LOCK.acquire(blocking=False):
        return None
    AUTO_BACKUP["running"] = True
    try:
        if runner is not None:                  # tests : cluster courant uniquement
            parts = [(None,) + _auto_backup_one(runner, dest)]
        else:
            parts = []
            cids = _cluster_ids()
            for cid in cids:
                with use_cluster(cid):
                    # Cluster local non configuré (outil utilisé uniquement avec des
                    # clusters ajoutés) : ignoré sans le compter comme un échec.
                    if cid == LOCAL_CID and len(cids) > 1 and not action_context().get("kubectl_ok"):
                        continue
                    parts.append((_cluster_label(cid),) + _auto_backup_one(action_backup_all, dest))
        ok = bool(parts) and all(p[1] for p in parts)
        if len(parts) <= 1:
            summary = parts[0][2] if parts else "aucun cluster disponible"
        else:
            summary = " | ".join("%s : %s" % (p[0], p[2]) for p in parts)
        AUTO_BACKUP.update({"last_run": now, "last_ok": ok, "last_summary": summary})
        _save_auto_backup_state()
        _apps_cache_clear()
        audit("auto_backup", ok=ok, summary=summary,
              **({"cluster": "*"} if len(parts) > 1 else {}))
        return ok
    finally:
        AUTO_BACKUP["running"] = False
        ACTION_LOCK.release()


def _auto_backup_one(runner, dest):
    """Sauvegarde auto + rétention sur le cluster ACTIF. Renvoie (ok, résumé).
    Un échec RÉEL par namespace (autre que « aucun PVC » / transaction en cours)
    rend le passage NON réussi : le pire défaut d'un outil de sauvegarde serait
    d'afficher « succès » alors que plus rien n'est sauvegardé (ex. jeton expiré)."""
    r = runner(dest)
    ok = bool(r.get("ok"))
    failed = [x.get("ns") for x in (r.get("results") or [])
              if not x.get("ok") and not x.get("skipped")]
    if ok and failed:
        ok = False
    summary = ("%d namespace(s) sauvegardé(s), %d volume(s)" % (r.get("backed_up", 0), r.get("volumes", 0))
               if r.get("ok") else (r.get("error") or "échec"))
    if failed:
        summary += " ; %d en ÉCHEC : %s" % (len(failed), ", ".join(failed[:5]))
    if ok and r.get("root"):
        # La rétention est appliquée par action_backup (une fois par namespace) ; on
        # additionne ce qu'elle a réellement supprimé.
        removed = 0
        for res in r.get("results") or []:
            if not (res.get("ok") and res.get("ns")):
                continue
            if "pruned" in res:                  # action_backup a déjà appliqué la rétention
                removed += int(res.get("pruned") or 0)
            else:                                # runner externe : appliquer ici
                removed += _prune_backups(r["root"], res["ns"], CONFIG.get("auto_backup_keep", 15))
        if removed:
            summary += " ; %d ancienne(s) version(s) supprimée(s)" % removed
    return ok, summary


def _auto_backup_loop():
    """Thread démon : vérifie ~toutes les 30 s si une sauvegarde auto est due.
    Tick sauté si une restauration est en cours (ACTION_LOCK pris) — la sauvegarde
    repassera au tick suivant."""
    _load_auto_backup_state()
    while True:
        time.sleep(30)
        try:
            if _auto_backup_due(time.time()) and not ACTION_LOCK.locked():
                _auto_backup_run()
        except Exception as e:
            print("Sauvegarde auto : erreur inattendue : %s" % e)
        try:
            enforce_storage_quota()
        except Exception as e:
            print("Quota de stockage : erreur inattendue : %s" % e)
        try:
            # Compaction quotidienne du journal d'audit (rétention audit_retention_days).
            if time.time() - _AUDIT_COMPACT["last"] >= 86400:
                n = _audit_compact()
                if n:
                    print("Journal d'audit : %d entrée(s) de plus de %s jours purgée(s)."
                          % (n, CONFIG.get("audit_retention_days")))
        except Exception as e:
            print("Compaction du journal d'audit : erreur inattendue : %s" % e)


def action_auto_backup_status():
    itv = _auto_backup_interval_s()
    last = float(AUTO_BACKUP.get("last_run") or 0)
    enabled = bool(CONFIG.get("auto_backup_enabled"))
    try:
        keep = max(0, int(CONFIG.get("auto_backup_keep", 15)))   # 0 = illimité (pas de compteur)
    except (TypeError, ValueError):
        keep = 15
    return {"ok": True, "enabled": enabled,
            "interval_hours": itv / 3600.0,
            "keep": keep,
            "retention": (CONFIG.get("auto_backup_retention") or "count"),
            "gfs": {"daily": CONFIG.get("auto_backup_keep_daily", 7),
                    "weekly": CONFIG.get("auto_backup_keep_weekly", 4),
                    "monthly": CONFIG.get("auto_backup_keep_monthly", 12)},
            "dest": CONFIG.get("auto_backup_dest") or "",
            "running": bool(AUTO_BACKUP.get("running")),
            "last_run": last or None, "last_ok": AUTO_BACKUP.get("last_ok"),
            "last_summary": AUTO_BACKUP.get("last_summary") or "",
            "next_due": (last + itv) if (enabled and last) else None}


def action_metrics_text():
    """Métriques au format texte Prometheus (exposition 0.0.4).

    Servies UNIQUEMENT en local (mêmes gardes Host/Origin que tout le reste : jamais
    exposées au réseau). Pour un scraping Prometheus réel, passez par un `kubectl
    port-forward` ou un sidecar sur la loopback du Pod. Aucune donnée sensible n'est
    exposée : uniquement des compteurs d'état."""
    itv = _auto_backup_interval_s()
    last = float(AUTO_BACKUP.get("last_run") or 0)
    out = []

    def metric(name, value, help_, typ="gauge", labels=""):
        out.append("# HELP %s %s\n# TYPE %s %s\n%s%s %s\n"
                    % (name, help_, name, typ, name, labels, value))

    metric("hycu_build_info", 1, "Version de build (label version).", labels='{version="%s"}' % VERSION)
    metric("hycu_up", 1, "1 si l'outil répond.")
    metric("hycu_operation_running", 1 if ACTION_LOCK.locked() else 0,
           "1 si une opération destructive (restore/clone) est en cours.")
    metric("hycu_auto_backup_enabled", 1 if CONFIG.get("auto_backup_enabled") else 0,
           "1 si la sauvegarde automatique de configuration est activée.")
    metric("hycu_auto_backup_interval_seconds", int(itv), "Intervalle configuré (s).")
    metric("hycu_auto_backup_last_run_timestamp_seconds", int(last),
           "Horodatage Unix de la dernière sauvegarde automatique (0 si jamais).", typ="counter")
    metric("hycu_auto_backup_last_success", 1 if AUTO_BACKUP.get("last_ok") else 0,
           "1 si la dernière sauvegarde automatique a réussi.")
    with CLUSTERS_LOCK:
        n_extra = len(CLUSTERS)
    metric("hycu_clusters_registered", 1 + n_extra,
           "Clusters Kubernetes connus (local + ajoutés depuis l'interface).")
    try:
        du = shutil.disk_usage(CONFIG["backup_root"])
        metric("hycu_backup_storage_total_bytes", du.total, "Taille du système de fichiers des sauvegardes.")
        metric("hycu_backup_storage_free_bytes", du.free, "Espace libre du système de fichiers des sauvegardes.")
    except OSError:
        pass
    if CLUSTER_HEALTH:
        out.append("# HELP hycu_cluster_reachable 1 si le dernier contrôle de santé du cluster a réussi.\n"
                   "# TYPE hycu_cluster_reachable gauge\n")
        for cid, h in sorted(CLUSTER_HEALTH.items()):
            out.append('hycu_cluster_reachable{cluster="%s"} %d\n' % (cid, 1 if h.get("ok") else 0))
    # État des connexions (par système) — un seul bloc HELP/TYPE, plusieurs lignes.
    out.append("# HELP hycu_connected 1 si le système externe est connecté (session en cours).\n"
               "# TYPE hycu_connected gauge\n")
    for sysname in ("hycu", "nutanix", "prismcentral", "s3"):
        out.append('hycu_connected{system="%s"} %d\n' % (sysname, 1 if SESSION_CREDS.get(sysname) else 0))
    return "".join(out)


# ------------------------------------------------------------------------------
# Vues « à la HYCU » (lecture seule) : Applications (namespaces + protection /
# conformité) et Tâches (historique des opérations, tiré du journal d'audit).
# ------------------------------------------------------------------------------
def _backup_freshness_s():
    """Âge maximal d'une sauvegarde de config pour être « conforme » : l'intervalle
    de la sauvegarde automatique si elle est activée, sinon 24 h (+10 % de marge)."""
    base = _auto_backup_interval_s() if CONFIG.get("auto_backup_enabled") else 24 * 3600.0
    return base * 1.1


def _backup_epoch(b):
    """Horodatage (epoch) d'une sauvegarde : champ `created` de l'index, sinon mtime."""
    created = (b.get("index") or {}).get("created")
    if created:
        try:
            return datetime.datetime.fromisoformat(str(created)).timestamp()
        except ValueError:
            pass
    try:
        return os.path.getmtime(b["path"])
    except OSError:
        return None


# ------------------------------------------------------------------------------
# Applications DANS les namespaces. Un namespace peut héberger plusieurs
# applications (ex. « wordpress » + un outil de supervision). Une application = le
# groupe de workloads portant la même étiquette d'application
# (app.kubernetes.io/instance > app.kubernetes.io/name > app ; sinon le nom du
# workload). Elle est STATEFUL si l'un de ses workloads monte un PVC (volumes
# persistentVolumeClaim, ou volumeClaimTemplates d'un StatefulSet), STATELESS sinon.
# Les SAUVEGARDES restent par namespace (une seule « recette » cohérente) ; l'application
# sert à CIBLER la restauration : volumes présélectionnés (stateful), objets de
# configuration filtrés (stateless). La récupération d'un namespace supprimé et la
# DR restent au niveau du namespace (elles recréent tout).
# ------------------------------------------------------------------------------
APP_WORKLOAD_KINDS = ("Deployment", "StatefulSet", "DaemonSet", "CronJob")
APP_LABEL_KEYS = ("app.kubernetes.io/instance", "app.kubernetes.io/name", "app")
APP_UNASSIGNED = "volumes sans workload"     # pseudo-application : PVC qu'aucun workload ne monte


def _app_key_of(obj):
    """Nom d'application d'un objet : première étiquette d'application présente,
    sinon le nom de l'objet (workload sans étiquette = application à lui seul)."""
    labels = (obj.get("metadata") or {}).get("labels") or {}
    for k in APP_LABEL_KEYS:
        if labels.get(k):
            return str(labels[k])
    return (obj.get("metadata") or {}).get("name") or "?"


def _workload_pod_spec(w):
    spec = w.get("spec") or {}
    if (w.get("kind") or "") == "CronJob":
        spec = (spec.get("jobTemplate") or {}).get("spec") or {}
    return ((spec.get("template") or {}).get("spec")) or {}


def _workload_pvcs(w, pvc_names=None):
    """PVC montés par un workload : volumes persistentVolumeClaim + volumeClaimTemplates
    d'un StatefulSet (PVC nommés <template>-<sts>-<n> : ceux qui existent si la liste
    des PVC du namespace est connue, sinon un par réplica)."""
    out = []
    for v in (_workload_pod_spec(w).get("volumes") or []):
        c = (v.get("persistentVolumeClaim") or {}).get("claimName")
        if c and c not in out:
            out.append(c)
    if (w.get("kind") or "") == "StatefulSet":
        spec = w.get("spec") or {}
        name = (w.get("metadata") or {}).get("name") or ""
        try:
            n = int(spec.get("replicas") if spec.get("replicas") is not None else 1)
        except (TypeError, ValueError):
            n = 1
        for t in (spec.get("volumeClaimTemplates") or []):
            tn = (t.get("metadata") or {}).get("name")
            if not tn:
                continue
            if pvc_names is not None:
                rx = re.compile(r"^%s-%s-\d+$" % (re.escape(tn), re.escape(name)))
                found = [p for p in pvc_names if rx.match(p)]
            else:
                found = ["%s-%s-%d" % (tn, name, i) for i in range(max(n, 1))]
            for c in found:
                if c not in out:
                    out.append(c)
    return out


def _apps_from_workloads(ns, workloads, pvc_names=None):
    """Regroupe les workloads d'un namespace en applications :
    [{name, namespace, workloads:[{kind,name,replicas}], pvcs:[...], type}] triées par
    nom. type = stateful | stateless | empty. Les objets DÉRIVÉS (Job d'un CronJob,
    ReplicaSet…) sont ignorés. Les PVC qu'aucun workload ne monte forment la
    pseudo-application « volumes sans workload » (restaurables comme stockage) ; un
    namespace sans workload ni PVC est une application « vide » portant son nom."""
    pvc_names = list(pvc_names or [])
    groups = {}
    for w in workloads or []:
        kind = w.get("kind") or ""
        if kind not in APP_WORKLOAD_KINDS:
            continue
        owners = {o.get("kind") for o in ((w.get("metadata") or {}).get("ownerReferences") or [])}
        if owners & (set(APP_WORKLOAD_KINDS) | {"Job", "ReplicaSet"}):
            continue
        key = _app_key_of(w)
        g = groups.setdefault(key, {"name": key, "namespace": ns, "workloads": [], "pvcs": []})
        spec = w.get("spec") or {}
        g["workloads"].append({"kind": kind, "name": (w.get("metadata") or {}).get("name") or "?",
                               "replicas": spec.get("replicas") if kind in ("Deployment", "StatefulSet") else None})
        for c in _workload_pvcs(w, pvc_names if pvc_names else None):
            if c not in g["pvcs"]:
                g["pvcs"].append(c)
    apps = sorted(groups.values(), key=lambda a: a["name"].lower())
    for a in apps:
        a["type"] = "stateful" if a["pvcs"] else "stateless"
    claimed = {c for a in apps for c in a["pvcs"]}
    orphans = [c for c in pvc_names if c not in claimed]
    if orphans and apps:
        apps.append({"name": APP_UNASSIGNED, "namespace": ns, "workloads": [], "pvcs": orphans,
                     "type": "stateful", "unassigned": True})
    elif not apps:
        apps.append({"name": ns, "namespace": ns, "workloads": [], "pvcs": orphans,
                     "type": "stateful" if orphans else "empty", "whole_ns": True})
    return apps


APP_WORKLOAD_RESOURCES = "deployments,statefulsets,daemonsets,cronjobs"
# Extraction LÉGÈRE des workloads (inventaire) : kubectl ne renvoie que les champs
# utiles (une ligne par objet, tabulations) au lieu du JSON complet — à 1 000
# namespaces, le JSON complet pèse des dizaines de Mo et dépasse la mémoire du pod.
_WL_LIGHT_TPL = ("{range .items[*]}{.metadata.namespace}{'\\t'}{.kind}{'\\t'}{.metadata.name}{'\\t'}"
                 "{.metadata.labels.app\\.kubernetes\\.io/instance}{'\\t'}{.metadata.labels.app\\.kubernetes\\.io/name}{'\\t'}"
                 "{.metadata.labels.app}{'\\t'}{.spec.replicas}{'\\t'}{.metadata.ownerReferences[*].kind}{'\\t'}"
                 "{.spec.template.spec.volumes[*].persistentVolumeClaim.claimName}{'\\t'}"
                 "{.spec.jobTemplate.spec.template.spec.volumes[*].persistentVolumeClaim.claimName}{'\\t'}"
                 "{.spec.volumeClaimTemplates[*].metadata.name}{'\\n'}{end}").replace("'", '"')
_PVC_LIGHT_TPL = '{range .items[*]}{.metadata.namespace}{"\\t"}{.metadata.name}{"\\n"}{end}'


def _wl_from_light_line(line):
    """Objet workload SYNTHÉTIQUE (mêmes chemins que le JSON kubectl, champs utiles
    seulement) depuis une ligne de _WL_LIGHT_TPL — consommé par _apps_from_workloads."""
    f = line.split("\t")
    if len(f) < 11 or not f[1] or not f[2]:
        return None
    labels = {}
    for key, val in (("app.kubernetes.io/instance", f[3]), ("app.kubernetes.io/name", f[4]), ("app", f[5])):
        if val:
            labels[key] = val
    claims = [c for c in (f[8] + " " + f[9]).split() if c]
    obj = {"kind": f[1], "metadata": {"namespace": f[0], "name": f[2], "labels": labels,
                                      "ownerReferences": [{"kind": k} for k in f[7].split() if k]},
           "spec": {"template": {"spec": {"volumes": [{"persistentVolumeClaim": {"claimName": c}} for c in claims]}},
                    "volumeClaimTemplates": [{"metadata": {"name": t}} for t in f[10].split() if t]}}
    if f[6].strip():
        try:
            obj["spec"]["replicas"] = int(f[6])
        except ValueError:
            pass
    return obj


def _kubectl_light(args, tpl):
    """kubectl … -o jsonpath=<tpl> -> (lignes, erreur). kubectl n'enveloppe pas UN
    objet unique dans une liste (.items absent -> sortie vide) : dans ce cas on
    relit en JSON (un seul objet : négligeable)."""
    r = run(_kubectl_base() + args + ["-o", "jsonpath=" + tpl], dry=False)
    if not r["ok"]:
        return None, r["stderr"]
    lines = [l for l in (r["stdout"] or "").splitlines() if l.strip()]
    if lines:
        return lines, None
    data, err = kubectl_json(args)
    if err:
        return None, err
    items = (data or {}).get("items")
    if items is None and (data or {}).get("kind"):
        items = [data]
    return ("__json__", items or []), None


def _list_namespace_workloads(namespaces, full=False):
    """({ns: [workloads]}, {ns: [noms de PVC]}, erreur) pour les namespaces donnés.
    `full=False` (inventaire) : extraction légère (jsonpath) -> objets synthétiques ne
    portant que les champs utiles au regroupement ; `full=True` (clone d'une application
    stateless) : JSON complet, réservé à UN namespace. Deux appels cluster-wide (-A)
    quand les droits le permettent ; sinon repli par namespace, BORNÉ (au-delà de
    `apps_fallback_max` namespaces, on renonce et on signale : un droit de liste
    cluster-wide est requis). Jamais bloquant : sans données, un namespace est
    présenté comme une application unique."""
    wl, pvcs, err_out = {}, {}, None
    wanted = set(namespaces)

    def add(store, it, key):
        n = (it.get("metadata") or {}).get("namespace") or key
        if n in wanted:
            store.setdefault(n, []).append(it)

    def fill(store, what, args, key=None):
        if full:
            data, err = kubectl_json(args)
            if err or not data:
                return err or "réponse vide"
            for it in data.get("items") or []:
                add(store, it, key)
            return None
        res, err = _kubectl_light(args, _WL_LIGHT_TPL if what == APP_WORKLOAD_RESOURCES else _PVC_LIGHT_TPL)
        if err:
            return err
        if isinstance(res, tuple):                      # relecture JSON (objet unique)
            for it in res[1]:
                if what == APP_WORKLOAD_RESOURCES:
                    add(store, it, key)
                else:
                    add(store, {"metadata": {"namespace": (it.get("metadata") or {}).get("namespace"),
                                             "name": (it.get("metadata") or {}).get("name")}}, key)
            return None
        for line in res:
            if what == APP_WORKLOAD_RESOURCES:
                obj = _wl_from_light_line(line)
                if obj:
                    add(store, obj, key)
            else:
                f = line.split("\t")
                if len(f) >= 2 and f[1]:
                    add(store, {"metadata": {"namespace": f[0], "name": f[1]}}, key)
        return None

    try:
        fb_max = int(CONFIG.get("apps_fallback_max", 50))
    except (TypeError, ValueError):
        fb_max = 50
    for store, what in ((wl, APP_WORKLOAD_RESOURCES), (pvcs, "pvc")):
        err = fill(store, what, ["get", what, "-A"])
        if err:
            if _kubectl_hint(err) != "other":
                return wl, pvcs, err              # kubectl absent / sans contexte : inutile d'insister
            if len(namespaces) > fb_max:
                return {}, {}, ("%s (liste cluster-wide refusée ; repli par namespace non tenté au-delà de %d "
                                "namespaces — accordez un droit de liste cluster-wide)" % (err, fb_max))
            err_out = err
            for ns in namespaces:
                e2 = fill(store, what, ["get", what, "-n", ns], key=ns)
                if not e2:
                    err_out = None
                store.setdefault(ns, store.get(ns, []))
        else:
            for ns in namespaces:
                store.setdefault(ns, [])
    pvc_names = {ns: [(p.get("metadata") or {}).get("name") for p in lst if (p.get("metadata") or {}).get("name")]
                 for ns, lst in pvcs.items()}
    return wl, pvc_names, err_out


def _apps_from_backup_index(ns, idx):
    """Applications mémorisées dans l'index d'une sauvegarde (clé `apps`, écrite à la
    sauvegarde) — utilisées quand le namespace n'existe plus sur le cluster."""
    apps = (idx or {}).get("apps") or []
    out = []
    for a in apps:
        if not isinstance(a, dict) or not a.get("name"):
            continue
        out.append({"name": a["name"], "namespace": ns, "workloads": list(a.get("workloads") or []),
                    "pvcs": list(a.get("pvcs") or []), "type": a.get("type") or ("stateful" if a.get("pvcs") else "stateless"),
                    "unassigned": bool(a.get("unassigned")), "whole_ns": bool(a.get("whole_ns"))})
    return out


def _app_object_indexes(items, app):
    """Indices des objets d'un instantané resources.json appartenant à l'application
    `app` : objets portant son étiquette d'application, ses workloads, les Secrets /
    ConfigMaps / ServiceAccount qu'ils référencent, et les Services dont le sélecteur
    cible ses pods. Sert à présélectionner la restauration d'objets d'UNE application
    (stateless) sans toucher aux autres applications du namespace."""
    if not app:
        return set(range(len(items or [])))
    wls = [o for o in (items or []) if (o.get("kind") or "") in APP_WORKLOAD_KINDS and _app_key_of(o) == app]
    secrets, cms, sas, pod_labels = set(), set(), set(), []
    for w in wls:
        r = _referenced_objects(w if (w.get("kind") or "") != "CronJob"
                                else {"spec": {"template": {"spec": _workload_pod_spec(w)}}})
        secrets |= r["secrets"]
        cms |= r["configmaps"]
        if r["serviceaccount"]:
            sas.add(r["serviceaccount"])
        spec = w.get("spec") or {}
        if (w.get("kind") or "") == "CronJob":
            spec = (spec.get("jobTemplate") or {}).get("spec") or {}
        lbls = (((spec.get("template") or {}).get("metadata") or {}).get("labels")) or {}
        if lbls:
            pod_labels.append(lbls)
    sel = set()
    for i, o in enumerate(items or []):
        kind = o.get("kind") or ""
        meta = o.get("metadata") or {}
        name = meta.get("name") or ""
        labels = meta.get("labels") or {}
        if any(str(labels.get(k)) == app for k in APP_LABEL_KEYS if labels.get(k)):
            sel.add(i)
        elif kind in APP_WORKLOAD_KINDS and _app_key_of(o) == app:
            sel.add(i)
        elif kind == "Secret" and name in secrets:
            sel.add(i)
        elif kind == "ConfigMap" and name in cms:
            sel.add(i)
        elif kind == "ServiceAccount" and name in sas:
            sel.add(i)
        elif kind == "Service":
            s = (o.get("spec") or {}).get("selector") or {}
            if s and any(all(pl.get(k) == v for k, v in s.items()) for pl in pod_labels):
                sel.add(i)
    return sel


def _backup_roots():
    """Dossiers de sauvegardes consultés : backup_root + dossier de la sauvegarde
    automatique s'il diffère. [None] désigne backup_root."""
    roots = [None]
    ab_dest = (CONFIG.get("auto_backup_dest") or "").strip()
    if ab_dest and os.path.abspath(os.path.expanduser(ab_dest)) != os.path.abspath(CONFIG["backup_root"]):
        roots.append(ab_dest)
    return roots


def _active_catalogs(roots=None, with_base=False):
    """Catalogues des sauvegardes du cluster/contexte ACTIF : dossier du cluster + ancienne
    disposition locale (versions du contexte courant, ou sans contexte — même règle que
    list_backups). Liste de {ns: [versions]} ; `with_base` : liste de (base, {ns: [versions]})."""
    out = []
    for root in (roots or _backup_roots()):
        base = os.path.abspath(os.path.expanduser(root)) if root else CONFIG["backup_root"]
        croot = _cluster_root(base)
        out.append((croot, _catalog_all(croot)))
        if _current_cid() == LOCAL_CID and croot != base:
            ctx = _local_context_name() or ""
            legacy = _catalog_all(base)
            out.append((base, {ns: [v for v in vs if (v.get("context") or "") in ("", ctx)] for ns, vs in legacy.items()}))
    return out if with_base else [c for _b, c in out]


def action_applications():
    """Applications des namespaces autorisés (une ligne par APPLICATION, plusieurs
    par namespace possibles — voir _apps_from_workloads), avec l'état de protection
    de configuration du namespace. Lecture seule : liste des namespaces + workloads
    et PVC (2 appels cluster-wide), le reste vient des sauvegardes sur disque
    (dossier par défaut + dossier de la sauvegarde automatique s'il diffère).

    Un namespace SUPPRIMÉ du cluster mais dont des sauvegardes existent reste
    listé (`missing: true`, applications lues dans sa dernière sauvegarde) : c'est
    précisément l'application qu'il faut pouvoir RESTAURER — la détruire ne doit
    jamais la faire disparaître de l'écran."""
    info = action_namespaces()
    names = list(info.get("namespaces") or [])
    live = set(names)
    roots = _backup_roots()
    # Sauvegardes du cluster/contexte ACTIF depuis le CATALOGUE (aucune lecture d'index.json).
    cats = _active_catalogs(roots)
    # namespaces présents UNIQUEMENT dans les sauvegardes
    flt = _ns_filter()
    if info.get("ok"):
        seen = set(names)
        for c in cats:
            for ns in sorted(c):
                if ns in seen or not c[ns]:
                    continue
                if flt and ns not in flt:
                    continue                     # filtre par noms (le sélecteur d'étiquettes ne
                seen.add(ns)                     # peut pas être vérifié sur un ns disparu)
                names.append(ns)
    now, fresh = time.time(), _backup_freshness_s()
    # Workloads + PVC des namespaces VIVANTS (pour découper chaque namespace en
    # applications). Sans droits / sans kubectl : un namespace = une application.
    wl_by_ns, pvc_by_ns, wl_err = ({}, {}, None)
    live_names = [n for n in names if n in live]
    if live_names and info.get("ok"):
        wl_by_ns, pvc_by_ns, wl_err = _list_namespace_workloads(live_names)
    apps = []
    for ns in names:
        bks = [v for c in cats for v in c.get(ns, [])]
        stamps = [v.get("epoch") for v in bks if v.get("epoch")]
        last = max(stamps) if stamps else None
        latest = max(bks, key=lambda v: v.get("epoch") or 0) if bks else None
        # `lidx` : résumé de la dernière sauvegarde (mêmes clés que l'index pour ce qui est utilisé)
        lidx = {"volumes": [{"pvc": p} for p in (latest.get("volumes") or [])],
                "apps": latest.get("apps") or [], "resources_count": latest.get("resources_count")} if latest else {}
        backed_pvcs = set((latest or {}).get("volumes") or [])
        missing = ns not in live
        if not missing and ns in wl_by_ns:
            ns_apps = _apps_from_workloads(ns, wl_by_ns.get(ns) or [], pvc_by_ns.get(ns) or [])
        elif missing:
            ns_apps = _apps_from_backup_index(ns, lidx) or \
                [{"name": ns, "namespace": ns, "workloads": [], "pvcs": sorted(backed_pvcs),
                  "type": "stateful" if backed_pvcs else ("stateless" if lidx.get("resources_count") else "empty"),
                  "whole_ns": True}]
        else:
            ns_apps = [{"name": ns, "namespace": ns, "workloads": [], "pvcs": [], "type": "unknown", "whole_ns": True}]
        base = {"namespace": ns, "backups": len(bks), "last_backup": last, "protected": bool(bks),
                "missing": missing, "compliant": bool(last and (now - last) <= fresh),
                "ns_apps": len(ns_apps)}
        for a in ns_apps:
            row = dict(base, name=a["name"], type=a["type"], workloads=a.get("workloads") or [],
                       pvcs=a.get("pvcs") or [], unassigned=bool(a.get("unassigned")),
                       whole_ns=bool(a.get("whole_ns")))
            if a.get("whole_ns") or a["type"] == "unknown":
                row["volumes"] = len(lidx.get("volumes") or []) if latest else None
                row["unbacked_pvcs"] = []
            else:
                row["volumes"] = len(a.get("pvcs") or [])
                # Volumes de l'application ABSENTS de la dernière sauvegarde du namespace
                # (PVC créé après) : la protection de cette application est incomplète.
                row["unbacked_pvcs"] = [p for p in (a.get("pvcs") or []) if p not in backed_pvcs] if latest else list(a.get("pvcs") or [])
            apps.append(row)
    return {"ok": bool(info.get("ok")), "error": info.get("error"), "apps": apps,
            "workloads_error": wl_err,
            "filtered": bool(_ns_filter()),
            "freshness_hours": round(fresh / 3600.0, 1),
            "policy": {"enabled": bool(CONFIG.get("auto_backup_enabled")),
                       "interval_hours": _auto_backup_interval_s() / 3600.0}}


# Cache de l'inventaire Applications (par cluster) : le tableau de bord (toutes les
# 30 s), la page Applications et le rapport partagent le même résultat pendant
# `apps_cache_ttl_s` secondes ; un seul calcul à la fois par cluster (les appels
# concurrents attendent le résultat au lieu de relancer kubectl). Vidé après toute
# écriture (POST) et à la fin d'une opération asynchrone ou d'un passage de sauvegarde ;
# le bouton Actualiser force un recalcul (?fresh=1).
_APPS_CACHE = {}
_APPS_CACHE_LOCK = threading.Lock()
_APPS_INFLIGHT = {}


def _apps_cache_clear():
    with _APPS_CACHE_LOCK:
        _APPS_CACHE.clear()


def action_applications_cached(fresh=False):
    cid = _current_cid()
    try:
        ttl = float(CONFIG.get("apps_cache_ttl_s", 45))
    except (TypeError, ValueError):
        ttl = 45.0
    with _APPS_CACHE_LOCK:
        e = _APPS_CACHE.get(cid)
        if e and not fresh and ttl > 0 and time.time() - e[0] < ttl:
            return dict(e[1], cached_age=round(time.time() - e[0], 1))
        lk = _APPS_INFLIGHT.setdefault(cid, threading.Lock())
    with lk:                                     # single-flight par cluster
        with _APPS_CACHE_LOCK:
            e = _APPS_CACHE.get(cid)
            if e and not fresh and ttl > 0 and time.time() - e[0] < ttl:
                return dict(e[1], cached_age=round(time.time() - e[0], 1))
        r = action_applications()
        if r.get("ok") or r.get("apps"):
            with _APPS_CACHE_LOCK:
                _APPS_CACHE[cid] = (time.time(), r)
        return r


def action_applications_all(fresh=False):
    """Applications de TOUS les clusters connus (en parallèle, 15 s max par requête
    kubectl pour qu'un cluster injoignable ne bloque pas la page), étiquetées par
    cluster et workspace NKP — pour la vue groupée workspace -> cluster -> namespace."""
    cids = _cluster_ids()

    def one(cid):
        with use_cluster(cid, req_timeout=15):
            c = _get_cluster(cid) if cid != LOCAL_CID else None
            meta = {"cluster_id": cid, "cluster": _cluster_label(cid),
                    "workspace": (c or {}).get("workspace") or ""}
            if cid == LOCAL_CID and not action_context().get("kubectl_ok"):
                return dict(meta, ok=False, skipped=True, error="Cluster local non configuré.", apps=[])
            try:
                r = action_applications_cached(fresh=fresh)
            except Exception as e:  # un cluster en erreur ne doit pas masquer les autres
                r = {"ok": False, "error": str(e), "apps": []}
            apps = [dict(a, **meta) for a in (r.get("apps") or [])]
            return dict(meta, ok=bool(r.get("ok")), error=r.get("error"), apps=apps)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(cids))) as ex:
        per = list(ex.map(one, cids))
    apps = [a for p in per for a in p["apps"]]
    fresh = _backup_freshness_s()
    return {"ok": any(p["ok"] for p in per), "error": None, "apps": apps,
            "clusters": [{k: p.get(k) for k in ("cluster_id", "cluster", "workspace", "ok", "error", "skipped")}
                         for p in per],
            "freshness_hours": round(fresh / 3600.0, 1),
            "policy": {"enabled": bool(CONFIG.get("auto_backup_enabled")),
                       "interval_hours": _auto_backup_interval_s() / 3600.0}}


# ------------------------------------------------------------------------------
# Rapport de conformité exportable (HTML autonome / CSV) — pour l'audit client :
# RPO atteint par application, tâches récentes, santé des clusters, export S3.
# ------------------------------------------------------------------------------
def _dir_size(path):
    """Taille totale (octets) et nombre de fichiers d'un dossier (récursif, robuste)."""
    total, files = 0, 0
    for dirpath, _dirs, fnames in os.walk(path):
        for n in fnames:
            try:
                total += os.path.getsize(os.path.join(dirpath, n))
                files += 1
            except OSError:
                pass
    return total, files


def action_storage():
    """État du stockage des sauvegardes de configuration : pour chaque dossier
    (backup_root + dossier de la sauvegarde auto s'il diffère) — espace disque
    total/libre du système de fichiers, volume occupé par les sauvegardes, taille
    du journal d'audit. `warn` = un des disques est rempli à 90 % ou plus."""
    roots = [CONFIG["backup_root"]]
    ab = (CONFIG.get("auto_backup_dest") or "").strip()
    if ab and os.path.abspath(os.path.expanduser(ab)) != os.path.abspath(CONFIG["backup_root"]):
        roots.append(os.path.abspath(os.path.expanduser(ab)))
    out, warn = [], False
    for root in roots:
        entry = {"path": root, "exists": os.path.isdir(root)}
        if entry["exists"]:
            try:
                du = shutil.disk_usage(root)
                pct = round(100.0 * (du.total - du.free) / du.total, 1) if du.total else 0.0
                entry.update(disk_total=du.total, disk_free=du.free, disk_used_pct=pct)
                warn = warn or pct >= 90.0
            except OSError as e:
                entry["error"] = str(e)
            # Volume occupé, fichiers et nombre de versions : depuis le catalogue (aucun
            # parcours de l'arbre : la tuile est rafraîchie toutes les 30 s).
            size = files = n = 0
            for base in _catalog_bases(root):
                for _ns, vs in _catalog_all(base).items():
                    for v in vs:
                        size += v.get("size") or 0
                        files += v.get("files") or 0
                        n += 1
            try:
                entry["audit_bytes"] = os.path.getsize(os.path.join(root, "audit.log"))
            except OSError:
                entry["audit_bytes"] = 0
            entry.update(backups_bytes=size + entry["audit_bytes"], files=files, backups_count=n)
        out.append(entry)
    try:
        quota_b = float(CONFIG.get("storage_quota_gb") or 0) * 1024 ** 3
    except (TypeError, ValueError):
        quota_b = 0
    if quota_b and out and out[0].get("backups_bytes", 0) > quota_b:
        warn = True
    return _ok(roots=out, warn=warn,
               min_free_mb=CONFIG.get("storage_min_free_mb") or 0,
               quota_gb=CONFIG.get("storage_quota_gb") or 0,
               retention={"mode": CONFIG.get("auto_backup_retention") or "count",
                          "keep": CONFIG.get("auto_backup_keep", 15),
                          "audit_days": CONFIG.get("audit_retention_days") or 0})


def _last_s3_exports():
    """Dernier export S3 réussi par namespace (depuis le journal d'audit)."""
    out = {}
    for rec in _read_audit_tail():
        if rec.get("event") == "s3_upload" and rec.get("ok") and rec.get("namespace"):
            out[rec["namespace"]] = rec.get("ts")
    return out


def action_report_data():
    apps = action_applications_all()
    jobs = action_jobs(limit=100)
    ab = action_auto_backup_status()
    s3 = action_conn_status().get("s3") or {}
    return {"generated": datetime.datetime.now().isoformat(timespec="seconds"),
            "version": VERSION, "apps": apps, "jobs": jobs, "auto_backup": ab,
            "s3_exports": _last_s3_exports(),
            "health": {cid: dict(h) for cid, h in CLUSTER_HEALTH.items()}, "s3": s3}


def report_csv(d):
    """CSV « applications » (une ligne par namespace x cluster) — pour Excel."""
    out = io.StringIO()
    out.write("cluster;workspace;namespace;application;type;protegee;conforme;versions;"
              "derniere_sauvegarde;volumes;politique_h;dernier_export_s3\n")
    itv = round((d["apps"].get("policy") or {}).get("interval_hours") or 24, 1)
    for a in d["apps"].get("apps") or []:
        last = (datetime.datetime.fromtimestamp(a["last_backup"]).isoformat(timespec="seconds")
                if a.get("last_backup") else "")
        ns = a.get("namespace") or a["name"]
        out.write("%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s\n" % (
            a.get("cluster") or "", a.get("workspace") or "", ns, a["name"], a.get("type") or "",
            "oui" if a.get("protected") else "non", "oui" if a.get("compliant") else "NON",
            a.get("backups") or 0, last,
            a.get("volumes") if a.get("volumes") is not None else "", itv,
            (d.get("s3_exports") or {}).get(ns) or ""))
    return out.getvalue()


def report_html(d):
    """Rapport HTML autonome (aucune ressource externe) aux couleurs de l'outil."""
    apps = d["apps"].get("apps") or []
    n = len(apps)
    prot = sum(1 for a in apps if a.get("protected"))
    comp = sum(1 for a in apps if a.get("compliant"))
    ab, jc = d["auto_backup"], (d["jobs"].get("counts") or {})
    esc_ = lambda x: (str(x) if x is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    ago = lambda ts: (datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "jamais")
    ic = lambda ok: ('<span class="ok">✓</span>' if ok else '<span class="ko">✕</span>')
    exp = d.get("s3_exports") or {}
    typ = {"stateful": "Stateful", "stateless": "Stateless", "empty": "Vide"}
    rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td><b>%s</b></td><td>%s</td><td class=c>%s</td><td class=c>%s</td>"
        "<td class=c>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc_(a.get("cluster")), esc_(a.get("workspace") or "—"), esc_(a.get("namespace") or a["name"]),
            esc_(a["name"]), esc_(typ.get(a.get("type"), "—")),   # « Vide » traduit via la paire >Vide<
            ic(a.get("protected")), ic(a.get("compliant")), a.get("backups") or 0,
            esc_(ago(a.get("last_backup"))),
            esc_((exp.get(a.get("namespace") or a["name"]) or "—")[:16].replace("T", " "))) for a in apps)
    hrows = "".join("<tr><td>%s</td><td class=c>%s</td><td>%s</td></tr>"
                    % (esc_(cid), ic(h.get("ok")), esc_(h.get("error") or "joignable"))
                    for cid, h in sorted((d.get("health") or {}).items()))
    jrows = "".join("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class=c>%s</td></tr>" % (
        esc_(j.get("ts")), esc_(j.get("event")), esc_(j.get("namespace") or "—"),
        esc_(j.get("cluster") or "—"), esc_(j.get("status")))
        for j in (d["jobs"].get("jobs") or [])[:30])
    s3txt = ("activé (chiffré)" if d["s3"].get("encrypt") else "activé") if d["s3"].get("auto_upload")         else ("configuré, export auto désactivé" if d["s3"].get("configured") else "non configuré")
    return ("""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Rapport de protection Kubernetes</title><style>
body{font-family:Segoe UI,Roboto,sans-serif;color:#2A2E44;margin:30px;background:#F3F4F9}
h1{color:#41327C;font-size:22px} h2{color:#4B5274;font-size:16px;margin-top:26px}
table{border-collapse:collapse;width:100%%;background:#fff;font-size:13px}
th{background:#41327C;color:#fff;text-align:left;padding:7px 10px;font-size:11px;text-transform:uppercase}
td{padding:6px 10px;border-bottom:1px solid #E3E7EE} .c{text-align:center}
.ok{color:#05A274;font-weight:700}.ko{color:#E9605A;font-weight:700}
.kpi{display:inline-block;background:#fff;border-radius:6px;padding:12px 22px;margin:4px 10px 4px 0;
     box-shadow:0 1px 2px rgba(65,50,124,.12)} .kpi b{font-size:22px;color:#41327C;display:block}
footer{margin-top:26px;color:#6B7089;font-size:11px}</style></head><body>
<h1>Rapport de protection des applications Kubernetes</h1>
<div>Généré le %s · outil v%s</div>
<div style="margin:14px 0">
<span class=kpi><b>%d</b>applications</span><span class=kpi><b>%d/%d</b>protégées</span>
<span class=kpi><b>%d/%d</b>conformes</span>
<span class=kpi><b>%s</b>sauvegarde automatique</span>
<span class=kpi><b>%d / %d / %d</b>tâches ok / échec / simulation</span></div>
<h2>Applications (protection de la configuration)</h2>
<table><tr><th>Cluster</th><th>Workspace</th><th>Namespace</th><th>Application</th><th>Type</th><th>Protégée</th>
<th>Conforme</th><th>Versions</th><th>Dernière sauvegarde</th><th>Dernier export S3</th></tr>%s</table>
<h2>Santé des clusters</h2>
<table><tr><th>Cluster</th><th>Joignable</th><th>Détail</th></tr>%s</table>
<h2>Dernières tâches (30)</h2>
<table><tr><th>Horodatage</th><th>Tâche</th><th>Application</th><th>Cluster</th><th>État</th></tr>%s</table>
<h2>Export hors cluster</h2><div>Stockage objet S3 : %s.</div>
<footer>Rapport généré par l'outil HYCU · Kubernetes · Nutanix — politique : sauvegarde
automatique %s, intervalle %s h, rétention %s.</footer></body></html>""" % (
        esc_(d["generated"]), esc_(d["version"]), n, prot, n, comp, n,
        "activée" if ab.get("enabled") else "désactivée",
        jc.get("success", 0), jc.get("failed", 0), jc.get("simulation", 0),
        rows or "<tr><td colspan=10>aucune application</td></tr>",
        hrows or "<tr><td colspan=3>aucun contrôle encore exécuté</td></tr>",
        jrows or "<tr><td colspan=5>aucune tâche</td></tr>", esc_(s3txt),
        "activée" if ab.get("enabled") else "désactivée",
        round(ab.get("interval_hours") or 24, 1),
        ("GFS %s j / %s sem / %s mois" % (ab.get("gfs", {}).get("daily"), ab.get("gfs", {}).get("weekly"),
                                          ab.get("gfs", {}).get("monthly"))
         if ab.get("retention") == "gfs" else "%s versions" % ab.get("keep"))))


# ------------------------------------------------------------------------------
# Page d'AIDE embarquée (« ? » en haut à droite -> Aide) : guide/tutoriel servi par
# l'outil lui-même (GET /help) — fonctionne hors-ligne / site isolé, traduit via
# l'i18n comme le reste. Contenu en sections ancrées avec sommaire.
# ------------------------------------------------------------------------------
HELP_SECTIONS = [
    ("demarrage", "Démarrage rapide", """
<ol>
<li><b>Enregistrez vos sources</b> : ⚙ (en haut à droite) → <b>Sources</b> → HYCU, Prism Central/Element, et vos <b>clusters Kubernetes</b> si besoin. Les identifiants restent en mémoire (ou dans le coffre chiffré).</li>
<li><b>Sauvegardez la configuration</b> : page <b>Applications</b> → cochez vos applications → <b>Sauvegarder</b>. Activez ensuite la <b>sauvegarde automatique</b> (page Politiques).</li>
<li><b>Testez une restauration</b> en <b>mode simulation</b> (bandeau du haut, activé par défaut) : Applications → une application → <b>Restaurer</b>. Rien n'est exécuté tant que la simulation est active.</li>
</ol>
<div class="tip">L'outil orchestre la <b>configuration</b> (manifestes PV/PVC, objets) ; les <b>données</b> des volumes sont protégées par <b>HYCU</b> (Volume Groups Nutanix). Les deux sont complémentaires.</div>"""),
    ("interface", "L'interface", """
<ul>
<li><b>Barre du haut</b> : pastilles d'état HYCU/PE/PC · <b>cluster actif</b> (cliquez pour changer de cluster ou en ajouter) · ⚙ <b>Sources / Réglages</b> · <b>?</b> Aide / À propos · <b>EN/FR</b>.</li>
<li><b>Tableau de bord</b> : anneaux protection/conformité, politique, sources, cluster, activité des tâches.</li>
<li><b>Applications</b> : une ligne par <b>application</b> (un namespace peut en contenir plusieurs : les workloads sont regroupés par étiquette <code>app.kubernetes.io/instance</code>, <code>app.kubernetes.io/name</code> ou <code>app</code>), avec son namespace et son <b>type</b> : <b>Stateful</b> (monte des volumes) ou <b>Stateless</b> (configuration seule). Sélectionnez, puis agissez en haut à droite : <b>Sauvegarder · Restaurer · Définir la politique · Vérifier</b>. La sauvegarde reste <b>par namespace</b> (une seule recette cohérente) ; Restaurer cible l'application choisie. Bascule <b>Cluster actif / Tous les clusters</b> (regroupés par workspace NKP).</li>
<li><b>Politiques</b> : sauvegarde automatique de la configuration (fréquence, rétention) + politiques HYCU.</li>
<li><b>Tâches</b> : historique (succès/échec/simulation), cluster de chaque tâche, boutons <b>Rapport HTML/CSV</b>.</li>
<li><b>Le bandeau Simulation</b> : tant qu'il est activé, AUCUNE commande destructive n'est exécutée — l'outil montre ce qu'il ferait. Désactivez-le seulement au moment d'agir.</li>
</ul>"""),
    ("clusters", "Clusters Kubernetes (multi-cluster & NKP)", """
<ul>
<li>Le <b>cluster local</b> vient de la configuration (kubeconfig/contexte — ⚙ → Réglages).</li>
<li><b>Ajouter un cluster</b> : ⚙ → Sources → <b>Ajouter un cluster Kubernetes</b> → chargez ou collez son kubeconfig → <b>Tester &amp; ajouter</b>. L'outil analyse l'authentification (jeton expiré, plugin exec…) et vous avertit.</li>
<li><b>NKP</b> : rendez le cluster de management actif, puis Sources → <b>Découvrir les workspaces NKP</b> → cochez les clusters → <b>Importer</b> (droits élevés requis, avertissement explicite).</li>
<li>Les sauvegardes de chaque cluster sont rangées <b>séparément</b>, et une sauvegarde ne se restaure que sur son cluster d'origine.</li>
<li>Les kubeconfigs sont des <b>secrets</b> : mémoire de session + coffre chiffré (jamais en clair sur disque).</li>
</ul>"""),
    ("sauvegarde", "Sauvegarder", """
<ul>
<li><b>Applications → Sauvegarder</b> : exporte et nettoie les manifestes <b>PV/PVC</b> (la « recette » du restore) + un <b>instantané des autres objets</b> (Deployments, Services, ConfigMaps, Secrets…) dans <code>resources.json</code> — les données des Secrets sont <b>chiffrées</b> (<code>secrets.enc</code>, phrase du coffre) ; sans coffre déverrouillé ni <code>HYCU_VAULT_PASSPHRASE</code>, elles restent en clair et la sauvegarde le signale (réglage <code>backup_secrets</code>).</li>
<li><b>Sauvegarder tous (filtrés)</b> : tous les namespaces autorisés d'un coup ; un namespace sans PVC <b>ni workload</b> est ignoré. Un namespace <b>stateless</b> (workloads sans volume) est sauvegardé : son instantané suffit à le restaurer.</li>
<li>Dossier par défaut : <code>hycu-backups/</code> — <b>copiez-le hors du cluster</b> (téléchargement .zip dans l'assistant de restauration, ou export S3 automatique, voir plus bas).</li>
<li>Le filtre des namespaces (entonnoir) et le <b>sélecteur d'étiquettes</b> (Réglages) bornent ce que l'outil voit et touche.</li>
<li><b>Grands clusters</b> : chaque dossier de sauvegardes porte un catalogue <code>_catalog.json</code> (résumé dérivé, reconstruit s'il manque — la restauration lit toujours <code>index.json</code>), l'inventaire est mis en cache quelques dizaines de secondes (<b>Actualiser</b> force le recalcul), la page est paginée par 100 et un passage « tous les namespaces » lit les PV une fois et travaille en parallèle. Réglages : <code>apps_fallback_max</code>, <code>apps_cache_ttl_s</code>, <code>backup_parallel</code>.</li>
</ul>"""),
    ("politiques", "Sauvegarde automatique & rétention", """
<ul>
<li>Page <b>Politiques</b> : activez la sauvegarde automatique (intervalle en heures). Elle couvre <b>tous les clusters connus</b>, tant que l'outil tourne ; un passage manqué est rattrapé au démarrage.</li>
<li><b>Rétention</b> : « N versions » (défaut), ou <b>GFS</b> — la plus récente de chaque jour / semaine / mois (7 j / 4 sem / 12 mois par défaut).</li>
<li>La sauvegarde d'une restauration en cours n'est jamais supprimée par la rétention.</li>
<li><b>Garde-fous du stockage</b> (Réglages) : plancher d'espace libre (sauvegarde refusée en dessous), quota global optionnel (purge des plus anciennes au-delà), historique des tâches borné (31 j par défaut). La tuile <b>Stockage</b> du tableau de bord surveille le disque.</li>
</ul>"""),
    ("hycu", "Protéger les données dans HYCU", """
<ul>
<li><b>Applications → Définir la politique</b> : l'outil associe chaque PVC à son <b>Volume Group</b> HYCU (correspondance par UUID), assigne une politique HYCU et peut lancer une sauvegarde.</li>
<li>Une correspondance « par nom » doit être <b>confirmée</b> (case à cocher) ; une ambiguïté n'est jamais tranchée automatiquement.</li>
</ul>"""),
    ("restaurer", "Restaurer — les 5 parcours", """
<ol>
<li><b>Restaurer toute l'application (copie)</b> : volumes + objets vers le même namespace (suffixe) ou un autre. L'original n'est pas modifié. Idéal pour vérifier une sauvegarde.</li>
<li><b>Restaurer le stockage sur place</b> : HYCU restaure les données <b>dans</b> les volumes d'origine ; l'application est arrêtée puis redémarrée. Choisissez un point de restauration par volume (le plus récent est présélectionné).</li>
<li><b>Restaurer le stockage vers de nouveaux volumes</b> : de nouveaux Volume Groups sont clonés, l'application y est rattachée ; les volumes d'origine sont conservés.</li>
<li><b>Restaurer des objets de configuration</b> : ré-applique des objets choisis depuis l'instantané d'une sauvegarde, avec <b>aperçu des différences</b> avant tout apply. Ne touche ni aux volumes ni aux données.</li>
</ol>
<div class="tip"><b>Application stateless (sans volume) ?</b> Cliquez <b>Restaurer</b> sur sa ligne : l'assistant ne propose que deux parcours — <b>copie</b> (clone de ses workloads et dépendances, même namespace avec suffixe ou autre namespace, comme pour une application stateful) et <b>objets de configuration</b> (présélectionné) avec <b>ses</b> objets précochés (workloads, Services, ConfigMaps/Secrets référencés) — les autres applications du namespace ne sont pas touchées. Pour une application <b>stateful</b>, seuls <b>ses</b> volumes sont présélectionnés dans les parcours de stockage. <b>Tout le namespace</b> (ex. mariadb + wordpress découpés par leurs étiquettes) : cochez plusieurs applications du même namespace puis <b>Restaurer le namespace</b>, ou cliquez le lien « tout le namespace » dans l'assistant.</div>
<div class="tip">Déroulé conseillé : lancez d'abord en <b>simulation</b> (plan affiché, aucun effet), relisez le récapitulatif, puis désactivez la simulation et relancez. En mode réel, l'outil demande de <b>retaper le nom du cluster</b>. Après une restauration réelle, la <b>Vérification</b> s'ouvre automatiquement (PVC Bound, pods Running).</div>
<div class="tip">Si une étape échoue, la séquence <b>s'arrête</b> et l'application reste arrêtée (jamais redémarrée sur des volumes incohérents). Corrigez puis <b>relancez</b> : la reprise est idempotente et les réplicas d'origine sont mémorisés.</div>
<div class="tip"><b>Application supprimée du cluster ?</b> Tant que ses sauvegardes existent, elle reste listée dans <b>Applications</b> avec le badge « Supprimée — restaurable ». Cliquez <b>Restaurer</b> : le parcours de récupération recrée tout (namespace, PV/PVC, workloads, dépendances non masquées) depuis la sauvegarde choisie, en <b>réutilisant les volumes d'origine</b> — rien à saisir. Si un Volume Group a été supprimé avec le namespace mais reste « Protected deleted » dans HYCU, il est <b>restauré automatiquement</b> (HYCU connecté). Décochez « réutiliser » seulement si vous avez restauré les données sur de nouveaux volumes. Aucune dérogation DR n'est requise : la récupération reste sur le même cluster/contexte.</div>"""),
    ("masse", "Restauration en masse (même cluster)", """
<ul>
<li><b>Applications → Restaurer en masse</b> : recrée d'un coup <b>tous les namespaces supprimés</b> du cluster actif depuis leur dernière sauvegarde antérieure à un <b>instant de référence</b> (namespace, PV/PVC, workloads, dépendances, Secrets si le coffre est déverrouillé, Volume Groups restaurés par HYCU s'ils ont disparu, applications stateless). Les namespaces <b>encore présents</b> sont ignorés : une application vivante se restaure depuis sa propre ligne.</li>
<li><b>Préparer le plan</b> montre, avant tout, les namespaces retenus (sauvegarde choisie, contenu, avertissements : Secrets masqués ou chiffrés avec coffre verrouillé, sauvegarde partielle, sans instantané) et ceux ignorés, avec la raison.</li>
<li><b>Simuler</b> exécute le plan en simulation, en arrière-plan, avec un journal par namespace ; <b>Lancer (réel)</b> n'est possible qu'après une simulation complète et sans échec du <b>même</b> plan, bandeau Simulation désactivé, et confirmation du cluster.</li>
<li>Exécution <b>séquentielle</b> (les restaurations HYCU durent des minutes chacune : comptez des heures pour des centaines de namespaces) ; <b>Arrêter</b> termine le namespace en cours ; <b>Reprendre</b> rejoue seulement les namespaces restants ou en échec — un namespace déjà recréé n'est jamais refait. Le journal (<code>_bulk_restore.json</code>) survit à un redémarrage ; la sauvegarde automatique est suspendue pendant le run.</li>
</ul>"""),
    ("s3", "Export S3 (optionnel)", """
<ul>
<li>⚙ → Sources → <b>Stockage objet S3</b> : endpoint compatible S3 (Nutanix Objects, MinIO, AWS…), bucket, clés d'accès → <b>Tester &amp; connecter</b>.</li>
<li>Cochez <b>Export automatique</b> : chaque sauvegarde réussie part aussi en <code>.zip</code> vers le bucket — le filet de sécurité vit hors du cluster.</li>
<li>Option <b>chiffrement</b> : les objets sont chiffrés avant l'envoi ; déchiffrement : <code>python3 hycu_k8s_nutanix.py --decrypt fichier.zip.enc</code>.</li>
<li><b>Importer depuis le bucket</b> (même carte) : rapatrie des exports vers <code>hycu-backups/_imports/…</code> — le chemin retour, indispensable en reprise d'activité.</li>
</ul>"""),
    ("dr", "Reprise d'activité (DR)", """
<ol>
<li><b>Préparez le retour</b> : activez l'export S3 automatique (chiffré de préférence) — le filet de sécurité doit vivre hors du cluster. Gardez en lieu sûr : <code>hycu_config.json</code>, <code>hycu_secrets.enc</code>, la phrase du coffre et celle des exports (kit DR).</li>
<li><b>Le jour J</b> : relancez l'outil (poste ou cluster de secours), reconnectez HYCU/Prism, ajoutez le cluster CIBLE (⚙ → Sources) et rendez-le actif. Rapatriez les sauvegardes : carte S3 → <b>Importer depuis le bucket</b>.</li>
<li><b>Restaurez les données</b> : dans HYCU, restaurez/clonez les Volume Groups de l'application vers le site cible, et notez leurs UUID.</li>
<li><b>Activez la dérogation</b> : ⚙ → Réglages → <b>Autoriser la restauration DR</b> (le temps de l'opération).</li>
<li><b>Assistant → Restauration DR</b> : choisissez la sauvegarde source (cluster disparu ou import S3), le namespace cible, collez l'UUID de chaque VG restauré, remappez la StorageClass si le site cible en utilise une autre — simulation d'abord, puis réel (re-saisie du cluster cible).</li>
<li><b>Sans saisie (HYCU connecté)</b> : le bouton <b>« Créer les volumes automatiquement via HYCU »</b> clone les Volume Groups depuis leurs sauvegardes HYCU et inscrit tout seul les nouveaux identifiants — plus aucun UUID à recopier. En simulation, seul le plan est affiché.</li>
<li><b>Après</b> : vérifiez l'application, re-protégez ses Volume Groups dans HYCU, désactivez la dérogation DR.</li>
</ol>
<div class="tip">Tout le reste du temps, laissez « Autoriser la restauration DR » désactivé : la garde inter-cluster/contexte protège contre les restaurations croisées accidentelles. Un Secret masqué à la sauvegarde n'est jamais restauré : re-provisionnez-le depuis sa source. Un Secret <b>chiffré</b> est recréé dès que le coffre est déverrouillé.</div>"""),
    ("rapport", "Rapport & supervision", """
<ul>
<li>Page <b>Tâches</b> → <b>Rapport HTML</b> (conformité : applications, RPO, santé des clusters, tâches) ou <b>CSV</b> (Excel).</li>
<li><code>GET /metrics</code> : métriques Prometheus (local uniquement) — outil actif, sauvegarde auto, clusters joignables, connexions.</li>
<li>La <b>santé des clusters</b> est contrôlée périodiquement (pastilles dans Sources).</li>
</ul>"""),
    ("securite", "Sécurité en bref", """
<ul>
<li>Serveur sur <b>127.0.0.1 uniquement</b>, anti-CSRF, mode simulation par défaut, confirmation du cluster avant toute action réelle, journal d'audit complet.</li>
<li>Identifiants et kubeconfigs : <b>mémoire de session</b> (verrouillés à chaque nouvelle session navigateur), coffre chiffré optionnel (phrase secrète maîtresse).</li>
<li>En mode Kubernetes, la frontière de sécurité est le <b>RBAC du namespace</b> de l'outil : qui peut faire un port-forward est opérateur.</li>
</ul>"""),
    ("depannage", "Dépannage express", """
<table><tr><th>Symptôme</th><th>Piste</th></tr>
<tr><td>« Contexte : indisponible »</td><td>kubectl absent du PATH ou contexte non configuré (⚙ → Réglages).</td></tr>
<tr><td>« Namespace non autorisé »</td><td>Hors du filtre des namespaces (entonnoir) ou du sélecteur d'étiquettes.</td></tr>
<tr><td>Namespace détruit, application absente ?</td><td>Elle reste listée tant qu'une sauvegarde existe (badge « Supprimée — restaurable ») : bouton Restaurer → récupération depuis la sauvegarde.</td></tr>
<tr><td>Les connexions redemandent le déverrouillage</td><td>Normal : nouvelle session navigateur = identifiants verrouillés. Saisissez la phrase du coffre.</td></tr>
<tr><td>« Cluster « x » inconnu »</td><td>Cluster retiré ou session verrouillée : déverrouillez le coffre ou re-choisissez un cluster (barre du haut).</td></tr>
<tr><td>« Cette sauvegarde provient du cluster « x » »</td><td>Sélectionnez le cluster d'origine de la sauvegarde dans la barre du haut.</td></tr>
<tr><td>Séquence « interrompue »</td><td>Lisez l'étape en échec dans le journal, corrigez, relancez (reprise idempotente).</td></tr>
<tr><td>Export S3 en 403</td><td>Clés refusées, ou horloge du serveur décalée (SigV4 exige une heure juste).</td></tr>
</table>
<div class="tip">Guide complet : fichiers <code>README.md</code> / <code>README.fr.md</code> du dépôt (installation, configuration détaillée, déploiement Kubernetes).</div>"""),
]


def help_html():
    toc = "".join('<a href="#%s">%s</a>' % (sid, title) for sid, title, _ in HELP_SECTIONS)
    body = "".join('<section id="%s"><h2>%s</h2>%s</section>' % (sid, title, html)
                   for sid, title, html in HELP_SECTIONS)
    return ("""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aide — Protection Kubernetes sur Nutanix</title><style>
body{font-family:Segoe UI,Roboto,sans-serif;color:#2A2E44;margin:0;background:#F3F4F9}
header{background:#41327C;color:#fff;padding:22px 34px}
header h1{margin:0;font-size:22px;font-weight:600}
header .sub{color:#B8B4FC;font-size:13px;margin-top:4px}
.wrap{display:flex;gap:26px;max-width:1180px;margin:0 auto;padding:24px 20px}
nav{flex:none;width:250px;position:sticky;top:16px;align-self:flex-start;background:#fff;
    border-radius:8px;padding:12px 0;box-shadow:0 1px 3px rgba(65,50,124,.12)}
nav a{display:block;padding:7px 16px;color:#3D4464;text-decoration:none;font-size:13.5px;border-left:3px solid transparent}
nav a:hover{background:#F3EFFD;border-left-color:#7530F0;color:#41327C}
main{flex:1;min-width:0}
section{background:#fff;border-radius:8px;padding:18px 24px;margin-bottom:18px;
        box-shadow:0 1px 2px rgba(65,50,124,.08);scroll-margin-top:14px}
h2{color:#41327C;font-size:17px;margin:0 0 10px}
ul,ol{margin:6px 0;padding-left:22px} li{margin:5px 0;font-size:14px;line-height:1.55}
code{background:#F3EFFD;border-radius:3px;padding:1px 5px;font-size:12.5px;color:#41327C}
.tip{background:#F7F5FD;border-left:3px solid #7530F0;border-radius:0 6px 6px 0;padding:10px 14px;
     font-size:13.5px;margin-top:10px;line-height:1.5}
table{border-collapse:collapse;width:100%%;font-size:13.5px}
th{background:#41327C;color:#fff;text-align:left;padding:7px 10px;font-size:11px;text-transform:uppercase}
td{padding:7px 10px;border-bottom:1px solid #E3E7EE;vertical-align:top}
footer{max-width:1180px;margin:0 auto;padding:0 20px 30px;color:#6B7089;font-size:12px}
@media(max-width:820px){.wrap{flex-direction:column}nav{position:static;width:auto}}
</style></head><body>
<header><h1>Aide — Protection Kubernetes sur Nutanix</h1>
<div class="sub">Plugin pour HYCU Enterprise Cloud · version v%s · toutes les actions destructives sont simulées par défaut</div></header>
<div class="wrap"><nav>%s</nav><main>%s</main></div>
<footer>Cette page est servie par l'outil (fonctionne hors-ligne). Fermez l'onglet pour revenir à l'interface.</footer>
</body></html>""" % (VERSION, toc, body))


# Événements d'audit présentés comme des « tâches » (le reste — connexions,
# coffre, filtre — relève du journal de sécurité, pas des opérations).
JOB_EVENTS = ("backup", "backup_all", "auto_backup", "restore_end", "clone_app",
              "orchestrate_inplace", "hycu_restore", "hycu_protect", "s3_upload",
              "restore_objects", "s3_import")


def _read_audit_tail(max_bytes=1024 * 1024):
    """Dernières lignes du journal d'audit (au plus `max_bytes`), décodées en JSON."""
    path = os.path.join(CONFIG["backup_root"], "audit.log")
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            raw = f.read().decode("utf-8", errors="replace")
    except OSError:
        return []
    lines = raw.splitlines()
    if size > max_bytes and lines:
        lines = lines[1:]                     # première ligne probablement tronquée
    out = []
    for line in lines:
        try:
            rec = json.loads(line)
            if isinstance(rec, dict):
                out.append(rec)
        except ValueError:
            pass
    return out


def _job_status(rec):
    """success | failed | simulation — même lecture que les états de tâche HYCU."""
    if rec.get("dry"):
        return "simulation"
    if rec.get("ok") is False or rec.get("aborted"):
        return "failed"
    return "success"


def action_jobs(limit=200):
    """Historique des opérations (plus récentes d'abord) + compteurs + activité des
    7 derniers jours, pour la page Tâches et le tableau de bord. Lecture seule."""
    jobs = []
    for rec in _read_audit_tail():
        ev = rec.get("event")
        if ev not in JOB_EVENTS:
            continue
        jobs.append({"ts": rec.get("ts"), "event": ev, "status": _job_status(rec),
                     "namespace": rec.get("namespace") or rec.get("target_namespace") or "",
                     "target_namespace": rec.get("target_namespace") or "",
                     "detail": rec.get("summary") or rec.get("mode") or "",
                     "cluster": rec.get("cluster") or "",
                     "volumes": rec.get("count") if ev == "backup" else None})
    jobs.reverse()
    counts = {"success": 0, "failed": 0, "simulation": 0}
    for j in jobs:
        counts[j["status"]] = counts.get(j["status"], 0) + 1
    today = datetime.date.today()
    days = [(today - datetime.timedelta(days=i)).isoformat() for i in range(6, -1, -1)]
    per_day = {d: {"success": 0, "failed": 0, "simulation": 0} for d in days}
    for j in jobs:
        d = str(j.get("ts") or "")[:10]
        if d in per_day:
            per_day[d][j["status"]] += 1
    with OP_LOCK:
        running = sum(1 for op in OPERATIONS.values() if not op.get("done"))
    return {"ok": True, "jobs": jobs[:max(1, int(limit))], "counts": counts,
            "total": len(jobs),                 # au-delà de `limit`, l'UI signale la troncature
            "retention_days": CONFIG.get("audit_retention_days") or 0,
            "running": running + (1 if AUTO_BACKUP.get("running") else 0),
            "days": [{"date": d, **per_day[d]} for d in days]}


# ------------------------------------------------------------------------------
# Workloads (scale down/up) et attente active
# ------------------------------------------------------------------------------
def _scan_workloads(ns):
    """Réplicas COURANTS des Deployments et StatefulSets (0 inclus).
    Renvoie (liste, erreur) : une erreur kubectl ne doit jamais passer pour
    « aucun workload » (sinon l'app n'est pas arrêtée avant la destruction des
    PVC, et une reprise après échec ne redémarre rien)."""
    captured = []
    for kind in ("deployment", "statefulset"):
        data, err = kubectl_json(["get", kind, "-n", ns])
        if err:
            return captured, "%s : %s" % (kind, err)
        for i in (data or {}).get("items", []):
            captured.append({"kind": kind, "name": i["metadata"]["name"],
                             "replicas": i.get("spec", {}).get("replicas", 1) or 0})
    return captured, None


def _replica_state_path(ns):
    return os.path.join(_cluster_root(CONFIG["backup_root"]), ns, "_replica_state.json")


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
    return os.path.join(_cluster_root(CONFIG["backup_root"]), ns, "_restore_txn.json")


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
    current, err = _scan_workloads(ns)
    if err:
        return [], [], err          # inventaire impossible : l'appelant doit avorter
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
    return current, desired, None


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
    """Scale-up des workloads à leur nombre de réplicas d'origine. Renvoie (ok, [commandes
    de redémarrage restantes]) : un scale-up en échec ne doit jamais passer inaperçu
    (l'application resterait à 0 réplica avec un résultat « terminé »)."""
    failed = []
    for w in desired:
        r = kubectl(["scale", w["kind"], w["name"], "-n", ns, "--replicas=%s" % w["replicas"]],
                    dry=dry, label="Redémarrage %s/%s -> %s" % (w["kind"], w["name"], w["replicas"]))
        log.append(r)
        if not (r["ok"] or r.get("dry")):
            failed.append("kubectl scale %s %s -n %s --replicas=%s" % (w["kind"], w["name"], ns, w["replicas"]))
    return (not failed), failed


def _pods_using_pvcs(ns, pvc_names):
    """Renvoie (pods montant l'un des PVC visés, erreur). Une erreur kubectl n'est
    JAMAIS assimilée à « aucun pod » : conclure à tort que les pods sont partis
    ferait supprimer de force des PVC encore montés (retrait des finalizers)."""
    data, err = kubectl_json(["get", "pods", "-n", ns])
    using = []
    if err:
        return using, err
    if not data:
        return using, None
    wanted = set(pvc_names)
    for pod in data.get("items", []):
        for vol in pod.get("spec", {}).get("volumes", []) or []:
            claim = (vol.get("persistentVolumeClaim") or {}).get("claimName")
            if claim in wanted:
                using.append(pod["metadata"]["name"])
                break
    return using, None


def _unmanaged_pods_using_pvcs(ns, pvc_names):
    """Pods montant les PVC ciblés dont le contrôleur racine N'EST PAS un
    Deployment (via ReplicaSet) ni un StatefulSet — donc NON arrêtés par le
    scale-down : DaemonSet, Job, pod nu, Operator/CRD. Renvoie ([(pod, owner_kind)], err)."""
    data, err = kubectl_json(["get", "pods", "-n", ns])
    out = []
    if err:
        return out, err
    if not data:
        return out, None
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
    return out, None


def _wait_pods_gone(ns, pvc_names, timeout, log):
    """Attend activement que plus aucun pod ne monte les PVC visés (corrige la
    course où l'on supprime le PVC alors qu'un pod le tient encore)."""
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        using, err = _pods_using_pvcs(ns, pvc_names)
        last_err = err
        if not err and not using:
            log.append({"ok": True, "dry": False, "label": "Pods arrêtés",
                        "cmd": "(attente) pods montant les PVC", "stdout": "aucun pod ne monte les volumes ciblés", "stderr": "", "rc": 0})
            return True
        time.sleep(2)      # erreur kubectl = état INCONNU : on réessaie jusqu'au délai
    using, err = _pods_using_pvcs(ns, pvc_names)
    detail = ("état des pods invérifiable (kubectl en erreur) : " + (err or last_err or "?")) if (err or not using)         else ("Délai dépassé, pods encore actifs : " + ", ".join(using))
    log.append({"ok": False, "dry": False, "label": "Pods encore présents",
                "cmd": "(attente) pods montant les PVC",
                "stdout": "", "stderr": detail, "rc": -1})
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
    """Applique le manifeste via STDIN (`kubectl apply -f -`) : rien n'est écrit sur
    disque — important pour les Secrets clonés (aucune trace en clair, même brève,
    sous backup_root). `basename` ne sert plus qu'au libellé de la commande."""
    if dry:
        return {"ok": True, "dry": True, "cmd": "kubectl apply -f - <%s.json>" % basename,
                "stdout": "", "stderr": "", "rc": None, "label": label}
    return kubectl(["apply", "-f", "-"], dry=False, label=label,
                   input_text=json.dumps(manifest))


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
def _backup_cluster_error(backup_path, backup_root=None, allow_dr=False):
    """Garde anti-confusion MULTI-CLUSTER : une sauvegarde ne peut servir qu'au cluster
    sur lequel elle a été prise (les manifestes PV référencent des Volume Groups et
    un driver CSI propres à ce cluster). Les sauvegardes antérieures au multi-cluster
    (sans « cluster_id ») sont rattachées au cluster local. Renvoie un message ou None.

    Une sauvegarde EXPLICITEMENT désignée mais invalide (chemin hors zone, index
    illisible) est une ERREUR : sans cela, l'outil se rabattait en silence sur les
    manifestes LIVE — l'opérateur croyait restaurer depuis la sauvegarde choisie.

    `allow_dr=True` (restauration DR demandée par l'opérateur ET autorisée par la
    configuration allow_dr_restore) : la garde inter-cluster/contexte est levée —
    les erreurs de validité de la sauvegarde restent, elles, bloquantes."""
    if not backup_path:
        return None                             # aucune sauvegarde choisie : repli live assumé
    bp = _safe_backup_path(backup_path, backup_root)
    if not bp:
        return ("Sauvegarde introuvable ou hors de la zone autorisée : %s. Vérifiez le dossier "
                "de sauvegardes (Avancé) puis resélectionnez la sauvegarde." % backup_path)
    try:
        with open(os.path.join(bp, "index.json"), encoding="utf-8") as f:
            idx = json.load(f)
    except (OSError, ValueError) as e:
        return "Sauvegarde illisible (%s) : index.json manquant ou corrompu (%s)." % (bp, e)
    src = idx.get("cluster_id") or LOCAL_CID
    if allow_dr:
        return None                             # dérogation DR explicite : garde levée
    if src != _current_cid():
        return ("Cette sauvegarde provient du cluster « %s », alors que le cluster actif est « %s ». "
                "La restauration inter-clusters n'est pas prise en charge : sélectionnez le cluster "
                "d'origine dans la barre du haut." % (idx.get("cluster") or src, _cluster_label()))
    # Même « cluster » local mais CONTEXTE kubectl différent (ex. prod vs dev avec les
    # mêmes namespaces) : refuser aussi — les PV référencent d'autres Volume Groups.
    if src == LOCAL_CID:
        bctx = (idx.get("context") or "").strip()
        cur = (_local_context_name() or "").strip()
        if bctx and cur and bctx != cur:
            return ("Cette sauvegarde a été prise sur le contexte kubectl « %s », alors que le "
                    "contexte actif est « %s ». Rebasculez sur le contexte d'origine (Réglages) "
                    "avant de restaurer." % (bctx, cur))
    return None


def _load_old_pv(ns, pvc_name, backup_path, backup_root=None, no_live=False):
    """Renvoie (old_pv, pv_name) depuis la sauvegarde si fournie, sinon en live.
    `no_live=True` (DR / récupération « depuis la sauvegarde seule ») : JAMAIS de repli
    sur le cluster — le « live » serait le cluster CIBLE, dont un PVC homonyme fournirait
    un mauvais gabarit et un mauvais UUID de référence."""
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
    if no_live:
        return None, None
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
            "looks_like_vg_name": bool(built.get("looks_like_vg_name")),
            "same_uuid": bool(built.get("same_uuid")),
            "pvc_captured": pvc_manifest is not None, "pvc_manifest": pvc_manifest,
            "manifest_preview": json.dumps(built["manifest"], indent=2),
            "manifest": built["manifest"]}


def _dr_allowed(payload):
    """(dérogation DR active ?, erreur si demandée mais interdite). La dérogation
    exige LES DEUX : la demande explicite de l'opérateur (payload.dr_restore) et le
    réglage allow_dr_restore — jamais l'un sans l'autre."""
    if not payload.get("dr_restore"):
        return False, None
    if not CONFIG.get("allow_dr_restore"):
        return False, ("Restauration DR refusée : le réglage « Autoriser la restauration DR » est "
                       "désactivé (⚙ → Réglages). Activez-le le temps de l'opération, puis réessayez.")
    return True, None


def action_prepare_restore(payload):
    """Aperçu du restore SANS rien exécuter, pour un ou plusieurs PVC."""
    ns = payload.get("namespace")
    if not _namespace_allowed(ns):
        return {"ok": False, "error": "Namespace '%s' non autorisé par la configuration." % ns}
    mode = payload.get("mode", "clone")
    backup_path = payload.get("backup_path")
    backup_root = payload.get("backup_root")
    dr, derr2 = _dr_allowed(payload)
    if derr2:
        return {"ok": False, "error": derr2, "results": []}
    xerr = _backup_cluster_error(backup_path, backup_root, allow_dr=dr)
    if xerr:
        return {"ok": False, "error": xerr, "results": []}
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
# ------------------------------------------------------------------------------
# Restauration GUIDÉE DES OBJETS de configuration (Deployments, Services,
# ConfigMaps…) depuis l'instantané resources.json d'une sauvegarde — avec aperçu
# des différences (sauvegarde vs live) AVANT tout apply. Complète la restauration
# PV/PVC : ici on répare la CONFIG, pas les volumes.
# ------------------------------------------------------------------------------
def _load_backup_resources(backup_path, backup_root=None, allow_dr=False, missing_ok=False):
    """(items, erreur) depuis resources.json d'une sauvegarde validée.
    `missing_ok=True` : un resources.json ABSENT n'est pas une erreur — on renvoie
    ([], None) pour permettre une restauration DÉGRADÉE (PV/PVC seulement). Les gardes
    de cluster/chemin et les erreurs de lecture restent bloquantes."""
    xerr = _backup_cluster_error(backup_path, backup_root, allow_dr=allow_dr)
    if xerr:
        return None, xerr
    bp = _safe_backup_path(backup_path, backup_root)
    if not bp:
        return None, "Sauvegarde introuvable ou hors de la zone autorisée."
    rp = os.path.join(bp, "resources.json")
    if not os.path.isfile(rp):
        if missing_ok:
            return [], None                       # dégradé : volumes seulement, l'appelant avertit
        return None, ("Cette sauvegarde ne contient pas d'instantané de ressources "
                      "(resources.json) : elle est antérieure à la fonction, ou "
                      "config_backup_full était désactivé.")
    try:
        with open(rp, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        return None, "resources.json illisible : %s" % e
    # Secrets chiffrés (secrets.enc) : recomposés si la phrase du coffre est disponible.
    items, _state = _merge_backup_secrets(bp, doc.get("items") or [])
    return items, None


def _obj_is_redacted(obj):
    """Secret dont les données ont été masquées à la sauvegarde : NE JAMAIS
    l'appliquer (il écraserait le vrai secret par « __REDACTED__ »)."""
    if (obj.get("kind") or "").lower() != "secret":
        return False
    ann = (obj.get("metadata") or {}).get("annotations") or {}
    if ann.get("hycu.backup/secret-data") == "redacted":
        return True
    return any(v == "__REDACTED__" for v in (obj.get("data") or {}).values())


def _obj_resource_arg(obj):
    """Argument kubectl non ambigu pour cet objet : kind.groupe (ex.
    ingress.networking.k8s.io) — indispensable si un CRD homonyme existe."""
    kind = (obj.get("kind") or "").lower()
    apiv = obj.get("apiVersion") or ""
    group = apiv.split("/")[0] if "/" in apiv else ""
    return "%s.%s" % (kind, group) if group else kind


def _obj_key(obj):
    return {"kind": obj.get("kind") or "?", "name": (obj.get("metadata") or {}).get("name") or "?",
            "resource": _obj_resource_arg(obj)}


def action_objects_list(payload):
    """Objets de l'instantané d'une sauvegarde, pour l'assistant (cases à cocher)."""
    ns = payload.get("namespace")
    dr, derr = _dr_allowed(payload)
    if derr:
        return _err(derr)
    if not _namespace_allowed(ns):
        return _err("Namespace '%s' non autorisé par la configuration." % ns)
    items, err = _load_backup_resources(payload.get("backup_path"), payload.get("backup_root"),
                                        allow_dr=dr)
    if err:
        return _err(err)
    # Ciblage d'UNE application du namespace (stateless : c'est SA restauration) :
    # `in_app` marque les objets qui lui appartiennent (étiquette, workloads,
    # dépendances référencées, Services qui la ciblent) — présélectionnés côté UI.
    app = (payload.get("app") or "").strip()
    in_app = _app_object_indexes(items, app) if app else None
    out = []
    for i, obj in enumerate(items):
        k = _obj_key(obj)
        row = {"i": i, "kind": k["kind"], "name": k["name"], "redacted": _obj_is_redacted(obj),
               "encrypted": _obj_secret_encrypted(obj)}      # chiffré et coffre verrouillé
        if in_app is not None:
            row["in_app"] = i in in_app
        out.append(row)
    out.sort(key=lambda x: (not x.get("in_app", True), x["kind"], x["name"]))
    return _ok(items=out, count=len(out), app=app or None,
               app_count=(len(in_app) if in_app is not None else None))


def _obj_diff_one(ns, obj):
    """Diff unifié entre l'objet SAUVEGARDÉ et l'état LIVE (nettoyé pareil).
    Renvoie {status: identical|differs|absent|error, diff, error}."""
    import difflib
    k = _obj_key(obj)
    live, err = kubectl_json(["get", k["resource"], k["name"], "-n", ns, "--ignore-not-found"])
    if err:
        return {"status": "error", "error": err, "diff": ""}
    if not live or not live.get("kind"):
        return {"status": "absent", "error": None, "diff": ""}
    live_c = _clean_resource(json.loads(json.dumps(live)),
                             include_secret_data=not _obj_is_redacted(obj))
    a = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False).splitlines()
    b = json.dumps(live_c, indent=2, sort_keys=True, ensure_ascii=False).splitlines()
    if a == b:
        return {"status": "identical", "error": None, "diff": ""}
    diff = "\n".join(difflib.unified_diff(b, a, "live", "sauvegarde", lineterm="", n=2))
    return {"status": "differs", "error": None, "diff": diff[:20000]}


def action_objects_diff(payload):
    """Aperçu : pour chaque objet coché, l'écart entre la sauvegarde et le live."""
    ns = payload.get("namespace")
    dr, derr = _dr_allowed(payload)
    if derr:
        return _err(derr)
    if not _namespace_allowed(ns):
        return _err("Namespace '%s' non autorisé par la configuration." % ns)
    items, err = _load_backup_resources(payload.get("backup_path"), payload.get("backup_root"),
                                        allow_dr=dr)
    if err:
        return _err(err)
    results = []
    for i in payload.get("indexes") or []:
        try:
            obj = items[int(i)]
        except (ValueError, TypeError, IndexError):
            continue
        k = _obj_key(obj)
        d = {"i": int(i), "kind": k["kind"], "name": k["name"]}
        if _obj_is_redacted(obj):
            d.update(status="redacted", error="Secret masqué à la sauvegarde : non restaurable.", diff="")
        else:
            d.update(_obj_diff_one(ns, obj))
        results.append(d)
    return _ok(results=results)


def action_objects_restore(payload, log=None):
    """Applique les objets cochés (kubectl apply, via stdin). Respecte le mode
    simulation ; en réel : verrou d'action + garde contexte + confirmation, comme
    les autres orchestrateurs. Les Secrets masqués sont TOUJOURS refusés."""
    ns = payload.get("namespace")
    dry = bool(payload.get("dry", True))
    if log is None:
        log = []
    dr, derr = _dr_allowed(payload)
    if derr:
        return _err(derr, log=[])
    if not _namespace_allowed(ns):
        return _err("Namespace '%s' non autorisé par la configuration." % ns, log=[])
    items, err = _load_backup_resources(payload.get("backup_path"), payload.get("backup_root"),
                                        allow_dr=dr)
    if err:
        return _err(err, log=[])
    if not dry:
        guard = _context_guard(payload)
        if guard:
            return guard
    chosen = []
    for i in payload.get("indexes") or []:
        try:
            chosen.append(items[int(i)])
        except (ValueError, TypeError, IndexError):
            pass
    if not chosen:
        return _err("Aucun objet sélectionné.", log=[])
    try:
        with action_lock(skip=dry):
            applied, skipped, failed = 0, 0, 0
            for obj in chosen:
                k = _obj_key(obj)
                label = "%s/%s" % (k["kind"], k["name"])
                if _obj_is_redacted(obj):
                    skipped += 1
                    log.append(logentry("Ignoré : %s (Secret masqué à la sauvegarde)" % label,
                                        ok=True, stdout="Restaurez ce Secret depuis sa source d'origine."))
                    continue
                r = _apply_manifest(obj, "objrestore_%s_%s" % (k["kind"], k["name"]), dry,
                                    "Appliquer %s" % label)
                log.append(r)
                if r["ok"]:
                    applied += 1
                else:
                    failed += 1
            ok = failed == 0
            audit("restore_objects", namespace=ns, dry=dry, ok=ok,
                  count=applied, skipped=skipped, failed=failed)
            return {"ok": ok, "error": None if ok else "%d objet(s) en échec." % failed,
                    "log": log, "applied": applied, "skipped": skipped, "failed": failed,
                    "dry": dry}
    except _Busy as e:
        return _err(str(e), log=log)


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
        # Une SIMULATION ne détruit rien : elle ne prend pas le verrou (et ne bloque
        # donc pas — ni n'est bloquée par — une opération réelle en cours), comme les
        # autres orchestrateurs (in-place, clone).
        with action_lock(skip=bool(payload.get("dry", True))):
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
    destructive_started = False      # vrai dès la première suppression réelle
    # Garde AVANT toute destruction (la prévisualisation n'émet qu'un avertissement) :
    # une référence qui est le NOM du VG (« pvc-<uuid-du-PVC> ») ou, en clone, l'UUID du
    # VG SOURCE détruirait PVC/PV pour recréer un PV sur un VG inexistant / partagé.
    if not dry and not payload.get("force_same_uuid"):
        bad_name = [r["pvc"] for r in prepared if r.get("looks_like_vg_name")]
        if bad_name:
            return {"ok": False, "log": [], "results": prep.get("results"),
                    "error": "Référence invalide pour %s : c'est le NOM du Volume Group (« pvc-<uuid> »), "
                             "pas son UUID. Rien n'a été modifié." % ", ".join(bad_name)}
        if payload.get("mode", "clone") == "clone":
            same = [r["pvc"] for r in prepared if r.get("same_uuid")]
            if same:
                return {"ok": False, "log": [], "results": prep.get("results"),
                        "error": "Référence identique au VG SOURCE pour %s : un clone doit pointer un "
                                 "NOUVEAU Volume Group (multi-attach sinon). Rien n'a été modifié."
                                 % ", ".join(same)}
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
            b = action_backup(ns, protect=[payload.get("backup_path")])
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
    current, desired, werr = _resolve_workloads(ns)
    if werr:
        log.append(logentry("Inventaire des workloads impossible", ok=False, rc=-1, stderr=werr))
        if not dry and not txn:
            _clear_txn(ns)           # rien n'a été détruit : pas de reprise à prévoir
        return _err("Inventaire des Deployments/StatefulSets impossible (%s) — restauration annulée : "
                    "sans lui, l'application ne serait ni arrêtée proprement ni redémarrée." % werr, log=log)
    log.append({"ok": True, "dry": dry, "label": "Réplicas mémorisés", "rc": 0, "stderr": "",
                "cmd": "(lecture) réplicas cibles",
                "stdout": ", ".join("%s/%s=%s" % (w["kind"], w["name"], w["replicas"]) for w in desired) or "aucun"})

    # Avertir si un pod montant un volume ciblé n'est PAS géré par un Deployment/
    # StatefulSet : le scale-down ne l'arrêtera pas et il pourrait recréer le pod /
    # tenir le PVC pendant la suppression.
    unmanaged, unm_err = _unmanaged_pods_using_pvcs(ns, [r["pvc"] for r in prepared])
    if unm_err:
        log.append(logentry("⚠ Liste des pods indisponible (contrôle des pods non gérés sauté)",
                            ok=True, stderr=unm_err))
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
        # Retain TOUJOURS forcé quand le nouveau PV re-pointe le MÊME Volume Group (restore
        # sur place) : avec reclaimPolicy=Delete, supprimer l'ancien PV détruirait le VG
        # sur lequel on s'apprête à redémarrer l'application. La config ne peut pas
        # désactiver cette protection.
        same_vg = bool(r.get("old_volume_handle")) and r.get("new_volume_handle") == r.get("old_volume_handle")
        retain = bool(CONFIG.get("retain_source_pv", True)) or same_vg or payload.get("mode") == "inplace"

        # Réécrire hypervisorAttachedDiskUUIDs avec le disque du VG cloné (clone) AVANT
        # l'apply : sans lui, le CSI tente l'attach iSCSI et l'attachement échoue.
        if payload.get("mode", "clone") == "clone":
            _fix_clone_iqn(r.get("manifest"), r.get("new_volume_handle"), dry, log)
            disk_ok = _set_clone_disk_uuids(r.get("manifest"), r.get("new_volume_handle"), dry, log,
                                            source_had="hypervisorAttachedDiskUUIDs" in (r.get("stripped") or []))
            if not disk_ok and not dry and CONFIG.get("clone_require_disk_uuids", True):
                aborted = True
                abort_detail = (("disque introuvable pour le Volume Group de %s : Prism Central n'est pas "
                                 "connecté (connectez-le puis relancez)" if not SESSION_CREDS.get("prismcentral")
                                 else "disque introuvable pour le Volume Group de %s : ce Volume Group "
                                 "n'existe plus côté Nutanix — restaurez-le dans HYCU puis relancez")
                                % pvc_name + " — PV non recréé pour éviter un volume non attachable")
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
            destructive_started = True
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
    restart_failed = []
    if not aborted:
        ok_restart, restart_failed = _restart_workloads(desired, ns, dry, log)
        if not ok_restart:
            log.append({"ok": False, "dry": dry, "label": "REDÉMARRAGE INCOMPLET", "rc": -1, "stdout": "",
                        "cmd": "", "stderr": "Les volumes sont restaurés mais un scale-up a échoué : "
                        "l'application est (partiellement) ARRÊTÉE. Relancez à la main : " + "; ".join(restart_failed)})
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
            if exp and not got:
                mism.append("%s non lié (aucun volumeHandle observé)" % r["pvc"])
            elif got and exp and got != exp:
                mism.append("%s lié à %s au lieu de %s" % (r["pvc"], got, exp))
        if mism:
            log.append(logentry("⚠ volumeHandle INATTENDU — vérifiez le volume réellement monté",
                                stdout="Incohérence(s) : " + " ; ".join(mism)
                                       + ". Le pod tourne peut-être sur le mauvais Volume Group."))
        else:
            log.append(logentry("volumeHandle conforme au VG attendu pour tous les volumes"))
        log.append(logentry("Vérification finale", cmd="kubectl get pvc/pv/pods",
                            stdout=json.dumps(v, indent=2)))

    ok_all = (not aborted) and not restart_failed and all(r["ok"] or r.get("dry") for r in log)
    # Transaction : effacée si la restauration s'est terminée sans interruption (réel),
    # y compris quand seul le redémarrage a échoué (PV/PVC cohérents : rejouer la
    # séquence serait inutile et destructif ; le scale-up manquant est indiqué).
    # Interrompue AVANT toute suppression (inventaire, arrêt, attente des pods) : le
    # marqueur est aussi effacé — rien n'est à reprendre, et le laisser bloquerait la
    # sauvegarde automatique du namespace.
    if not dry and (not aborted or not destructive_started):
        _clear_txn(ns)
    # Rappel : un VG CLONÉ tout neuf n'est pas protégé dans HYCU -> le signaler.
    reprotect = []
    if payload.get("mode", "clone") == "clone" and not dry and not aborted:
        reprotect = [{"pvc": r["pvc"], "new_pv_name": r["new_pv_name"],
                      "new_volume_handle": r["new_volume_handle"]} for r in prepared]
    audit("restore_end", namespace=ns, dry=dry, ok=ok_all, aborted=aborted,
          restart_failed=bool(restart_failed))
    err = None
    if restart_failed:
        err = ("Volumes restaurés mais redémarrage incomplet — relancez à la main : "
               + "; ".join(restart_failed))
    return {"ok": ok_all, "error": err, "dry": dry, "aborted": aborted, "log": log,
            "reprotect": reprotect}


def action_verify(ns):
    """État des PVC et des pods du namespace."""
    out = {"ok": True, "namespace": ns, "pvcs": [], "pods": [], "error": None}
    if not _namespace_allowed(ns):
        out["ok"] = False
        out["error"] = "Namespace '%s' non autorisé par la configuration." % ns
        out["ns_not_allowed"] = True   # l'UI propose « Autoriser ce namespace »
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
        # Raison d'un pod bloqué : dernier événement Warning du pod (FailedAttachVolume,
        # FailedScheduling, FailedMount…) + raison d'attente du conteneur — l'information
        # qui manque quand l'écran ne montre que « Pending ».
        events = {}
        ev_data, _e = kubectl_json(["get", "events", "-n", ns, "--field-selector", "involvedObject.kind=Pod"])
        for ev in ((ev_data or {}).get("items") or []):
            if (ev.get("type") or "") != "Warning":
                continue
            pod = ((ev.get("involvedObject") or {}).get("name")) or ""
            when = ev.get("lastTimestamp") or ev.get("eventTime") or ((ev.get("series") or {}).get("lastObservedTime")) or ""
            cur = events.get(pod)
            if not cur or str(when) >= str(cur["when"]):
                events[pod] = {"when": str(when), "reason": ev.get("reason") or "", "count": ev.get("count") or 1,
                               "message": str(ev.get("message") or "")[:400]}
        for i in pod_data.get("items", []):
            cs = i.get("status", {}).get("containerStatuses", []) or []
            ready = sum(1 for c in cs if c.get("ready"))
            waiting = sorted({((c.get("state") or {}).get("waiting") or {}).get("reason") or "" for c in cs} - {""})
            entry = {"name": i["metadata"]["name"], "phase": i.get("status", {}).get("phase"),
                     "ready": "%d/%d" % (ready, len(cs)), "waiting": ", ".join(waiting)}
            ev = events.get(i["metadata"]["name"])
            scheduled = bool((i.get("spec") or {}).get("nodeName"))
            # Un FailedScheduling est un vestige dès que le pod est placé sur un nœud
            # (PVC lié entre-temps) : ne pas l'afficher comme problème courant.
            if ev and ev["reason"] == "FailedScheduling" and scheduled:
                ev = None
            if ev and (i.get("status", {}).get("phase") != "Running" or ready < len(cs)):
                entry["issue"] = {"reason": ev["reason"], "message": ev["message"], "count": ev["count"]}
            out["pods"].append(entry)
    return out


def action_get_config():
    return {"config": CONFIG, "defaults": DEFAULT_CONFIG,
            "exists": os.path.isfile(CONFIG_PATH),
            # Chemins affichés dans la fenêtre « À propos ».
            "config_path": CONFIG_PATH,
            "audit_log": os.path.join(CONFIG["backup_root"], "audit.log"),
            "backup_root": CONFIG["backup_root"]}


def action_set_config(payload):
    ok, err = save_config(payload.get("config") or {})
    _LOCAL_CTX["at"] = 0.0          # contexte local peut-être changé : relire
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
        return {"ok": False, "error": "URL %s non configurée (⚙ Sources)." % system.upper()}
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
        return {"ok": False, "error": "URL %s non configurée (⚙ Sources)." % system.upper()}
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
        return {"ok": False, "error": "URL %s non configurée (⚙ Sources)." % system.upper()}

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


# ------------------------------------------------------------------------------
# Export S3 (OPTIONNEL) — signature AWS SigV4 en stdlib pure (Nutanix Objects,
# MinIO, AWS S3…). Le filet de sécurité (sauvegardes de config) peut ainsi vivre
# HORS du cluster qu'il protège. Identifiants en RAM/coffre, jamais dans la config.
# ------------------------------------------------------------------------------
def _sigv4_auth(method, host, path, query, headers, payload_hash, region, service,
                access, secret, amzdate):
    """En-tête Authorization AWS Signature v4. `headers` = en-têtes À SIGNER
    (host inclus), clés en minuscules. Vérifié contre le vecteur officiel AWS."""
    datestamp = amzdate[:8]
    signed = ";".join(sorted(headers))
    # `path` est DÉJÀ encodé par l'appelant (_s3_object_url) : ne pas le ré-encoder (un
    # « % » deviendrait « %25 » et la signature ne correspondrait plus à l'URL envoyée).
    # La chaîne de requête canonique est TRIÉE par nom de paramètre (exigence SigV4) :
    # sans tri, « continuation-token » ajouté en fin casse la page 2 d'un listing.
    canonical_query = "&".join(sorted(query.split("&"))) if query else ""
    canonical = "\n".join([
        method,
        path or "/",
        canonical_query,
        "".join("%s:%s\n" % (k, " ".join(str(headers[k]).split())) for k in sorted(headers)),
        signed,
        payload_hash,
    ])
    scope = "%s/%s/%s/aws4_request" % (datestamp, region, service)
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope,
                         hashlib.sha256(canonical.encode("utf-8")).hexdigest()])
    k = hmac.new(("AWS4" + secret).encode("utf-8"), datestamp.encode(), hashlib.sha256).digest()
    for part in (region, service, "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    return ("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
            % (access, scope, signed, sig))


def _s3_object_url(key=""):
    """(url complète, host, chemin signé) pour un objet du bucket configuré."""
    base = (CONFIG.get("s3_url") or "").strip().rstrip("/")
    bucket = (CONFIG.get("s3_bucket") or "").strip()
    u = urllib.parse.urlparse(base)
    host = u.netloc
    if CONFIG.get("s3_path_style", True):
        path = "%s/%s" % (u.path.rstrip("/"), bucket)
    else:                                       # bucket en sous-domaine (AWS virtual-host)
        host = "%s.%s" % (bucket, u.netloc)
        path = u.path.rstrip("/")
    if key:
        path += "/" + urllib.parse.quote(key, safe="/-_.~")
    path = path or "/"
    return "%s://%s%s" % (u.scheme, host, path), host, path


def _s3_request(method, key="", body=b"", query="", want_body=False):
    """Requête S3 signée SigV4. Renvoie {"ok", "status", "error", "body"} ;
    `want_body=True` renvoie le corps COMPLET en octets dans "data" (listing XML,
    téléchargement d'objet), sinon un extrait texte de 2 Ko."""
    base = (CONFIG.get("s3_url") or "").strip()
    bucket = (CONFIG.get("s3_bucket") or "").strip()
    if not base or not bucket:
        return {"ok": False, "error": "Endpoint S3 ou bucket non configuré (⚙ Sources)."}
    creds = SESSION_CREDS.get("s3")
    if not creds:
        return {"ok": False, "error": "Non connecté au stockage objet : renseignez les clés d'accès (⚙ Sources)."}
    url, host, path = _s3_object_url(key)
    if query:
        url += "?" + query
    region = (CONFIG.get("s3_region") or "us-east-1").strip() or "us-east-1"
    amzdate = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    payload_hash = hashlib.sha256(body or b"").hexdigest()
    hdrs = {"host": host, "x-amz-date": amzdate, "x-amz-content-sha256": payload_hash}
    auth = _sigv4_auth(method, host, path, query, hdrs, payload_hash, region, "s3",
                       creds.get("access") or "", creds.get("secret") or "", amzdate)
    req = urllib.request.Request(url, data=(body if method in ("PUT", "POST") else None), method=method)
    for k, v in hdrs.items():
        if k != "host":
            req.add_header(k, v)
    req.add_header("Authorization", auth)
    if method in ("PUT", "POST"):
        req.add_header("Content-Type", "application/zip")
    ctx = _ssl_ctx(bool(CONFIG.get("s3_verify_tls"))) if url.lower().startswith("https") else None
    try:
        with urllib.request.urlopen(req, timeout=300 if want_body else 60, context=ctx) as resp:
            if want_body:
                return {"ok": True, "status": resp.status, "error": None,
                        "data": resp.read(), "body": ""}
            return {"ok": True, "status": resp.status, "error": None,
                    "body": resp.read(2048).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read(500).decode("utf-8", "replace")
        except Exception:
            pass
        hint = {403: " — clés d'accès refusées (ou horloge du serveur décalée : SigV4 exige une heure juste).",
                404: " — bucket introuvable : vérifiez son nom (et s3_path_style).",
                301: " — mauvaise région (s3_region) ou style d'URL (s3_path_style)."}.get(e.code, "")
        return {"ok": False, "status": e.code, "error": "HTTP %s%s %s" % (e.code, hint, detail[:200])}
    except Exception as e:
        return {"ok": False, "status": None, "error": "Stockage objet injoignable : %s" % e}


def action_s3_list():
    """Liste les exports présents dans le bucket (préfixe configuré) — le chemin
    RETOUR de l'export : indispensable en reprise d'activité, quand le PVC de
    l'outil a disparu avec le cluster. Parse le XML ListObjectsV2 (stdlib)."""
    import xml.etree.ElementTree as ET
    prefix = (CONFIG.get("s3_prefix") or "hycu-backups").strip().strip("/")
    out, token = [], None
    for _page in range(20):                          # garde-fou : 20 000 objets max
        q = "list-type=2&max-keys=1000&prefix=" + urllib.parse.quote(prefix + "/", safe="")
        if token:
            q += "&continuation-token=" + urllib.parse.quote(token, safe="")
        r = _s3_request("GET", "", b"", q, want_body=True)
        if not r["ok"]:
            return _err("Liste du bucket impossible : %s" % r.get("error"))
        try:
            root = ET.fromstring(r["data"])
        except ET.ParseError as e:
            return _err("Réponse du bucket illisible (XML) : %s" % e)
        nsm = {"s3": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else None
        def find(el, name):
            return el.find("s3:" + name, nsm) if nsm else el.find(name)
        def findall(el, name):
            return el.findall("s3:" + name, nsm) if nsm else el.findall(name)
        for c in findall(root, "Contents"):
            key = (find(c, "Key").text or "")
            size = int(find(c, "Size").text or 0)
            modified = (find(c, "LastModified").text or "")[:19]
            rel = key[len(prefix) + 1:] if key.startswith(prefix + "/") else key
            parts = rel.split("/")
            if len(parts) != 3 or not (parts[2].endswith(".zip") or parts[2].endswith(".zip.enc")):
                continue                             # objet étranger au format de l'outil : ignoré
            enc = parts[2].endswith(".enc")
            out.append({"key": key, "size": size, "modified": modified,
                        "cluster": parts[0], "namespace": parts[1],
                        "timestamp": parts[2][:-8] if enc else parts[2][:-4],
                        "encrypted": enc})
        token_el = find(root, "NextContinuationToken")
        token = token_el.text if (token_el is not None and (find(root, "IsTruncated") is not None
                                  and (find(root, "IsTruncated").text or "") == "true")) else None
        if not token:
            break
    out.sort(key=lambda x: (x["cluster"], x["namespace"], x["timestamp"]), reverse=True)
    return _ok(objects=out, prefix=prefix, bucket=CONFIG.get("s3_bucket"))


IMPORT_MAX_BYTES = 2 * 1024 ** 3     # taille DÉCOMPRESSÉE maximale d'un export importé


def _safe_extract_zip(data, dest, max_bytes=IMPORT_MAX_BYTES):
    """Extrait un zip en mémoire vers `dest`, en retirant le dossier racine unique
    et en BLOQUANT toute traversée (zip-slip) et toute archive « gonflée » (zip bomb :
    taille annoncée ET taille réellement écrite bornées). Renvoie (nb fichiers, erreur)."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return 0, "l'objet n'est pas un zip valide (mauvaise phrase de déchiffrement ?)"
    names = [n for n in zf.namelist() if not n.endswith("/")]
    announced = sum((zf.getinfo(n).file_size or 0) for n in names)
    if announced > max_bytes:
        return 0, "archive rejetée : taille décompressée annoncée %d Mo > %d Mo" % (
            announced // (1024 * 1024), max_bytes // (1024 * 1024))
    written = 0
    roots = {n.split("/", 1)[0] for n in names if "/" in n}
    strip = (roots.pop() + "/") if (len(roots) == 1 and all("/" in n for n in names)) else ""
    dest_real = os.path.realpath(dest)
    count = 0
    for n in names:
        rel = n[len(strip):] if n.startswith(strip) else n
        target = os.path.realpath(os.path.join(dest, rel))
        if not (target == dest_real or target.startswith(dest_real + os.sep)):
            return 0, "archive rejetée : chemin hors zone (« %s »)" % n
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with zf.open(n) as src, open(target, "wb") as f:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:          # taille réelle > annoncée (bombe)
                    return 0, "archive rejetée : contenu décompressé supérieur à %d Mo" % (max_bytes // (1024 * 1024))
                f.write(chunk)
        count += 1
    return count, None


def action_s3_import(payload):
    """Rapatrie des exports du bucket vers <backup_root>/_imports/<cluster>/<ns>/<ts>/.
    Les sauvegardes importées gardent leur cluster/contexte d'origine : elles ne se
    restaurent que via la restauration DR (garde-fou allow_dr_restore) ou sur leur
    cluster d'origine. Déchiffre les .enc (phrase fournie ou mémorisée)."""
    results, imported = [], 0
    pw = (payload.get("enc_passphrase") or "").strip() or ((SESSION_CREDS.get("s3") or {}).get("enc") or "")
    for it in payload.get("items") or []:
        key = it.get("key") or ""
        label = key.rsplit("/", 3)
        label = "/".join(label[-3:]) if len(label) >= 3 else key
        rel = key.split("/")
        if len(rel) < 3 or any(p in ("", ".", "..") for p in rel):
            results.append({"key": label, "ok": False, "error": "clé invalide"})
            continue
        cluster, nsname, fname = rel[-3], rel[-2], rel[-1]
        ts = fname[:-8] if fname.endswith(".zip.enc") else fname[:-4]
        if not (K8S_NAME_RE.match(nsname) and re.fullmatch(r"[A-Za-z0-9._-]{1,80}", cluster)
                and re.fullmatch(r"[A-Za-z0-9._-]{1,80}", ts)):
            results.append({"key": label, "ok": False, "error": "clé invalide"})
            continue
        ferr = _storage_floor_error(CONFIG["backup_root"])   # AVANT de télécharger
        if ferr:
            results.append({"key": label, "ok": False, "error": ferr})
            break
        r = _s3_request("GET", key, b"", "", want_body=True)
        if not r["ok"]:
            results.append({"key": label, "ok": False, "error": r.get("error")})
            continue
        data = r["data"]
        if fname.endswith(".enc"):
            if not pw:
                results.append({"key": label, "ok": False,
                                "error": "objet chiffré : renseignez la phrase de déchiffrement"})
                continue
            data = decrypt_bytes(data, pw)
            if data is None:
                results.append({"key": label, "ok": False,
                                "error": "déchiffrement impossible (phrase incorrecte ou objet altéré)"})
                continue
        dest = os.path.join(CONFIG["backup_root"], "_imports", cluster, nsname, ts)
        n, err = _safe_extract_zip(data, dest)
        if err:
            shutil.rmtree(dest, ignore_errors=True)
            results.append({"key": label, "ok": False, "error": err})
            continue
        imported += 1
        _catalog_forget_path(dest)
        results.append({"key": label, "ok": True, "files": n, "path": dest})
        audit("s3_import", key=key, namespace=nsname, files=n, path=dest)
    return {"ok": imported > 0 or not results, "results": results, "imported": imported,
            "error": None if imported or not results else "Aucun export importé."}


def action_s3_connect(payload):
    """Enregistre endpoint/bucket (config) + clés (RAM), puis teste par une
    LISTE du bucket limitée à 1 objet (lecture seule)."""
    updates = {}
    for k in ("s3_url", "s3_bucket", "s3_region", "s3_prefix"):
        if k in payload:
            updates[k] = str(payload.get(k) or "").strip()
    for k in ("s3_verify_tls", "s3_path_style", "s3_auto_upload", "s3_encrypt"):
        if k in payload:
            updates[k] = bool(payload.get(k))
    if updates:
        save_config(updates)
    access = (payload.get("access") or "").strip()
    secret = (payload.get("secret") or "").strip()
    if not access or not secret:
        return _err("Renseignez la clé d'accès (Access key) et la clé secrète (Secret key).")
    enc_pw = (payload.get("enc_passphrase") or "").strip()
    if CONFIG.get("s3_encrypt") and not enc_pw:
        return _err("Chiffrement activé : choisissez une phrase de chiffrement des exports "
                    "(elle servira aussi au déchiffrement — conservez-la précieusement).")
    with CRED_LOCK:
        SESSION_CREDS["s3"] = {"access": access, "secret": secret}
        if enc_pw:
            SESSION_CREDS["s3"]["enc"] = enc_pw
    r = _s3_request("GET", "", b"", "list-type=2&max-keys=1")
    if not r["ok"]:
        with CRED_LOCK:
            SESSION_CREDS["s3"] = None
        return _err("Test du bucket impossible : %s" % r.get("error"))
    audit("connect", system="s3", url=CONFIG.get("s3_url"), bucket=CONFIG.get("s3_bucket"),
          encrypted=bool(CONFIG.get("s3_encrypt")))
    return _ok(connected=True, bucket=CONFIG.get("s3_bucket"),
               auto_upload=bool(CONFIG.get("s3_auto_upload")),
               encrypted=bool(CONFIG.get("s3_encrypt")))


def _zip_backup_dir(path, top, max_bytes=512 * 1024 * 1024):
    """Zippe un dossier de sauvegarde en mémoire. Renvoie (bytes, erreur)."""
    buf, total = io.BytesIO(), 0
    try:
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for dirpath, _dirs, fnames in os.walk(path):
                for n in sorted(fnames):
                    fp = os.path.join(dirpath, n)
                    if not os.path.isfile(fp):
                        continue
                    total += os.path.getsize(fp)
                    if total > max_bytes:
                        return None, "sauvegarde trop volumineuse pour l'export (%d Mo max)" % (max_bytes // 1024 // 1024)
                    z.write(fp, os.path.join(top, os.path.relpath(fp, path)))
    except OSError as e:
        return None, str(e)
    return buf.getvalue(), None


def s3_upload_backup(backup_dir, ns, ts):
    """Envoie une sauvegarde (.zip) vers le bucket : clé
    <préfixe>/<cluster>/<namespace>/<horodatage>.zip[.enc]. Si le chiffrement est
    activé (s3_encrypt + phrase saisie dans ⚙ Sources), l'objet est chiffré AVANT
    l'envoi : le bucket peut être un stockage non maîtrisé. Renvoie (ok, clé|erreur)."""
    cid = _current_cid()
    if cid == LOCAL_CID:
        ctx = _local_context_name()
        if ctx:
            cid = "local-" + _cluster_slug(ctx)
    data, err = _zip_backup_dir(backup_dir, "%s_%s" % (ns, ts))
    if err:
        return False, err
    ext = ".zip"
    if CONFIG.get("s3_encrypt"):
        enc_pw = ((SESSION_CREDS.get("s3") or {}).get("enc") or "")
        if not enc_pw:
            return False, ("chiffrement activé mais phrase de chiffrement absente : "
                           "renseignez-la dans ⚙ Sources > Stockage objet S3")
        data = encrypt_bytes(data, enc_pw)
        ext = ".zip.enc"
    prefix = (CONFIG.get("s3_prefix") or "hycu-backups").strip().strip("/")
    key = "/".join(x for x in (prefix, cid, ns, ts + ext) if x)
    r = _s3_request("PUT", key, data)
    if not r["ok"]:
        return False, r.get("error") or "envoi refusé"
    return True, key


def _s3_after_backup(result):
    """Crochet post-sauvegarde : export auto vers le bucket si activé et connecté.
    BEST-EFFORT : un échec d'export n'échoue jamais la sauvegarde locale (il est
    journalisé et visible dans les Tâches)."""
    if not (CONFIG.get("s3_auto_upload") and SESSION_CREDS.get("s3") and result.get("ok")):
        return result
    d = result.get("dir") or ""
    ns = result.get("count") is not None and os.path.basename(os.path.dirname(d)) or ""
    ts = os.path.basename(d)
    try:
        ok, info = s3_upload_backup(d, ns, ts)
    except Exception as e:                      # jamais bloquant
        ok, info = False, str(e)
    audit("s3_upload", ok=ok, namespace=ns, key=info if ok else None,
          error=None if ok else info, bucket=CONFIG.get("s3_bucket"))
    result["s3"] = {"ok": ok, "key": info if ok else None, "error": None if ok else info}
    return result


def action_disconnect(payload):
    system = payload.get("system")
    with CRED_LOCK:
        if system in SESSION_CREDS:
            SESSION_CREDS[system] = None
    return {"ok": True, "system": system, "connected": False}


def check_ui_session(cookie_header):
    """Lie les identifiants (SESSION_CREDS) à une session de navigateur.

    Appelée au chargement de la page ("/"). Si le cookie « hycu_sess » porte l'id
    de la session courante, rien ne change (rechargement F5). Sinon — premier
    chargement, navigateur relancé, autre navigateur — une nouvelle session est
    ouverte et les identifiants en mémoire sont EFFACÉS : la phrase secrète du
    coffre (ou les mots de passe) sont redemandés à chaque nouvelle session.
    Renvoie la valeur Set-Cookie à poser, ou None si la session est inchangée."""
    m = re.search(r"(?:^|;\s*)hycu_sess=([A-Za-z0-9_-]+)", cookie_header or "")
    tok = m.group(1) if m else None
    # Une opération destructive en cours (restore/clone, ou opération asynchrone non
    # terminée) dépend des identifiants ET des kubeconfigs en mémoire : verrouiller la
    # session MAINTENANT supprimerait le kubeconfig du cluster en pleine séquence
    # (application laissée arrêtée, PVC détruits). On garde la session courante ;
    # le verrouillage se fera au prochain chargement une fois l'opération finie.
    if ACTION_LOCK.locked():
        return None
    with OP_LOCK:
        if any(not op["done"] for op in OPERATIONS.values()):
            return None
    with CRED_LOCK:
        cur = UI_SESSION["id"]
        if tok and cur and hmac.compare_digest(tok, cur):
            return None
        UI_SESSION["id"] = secrets.token_urlsafe(24)
        locked = [k for k, v in SESSION_CREDS.items() if v]
        for k in SESSION_CREDS:
            SESSION_CREDS[k] = None
        new_id = UI_SESSION["id"]
    # Les kubeconfigs ajoutés depuis l'interface sont des identifiants : même règle.
    gone = _wipe_clusters()
    if locked or gone:
        audit("creds_locked", reason="new_browser_session", systems=sorted(locked), clusters=gone)
    # Déverrouillage auto (phrase secrète fournie par l'environnement) : recharger
    # aussitôt — l'opérateur a explicitement choisi ce mode « serveur de confiance »,
    # la rotation de session reste effective (cookie), et la sauvegarde automatique
    # des clusters ajoutés ne s'interrompt pas à chaque nouvelle session navigateur.
    if gone or locked:
        auto_unlock_vault("session_relock")
    return "hycu_sess=%s; Path=/; HttpOnly; SameSite=Strict" % new_id


def action_conn_status():
    out = {}
    for s in ("hycu", "nutanix", "prismcentral"):
        base, api, verify = _system_cfg(s)
        out[s] = {"configured": bool(base), "url": base, "api_base": api,
                  "verify_tls": verify, "connected": SESSION_CREDS.get(s) is not None}
    out["s3"] = {"configured": bool((CONFIG.get("s3_url") or "").strip() and (CONFIG.get("s3_bucket") or "").strip()),
                 "url": (CONFIG.get("s3_url") or "").strip(), "bucket": CONFIG.get("s3_bucket") or "",
                 "region": CONFIG.get("s3_region") or "us-east-1",
                 "verify_tls": bool(CONFIG.get("s3_verify_tls")),
                 "auto_upload": bool(CONFIG.get("s3_auto_upload")),
                 "encrypt": bool(CONFIG.get("s3_encrypt")),
                 "connected": SESSION_CREDS.get("s3") is not None}
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
# En-tête du format v2 du coffre : « HV2 » + itérations PBKDF2 (4 octets). Sans lui
# (anciens coffres), le nombre d'itérations venait de la config : le changer rendait
# le coffre indéchiffrable (« phrase secrète incorrecte » à tort).
_VAULT_MAGIC = b"HV2"


def _derive_keys(passphrase, salt, iters=None):
    if iters is None:
        iters = _pbkdf2_iters()
    dk = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iters, dklen=64)
    return dk[:32], dk[32:]   # (clé de chiffrement, clé MAC)


def _keystream(enc_key, nonce, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hmac.new(enc_key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest())
        counter += 1
    return bytes(out[:length])


def _pbkdf2_iters():
    """Itérations PBKDF2 BORNÉES [1000 ; 10 000 000] à l'écriture — les mêmes bornes que
    le déchiffrement, sinon un réglage hors bornes produit un coffre/export illisible."""
    try:
        v = int(CONFIG.get("pbkdf2_iterations") or 200000)
    except (TypeError, ValueError):
        v = 200000
    return max(1000, min(v, 10_000_000))


def _xor(data, ks):
    return bytes(a ^ b for a, b in zip(data, ks))


def encrypt_secret(plaintext, passphrase):
    iters = _pbkdf2_iters()
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    enc_key, mac_key = _derive_keys(passphrase, salt, iters)
    ct = _xor(plaintext, _keystream(enc_key, nonce, len(plaintext)))
    head = _VAULT_MAGIC + iters.to_bytes(4, "big")
    tag = hmac.new(mac_key, head + salt + nonce + ct, hashlib.sha256).digest()
    return base64.b64encode(head + salt + nonce + ct + tag).decode("ascii")


def decrypt_secret(blob_b64, passphrase):
    try:
        raw = base64.b64decode(blob_b64)
        head = b""
        iters = None
        if raw.startswith(_VAULT_MAGIC):        # format v2 : itérations dans le blob
            head, iters = raw[:7], int.from_bytes(raw[3:7], "big")
            raw = raw[7:]
            if not (1000 <= iters <= 10_000_000):
                return None
        if len(raw) < 64:
            return None
        salt, nonce, body = raw[:16], raw[16:32], raw[32:]
        ct, tag = body[:-32], body[-32:]
        enc_key, mac_key = _derive_keys(passphrase, salt, iters)
        expected = hmac.new(mac_key, head + salt + nonce + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, tag):
            return None   # mauvaise phrase secrète ou fichier altéré
        return _xor(ct, _keystream(enc_key, nonce, len(ct)))
    except Exception:
        return None


# Variante BINAIRE du chiffrement du coffre, pour les fichiers volumineux (exports
# S3) : « HV2B » + itérations (4 o) + sel (16) + nonce (16) + chiffré + scellé (32).
_VAULT_MAGIC_BIN = b"HV2B"


def encrypt_bytes(data, passphrase):
    iters = _pbkdf2_iters()
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    enc_key, mac_key = _derive_keys(passphrase, salt, iters)
    ct = _xor(data, _keystream(enc_key, nonce, len(data)))
    head = _VAULT_MAGIC_BIN + iters.to_bytes(4, "big") + salt + nonce
    tag = hmac.new(mac_key, head + ct, hashlib.sha256).digest()
    return head + ct + tag


def decrypt_bytes(blob, passphrase):
    """Renvoie les octets déchiffrés, ou None (mauvaise phrase / fichier altéré)."""
    try:
        if not blob.startswith(_VAULT_MAGIC_BIN) or len(blob) < 4 + 4 + 16 + 16 + 32:
            return None
        iters = int.from_bytes(blob[4:8], "big")
        if not (1000 <= iters <= 10_000_000):
            return None
        head, salt, nonce = blob[:40], blob[8:24], blob[24:40]
        ct, tag = blob[40:-32], blob[-32:]
        enc_key, mac_key = _derive_keys(passphrase, salt, iters)
        if not hmac.compare_digest(hmac.new(mac_key, head + ct, hashlib.sha256).digest(), tag):
            return None
        return _xor(ct, _keystream(enc_key, nonce, len(ct)))
    except Exception:
        return None


def cli_decrypt(path):
    """Mode CLI : `--decrypt <fichier>.zip.enc` — déchiffre un export S3 chiffré
    (récupération / DR, sans passer par l'interface). Écrit le fichier sans `.enc`."""
    import getpass
    try:
        with open(path, "rb") as f:
            blob = f.read()
    except OSError as e:
        print("Lecture impossible : %s" % e)
        return 1
    pw = getpass.getpass("Phrase de chiffrement : ")
    data = decrypt_bytes(blob, pw)
    if data is None:
        print("Échec : phrase incorrecte ou fichier altéré.")
        return 1
    out = path[:-4] if path.endswith(".enc") else path + ".dec"
    with open(out, "wb") as f:
        f.write(data)
    print("Déchiffré -> %s" % out)
    return 0


def action_save_credentials(payload):
    """Chiffre les identifiants de session courants dans hycu_secrets.enc."""
    pw = payload.get("passphrase") or ""
    if len(pw) < 8:
        return {"ok": False, "error": "Choisissez une phrase secrète d'au moins 8 caractères."}
    with CRED_LOCK:
        creds = {k: v for k, v in SESSION_CREDS.items() if v}
    # Clusters Kubernetes ajoutés depuis l'interface : leur kubeconfig est un secret,
    # conservé uniquement ici (chiffré), jamais dans hycu_config.json.
    with CLUSTERS_LOCK:
        clusters = [{k: c.get(k) for k in ("name", "kubeconfig", "context", "workspace",
                                           "source", "nkp_ref", "management")}
                    for c in CLUSTERS.values()]
    if not creds and not clusters:
        return {"ok": False, "error": "Connectez-vous d'abord à au moins un système."}
    names = sorted(creds.keys())
    if clusters:
        creds = dict(creds, _clusters=clusters)
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
    global _VAULT_PW
    _VAULT_PW = pw                      # sert aussi à chiffrer les Secrets des sauvegardes
    save_config({"remember_credentials": True})
    audit("creds_saved", systems=names, clusters=[c["name"] for c in clusters])
    return {"ok": True, "saved": names, "clusters": [c["name"] for c in clusters]}


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
    global _VAULT_PW
    _VAULT_PW = pw                      # phrase validée : chiffre/déchiffre les Secrets sauvegardés
    loaded = []
    with CRED_LOCK:
        for k, v in creds.items():
            if k in SESSION_CREDS and isinstance(v, dict):
                SESSION_CREDS[k] = v
                loaded.append(k)
    # Clusters mémorisés : réenregistrés SANS test réseau (chargement rapide) ; un
    # cluster déjà présent (même nom) est laissé tel quel.
    cl_ok, cl_err = [], []
    for c in creds.get("_clusters") or []:
        if not isinstance(c, dict):
            continue
        with CLUSTERS_LOCK:
            present = any(x["name"] == c.get("name") for x in CLUSTERS.values())
        if present:
            cl_ok.append(c.get("name"))
            continue
        r = _register_cluster(c.get("name"), c.get("kubeconfig"), c.get("context"),
                              workspace=c.get("workspace") or "", source=c.get("source") or "upload",
                              nkp_ref=c.get("nkp_ref") or "", management=c.get("management") or "",
                              test=False, allow_exec=(c.get("source") or "upload") != "nkp")
        (cl_ok if r.get("ok") else cl_err).append(c.get("name") if r.get("ok")
                                                  else "%s (%s)" % (c.get("name"), r.get("error")))
    audit("creds_loaded", systems=loaded, clusters=cl_ok)
    return {"ok": True, "loaded": sorted(loaded), "clusters": cl_ok, "cluster_errors": cl_err}


def _vault_env_passphrase():
    """Phrase secrète du coffre fournie par l'environnement (mode conteneur) :
    HYCU_VAULT_PASSPHRASE_FILE (fichier monté depuis un Secret K8s — préférable)
    ou HYCU_VAULT_PASSPHRASE (variable directe). Vide = fonctionnalité inactive."""
    path = (os.environ.get("HYCU_VAULT_PASSPHRASE_FILE") or "").strip()
    if path:
        try:
            with open(path, encoding="utf-8") as f:
                return f.read().strip()
        except OSError as e:
            print("HYCU_VAULT_PASSPHRASE_FILE illisible (%s) : déverrouillage auto inactif." % e)
            return ""
    return (os.environ.get("HYCU_VAULT_PASSPHRASE") or "").strip()


def auto_unlock_vault(reason):
    """Déverrouille le coffre SANS interaction quand l'opérateur a fourni la phrase
    secrète via l'environnement (déploiement Kubernetes : Secret monté). Utile pour
    que les clusters ajoutés (et les connexions) survivent à un redémarrage du Pod
    et restent disponibles pour la sauvegarde automatique. Best-effort : un échec
    n'empêche jamais le démarrage. Renvoie True si quelque chose a été rechargé."""
    pw = _vault_env_passphrase()
    if not pw or not os.path.isfile(SECRETS_PATH):
        return False
    r = action_load_credentials({"passphrase": pw})
    if r.get("ok"):
        audit("vault_auto_unlock", reason=reason, systems=r.get("loaded") or [],
              clusters=r.get("clusters") or [])
        return bool((r.get("loaded") or r.get("clusters")))
    print("Déverrouillage automatique du coffre impossible : %s" % r.get("error"))
    return False


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
            if not items or fresh == 0:
                break
            if total is not None:
                if len(seen) >= total:
                    break
            elif len(items) < page_size:
                break                            # sans total : une page courte = la dernière
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
            if not items or fresh == 0:
                break
            if total is not None:
                if len(seen) >= total:
                    break
            elif len(items) < page_size:
                break
            offset += len(items)                 # avancer de ce que le serveur a réellement renvoyé
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


def _vg_target_name(vg_uuid):
    """Nom de la cible iSCSI (`targetName`) d'un VG, via Prism Central v4 ; None si illisible."""
    enc = urllib.parse.quote(str(vg_uuid))
    r = _rest_raw("prismcentral", "GET", "/api/volumes/v4.0.b1/config/volume-groups/%s" % enc)
    if not r.get("ok"):
        return None
    return (((r.get("json") or {}).get("data") or {}).get("targetName")) or None


def _iqn_for_target(iqn, target_name):
    """IQN attendu par le CSI pour une cible : préfixe de l'IQN source (« iqn.2010-06.com.nutanix: »),
    nom de cible réel, suffixe conservé (« -tgt0 »)."""
    prefix, sep, rest = (iqn or "").partition(":")
    if not sep:
        return None
    m = re.search(r"(-tgt\d+)$", rest)
    return "%s:%s%s" % (prefix, target_name, m.group(1) if m else "")


def _fix_clone_iqn(pv_manifest, new_volume_handle, dry, log):
    """Aligne `volumeAttributes.iqn` du PV sur le NOM DE CIBLE RÉEL du Volume Group.
    L'outil dérive l'IQN en remplaçant l'UUID dans l'IQN source (« ntnx-k8s-<uuid> »,
    convention du CSI), mais un VG créé par HYCU porte une cible « hycu-clone-vg-<uuid> » :
    le worker cherche alors une cible inexistante (« iscsiadm: No records found »). Lu via
    Prism Central v4 ; sans PC, l'IQN dérivé est conservé et signalé. Jamais bloquant."""
    csi = (pv_manifest.get("spec") or {}).get("csi") if isinstance(pv_manifest, dict) else None
    va = csi.get("volumeAttributes") if isinstance(csi, dict) else None
    iqn = (va or {}).get("iqn")
    vg_uuid = split_volume_handle(new_volume_handle or "")[1]
    if not iqn or ":" not in iqn or not vg_uuid:
        return True
    if dry:
        log.append(logentry("Aligner l'IQN du PV sur la cible iSCSI réelle du VG %s" % vg_uuid, dry=True, rc=None,
                            stdout="Lu via Prism Central v4 (un VG créé par HYCU porte une cible « hycu-clone-vg-… »)."))
        return True
    if not SESSION_CREDS.get("prismcentral"):
        log.append(logentry("IQN du PV non vérifié (Prism Central non connecté)", ok=False, rc=-1,
                            stderr="Si le pod reste en FailedMount (« iscsiadm: No records found »), connectez "
                                   "Prism Central et relancez : la cible iSCSI du VG restauré peut différer de l'IQN dérivé."))
        return True
    tn = _vg_target_name(vg_uuid)
    if not tn:
        log.append(logentry("IQN du PV non vérifié (cible iSCSI du VG %s illisible)" % vg_uuid, ok=False, rc=-1,
                            stderr="Prism Central n'a pas renvoyé le targetName du VG."))
        return True
    new_iqn = _iqn_for_target(iqn, tn)
    if new_iqn and new_iqn != iqn:
        va["iqn"] = new_iqn
        log.append(logentry("IQN du PV aligné sur la cible iSCSI réelle du VG",
                            stdout="%s -> %s" % (iqn, new_iqn)))
    else:
        log.append(logentry("IQN du PV conforme à la cible iSCSI du VG", stdout=iqn))
    return True


def _set_clone_disk_uuids(pv_manifest, new_volume_handle, dry, log, source_had=True):
    """Réécrit `volumeAttributes.hypervisorAttachedDiskUUIDs` du PV cloné avec l'extId
    du disque du VG CLONÉ (lu via Prism Central v4) — UNIQUEMENT si le PV SOURCE portait
    cet attribut (`source_had`). Politique « miroir de la source » : le PV d'origine a
    été provisionné par le CSI de CE cluster et s'attache ; on reproduit sa forme.
      - source avec l'attribut : il pointait le disque source -> réécrit avec le disque du
        VG cloné (sinon le CSI tente l'attach iSCSI, ou attache le mauvais disque) ;
      - source SANS l'attribut : on n'en ajoute PAS (constaté : l'ajouter fait échouer la
        tâche d'attachement Nutanix « hypervisor Attach Client failed »).
    À appeler AVANT l'apply du PV. Renvoie True s'il faut/peut continuer, False si l'info
    est INTROUVABLE en mode réel (l'appelant décidera selon `clone_require_disk_uuids`)."""
    if not CONFIG.get("clone_fix_disk_uuids", True):
        return True
    vg_uuid = split_volume_handle(new_volume_handle or "")[1]
    csi = (pv_manifest.get("spec") or {}).get("csi") if isinstance(pv_manifest, dict) else None
    if not vg_uuid or not isinstance(csi, dict):
        return True
    if not source_had:
        (csi.get("volumeAttributes") or {}).pop("hypervisorAttachedDiskUUIDs", None)
        log.append(logentry("hypervisorAttachedDiskUUIDs non ajouté (le PV source ne le porte pas)",
                            dry=dry, rc=None,
                            stdout="Le CSI de ce cluster attache le Volume Group sans cet attribut, "
                                   "comme pour le PV d'origine : forme du PV source reproduite."))
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
    # Une ERREUR kubectl n'est pas « PVC absent » : sauter silencieusement le
    # rafraîchissement redémarrerait l'app sur un disque périmé (FailedMount,
    # « failed to get symlink for disk … ») en affichant un succès.
    pvc_live, perr = kubectl_json(["get", "pvc", pvc_name, "-n", ns])
    if perr:
        log.append(logentry("Vérification du disque du PV impossible (lecture du PVC %s)" % pvc_name,
                            ok=False, rc=-1, stderr=perr))
        return False, ("Lecture du PVC « %s » impossible (%s) : impossible de vérifier si HYCU a "
                       "remplacé le disque du VG. Corrigez l'accès kubectl puis relancez la "
                       "restauration sur place (idempotente)." % (pvc_name, perr))
    pv_name = (pvc_live.get("spec") or {}).get("volumeName") if pvc_live else None
    if not pv_name:
        return True, ""                                  # PVC/PV réellement absents : rien à rafraîchir
    pv_live, verr = kubectl_json(["get", "pv", pv_name])
    if verr:
        log.append(logentry("Vérification du disque du PV impossible (lecture du PV %s)" % pv_name,
                            ok=False, rc=-1, stderr=verr))
        return False, ("Lecture du PV « %s » impossible (%s) : impossible de vérifier le disque du VG. "
                       "Corrigez l'accès kubectl puis relancez la restauration sur place." % (pv_name, verr))
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
    # Le PV ne porte l'attribut disque que s'il l'avait (politique miroir) : on ne
    # compare le disque que dans ce cas. La cible iSCSI (targetName), elle, peut changer
    # à chaque restore in-place (HYCU recrée le VG avec une cible « hycu-… »).
    disk_changed = bool(old_disk) and bool(new_disk) and _disk_set(new_disk) != _disk_set(old_disk)
    old_iqn = (csi.get("volumeAttributes") or {}).get("iqn")
    tn = _vg_target_name(vg_uuid) if old_iqn else None
    new_iqn = _iqn_for_target(old_iqn, tn) if tn else None
    iqn_changed = bool(new_iqn) and new_iqn != old_iqn
    if not disk_changed and not iqn_changed:
        return True, ""                                  # rien n'a changé -> rien à faire
    what = []
    if disk_changed:
        what.append("hypervisorAttachedDiskUUIDs : %s -> %s" % (old_disk, new_disk))
    if iqn_changed:
        what.append("iqn : %s -> %s" % (old_iqn, new_iqn))
    log.append(logentry("VG modifié par le restore in-place — rafraîchissement du PV %s" % pv_name,
                        stdout=" ; ".join(what)))
    if dry:
        log.append(logentry("Recréer le PV %s avec les attributs à jour (Retain -> delete -> apply)" % pv_name,
                            dry=True, rc=None))
        return True, ""
    new_pv = clean_pv(json.loads(json.dumps(pv_live)))
    va_new = new_pv.setdefault("spec", {}).setdefault("csi", {}).setdefault("volumeAttributes", {})
    if disk_changed:
        va_new["hypervisorAttachedDiskUUIDs"] = new_disk
    if iqn_changed:
        va_new["iqn"] = new_iqn
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
        if not items or fresh == 0:              # fresh==0 -> page qui ne progresse plus
            break
        if total is not None:
            if len(out) >= total:
                break
        elif len(items) < page_size:             # sans total : une page courte = la dernière
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
        try:
            ms_i = int(ms) if ms else 0
        except (ValueError, TypeError):
            ms_i = 0
        out.append({"id": it.get("uuid"), "time": when, "ms": ms_i,
                    "status": it.get("status"),
                    "restorable": it.get("restoreAvailable", True)})
    # L'API ne garantit pas l'ordre : « le plus récent » = points[0] pour tous les
    # appelants (auto-provisionnement, contrat, UI) -> tri explicite, plus récent d'abord.
    out.sort(key=lambda p: p.get("ms") or 0, reverse=True)
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


# ---- Auto-provisionnement (P2) : cloner un VG via HYCU et DÉCOUVRIR son nouvel UUID,
#      pour supprimer la saisie manuelle d'UUID lors des restaurations. -----------------
# Statuts terminaux de job HYCU — UNE seule source de vérité pour toutes les attentes
# (serveur et JS). WARNING = terminé avec avertissements : succès, signalé au journal.
_JOB_OK = {"OK", "SUCCESS", "SUCCEEDED", "COMPLETED", "COMPLETE", "DONE", "FINISHED", "WARNING"}
_JOB_KO = {"ERROR", "FAILED", "FATAL", "ABORTED", "ABORT", "CANCELED", "CANCELLED", "TIMEOUT"}
_JOB_READ_ERRORS_TOLERATED = 5       # hoquets réseau consécutifs tolérés avant abandon


def _discover_vg_uuid_by_name(name):
    """UUID d'un Volume Group à partir de son NOM (après un clone HYCU qui lui a donné
    ce nom). Prism d'abord (source de vérité côté Nutanix), repli HYCU. Une ambiguïté
    (plusieurs VG du même nom) n'est JAMAIS tranchée au hasard. Renvoie (uuid, erreur)."""
    nl = (name or "").strip().lower()
    if not nl:
        return None, "Nom de Volume Group vide."
    try:
        res = action_nutanix_vgs(query=name)
    except Exception as e:
        res = {"ok": False, "error": str(e)}
    if res.get("ok"):
        hits = [v for v in (res.get("vgs") or [])
                if (v.get("name") or "").strip().lower() == nl and v.get("uuid")]
        uniq = list(dict.fromkeys(v["uuid"] for v in hits))
        if len(uniq) == 1:
            return uniq[0], None
        if len(uniq) > 1:
            return None, ("Plusieurs Volume Groups nommés « %s » côté Nutanix : ambiguïté — "
                          "résolution manuelle requise." % name)
    # Repli HYCU (le VG cloné peut y apparaître).
    try:
        items, herr = _hycu_list_vgs()
    except Exception as e:
        items, herr = None, str(e)
    if not herr:
        ext = []
        for v in items or []:
            if isinstance(v, dict) and (v.get("name") or "").strip().lower() == nl:
                m = UUID_RE.search(v.get("externalId") or "")     # jamais l'uuid interne HYCU
                if m:
                    ext.append(m.group(0))
        ext = list(dict.fromkeys(ext))
        if len(ext) == 1:
            return ext[0], None
        if len(ext) > 1:
            return None, "Plusieurs Volume Groups nommés « %s » côté HYCU : ambiguïté." % name
    return None, "Volume Group « %s » introuvable après le clone (Prism/HYCU)." % name


def _resolve_hycu_vg(source_uuid, vg_name=None):
    """Identité HYCU (uuid) d'un Volume Group à partir de son UUID Nutanix (externalId)
    ou de son NOM. Nécessaire pour lister les points de restauration d'un VG même s'il a
    été SUPPRIMÉ du cluster (HYCU conserve le catalogue de sauvegardes sous SA propre
    identité, distincte de l'externalId Nutanix). Renvoie (hycu_uuid, erreur) ; (None,None)
    si simplement introuvable. L'ambiguïté n'est jamais tranchée au hasard."""
    su = (source_uuid or "").strip().lower()
    nm = (vg_name or "").strip().lower()
    try:
        items, herr = _hycu_list_vgs()
    except Exception as e:
        return None, str(e)
    if herr:
        return None, herr
    items = items or []
    if su:                                        # 1) déjà l'uuid HYCU ?
        for v in items:
            if isinstance(v, dict) and (v.get("uuid") or "").lower() == su:
                return v["uuid"], None
        for v in items:                           # 2) par externalId == UUID Nutanix
            if isinstance(v, dict):
                m = UUID_RE.search(v.get("externalId") or "")
                if m and m.group(0).lower() == su and v.get("uuid"):
                    return v["uuid"], None
    if nm:                                        # 3) par nom (nom du VG = nom du PV CSI)
        uniq = list(dict.fromkeys(v["uuid"] for v in items
                    if isinstance(v, dict) and (v.get("name") or "").strip().lower() == nm and v.get("uuid")))
        if len(uniq) == 1:
            return uniq[0], None
        if len(uniq) > 1:
            return None, "Plusieurs Volume Groups HYCU nommés « %s » : ambiguïté." % vg_name
    return None, None


def _vg_exists(uuid):
    """Le Volume Group existe-t-il encore côté Nutanix ? True / False / None.
    SEUL un 404 explicite vaut « absent » (False) : toute autre erreur (500, session
    expirée, timeout) renvoie None = indéterminable, et l'appelant NE déclenche PAS de
    restauration in-place (qui écraserait un VG encore vivant)."""
    sysname = _nutanix_source()
    if not uuid or not sysname:
        return None
    try:
        r = _rest(sysname, "GET", "/volume_groups/%s" % urllib.parse.quote(str(uuid)))
    except Exception:
        return None
    if r.get("ok"):
        return True
    return False if r.get("status") == 404 else None


def _await_hycu_job(job_id, timeout_s=600, poll_s=3):
    """Attend la fin d'un job HYCU. Renvoie (ok, dernier_statut, erreur)."""
    if not job_id:
        return False, None, "Identifiant de job HYCU manquant."
    deadline = time.time() + max(5, int(timeout_s))
    last, read_errors = None, 0
    while time.time() < deadline:
        j = action_hycu_job(job_id)
        if not j.get("ok"):
            # Un hoquet réseau pendant un clone de plusieurs minutes ne doit pas faire
            # échouer le provisionnement (VG orphelin jamais découvert) : on retente.
            read_errors += 1
            if read_errors > _JOB_READ_ERRORS_TOLERATED:
                return False, last, j.get("error") or "Lecture du job HYCU impossible."
            time.sleep(max(1, int(poll_s)))
            continue
        read_errors = 0
        st = (j.get("status") or "").strip().upper()
        last = st or last
        if st in _JOB_OK:
            return True, st, None
        if st in _JOB_KO:
            return False, st, "Job HYCU terminé en échec (%s)." % st
        time.sleep(max(1, int(poll_s)))
    return False, last, "Délai dépassé en attendant le job HYCU %s (dernier statut : %s)." % (job_id, last or "?")


def action_hycu_provision_clone(payload):
    """Auto-provisionnement : pour chaque volume, clone le Volume Group source via HYCU
    (nom imposé, unique et horodaté), attend le job, puis DÉCOUVRE l'UUID du nouveau VG
    (Prism, repli HYCU). But : remplir automatiquement les `items` d'une restauration
    SANS aucune saisie d'UUID par l'humain.

    payload : { volumes:[{pvc, source_vg_uuid, restore_point_id?}], dry, job_timeout_s? }.
      - dry=True (défaut) : n'appelle PAS HYCU (aucun VG créé) ; renvoie le PLAN.
      - restore_point_id absent : le point de restauration le PLUS RÉCENT est choisi.
    Renvoie { ok, dry, items:[{pvc, new_ref}], log:[...], error }.
    Repli : en cas d'échec/ambiguïté/HYCU indisponible, `ok=False` + message clair —
    l'appelant garde la saisie manuelle."""
    dry = bool(payload.get("dry", True))
    vols = payload.get("volumes") or []
    if not vols:
        return {"ok": False, "error": "Aucun volume à provisionner.", "items": [], "log": []}
    if not dry and not SESSION_CREDS.get("hycu"):
        return {"ok": False, "error": "Connectez HYCU pour créer les volumes automatiquement "
                "(sinon, saisissez les UUID manuellement).", "items": [], "log": []}
    if not dry and not (SESSION_CREDS.get("prismcentral") or SESSION_CREDS.get("nutanix")):
        return {"ok": False, "error": "Connectez Prism (Element ou Central) : la découverte de "
                "l'UUID du VG cloné s'y fait.", "items": [], "log": []}
    ts = time.strftime("%Y%m%d-%H%M%S")
    timeout_s = int(payload.get("job_timeout_s") or 600)
    items, log = [], []
    for i, v in enumerate(vols):
        pvc = v.get("pvc")
        src = (v.get("source_vg_uuid") or "").strip()
        if not pvc or not src or not UUID_RE.search(src):
            return {"ok": False, "error": "Volume « %s » : UUID du VG source manquant/invalide "
                    "(re-lancez l'analyse HYCU)." % (pvc or "?"), "items": [], "log": log}
        # Nom imposé, UNIQUE : garantit une découverte non ambiguë par le nom.
        # Unicité (horodatage + index) EN TÊTE : seule la partie « pvc » peut être tronquée,
        # sinon deux volumes aux noms longs recevraient le même nom (clone réel + ambiguïté).
        new_name = re.sub(r"[^a-zA-Z0-9-]", "-", "hycurestore-%s-%d-%s" % (ts, i, pvc))[:60].strip("-")
        # Identité HYCU du VG source : les points de restauration se listent avec l'uuid
        # HYCU, distinct de l'externalId Nutanix. Résolu depuis l'UUID Nutanix ou le nom
        # (le VG peut avoir été SUPPRIMÉ du cluster ; HYCU garde son catalogue).
        hy_src = src
        rp = (v.get("restore_point_id") or "").strip()
        if not rp:
            good = [p for p in (action_hycu_restore_points(hy_src).get("points") or [])
                    if p.get("restorable", True)]
            if not good:
                resolved, rerr = _resolve_hycu_vg(src, v.get("vg_name"))
                if rerr:
                    return {"ok": False, "error": "Volume « %s » : %s" % (pvc, rerr), "items": [], "log": log}
                if resolved and resolved.lower() != hy_src.lower():
                    hy_src = resolved
                    log.append(logentry("Identité HYCU du VG résolue pour %s" % pvc,
                                        stdout="%s -> %s" % (src, hy_src)))
                    good = [p for p in (action_hycu_restore_points(hy_src).get("points") or [])
                            if p.get("restorable", True)]
            if not good:
                return {"ok": False, "error": "Volume « %s » : aucun point de restauration HYCU "
                        "trouvé pour ce Volume Group. Vérifiez que l'application est (ou était) "
                        "protégée dans HYCU." % pvc, "items": [], "log": log}
            rp = good[0].get("id")
        else:
            resolved, _ = _resolve_hycu_vg(src, v.get("vg_name"))
            if resolved:
                hy_src = resolved
        if dry:
            resolved_note = (" (identité HYCU résolue depuis %s)" % src) if hy_src != src else ""
            detail = "%s : source HYCU %s%s, point de restauration %s, nouveau VG %s" % (
                pvc, hy_src, resolved_note, rp, new_name)
            log.append(logentry("Simulation du clone automatique via HYCU (aucun clone réel lancé).",
                                dry=True, rc=None, stdout=detail))
            items.append({"pvc": pvc, "new_ref": None, "planned_name": new_name,
                          "hycu_source": hy_src, "restore_point_id": rp})
            continue
        # Réel : déclencher le clone HYCU (nom imposé), attendre, découvrir l'UUID.
        rr = action_hycu_restore({"restore_point_id": rp, "mode": "clone", "new_name": new_name,
                                  "source_uuid": hy_src, "dry": False})
        if not rr.get("ok"):
            return {"ok": False, "error": "Volume « %s » : clone HYCU refusé : %s"
                    % (pvc, rr.get("error")), "items": items, "log": log}
        job_id = rr.get("job_id")
        log.append(logentry("Clone HYCU lancé pour %s (VG source %s, point %s, job %s)"
                            % (pvc, src, rp, job_id), stdout="Nouveau VG demandé : %s" % new_name))
        ok, st, jerr = _await_hycu_job(job_id, timeout_s=timeout_s)
        if not ok:
            return {"ok": False, "error": "Volume « %s » : %s" % (pvc, jerr), "items": items, "log": log}
        new_uuid, derr = _discover_vg_uuid_by_name(new_name)
        if not new_uuid:
            return {"ok": False, "error": "Volume « %s » : clone HYCU terminé mais %s"
                    % (pvc, (derr or "UUID introuvable")), "items": items, "log": log}
        log.append(logentry("UUID du VG cloné découvert automatiquement pour %s" % pvc,
                            stdout="%s -> %s (VG « %s »)" % (src, new_uuid, new_name)))
        items.append({"pvc": pvc, "new_ref": new_uuid, "vg_name": new_name})
    audit("hycu_provision_clone", count=len(items), dry=dry)
    return {"ok": True, "dry": dry, "items": items, "log": log}


def _resolve_source_and_point(pvc, src, vg_name, log):
    """Commun aux deux modes : résout l'identité HYCU du VG (depuis le Source UUID
    Nutanix ou le nom) et choisit le point de restauration le plus récent.
    Renvoie (hycu_uuid, restore_point_id, erreur)."""
    good = [p for p in (action_hycu_restore_points(src).get("points") or []) if p.get("restorable", True)]
    hy_src = src
    if not good:
        resolved, rerr = _resolve_hycu_vg(src, vg_name)
        if rerr:
            return None, None, rerr
        if resolved and resolved.lower() != src.lower():
            hy_src = resolved
            log.append(logentry("Identité HYCU du VG résolue pour %s" % pvc,
                                stdout="%s -> %s" % (src, hy_src)))
            good = [p for p in (action_hycu_restore_points(hy_src).get("points") or []) if p.get("restorable", True)]
    else:
        resolved, _ = _resolve_hycu_vg(src, vg_name)
        if resolved:
            hy_src = resolved
    if not good:
        return None, None, ("aucun point de restauration HYCU trouvé pour ce Volume Group. Vérifiez "
                            "que l'application est (ou était) protégée dans HYCU.")
    return hy_src, good[0].get("id"), None


def action_hycu_provision_restore(payload):
    """Restauration IN-PLACE d'un Volume Group supprimé via HYCU (createVolumeGroup=false) :
    HYCU recrée le VG à SON IDENTITÉ D'ORIGINE (même UUID). Aucune découverte d'UUID —
    on réutilise le Source UUID de la sauvegarde et le PV d'origine tel quel. Le plus
    simple quand HYCU préserve l'UUID.
    payload : { volumes:[{pvc, source_vg_uuid, vg_name?}], dry, job_timeout_s? }.
    Renvoie { ok, dry, log, error }."""
    dry = bool(payload.get("dry", True))
    vols = payload.get("volumes") or []
    if not vols:
        return {"ok": False, "error": "Aucun volume à restaurer.", "log": []}
    if not dry and not SESSION_CREDS.get("hycu"):
        return {"ok": False, "error": "Connectez HYCU pour restaurer les volumes automatiquement "
                "(sinon, saisissez les UUID manuellement).", "log": []}
    timeout_s = int(payload.get("job_timeout_s") or 600)
    log = []
    for v in vols:
        pvc = v.get("pvc")
        src = (v.get("source_vg_uuid") or "").strip()
        if not pvc or not src or not UUID_RE.search(src):
            return {"ok": False, "error": "Volume « %s » : UUID du VG source manquant/invalide "
                    "(re-lancez l'analyse HYCU)." % (pvc or "?"), "log": log}
        hy_src, rp, err = _resolve_source_and_point(pvc, src, v.get("vg_name"), log)
        if err:
            return {"ok": False, "error": "Volume « %s » : %s" % (pvc, err), "log": log}
        if dry:
            log.append(logentry("Simulation : HYCU restaurera le Volume Group sur place (identité "
                                "conservée) — aucune restauration réelle lancée.", dry=True, rc=None,
                                stdout="%s : source HYCU %s, point de restauration %s, UUID conservé %s"
                                       % (pvc, hy_src, rp, src)))
            continue
        rr = action_hycu_restore({"restore_point_id": rp, "mode": "inplace", "source_uuid": hy_src, "dry": False})
        if not rr.get("ok"):
            return {"ok": False, "error": "Volume « %s » : restauration HYCU refusée : %s"
                    % (pvc, rr.get("error")), "log": log}
        job_id = rr.get("job_id")
        log.append(logentry("Restauration HYCU (sur place) lancée pour %s (VG %s, point %s, job %s)"
                            % (pvc, hy_src, rp, job_id), stdout="Le VG est recréé à son UUID d'origine : %s" % src))
        ok, st, jerr = _await_hycu_job(job_id, timeout_s=timeout_s)
        if not ok:
            return {"ok": False, "error": "Volume « %s » : %s" % (pvc, jerr), "log": log}
        log.append(logentry("Volume Group restauré à son identité d'origine pour %s" % pvc,
                            stdout="UUID conservé : %s" % src))
    audit("hycu_provision_restore", count=len(vols), dry=dry)
    return {"ok": True, "dry": dry, "log": log}


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
    # Seule une correspondance de CONFIANCE (UUID exact) autorise une opération HYCU :
    # un match « par nom » n'est qu'une suggestion (cf. action_hycu_match) et ne doit
    # jamais suffire à restaurer/protéger un volume.
    allowed = {m["hycu_vg_uuid"] for m in match.get("matches", [])
               if m.get("matched") and m.get("trusted") and m.get("hycu_vg_uuid")}
    bad = [u for u in uuids if u and u not in allowed]
    if bad:
        return ("Volume Group(s) hors de la correspondance actuelle du namespace « %s » : %s. "
                "Relancez l'analyse." % (ns, ", ".join(bad)))
    return None


def _vg_pe_uuid(vg_uuid):
    """Best-effort : UUID du Prism Element hébergeant le VG (multi-PE), lu dans l'objet
    v4 du VG. Renvoie None si Prism non connecté ou champ absent (tolérant au schéma)."""
    if not SESSION_CREDS.get("prismcentral"):
        return None
    try:
        r = _rest_raw("prismcentral", "GET",
                      "/api/volumes/v4.0.b1/config/volume-groups/%s" % urllib.parse.quote(str(vg_uuid)))
    except Exception:
        return None
    data = (r.get("json") or {}).get("data") if r.get("ok") else None
    if not isinstance(data, dict):
        return None
    # Le champ exact varie selon les versions : on cherche une référence de cluster.
    for k in ("clusterReference", "clusterExtId", "cluster_uuid", "clusterUuid"):
        v = data.get(k)
        if isinstance(v, str) and UUID_RE.search(v):
            return UUID_RE.search(v).group(0)
        if isinstance(v, dict):
            for kk in ("extId", "uuid"):
                if isinstance(v.get(kk), str) and UUID_RE.search(v[kk]):
                    return UUID_RE.search(v[kk]).group(0)
    return None


def _collect_restore_contract(ns, volumes):
    """« Contrat de restauration » (P1) : enrichit best-effort chaque volume avec ce qui
    permettra une RESTAURATION SANS SAISIE (nom/UUID du VG côté HYCU, disque(s), Prism
    Element, dernier point de restauration HYCU). N'échoue JAMAIS la sauvegarde : toute
    erreur est avalée. Renvoie un bloc `systems` (endpoints utilisés) à joindre à l'index.
    - `volumes` : la liste index["volumes"] (mutée en place, ajout de `restore_contract`).
    Requiert HYCU et/ou Prism connectés ; sinon ne fait (presque) rien."""
    systems = {}
    hy_on = bool(SESSION_CREDS.get("hycu"))
    pc_on = bool(SESSION_CREDS.get("prismcentral"))
    ne_on = bool(SESSION_CREDS.get("nutanix"))
    if hy_on:
        b, a, _ = _system_cfg("hycu")
        systems["hycu"] = {"url": b, "api_base": a}
    if pc_on or ne_on:
        src = "prismcentral" if pc_on else "nutanix"
        b, a, _ = _system_cfg(src)
        systems["nutanix"] = {"kind": src, "url": b}
    if not (hy_on or pc_on or ne_on):
        return systems                                   # rien de connecté : contrat non collecté

    # Index HYCU par externalId (= UUID du VG) — une seule liste pour tout le namespace.
    by_ext = {}
    if hy_on:
        try:
            items, herr = _hycu_list_vgs()
            if not herr:
                for vg in items or []:
                    m = UUID_RE.search((vg.get("externalId") or "")) if isinstance(vg, dict) else None
                    if m:
                        by_ext[m.group(0).lower()] = vg
        except Exception:
            by_ext = {}

    for v in volumes:
        try:
            vh = ((v.get("analysis") or {}).get("old_volume_handle")) or ""
            m = UUID_RE.search(vh)
            if not m:
                continue
            vg_uuid = m.group(0)
            contract = {"vg_uuid": vg_uuid}
            vg = by_ext.get(vg_uuid.lower())
            if vg:
                contract["hycu_uuid"] = vg.get("uuid") or vg_uuid
                contract["vg_name"] = vg.get("name") or v.get("pv")
                # Dernier point de restauration HYCU (pour aligner les lignes de temps).
                try:
                    rp = action_hycu_restore_points(contract["hycu_uuid"])
                    pts = [p for p in (rp.get("points") or []) if p.get("restorable", True)]
                    if pts:
                        contract["hycu_latest_backup"] = {"uuid": pts[0].get("id"),
                                                          "at": pts[0].get("time")}
                except Exception:
                    pass
            if pc_on:
                try:
                    disks = _clone_vg_disk_uuids(vg_uuid)
                    if disks:
                        contract["disk_extids"] = [x for x in disks.split(",") if x]
                except Exception:
                    pass
                pe = _vg_pe_uuid(vg_uuid)
                if pe:
                    contract["pe_uuid"] = pe
            v["restore_contract"] = contract
        except Exception:
            continue                                     # un volume ne doit jamais bloquer les autres
    return systems


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
            if status in _JOB_OK:
                log.append({"ok": True, "dry": False, "label": "%s terminé" % label, "rc": 0,
                            "stdout": status, "stderr": ""})
                return True
            if status in _JOB_KO:
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

        current, desired, werr = _resolve_workloads(ns)
        if werr:
            return _err("Inventaire des Deployments/StatefulSets impossible (%s) — séquence annulée." % werr,
                        log=log, aborted=False)
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
    if same_ns and (w.get("kind") or "") == "CronJob":
        meta["name"] = meta.get("name", "") + suffix       # pas de sélecteur : simple renommage
    elif same_ns:
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


def _items_find(bitems, kind, name):
    for o in bitems or []:
        if (o.get("kind") or "") == kind and ((o.get("metadata") or {}).get("name") or "") == name:
            return json.loads(json.dumps(o))
    return None


def _workloads_from_items(bitems, pvc_names):
    """Équivalent de _find_workloads_using_pvcs, mais depuis l'instantané
    resources.json d'une sauvegarde (mode DR : le cluster source n'existe plus)."""
    wanted = set(pvc_names)
    out = []
    for o in bitems or []:
        if (o.get("kind") or "") not in ("Deployment", "StatefulSet"):
            continue
        vols = ((o.get("spec") or {}).get("template", {}).get("spec", {}).get("volumes")) or []
        used = [(v.get("persistentVolumeClaim") or {}).get("claimName") for v in vols]
        if any(c in wanted for c in used):
            out.append(json.loads(json.dumps(o)))
    return out


def _fetch_from_items(bitems, kind, name, target_ns):
    """Équivalent de _fetch_for_clone depuis l'instantané. Un Secret MASQUÉ à la
    sauvegarde est considéré introuvable (jamais restauré avec __REDACTED__)."""
    kind_cc = {"secret": "Secret", "configmap": "ConfigMap",
               "serviceaccount": "ServiceAccount"}.get(kind, kind)
    o = _items_find(bitems, kind_cc, name)
    if not o:
        return None
    if kind == "secret" and (_obj_is_redacted(o) or o.get("type") == "kubernetes.io/service-account.token"):
        return None
    return _prepare_cloned_object(o, target_ns)


def _services_from_items(bitems, cloned_workloads, target_ns):
    """Équivalent de _services_for_workloads depuis l'instantané."""
    pod_label_sets = []
    for w in cloned_workloads:
        lbls = (((w.get("spec") or {}).get("template") or {}).get("metadata") or {}).get("labels") or {}
        if lbls:
            pod_label_sets.append(lbls)
    out = []
    for svc in bitems or []:
        if (svc.get("kind") or "") != "Service":
            continue
        sel = (svc.get("spec") or {}).get("selector") or {}
        if not sel:
            continue
        if any(all(pl.get(k) == v for k, v in sel.items()) for pl in pod_label_sets):
            out.append(_prepare_cloned_object(json.loads(json.dumps(svc)), target_ns))
    return out


def action_dr_backups():
    """Inventaire de TOUTES les sauvegardes sous backup_root (tous clusters,
    contextes, imports S3, ancienne disposition) pour l'assistant de restauration
    DR. Lecture seule ; le champ `allowed` reflète le réglage allow_dr_restore."""
    root = CONFIG["backup_root"]
    out = []
    # « Restaurable ici » = même règle que _backup_cluster_error (cluster d'origine et,
    # pour le cluster local, même contexte kubectl), évaluée sur le résumé du catalogue
    # — le serveur la re-vérifie sur l'index réel au moment de restaurer.
    cur_cid = _current_cid()
    cur_ctx = (_local_context_name() or "").strip() if cur_cid == LOCAL_CID else ""
    for base in _catalog_bases(root):
        imported = os.path.relpath(base, root).split(os.sep)[0] == "_imports"
        for ns, vs in _catalog_all(base).items():
            for v in vs:
                src = v.get("cluster_id") or LOCAL_CID
                bctx = (v.get("context") or "").strip()
                restorable = (src == cur_cid) and not (src == LOCAL_CID and bctx and cur_ctx and bctx != cur_ctx)
                # vol_refs : UUID du Volume Group d'ORIGINE de chaque volume — l'assistant
                # PRÉ-REMPLIT le champ en récupération (aucune saisie manuelle) ; vol_hycu :
                # identité HYCU (contrat P1) ; vol_names : nom du VG (contrat, sinon PV).
                out.append({"path": _catalog_backup_path(base, ns, v), "restorable_here": restorable,
                            "namespace": v.get("namespace") or ns,
                            "timestamp": v["ts"], "created": v.get("created") or "",
                            "cluster": v.get("cluster") or v.get("cluster_id") or "local",
                            "cluster_id": v.get("cluster_id") or "local",
                            "context": v.get("context") or "",
                            "volumes": list(v.get("volumes") or []),
                            "vol_refs": dict(v.get("vol_refs") or {}),
                            "vol_hycu": dict(v.get("vol_hycu") or {}),
                            "vol_names": dict(v.get("vol_names") or {}),
                            "resources_count": v.get("resources_count"),
                            "has_resources": bool(v.get("has_resources")),
                            # Sauvegarde STATELESS : aucun volume, mais des workloads à recréer.
                            "stateless": (not (v.get("volumes") or [])
                                          and any((a.get("type") == "stateless") for a in (v.get("apps") or []))),
                            "apps": [a.get("name") for a in (v.get("apps") or []) if a.get("name")],
                            # Secrets : encrypted (phrase du coffre requise) | clear | redacted | None (ancien)
                            "secrets": v.get("secrets"),
                            "imported": imported})
    out.sort(key=lambda b: b.get("created") or "", reverse=True)
    return _ok(backups=out, allowed=bool(CONFIG.get("allow_dr_restore")))


# ------------------------------------------------------------------------------
# RESTAURATION EN MASSE (même cluster) : recréer d'un coup tous les namespaces
# SUPPRIMÉS du cluster actif depuis leur dernière sauvegarde antérieure à un instant
# de référence T. C'est l'orchestration de la récupération existante (action_clone_app
# « depuis la sauvegarde seule » : namespace, PV/PVC, workloads, dépendances, Secrets
# déchiffrés, VG restaurés par HYCU s'ils ont disparu, applications stateless).
#   - plan lisible AVANT tout (namespaces retenus / ignorés, sauvegarde choisie,
#     avertissements) ; les namespaces encore PRÉSENTS sont ignorés : une application
#     vivante se restaure depuis sa propre ligne, jamais en masse à l'insu de l'opérateur ;
#   - journal persistant <dossier du cluster>/_bulk_restore.json : survit à un
#     redémarrage, un namespace déjà recréé n'est jamais refait (reprise idempotente) ;
#   - exécution SÉQUENTIELLE en arrière-plan (un seul verrou d'action, HYCU sollicité
#     proprement), arrêt propre (le namespace en cours se termine), reprise ;
#   - le RÉEL exige une simulation complète et réussie du MÊME plan, puis la
#     confirmation du contexte comme les autres orchestrateurs.
# ------------------------------------------------------------------------------
BULK_FILE = "_bulk_restore.json"
BULK = {"running": False, "stop": False}
BULK_LOCK = threading.Lock()


def _bulk_path():
    return os.path.join(_cluster_root(CONFIG["backup_root"]), BULK_FILE)


def _bulk_load():
    try:
        with open(_bulk_path(), encoding="utf-8") as f:
            j = json.load(f)
        return j if isinstance(j, dict) and isinstance(j.get("items"), list) else None
    except (OSError, ValueError):
        return None


def _bulk_save(j):
    p = _bulk_path()
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p + ".tmp", "w", encoding="utf-8") as f:
            json.dump(j, f)
        os.replace(p + ".tmp", p)
    except OSError as e:
        print("Journal de restauration en masse non écrit : %s" % e)


def _parse_as_of(s):
    """Instant de référence (ISO local, ex. 2026-09-26T08:30) -> (epoch, erreur) ; vide = maintenant."""
    s = (s or "").strip()
    if not s:
        return time.time(), None
    try:
        return datetime.datetime.fromisoformat(s.replace("Z", "")).timestamp(), None
    except ValueError:
        return None, "Instant de référence invalide : « %s » (format AAAA-MM-JJTHH:MM)." % s


def action_bulk_plan(payload):
    """Plan de restauration en masse (lecture seule) : pour chaque namespace du
    cluster/contexte actif ayant une sauvegarde, la dernière version antérieure à
    l'instant de référence (complète de préférence). Retenu si le namespace est ABSENT
    du cluster ; ignoré (avec la raison) sinon. Avertissements par namespace : Secrets
    masqués / chiffrés avec coffre verrouillé, sauvegarde partielle, sans instantané."""
    as_of, err = _parse_as_of(payload.get("as_of"))
    if err:
        return _err(err)
    exclude = {str(x).strip() for x in (payload.get("exclude") or []) if str(x).strip()}
    only = {str(x).strip() for x in (payload.get("namespaces") or []) if str(x).strip()}
    live, lerr = kubectl_json(["get", "ns"])
    if lerr:
        return _err("Liste des namespaces du cluster impossible (%s) : plan refusé par prudence." % lerr)
    present = {(i.get("metadata") or {}).get("name") for i in ((live or {}).get("items") or [])}
    flt = _ns_filter()
    pw_ok = bool(_backup_secret_passphrase())
    allv = {}
    for base, cat in _active_catalogs(with_base=True):
        for ns, vs in cat.items():
            for v in vs:
                allv.setdefault(ns, []).append((base, v))
    items, skipped = [], []
    for ns in sorted(allv):
        if flt and ns not in flt:
            continue
        if only and ns not in only:
            continue
        if ns in exclude:
            skipped.append({"ns": ns, "reason": "exclu par l'opérateur"})
            continue
        vs = [(b, v) for b, v in allv[ns] if (v.get("epoch") or 0) <= as_of]
        if not vs:
            skipped.append({"ns": ns, "reason": "aucune sauvegarde antérieure à l'instant de référence"})
            continue
        full = [(b, v) for b, v in vs if not v.get("partial")]
        base, v = max(full or vs, key=lambda bv: bv[1].get("epoch") or 0)
        if ns in present:
            skipped.append({"ns": ns, "reason": "présent sur le cluster — se restaure depuis sa propre ligne (Applications)"})
            continue
        stateless = bool(not v.get("volumes") and any(a.get("type") == "stateless" for a in (v.get("apps") or [])))
        if not v.get("volumes") and not stateless:
            skipped.append({"ns": ns, "reason": "sauvegarde sans volume ni workload : rien à recréer"})
            continue
        warns = []
        if v.get("partial"):
            warns.append("sauvegarde PARTIELLE (un PV était illisible) : seule version antérieure à l'instant de référence")
        if not v.get("has_resources"):
            warns.append("sans instantané de ressources : volumes seuls, workloads et dépendances à recréer à la main")
        elif v.get("secrets") == "redacted" or (v.get("secrets") is None):
            warns.append("Secrets masqués dans cette sauvegarde : à recréer à la main après la restauration")
        elif v.get("secrets") == "encrypted" and not pw_ok:
            warns.append("Secrets chiffrés et coffre VERROUILLÉ : ils ne seront pas recréés — déverrouillez le coffre avant de lancer")
        items.append({"ns": ns, "backup_path": _catalog_backup_path(base, ns, v), "timestamp": v.get("ts"),
                      "created": v.get("created") or "", "volumes": list(v.get("volumes") or []),
                      "stateless": stateless, "secrets": v.get("secrets"), "partial": bool(v.get("partial")),
                      "apps": [a.get("name") for a in (v.get("apps") or []) if a.get("name")],
                      "warnings": warns})
    return _ok(as_of=as_of, as_of_iso=datetime.datetime.fromtimestamp(as_of).isoformat(timespec="minutes"),
               items=items, skipped=skipped, cluster=_cluster_label(), context=action_context().get("context"),
               vault_unlocked=pw_ok, hycu=bool(SESSION_CREDS.get("hycu")),
               prism=bool(SESSION_CREDS.get("prismcentral") or SESSION_CREDS.get("nutanix")),
               running=BULK["running"])


def _bulk_counts(j):
    c = {"total": len(j.get("items") or []), "done": 0, "failed": 0, "pending": 0, "running": 0, "stopped": 0}
    for it in j.get("items") or []:
        c[it.get("status") or "pending"] = c.get(it.get("status") or "pending", 0) + 1
    return c


def action_bulk_status():
    """Journal courant (plan, états par namespace, journal des étapes borné) + progression."""
    j = _bulk_load()
    if not j:
        return _ok(journal=None, running=BULK["running"], counts=None)
    return _ok(journal=j, running=BULK["running"], counts=_bulk_counts(j))


def action_bulk_stop():
    if not BULK["running"]:
        return _err("Aucune restauration en masse en cours.")
    BULK["stop"] = True
    return _ok(stopping=True)


def _bulk_worker(j, confirm_context, cid):
    """Exécute les namespaces en attente, un par un, en journalisant chaque verdict."""
    try:
        with use_cluster(cid):
            for it in j["items"]:
                if BULK["stop"]:
                    for x in j["items"]:
                        if x.get("status") in ("pending", "running"):
                            x["status"] = "stopped"
                    j["stopped"] = True
                    break
                if it.get("status") == "done":
                    continue                              # reprise : jamais refait
                it.update(status="running", started=datetime.datetime.now().isoformat(timespec="seconds"),
                          error=None)
                _bulk_save(j)
                body = {"namespace": it["ns"], "target_namespace": it["ns"], "backup_path": it["backup_path"],
                        "items": [{"pvc": p, "new_ref": ""} for p in (it.get("volumes") or [])],
                        "dry": bool(j.get("dry", True)), "from_backup_only": True, "clone_refs": True,
                        "confirm_context": confirm_context}
                log = []
                try:
                    r = action_clone_app(body, log=log)
                except Exception as e:                   # un namespace en erreur n'arrête pas les autres
                    r = {"ok": False, "error": "Erreur interne : %s" % e, "log": log}
                it["status"] = "done" if r.get("ok") else "failed"
                it["error"] = r.get("error")
                it["run_warnings"] = [str(w)[:300] for w in (r.get("warnings") or [])][:10]
                it["log"] = [{"ok": bool(l.get("ok")), "dry": bool(l.get("dry")), "label": str(l.get("label") or "")[:200],
                              "stderr": str(l.get("stderr") or "")[:200]} for l in (r.get("log") or log)][-25:]
                it["ended"] = datetime.datetime.now().isoformat(timespec="seconds")
                _bulk_save(j)
                _apps_cache_clear()
            else:
                j["done"] = True
                j["stopped"] = False
            j["ended"] = datetime.datetime.now().isoformat(timespec="seconds")
            _bulk_save(j)
            c = _bulk_counts(j)
            audit("bulk_restore", dry=bool(j.get("dry", True)), ok=(c["failed"] == 0 and not j.get("stopped")),
                  namespaces=c["total"], done=c["done"], failed=c["failed"], stopped=bool(j.get("stopped")),
                  as_of=j.get("as_of"))
    finally:
        BULK["running"] = False
        BULK["stop"] = False


def action_bulk_run(payload):
    """Démarre (ou reprend) une restauration en masse en arrière-plan. Simulation par
    défaut ; le RÉEL exige : garde contexte, ET une simulation terminée sans échec du même
    plan (mêmes namespaces, même instant de référence) — sauf reprise d'un run réel."""
    dry = bool(payload.get("dry", True))
    resume = bool(payload.get("resume"))
    with BULK_LOCK:
        if BULK["running"]:
            return _err("Une restauration en masse est déjà en cours.")
        if not dry:
            guard = _context_guard(payload)
            if guard:
                return guard
        prev = _bulk_load()
        if resume:
            if not prev:
                return _err("Aucun journal à reprendre.")
            todo = [it for it in prev["items"] if it.get("status") != "done"]
            if not todo:
                return _err("Rien à reprendre : tous les namespaces du journal sont déjà recréés.")
            if not dry and prev.get("dry", True):
                return _err("Ce journal est une simulation : lancez le réel depuis le plan, pas par reprise.")
            for it in todo:
                it["status"] = "pending"
            j = prev
            j.update(dry=dry, done=False, stopped=False,
                     resumed=datetime.datetime.now().isoformat(timespec="seconds"))
        else:
            plan = action_bulk_plan(payload)
            if not plan.get("ok"):
                return plan
            if not plan["items"]:
                return _err("Rien à restaurer : aucun namespace supprimé avec une sauvegarde antérieure "
                            "à l'instant de référence.")
            wanted = {it["ns"] for it in plan["items"]}
            if not dry:
                sim_ok = (prev and prev.get("dry") and prev.get("done") and not prev.get("stopped")
                          and _bulk_counts(prev)["failed"] == 0 and prev.get("as_of") == plan["as_of_iso"]
                          and {it["ns"] for it in prev["items"]} == wanted)
                if not sim_ok:
                    return _err("Lancez d'abord une SIMULATION complète et sans échec de ce plan (mêmes "
                                "namespaces, même instant de référence) avant le réel.")
            j = {"id": secrets.token_hex(6), "started": datetime.datetime.now().isoformat(timespec="seconds"),
                 "dry": dry, "as_of": plan["as_of_iso"], "cluster": plan["cluster"], "context": plan["context"],
                 "done": False, "stopped": False, "skipped": plan["skipped"],
                 "items": [dict(it, status="pending", error=None, log=[]) for it in plan["items"]]}
        BULK["running"] = True
        BULK["stop"] = False
        _bulk_save(j)
    audit("bulk_restore_start", dry=dry, resume=resume, namespaces=len(j["items"]), as_of=j.get("as_of"))
    t = threading.Thread(target=_bulk_worker, args=(j, payload.get("confirm_context"), _current_cid()), daemon=True)
    t.start()
    return _ok(id=j["id"], dry=dry, namespaces=len(j["items"]), resumed=resume)


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
    # Mode DR : dérogation explicite + autorisée par la configuration. Le clone lit
    # alors TOUT depuis la sauvegarde (le cluster source n'existe plus), et cible le
    # cluster ACTIF ; le namespace source (d'un cluster disparu) n'est pas soumis au
    # filtre, et un namespace cible du même nom n'est PAS un clone « même namespace ».
    dr, derr2 = _dr_allowed(payload)
    if derr2:
        return {"ok": False, "error": derr2, "log": []}
    target_ns = (payload.get("target_namespace") or "").strip() or ns
    suffix = (payload.get("suffix") or "").strip()
    same_ns = (target_ns == ns) and not dr and not payload.get("from_backup_only")
    backup_path = payload.get("backup_path")
    backup_root = payload.get("backup_root")
    items = payload.get("items") or []
    # « Depuis la sauvegarde seule » : demandé explicitement (récupération d'un
    # namespace SUPPRIMÉ sur ce même cluster) ou imposé par le mode DR. Hors DR, le
    # garde inter-cluster/contexte reste appliqué tel quel ; le filtre par noms
    # aussi (le sélecteur d'étiquettes est invérifiable sur un namespace disparu).
    from_backup = bool(payload.get("from_backup_only")) or dr
    # Récupération d'une application SUPPRIMÉE sur CE cluster (pas de reprise d'activité) :
    # l'app d'origine n'existe plus, on peut donc réutiliser son Volume Group d'ORIGINE
    # (aucun risque de multi-attach) et l'UUID est déjà dans la sauvegarde -> saisie nulle.
    recover = bool(payload.get("from_backup_only")) and not dr
    if recover:
        # La garde `same_uuid` n'est levée que parce que l'app d'origine n'existe plus :
        # on le VÉRIFIE (une lecture, celle du namespace) — un namespace encore présent
        # doit passer par le clone ordinaire (nouveau VG), jamais par ce raccourci.
        st_ns, st_err = resource_state("namespace", ns)
        if st_ns == "present":
            return {"ok": False, "log": [], "error":
                    "Le namespace « %s » existe encore sur le cluster : la récupération est réservée "
                    "à une application SUPPRIMÉE. Pour une copie, utilisez « Restaurer toute "
                    "l'application (copie) »." % ns}
        if st_ns != "absent":
            return {"ok": False, "log": [], "error":
                    "Impossible de vérifier l'existence du namespace « %s » (%s) : récupération refusée "
                    "par prudence." % (ns, st_err or "kubectl")}
    if from_backup and not backup_path:
        return {"ok": False, "error": "Restauration DR : choisissez une sauvegarde source.", "log": []}
    if not from_backup and not _namespace_allowed(ns):
        return {"ok": False, "error": "Namespace '%s' non autorisé." % ns, "log": []}
    if from_backup and not dr and _ns_filter() and ns not in _ns_filter():
        return {"ok": False, "error": "Namespace '%s' non autorisé." % ns, "log": []}
    # NB : le namespace CIBLE d'un clone est une destination de COPIE (créée par l'outil),
    # pas une source : on ne le restreint donc PAS au namespace_filter (qui borne les
    # sources). On valide seulement son nom (RFC 1123) ; il est créé s'il n'existe pas.
    if same_ns and not suffix:
        return {"ok": False, "error": "Un suffixe est requis pour cloner dans le même namespace.", "log": []}
    if not K8S_NAME_RE.match(target_ns):
        return {"ok": False, "error": "Nom de namespace cible invalide : '%s'." % target_ns, "log": []}
    # Sans volume : clone d'une application STATELESS (`app` : workloads live du
    # namespace, aucun PVC), ou récupération/DR d'une sauvegarde STATELESS (namespace
    # sans PVC, workloads dans l'instantané) — vérifié plus bas, une fois l'instantané lu.
    app = (payload.get("app") or "").strip()
    if not items and not from_backup and not app:
        return {"ok": False, "error": "Aucun volume sélectionné.", "log": []}
    xerr = _backup_cluster_error(backup_path, backup_root, allow_dr=dr) if (items or from_backup) else None
    if xerr:
        return {"ok": False, "error": xerr, "log": []}
    bitems = None
    stateless = False
    live_stateless = []               # workloads live de l'application stateless clonée
    if from_backup:
        # resources.json ABSENT ne bloque PAS : on restaure les volumes (PV/PVC) et on
        # avertit que workloads/dépendances ne seront pas recréés (sauvegarde ancienne).
        bitems, berr = _load_backup_resources(backup_path, backup_root, allow_dr=dr, missing_ok=True)
        if berr:
            return {"ok": False, "error": "Restauration DR : %s" % berr, "log": []}
        if not items:
            stateless = any((o.get("kind") or "") in APP_WORKLOAD_KINDS for o in (bitems or []))
            if not stateless:
                return {"ok": False, "log": [], "error":
                        "Aucun volume sélectionné et aucun workload dans l'instantané de cette "
                        "sauvegarde : rien à recréer."}
    elif not items:
        # Clone STATELESS depuis le cluster : les workloads de l'application, qui ne
        # doivent monter aucun PVC (sinon : sélectionner ses volumes, clone stateful).
        wl_map, pvc_map, werr = _list_namespace_workloads([ns], full=True)   # manifestes COMPLETS : ils sont copiés
        if werr and not wl_map.get(ns):
            return {"ok": False, "error": "Lecture des workloads de « %s » impossible : %s" % (ns, werr), "log": []}
        for w in wl_map.get(ns) or []:
            owners = {o.get("kind") for o in ((w.get("metadata") or {}).get("ownerReferences") or [])}
            if (w.get("kind") or "") in APP_WORKLOAD_KINDS and _app_key_of(w) == app \
                    and not (owners & (set(APP_WORKLOAD_KINDS) | {"Job", "ReplicaSet"})):
                live_stateless.append(json.loads(json.dumps(w)))
        if not live_stateless:
            return {"ok": False, "log": [], "error":
                    "Application « %s » introuvable dans le namespace « %s » (aucun workload)." % (app, ns)}
        mounted = sorted({c for w in live_stateless for c in _workload_pvcs(w, pvc_map.get(ns) or [])})
        if mounted:
            return {"ok": False, "log": [], "error":
                    "L'application « %s » monte le(s) volume(s) %s : ce n'est pas une application stateless — "
                    "sélectionnez ses volumes pour la cloner." % (app, ", ".join(mounted))}
        stateless = True
    # Remap optionnel de la StorageClass (site DR : classes souvent différentes).
    dr_sc = (payload.get("dr_storageclass") or "").strip()
    if dr_sc and not K8S_NAME_RE.match(dr_sc):
        return {"ok": False, "error": "Nom de StorageClass cible invalide : « %s »." % dr_sc, "log": []}
    # Garde contexte (mode réel) : appliquer des manifestes (PV/PVC/workloads/Secrets)
    # sur le cluster courant exige un contexte autorisé/reconfirmé, comme la restauration.
    if not dry:
        guard = _context_guard(payload)
        if guard:
            return guard

    prepared, pvc_rename = [], {}
    warnings = []
    deferred_provision = []           # effets HYCU RÉELS : après verrou + pré-vol seulement
    for it in items:
        pvc_name = it.get("pvc")
        new_ref = (it.get("new_ref") or it.get("new_iqn") or "").strip()
        old_pv, _ = _load_old_pv(ns, pvc_name, backup_path, backup_root, no_live=from_backup)
        if old_pv is None:
            return {"ok": False, "error": "Manifeste du PV introuvable pour « %s »%s." % (
                pvc_name, " dans la sauvegarde (aucune lecture du cluster en mode « depuis la sauvegarde seule »)"
                if from_backup else ""), "log": []}
        # Récupération : si l'humain n'a rien saisi, on réutilise le VG d'ORIGINE dont
        # l'UUID (Source UUID Nutanix) est dans la sauvegarde. MAIS si ce VG n'existe plus
        # sur le cluster (reclaimPolicy=Delete) et qu'il est « Protected deleted » dans
        # HYCU, on le RESTAURE automatiquement via HYCU et on découvre le nouvel UUID —
        # en un seul clic. (Prism sert à savoir si le VG existe encore.)
        if recover and not new_ref:
            vh = (analyse_pv(old_pv) or {}).get("old_volume_handle") or ""
            m = UUID_RE.search(vh)
            orig = m.group(0) if m else None
            if orig:
                new_ref = orig                       # défaut : réutiliser le VG d'origine
                if (CONFIG.get("recover_restore_deleted_vg", True) and SESSION_CREDS.get("hycu")
                        and _vg_exists(orig) is False):
                    # VG supprimé du cluster mais protégé dans HYCU -> restauration auto.
                    orig_pv_name = (old_pv.get("metadata") or {}).get("name") or ""
                    vol = {"pvc": pvc_name, "source_vg_uuid": orig, "vg_name": orig_pv_name}
                    mode = CONFIG.get("recover_deleted_vg_mode", "restore")
                    log.append(logentry("Volume d'origine de %s introuvable sur le cluster — "
                                        "restauration automatique depuis HYCU (« Protected deleted »)."
                                        % pvc_name, dry=dry, rc=None))
                    prov_fn = action_hycu_provision_clone if mode == "clone" else action_hycu_provision_restore
                    if dry:
                        # Simulation : lectures HYCU seulement (plan, points de restauration).
                        prov = prov_fn({"volumes": [vol], "dry": True})
                        for l in prov.get("log", []):
                            log.append(l)
                        if not prov.get("ok"):
                            return {"ok": False, "error": "« %s » : le volume d'origine n'existe plus et "
                                    "sa restauration automatique via HYCU a échoué : %s"
                                    % (pvc_name, prov.get("error")), "log": log}
                        if mode == "clone":
                            warnings.append("« %s » : HYCU créera un NOUVEAU Volume Group (nouvel UUID "
                                            "découvert à l'exécution réelle) — l'aperçu montre encore "
                                            "l'UUID d'origine." % pvc_name)
                    else:
                        # Réel : DIFFÉRÉ après le verrou d'action et le pré-vol de collision —
                        # aucun clone/restore HYCU ne doit partir si le run va être refusé.
                        deferred_provision.append({"pvc": pvc_name, "vol": vol, "mode": mode,
                                                   "orig": orig, "old_vh": vh})
                    # mode "restore" : new_ref reste = orig (UUID d'origine conservé) ; mode
                    # "clone" : le PV préparé est re-pointé après découverte (réel).
        if not new_ref or not UUID_RE.search(new_ref):
            return {"ok": False, "error": "Référence du VG cloné manquante/invalide pour « %s » "
                    "(UUID du VG, volumeHandle, ou IQN)." % pvc_name, "log": []}
        built, err = build_new_pv(old_pv, new_ref, (it.get("new_name") or "").strip(), "clone")
        if err:
            return {"ok": False, "error": "%s : %s" % (pvc_name, err), "log": []}
        # Garde anti-confusion (comme la prévisualisation du restore) : refuser si la réf
        # est l'UUID du VG SOURCE (le clone pointerait vers le MÊME disque que l'app
        # d'origine -> multi-attach/corruption) ou le NOM du VG au lieu de son UUID.
        # EXCEPTION en récupération : l'app d'origine n'existe plus, réutiliser son VG
        # d'origine est justement le but (rebranchement à l'identique, pas un clone).
        if built.get("same_uuid") and not recover:
            return {"ok": False, "error": "« %s » : la référence est identique au volume SOURCE — le clone "
                    "pointerait vers le même disque Nutanix que l'application d'origine (risque de "
                    "multi-attach/corruption). Collez l'UUID du VG CLONÉ." % pvc_name, "log": []}
        if built.get("looks_like_vg_name"):
            return {"ok": False, "error": "« %s » : la référence correspond au NOM du Volume Group "
                    "(« pvc-<uuid-du-PVC> ») et non à son UUID. Collez l'UUID du VG cloné." % pvc_name, "log": []}
        src_pvc = _load_backup_pvc(backup_path, pvc_name, backup_root)
        if src_pvc is None and not from_backup:          # depuis-la-sauvegarde : jamais de live
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
        if dr_sc:                                        # remap DR de la StorageClass
            pv.setdefault("spec", {})["storageClassName"] = dr_sc
            pvc_manifest.setdefault("spec", {})["storageClassName"] = dr_sc
        pvc_rename[pvc_name] = new_pvc_name
        prepared.append({"pvc": pvc_name, "pv": pv, "pvc_manifest": pvc_manifest,
                         "new_pv_name": clone_pv_name, "new_pvc_name": new_pvc_name,
                         "orig_pv_name": orig_pv_name,
                         # le PV SOURCE portait-il hypervisorAttachedDiskUUIDs ? (politique miroir)
                         "src_disk_attr": "hypervisorAttachedDiskUUIDs" in (built.get("stripped") or [])})

    if stateless and live_stateless:
        # Clone STATELESS depuis le cluster : copie des workloads de l'application.
        workloads = live_stateless
        warnings.append("Application stateless « %s » : aucun volume — seuls ses workloads (%s) et leurs "
                        "dépendances sont copiés." % (app, ", ".join("%s/%s" % (w["kind"], w["metadata"]["name"])
                                                                        for w in workloads)))
    elif stateless:
        # Récupération STATELESS : les workloads de l'instantané qui ne montent aucun PVC
        # (le namespace n'en avait pas) — ceux de l'application `app` si elle est précisée.
        workloads = [json.loads(json.dumps(o)) for o in (bitems or [])
                     if (o.get("kind") or "") in APP_WORKLOAD_KINDS and not _workload_pvcs(o, [])
                     and (not app or _app_key_of(o) == app)
                     and not ({x.get("kind") for x in ((o.get("metadata") or {}).get("ownerReferences") or [])}
                              & (set(APP_WORKLOAD_KINDS) | {"Job", "ReplicaSet"}))]
        if not workloads:
            return {"ok": False, "log": [], "error":
                    "Aucun workload sans volume%s dans l'instantané de cette sauvegarde : rien à recréer."
                    % ((" pour l'application « %s »" % app) if app else "")}
        warnings.append("Sauvegarde sans volume (application stateless) : seuls les workloads et "
                        "leurs dépendances sont recréés depuis l'instantané.")
    else:
        workloads = (_workloads_from_items(bitems, [it["pvc"] for it in items]) if from_backup
                     else _find_workloads_using_pvcs(ns, [it["pvc"] for it in items]))
    if from_backup and not dr:
        warnings.append("Récupération « depuis la sauvegarde seule » : workloads et dépendances "
                        "proviennent de la sauvegarde « %s » (le namespace n'existe plus sur le "
                        "cluster)." % os.path.basename(backup_path or ""))
        if dr_sc:
            warnings.append("StorageClass remappée vers « %s » sur les PV/PVC recréés." % dr_sc)
        if bitems is None or not bitems:
            warnings.append("Cette sauvegarde ne contient pas d'instantané de ressources : seuls les "
                            "volumes (PV/PVC) sont restaurés. Recréez les workloads et dépendances "
                            "depuis une sauvegarde plus récente, ou manuellement.")
    if dr:
        warnings.append("MODE DR : toutes les sources (workloads, dépendances) proviennent de la "
                        "sauvegarde « %s » — aucune lecture du cluster d'origine." % os.path.basename(backup_path or ""))
        if dr_sc:
            warnings.append("StorageClass remappée vers « %s » sur les PV/PVC recréés." % dr_sc)
        if bitems is None or not bitems:
            warnings.append("Instantané resources.json vide ou absent : seuls PV et PVC seront recréés.")
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
        fetch = (lambda k, n, s_, t_: _fetch_from_items(bitems, k, n, t_)) if from_backup else _fetch_for_clone
        for sa in sorted(want_sas):
            o = fetch("serviceaccount", sa, ns, target_ns)
            (dep_manifests.append(o) or dep_summary.append("ServiceAccount " + sa)) if o else dep_missing.append("ServiceAccount " + sa)
        for cm in sorted(want_cms):
            o = fetch("configmap", cm, ns, target_ns)
            (dep_manifests.append(o) or dep_summary.append("ConfigMap " + cm)) if o else dep_missing.append("ConfigMap " + cm)
        for sec in sorted(want_secrets):
            o = fetch("secret", sec, ns, target_ns)
            (dep_manifests.append(o) or dep_summary.append("Secret " + sec)) if o else dep_missing.append("Secret " + sec)
        for s in (_services_from_items(bitems, cloned_workloads, target_ns) if from_backup
                  else _services_for_workloads(ns, cloned_workloads, target_ns)):
            dep_manifests.append(s)
            dep_summary.append("Service " + s["metadata"]["name"])
        if dep_summary:
            warnings.append("Dépendances clonées automatiquement vers « %s » : %s." % (target_ns, ", ".join(dep_summary)))
        if dep_missing:
            warnings.append(("Référencé(s) par l'app mais absent(s) de la SAUVEGARDE (ou Secret masqué) — "
                             "à recréer à la main dans « %s » : %s." % (target_ns, ", ".join(dep_missing))) if from_backup else
                            ("Référencé(s) par l'app mais INTROUVABLE(S) dans « %s » — à créer à la main : %s."
                             % (ns, ", ".join(dep_missing))))
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
            # Un VG ne doit être pointé que par UN PV : refuser si un PV vivant porte déjà
            # le volumeHandle qu'on s'apprête à créer (DR relancée deux fois, PV « Released »
            # de l'app supprimée encore présent…). Les volumes qui vont être CLONÉS par HYCU
            # (nouvel UUID découvert plus bas) ne sont pas concernés par ce contrôle.
            deferred_clone = {dp["pvc"] for dp in deferred_provision if dp["mode"] == "clone"}
            pvs_live, pverr = kubectl_json(["get", "pv"])
            if pverr:
                return {"ok": False, "error": "Pré-vol impossible (liste des PV : %s) — rien n'a été créé." % pverr,
                        "log": []}
            handles = {}
            for pv in (pvs_live or {}).get("items", []) or []:
                h = ((pv.get("spec") or {}).get("csi") or {}).get("volumeHandle")
                if h:
                    handles.setdefault(h, []).append((pv.get("metadata") or {}).get("name"))
            for p in prepared:
                if p["pvc"] in deferred_clone:
                    continue
                h = ((p["pv"].get("spec") or {}).get("csi") or {}).get("volumeHandle")
                others = [n for n in handles.get(h, []) if n != p["new_pv_name"]]
                if h and others:
                    coll.append("Volume Group %s déjà pointé par le PV %s (volume %s) — supprimez ce PV "
                                "d'abord" % (h, ", ".join(str(x) for x in others), p["pvc"]))
            if coll:
                return {"ok": False, "error": "Objet(s) déjà présent(s) — refus pour ne rien écraser : %s. "
                        "Changez le suffixe ou le namespace cible." % ", ".join(coll), "log": []}
        # Provisionnement HYCU DIFFÉRÉ (réel) : après verrou et pré-vol, jamais avant.
        for dp in deferred_provision:
            prov_fn = action_hycu_provision_clone if dp["mode"] == "clone" else action_hycu_provision_restore
            prov = prov_fn({"volumes": [dp["vol"]], "dry": False})
            for l in prov.get("log", []):
                log.append(l)
            if not prov.get("ok"):
                return {"ok": False, "log": log, "warnings": warnings, "preview": preview,
                        "error": "« %s » : le volume d'origine n'existe plus et sa restauration "
                                 "automatique via HYCU a échoué : %s" % (dp["pvc"], prov.get("error"))}
            if dp["mode"] == "clone" and prov.get("items"):
                disc = (prov["items"][0].get("new_ref") or "").strip()
                new_vh = derive_volume_handle(disc, dp["old_vh"]) if disc else None
                if disc and new_vh:
                    for p in prepared:
                        if p["pvc"] == dp["pvc"]:
                            p["pv"] = _replace_in_leaves(p["pv"], [(dp["orig"], disc)])
                            csi = (p["pv"].get("spec") or {}).get("csi")
                            if isinstance(csi, dict):
                                csi["volumeHandle"] = new_vh
                    log.append(logentry("PV de %s re-pointé sur le VG cloné par HYCU" % dp["pvc"],
                                        stdout="%s -> %s" % (dp["orig"], disc)))
        # Pré-résoudre le disque de CHAQUE VG cloné (renseigne hypervisorAttachedDiskUUIDs)
        # AVANT toute création : si introuvable en réel, on abandonne sans rien créer.
        for p in prepared:
            handle = ((p["pv"].get("spec") or {}).get("csi") or {}).get("volumeHandle")
            _fix_clone_iqn(p["pv"], handle, dry, log)        # cible iSCSI réelle (VG HYCU : « hycu-clone-vg-… »)
            if not _set_clone_disk_uuids(p["pv"], handle, dry, log, source_had=p.get("src_disk_attr", True)) \
                    and not dry and CONFIG.get("clone_require_disk_uuids", True):
                return {"ok": False, "log": log, "warnings": warnings, "preview": preview,
                        "error": (("Prism Central n'est pas connecté : impossible de renseigner le disque "
                                   "du volume « %s » — rien n'a été créé." if not SESSION_CREDS.get("prismcentral")
                                   else "Volume Group du volume « %s » introuvable côté Nutanix (supprimé ?) — "
                                   "connectez HYCU pour qu'il soit restauré automatiquement, ou décochez "
                                   "« réutiliser les volumes d'origine » et utilisez « Créer les volumes "
                                   "automatiquement via HYCU ». Rien n'a été créé.") % p["new_pvc_name"])}
        if not same_ns:
            log.append(_apply_manifest({"apiVersion": "v1", "kind": "Namespace",
                                        "metadata": {"name": target_ns}},
                                       "ns_%s" % target_ns, dry, "Namespace cible « %s »" % target_ns))
            # Namespace créé par l'outil -> l'ajouter à la liste blanche, sinon les
            # onglets Vérifier/Restaurer refuseront ce namespace juste après le clone.
            if not dry and log[-1].get("ok"):
                _allow_namespace(target_ns, log)
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
              items=[it["pvc"] for it in items],
              **({"dr": dr, "from_backup": True, "backup": os.path.basename(backup_path or ""),
                  "storageclass": dr_sc or None} if from_backup else {}))
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
    # Un client qui annonce un Content-Length sans envoyer le corps ne doit pas
    # bloquer un thread indéfiniment (le serveur est multi-thread mais pas infini).
    timeout = 60

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
            # Anti-clickjacking : la page (jeton CSRF dans le DOM, confirmations « réel ») ne
            # doit être encadrable par aucun site tiers.
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
            self.send_header("Referrer-Policy", "no-referrer")
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

    def _lang(self):
        """Langue de l'interface : cookie « hycu_lang » posé par le bouton FR/EN.
        Défaut : français (langue canonique du code)."""
        m = re.search(r"(?:^|;\s*)hycu_lang=(\w+)", self.headers.get("Cookie") or "")
        return "en" if (m and m.group(1) == "en") else "fr"

    def _json(self, obj, code=200):
        if self._lang() == "en":
            obj = _tr_json_en(obj)
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

    def _req_cluster(self, qs=None):
        """Cluster ciblé par la requête : en-tête X-HYCU-Cluster (ou ?cluster= pour les
        liens de téléchargement). Absent = cluster local (compatibilité)."""
        cid = (self.headers.get("X-HYCU-Cluster") or (qs or {}).get("cluster") or "").strip()
        if not cid:
            return LOCAL_CID
        # Le cid sert aussi de nom de dossier (_cluster_root) : n'accepter que le
        # format slug — un cid invalide devient un cluster inconnu (aucune commande,
        # aucun chemin construit avec des séparateurs).
        if not re.fullmatch(r"[a-z0-9._-]{1,63}", cid):
            return "cluster-invalide"
        return cid

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        with use_cluster(self._req_cluster(qs)):
            return self._do_GET()

    def do_POST(self):
        _apps_cache_clear()                      # toute écriture invalide l'inventaire
        with use_cluster(self._req_cluster()):
            return self._do_POST()

    def _do_GET(self):
        if not self._origin_ok():
            return self._send(403, "Forbidden", "text/plain")
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        if path == "/":
            set_cookie = check_ui_session(self.headers.get("Cookie"))
            page = _html_for_lang(self._lang())
            return self._send(200, page.replace("__CSRF_TOKEN__", CSRF_TOKEN)
                              .replace("__VERSION__", VERSION).replace("__LOGO__", _logo_markup()),
                              "text/html", {"Set-Cookie": set_cookie} if set_cookie else None)
        if path == "/help":
            page = help_html()
            return self._send(200, _tr_en(page) if self._lang() == "en" else page, "text/html")
        if path == "/metrics":
            # Format Prometheus, texte brut, local uniquement (garde _origin_ok ci-dessus).
            return self._send(200, action_metrics_text(), "text/plain; version=0.0.4")
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
            if path == "/api/storage":
                return self._json(action_storage())
            if path == "/api/s3/list":
                return self._json(action_s3_list())
            if path == "/api/dr/backups":
                return self._json(action_dr_backups())
            if path == "/api/bulk/status":
                return self._json(action_bulk_status())
            if path == "/api/auto_backup":
                return self._json(action_auto_backup_status())
            if path == "/api/applications":
                fresh = qs.get("fresh") == "1"
                if qs.get("scope") == "all":
                    return self._json(action_applications_all(fresh=fresh))
                return self._json(action_applications_cached(fresh=fresh))
            if path == "/api/clusters":
                return self._json(action_clusters())
            if path == "/api/nkp/discover":
                return self._json(action_nkp_discover())
            if path == "/api/jobs":
                return self._json(action_jobs())
            if path == "/api/report":
                d = action_report_data()
                today = datetime.date.today().isoformat()
                if qs.get("format") == "csv":
                    return self._send(200, report_csv(d), "text/csv",
                                      {"Content-Disposition": 'attachment; filename="rapport_hycu_%s.csv"' % today})
                return self._send(200, report_html(d) if self._lang() != "en" else _tr_en(report_html(d)),
                                  "text/html",
                                  {"Content-Disposition": 'attachment; filename="rapport_hycu_%s.html"' % today})
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

    def _do_POST(self):
        if not self._origin_ok(require_origin=True):
            return self._send(403, "Forbidden", "text/plain")
        if self.headers.get("X-CSRF-Token") != CSRF_TOKEN:
            return self._json({"error": "Jeton anti-CSRF invalide ou absent."}, 403)
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            return self._json({"error": "En-tête Content-Length invalide."}, 400)
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
            if path == "/api/hycu/provision_clone":
                return self._json(action_hycu_provision_clone(payload))
            if path == "/api/creds/save":
                return self._json(action_save_credentials(payload))
            if path == "/api/creds/load":
                return self._json(action_load_credentials(payload))
            if path == "/api/creds/forget":
                return self._json(action_forget_credentials())
            if path == "/api/ns_filter":
                return self._json(action_set_ns_filter(payload))
            if path == "/api/clusters/inspect":
                return self._json(action_clusters_inspect(payload))
            if path == "/api/clusters/add":
                return self._json(action_clusters_add(payload))
            if path == "/api/clusters/remove":
                return self._json(action_clusters_remove(payload))
            if path == "/api/nkp/import":
                return self._json(action_nkp_import(payload))
            if path == "/api/s3/connect":
                return self._json(action_s3_connect(payload))
            if path == "/api/s3/import":
                return self._json(action_s3_import(payload))
            if path == "/api/objects/list":
                return self._json(action_objects_list(payload))
            if path == "/api/objects/diff":
                return self._json(action_objects_diff(payload))
            if path == "/api/objects/restore":
                return self._json(action_objects_restore(payload))
            if path == "/api/hycu/protect":
                return self._json(action_hycu_protect(payload))
            if path == "/api/orchestrate/inplace":
                return self._json(_run_async(action_orchestrate_inplace, payload))
            if path == "/api/clone_app":
                return self._json(_run_async(action_clone_app, payload))
            if path == "/api/bulk/plan":
                return self._json(action_bulk_plan(payload))
            if path == "/api/bulk/run":
                return self._json(action_bulk_run(payload))
            if path == "/api/bulk/stop":
                return self._json(action_bulk_stop())
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
  /* ==========================================================================
     Charte « HYCU Enterprise Cloud » — couleurs PRÉLEVÉES sur l'interface HYCU
     (aucune autre teinte : pas d'accent fluo, pas de dégradé).
       barre du haut #41327C · action/sélection #7530F0 · fond #F3F4F9
       titres #4B5274 · texte #3D4464 / #2A2E44 · gris #A5A8B9 · filets #AFC2D6
       succès #05A274 (anneau clair #9BDAC7) · échec #E9605A · avertissement #CA923E
     ========================================================================== */
  :root{
    --top:#41327C; --purple:#7530F0; --purple-d:#5F22D6; --purple-t:#EFE8FD;
    --bg:#F3F4F9; --card:#FFFFFF; --title:#4B5274; --text:#3D4464; --strong:#2A2E44;
    --muted:#6B7089; --grey:#A5A8B9; --rule:#AFC2D6; --line:#E3E7EE;
    --green:#05A274; --green-l:#9BDAC7; --red:#E9605A; --orange:#CA923E; --blue:#6688FF;
    /* alias historiques (utilisés par du HTML/JS existant) */
    --ink:var(--strong); --paper:var(--bg); --teal:var(--purple); --teal-d:var(--top);
    --accent:var(--purple); --amber:var(--orange); --good:var(--green); --warn:var(--orange);
  }
  *{box-sizing:border-box}
  html,body{height:100%}
  body{margin:0;font-family:Ubuntu,"Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif;
       background:var(--bg);color:var(--text);font-size:14px;line-height:1.45}
  .mono,code,pre,textarea,.tag{font-family:"Ubuntu Mono",Consolas,"SF Mono",Menlo,monospace}
  code{font-size:12.5px}
  a{color:var(--purple)}
  button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible,[tabindex]:focus-visible{
    outline:2px solid var(--purple);outline-offset:2px}

  /* ---------- Barre du haut ---------- */
  .topbar{position:sticky;top:0;z-index:70;height:64px;background:var(--top);color:#fff;
          display:flex;align-items:center;justify-content:space-between;padding:0 22px}
  .tb-brand{display:flex;align-items:center;gap:10px;color:#fff;text-decoration:none}
  .tb-brand .logo{height:30px;width:auto;display:block}
  .tb-word{font-size:27px;font-weight:700;letter-spacing:.5px}
  .tb-word sup{font-size:9px;font-weight:400;margin-left:1px}
  .tb-prod{font-size:13px;color:#fff;opacity:.85;border-left:1px solid rgba(255,255,255,.35);
           padding-left:12px;margin-left:4px}
  .tb-right{display:flex;align-items:center;gap:20px}
  .tb-link{display:flex;align-items:center;gap:8px;color:#fff;font-size:14px;cursor:pointer;
           background:none;border:none;padding:0;font-family:inherit}
  .tb-link u{text-underline-offset:3px}
  .tb-ico{background:none;border:none;color:#fff;cursor:pointer;padding:0;display:flex;align-items:center}
  .tb-ico svg,.tb-link svg{display:block}
  .tb-ico:hover,.tb-link:hover{opacity:.8}
  .tb-lang{background:none;border:1px solid rgba(255,255,255,.55);color:#fff;border-radius:4px;
           padding:2px 9px;font-size:12px;font-weight:700;cursor:pointer;font-family:inherit}
  .hdrconn{display:flex;gap:10px;cursor:pointer}
  .hdrconn .hc{font-size:11px;font-weight:700;color:#fff;letter-spacing:.3px;display:flex;align-items:center}
  .ctx{display:none}
  #ctxWarn .bad{color:#fff;background:var(--red);border-radius:3px;padding:0 6px;font-size:11px;margin-left:6px}

  /* ---------- Coquille : barre latérale + contenu ---------- */
  .shell{display:flex;align-items:flex-start;min-height:calc(100vh - 64px)}
  nav.sidebar{position:sticky;top:64px;flex:none;width:204px;height:calc(100vh - 64px);background:#fff;
              display:flex;flex-direction:column;padding:12px 0 10px;border-right:1px solid var(--line);
              border-radius:0 10px 0 0;margin-top:0}
  nav.sidebar button{display:flex;align-items:center;gap:13px;width:calc(100% - 16px);margin:2px 8px;
              background:none;border:none;border-radius:6px;padding:9px 12px;font-size:14px;color:var(--strong);
              cursor:pointer;text-align:left;font-family:inherit}
  nav.sidebar button svg{flex:none;width:24px;height:24px;color:var(--top)}
  nav.sidebar button:hover{background:var(--purple-t)}
  nav.sidebar button.on{background:var(--purple);color:#fff}
  nav.sidebar button.on svg{color:#fff}
  nav.sidebar .sb-sep{height:1px;background:var(--grey);opacity:.5;margin:10px 22px}
  nav.sidebar .sb-foot{margin-top:auto;text-align:center;color:var(--grey);font-size:12px}
  nav.sidebar .sb-col{background:none;border:none;color:var(--top);cursor:pointer;width:auto;margin:0 auto 6px;
              display:block;padding:4px 10px}
  nav.sidebar .sb-col svg{width:20px;height:20px}
  nav.sidebar .sb-col:hover{background:none;opacity:.7}
  body.sb-min nav.sidebar{width:64px}
  body.sb-min nav.sidebar button .nl{display:none}
  body.sb-min nav.sidebar button{justify-content:center;padding:9px 0}
  body.sb-min nav.sidebar .sb-col svg{transform:rotate(180deg)}
  body.sb-min nav.sidebar .ver{display:none}
  main.wrap{flex:1;min-width:0;padding:18px 26px 40px}

  /* ---------- En-tête de page (titre + actions à droite) ---------- */
  .pagehead{display:flex;align-items:center;justify-content:space-between;gap:16px;margin:2px 0 14px;flex-wrap:wrap}
  .ptitle{margin:0;font-size:27px;font-weight:500;color:var(--title);display:flex;align-items:center;gap:10px}
  .ptitle .crumb{color:var(--title);cursor:pointer;text-decoration:none}
  .ptitle .crumb:hover{text-decoration:underline}
  .ptitle .sep{font-size:22px;color:var(--grey)}
  .pacts{display:flex;gap:22px;align-items:center;flex-wrap:wrap}
  .pact{display:flex;align-items:center;gap:7px;background:none;border:none;padding:4px 0;cursor:pointer;
        font-size:14px;color:var(--text);font-family:inherit}
  .pact svg{width:22px;height:22px;color:var(--top);flex:none}
  .pact:hover:not(:disabled){color:var(--purple)}
  .pact:disabled{color:var(--grey);cursor:not-allowed}
  .pact:disabled svg{color:var(--grey)}
  .refresh{background:none;border:none;cursor:pointer;color:var(--top);padding:0;display:flex}
  .refresh svg{width:22px;height:22px}
  .refresh.busy svg{animation:sp .9s linear infinite}

  /* ---------- Bandeau simulation / mode réel ---------- */
  .dry{display:flex;align-items:center;gap:12px;background:#fff;border:1px solid var(--line);
       border-left:4px solid var(--purple);border-radius:4px;padding:8px 14px;font-size:13px;margin-bottom:16px;
       color:var(--text)}
  .dry b{color:var(--strong)}
  .dry.live{border-left-color:var(--red);background:#FDF0EF}
  .dry.live b{color:var(--red)}
  .realbar{position:fixed;top:0;left:0;right:0;height:4px;background:var(--red);z-index:200;display:none}
  body.realmode .realbar{display:block}

  /* ---------- Cartes, champs, boutons ---------- */
  .card{background:var(--card);border-radius:6px;padding:18px 20px;margin-bottom:16px;
        box-shadow:0 1px 2px rgba(65,50,124,.06)}
  .card h3{margin:0 0 4px;font-size:17px;font-weight:500;color:var(--title);display:flex;align-items:center}
  .card p.sub{margin:0 0 12px;color:var(--muted);font-size:13px}
  .step-no{display:inline-flex;align-items:center;justify-content:center;min-width:24px;height:24px;padding:0 5px;
           border-radius:12px;background:var(--purple-t);color:var(--top);font-size:12px;font-weight:700;
           margin-right:9px;flex:none}
  label.fld{display:block;font-size:13px;color:var(--text);margin:12px 0 5px}
  select,input[type=text],input[type=password],input[type=number],textarea{width:100%;padding:8px 11px;
        border:1px solid var(--rule);border-radius:4px;background:#fff;font-size:14px;color:var(--strong);
        font-family:inherit;min-height:38px}
  select{appearance:none;-webkit-appearance:none;padding-right:34px;cursor:pointer;
        background:#fff url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'><path d='M1 1.5l5 5 5-5' fill='none' stroke='%2341327C' stroke-width='1.8'/></svg>") no-repeat right 12px center}
  select:focus,input:focus,textarea:focus{outline:none;border-color:var(--purple);box-shadow:0 0 0 2px var(--purple-t)}
  input[type=checkbox]{accent-color:var(--purple);width:15px;height:15px;vertical-align:-2px}
  textarea{resize:vertical;min-height:46px;font-size:12.5px}
  .row{display:flex;gap:12px;flex-wrap:wrap}
  .row > div{flex:1;min-width:180px}
  .btn{background:var(--purple);color:#fff;border:1px solid var(--purple);border-radius:4px;padding:8px 20px;
       font-size:14px;cursor:pointer;font-weight:500;font-family:inherit;min-height:38px;
       display:inline-flex;align-items:center;justify-content:center;gap:6px}
  .btn:hover{background:var(--purple-d);border-color:var(--purple-d)}
  .btn:disabled{opacity:.45;cursor:not-allowed}
  .btn.ghost{background:#fff;color:var(--top);border:1px solid var(--top)}
  .btn.ghost:hover{background:var(--purple-t)}
  .btn.danger{background:var(--red);border-color:var(--red)}
  .btn.danger:hover{background:#D64B45;border-color:#D64B45}
  .lnk{background:none;border:none;padding:6px 4px;color:var(--strong);text-decoration:underline;
       text-underline-offset:3px;cursor:pointer;font-size:14px;font-family:inherit}
  .lnk:hover{color:var(--purple)}
  .seg{display:inline-flex;border:1px solid var(--rule);border-radius:4px;overflow:hidden}
  .seg button{background:#fff;border:none;border-right:1px solid var(--rule);padding:8px 16px;font-size:13px;
              cursor:pointer;color:var(--text);font-family:inherit}
  .seg button:last-child{border-right:none}
  .seg button.on{background:var(--top);color:#fff}
  .conn-dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--grey);margin-right:6px;vertical-align:0}
  .conn-dot.on{background:var(--green)}
  .topbar .conn-dot{background:rgba(255,255,255,.45)}
  .topbar .conn-dot.on{background:#fff}
  .switch{position:relative;display:inline-block;width:38px;height:20px;flex:none}
  .switch input{opacity:0;width:0;height:0}
  .slider{position:absolute;inset:0;background:var(--red);border-radius:20px;cursor:pointer;transition:.2s}
  .slider:before{content:"";position:absolute;height:14px;width:14px;left:3px;top:3px;background:#fff;
                 border-radius:50%;transition:.2s}
  input:checked + .slider{background:var(--purple)}
  input:checked + .slider:before{transform:translateX(18px)}
  .switch.onoff .slider{background:#fff;border:1px solid var(--rule)}
  .switch.onoff .slider:before{background:#C9B8F7;top:2px;left:2px}
  .switch.onoff input:checked + .slider{background:var(--purple);border-color:var(--purple)}
  .switch.onoff input:checked + .slider:before{background:#fff}

  /* ---------- Tableaux « entités » (Applications, Tâches, Sources, Politiques) ---------- */
  .tcard{background:#fff;border-radius:6px;box-shadow:0 1px 2px rgba(65,50,124,.06);overflow:hidden}
  .tbar{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:12px 16px;flex-wrap:wrap}
  .tbar input[type=text]{width:230px;min-height:36px}
  .tbar .tinfo{font-size:13px;color:var(--text)}
  table.ht{width:100%;border-collapse:collapse;font-size:14px}
  table.ht th{text-align:left;font-size:11.5px;font-weight:700;letter-spacing:.4px;text-transform:uppercase;
              color:var(--top);padding:10px 12px;border-bottom:1px solid var(--rule);white-space:nowrap;
              border-right:1px solid var(--line)}
  table.ht th:last-child{border-right:none}
  table.ht td{padding:11px 12px;color:var(--text);border-bottom:1px solid #F0F2F6;vertical-align:middle}
  table.ht tr:last-child td{border-bottom:none}
  table.ht tbody tr:hover td{background:#FAF8FF}
  table.ht tbody tr.sel td{background:var(--purple-t)}
  table.ht tbody tr.clk{cursor:pointer}
  table.ht .cb{width:36px;text-align:center}
  table.ht .ctr{text-align:center}
  .tempty{padding:26px;text-align:center;color:var(--muted);font-size:14px}
  /* ---------- Multi-cluster : sélecteur (barre du haut), groupes, Sources ---------- */
  .tb-link .caret{opacity:.8}
  .clmenu{position:fixed;top:58px;z-index:90;background:#fff;border-radius:6px;min-width:290px;max-width:400px;
          box-shadow:0 6px 24px rgba(42,46,68,.18);padding:6px 0;display:none;max-height:70vh;overflow:auto}
  .clmenu .cli{display:flex;align-items:center;gap:10px;padding:9px 14px;cursor:pointer;font-size:14px;color:var(--strong)}
  .clmenu .cli:hover{background:var(--purple-t)}
  .clmenu .cli.on{font-weight:700}
  .clmenu .cli .ws{color:var(--muted);font-size:12px;margin-left:auto;padding-left:12px;white-space:nowrap;font-weight:400}
  .clmenu .chk{width:16px;flex:none;color:var(--purple);display:flex}
  .clmenu .msep{height:1px;background:var(--line);margin:6px 0}
  .clmenu .act{color:var(--top)}
  table.ht .mc{display:none}
  table.ht.multi .mc{display:table-cell}
  table.ht tr.grp td{background:#F6F7FB;color:var(--title);font-size:12.5px;font-weight:700;padding:7px 12px}
  table.ht tbody tr.grp:hover td{background:#F6F7FB}
  table.ht tr.grp .gs{color:var(--grey);margin:0 7px;font-weight:400}
  table.ht tr.grp .ge{color:var(--red);font-weight:400;margin-left:10px}
  table.ht tr.srcsec td{background:#F6F7FB;color:var(--title);font-size:11.5px;font-weight:700;text-transform:uppercase;
               letter-spacing:.4px;padding:7px 12px}
  table.ht tbody tr.srcsec:hover td{background:#F6F7FB}
  .srctools{display:flex;gap:22px;margin:0 0 10px;flex-wrap:wrap}
  .tag{display:inline-block;font-size:11px;font-weight:700;color:var(--top);border:1px solid var(--rule);border-radius:3px;
       padding:0 6px;margin-left:8px;vertical-align:middle}
  textarea.kc{width:100%;min-height:120px;font-family:ui-monospace,Consolas,monospace;font-size:12px;box-sizing:border-box;
       border:1px solid var(--rule);border-radius:4px;padding:8px 10px;color:var(--strong);resize:vertical}
  ul.wl{margin:6px 0 0;padding-left:18px;font-size:13px;color:var(--text)}
  /* Icônes d'état HYCU : pastille pleine, symbole blanc */
  .st,.ic.ok,.ic.ko,.ic.sim{display:inline-flex;width:18px;height:18px;border-radius:50%;flex:none;
      color:transparent !important;font-size:0 !important;vertical-align:middle;
      background-repeat:no-repeat;background-position:center;background-size:18px 18px}
  .st.ok,.ic.ok{background-color:var(--green);background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 18 18'><path d='M5.2 9.3l2.5 2.5 5-5.3' stroke='white' stroke-width='1.9' fill='none' stroke-linecap='round' stroke-linejoin='round'/></svg>")}
  .st.ko,.ic.ko{background-color:var(--red);background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 18 18'><path d='M6 6l6 6M12 6l-6 6' stroke='white' stroke-width='1.9' stroke-linecap='round'/></svg>")}
  .st.wn{background-color:var(--orange);background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 18 18'><path d='M9 4.8v5.2' stroke='white' stroke-width='2' stroke-linecap='round'/><circle cx='9' cy='13' r='1.15' fill='white'/></svg>")}
  .st.na{background-color:#8C91A5;background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 18 18'><path d='M7 7.1a2.1 2.1 0 1 1 3 1.9c-.7.4-1 .8-1 1.6' stroke='white' stroke-width='1.7' fill='none' stroke-linecap='round'/><circle cx='9' cy='13.2' r='1.05' fill='white'/></svg>")}
  .st.sim,.ic.sim{background-color:var(--blue);background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 18 18'><circle cx='9' cy='9' r='3.3' stroke='white' stroke-width='1.7' fill='none'/></svg>")}
  .st.run{background-color:var(--purple);background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 18 18'><path d='M7.3 5.8v6.4l5-3.2z' fill='white'/></svg>")}

  /* ---------- Tableau de bord ---------- */
  .dgrid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:18px}
  .dgrid .span2{grid-column:span 2}
  .span3{grid-column:span 3}
  .span4{grid-column:1/-1}
  .dtitle{margin:0 0 8px;font-size:26px;font-weight:500;color:var(--title);display:flex;align-items:center;gap:8px}
  .dgrid > div{display:flex;flex-direction:column}
  .dcard{flex:1;background:#fff;border-radius:6px;padding:18px;min-height:250px;box-shadow:0 1px 2px rgba(65,50,124,.06)}
  .donut{display:block;margin:4px auto 10px}
  .dnums{display:grid;grid-template-columns:1fr 1fr;text-align:center}
  .dnums > div + div{border-left:1px solid var(--line)}
  .dnums .l{font-size:14px;color:var(--text)}
  .dnums .v{font-size:32px;font-weight:300;color:var(--title)}
  .dnums .v.bad{color:var(--red)}
  .dlist{list-style:none;margin:0;padding:0}
  .dlist li{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:9px 0;
            border-bottom:1px solid #F0F2F6;font-size:14px}
  .dlist li:last-child{border-bottom:none}
  .dlist .k{color:var(--text)} .dlist .v{color:var(--strong);font-weight:500;text-align:right}
  .dbig{font-size:30px;font-weight:300;color:var(--title);margin:6px 0 2px}
  .jcounts{display:grid;grid-template-columns:repeat(4,1fr);text-align:center;margin-top:10px}
  .jcounts .n{font-size:15px;color:var(--strong)} .jcounts .l{font-size:13px;color:var(--text)}
  .jcounts .st{width:20px;height:20px;margin:3px 0}

  /* ---------- Modales HYCU (assistants) ---------- */
  .hmodal-bg,.wiz,.modal-bg{position:fixed;inset:0;background:rgba(42,46,68,.45);display:flex;align-items:center;
       justify-content:center;z-index:1000;padding:18px}
  .hmodal,.wiz-card,.modal{background:#fff;border-radius:4px;width:100%;max-width:620px;max-height:94vh;
       display:flex;flex-direction:column;box-shadow:0 12px 40px rgba(42,46,68,.35)}
  .hm-head,.wiz-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 18px;
       border-bottom:1px solid var(--rule);color:var(--title);background:#fff;border-radius:4px 4px 0 0}
  .hm-head h2{flex:1;min-width:0;line-height:1.25}
  .hm-head h2,.wiz-head h2{margin:0;font-size:22px;font-weight:500;color:var(--title)}
  .hm-head h2 .sep{color:var(--title);margin:0 6px}
  .hm-ico{display:flex;gap:14px;align-items:center}
  .hm-ico button{background:none;border:none;cursor:pointer;color:var(--top);padding:0;font-size:22px;line-height:1;
                 font-family:inherit;font-weight:700}
  .hm-body,.wiz-body{padding:16px 18px;overflow:auto}
  .hm-foot,.wiz-foot{display:flex;align-items:center;justify-content:flex-end;gap:14px;padding:12px 18px;
       border-top:1px solid var(--rule)}
  .wiz-foot{justify-content:space-between}
  .hm-foot .btn,.wiz-foot .btn:not(.ghost){min-width:92px}
  .wiz-foot .btn.ghost,.modal-actions .btn.ghost{background:none;border:none;color:var(--strong);
       text-decoration:underline;text-underline-offset:3px;min-height:0;padding:6px 4px}
  .wiz-brand{display:none}
  .wiz-head{flex-direction:column;align-items:stretch}
  .wiz-bar{height:4px;background:var(--line);border-radius:4px;overflow:hidden;margin-top:10px}
  .wiz-bar span{display:block;height:100%;width:0;background:var(--purple);transition:width .3s}
  .wiz-body h3{margin:0 0 6px;font-size:17px;font-weight:500;color:var(--title)}
  .wiz-body p.q{color:var(--muted);font-size:13px;margin:0 0 14px}
  .wiz-opt{display:block;border:1px solid var(--rule);border-radius:4px;padding:12px 14px;margin:8px 0;cursor:pointer}
  .wiz-opt.sel{border-color:var(--purple);box-shadow:0 0 0 1px var(--purple)}
  .wiz-opt b{font-size:14px;color:var(--strong)} .wiz-opt .d{font-size:13px;color:var(--text);margin-top:2px}
  .wiz-recap{background:var(--strong);color:#E6E8F0;border-radius:4px;padding:14px;font-size:12px;white-space:pre-wrap;
             font-family:"Ubuntu Mono",Consolas,monospace}
  .chip{display:inline-block;border:1px solid var(--rule);border-radius:4px;padding:6px 13px;margin:4px 6px 4px 0;
        font-size:13px;cursor:pointer;background:#fff;color:var(--text)}
  .chip.sel{background:var(--purple);color:#fff;border-color:var(--purple)}
  /* « À propos » : en-tête sombre (logo blanc) */
  .wiz-head.dark{background:var(--top);color:#fff;border-bottom:none}
  .wiz-head.dark h2{color:#fff}
  .wiz-head.dark .wiz-brand{display:block}
  .wiz-head.dark .logo{height:34px;width:auto}
  /* Modale de confirmation (actions destructives) */
  .modal{max-width:540px;padding:0}
  .modal h3{margin:0;padding:14px 18px;border-bottom:1px solid var(--rule);color:var(--red);font-size:20px;font-weight:500}
  .modal #dmBody,.modal .dm-need{padding:0 18px}
  .modal #dmBody{padding-top:12px}
  .modal .dm-line{font-size:14px;margin:6px 0;line-height:1.5}
  .modal .dm-need{margin:10px 0 4px}
  .modal-actions{margin-top:14px;display:flex;gap:14px;justify-content:flex-end;padding:12px 18px;border-top:1px solid var(--rule)}
  /* Cartes d'option (choix du type de restauration) */
  .opt{display:flex;gap:18px;align-items:flex-start;border:1px solid var(--rule);border-radius:4px;padding:16px 18px;
       margin-bottom:12px;cursor:pointer;background:#fff}
  .opt:hover{border-color:var(--top)}
  .opt.sel{border-color:var(--purple);box-shadow:0 0 0 1px var(--purple)}
  .opt svg{flex:none;width:52px;height:52px;color:var(--top)}
  .opt b{display:block;font-size:15px;color:var(--strong);margin-bottom:4px;font-weight:700}
  .opt span{font-size:14px;color:var(--text)}
  .fbox{border:1px solid var(--rule);border-radius:4px;padding:8px 11px;min-height:38px;display:flex;align-items:center;
        gap:8px;background:#fff;color:var(--strong)}
  .fbox .dim{color:var(--muted)}

  /* ---------- Listes, états, journaux (contenus générés par le JS) ---------- */
  .pvc-list{list-style:none;padding:0;margin:0;border:1px solid var(--rule);border-radius:4px;overflow:hidden}
  .pvc-list:empty{display:none}
  .pvc-list li{display:flex;align-items:center;gap:12px;padding:10px 12px;border-bottom:1px solid #F0F2F6;background:#fff}
  .pvc-list li:last-child{border-bottom:none}
  .pvc-list li.sel{background:var(--purple-t)}
  .pvc-list .nm{font-weight:500;font-size:14px;color:var(--strong)}
  .pvc-list .meta{font-size:12px;color:var(--muted)}
  .pvc-list > .hint{padding:10px 12px;margin:0}
  .vol-cfg{border:1px solid var(--rule);border-radius:4px;padding:12px 14px;margin:10px 0;background:#fff}
  .vol-cfg > .nm{font-weight:500;color:var(--strong)}
  .vol-cfg.disabled{opacity:.5}
  .rsAdv{margin-top:10px;border:1px solid var(--line);border-radius:4px;background:#FAFBFD;padding:6px 10px}
  .rsAdvSum{cursor:pointer;font-weight:500;font-size:13px;color:var(--top);user-select:none}
  .rsAdv[open] .rsAdvSum{margin-bottom:8px}
  .rsManualPlain{border:none;background:none;padding:0}
  .rsManualPlain > .rsAdvSum{display:none}
  .rsGuide{margin:0 0 12px;padding:9px 12px;border-left:3px solid var(--purple);background:#F7F5FD;border-radius:0 4px 4px 0;
           font-size:13px;color:var(--text)}
  .badge{font-size:11px;padding:2px 8px;border-radius:10px;font-weight:500}
  .b-bound{background:#E1F4EE;color:var(--green)} .b-lost{background:#FCE9E8;color:var(--red)}
  .b-pending{background:#F8EFE0;color:var(--orange)} .b-na{background:#EEF0F5;color:var(--muted)}
  pre.box{background:var(--strong);color:#E6E8F0;border-radius:4px;padding:12px 14px;font-size:12px;
          overflow:auto;max-height:340px;white-space:pre-wrap;word-break:break-word}
  .drVol{display:flex;align-items:center;gap:12px;margin:7px 0}
  .drVol .drVolNm{flex:none;width:180px;font-weight:600;font-size:13px;color:var(--ink);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .drVol .drRef{flex:1;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
  .repl{font-size:13px;border:1px solid var(--line);border-radius:4px;padding:10px 12px;margin:10px 0;background:#FAFBFD}
  .repl div{margin:4px 0} .repl .k{color:var(--top);font-weight:500}
  .repl .old{color:var(--red);text-decoration:line-through} .repl .new{color:var(--green)}
  ol.plan{margin:6px 0 0;padding-left:20px;font-size:13px}
  ol.plan li{margin:3px 0}
  .logline{display:flex;gap:8px;align-items:flex-start;font-size:13px;padding:7px 0;border-bottom:1px solid #F0F2F6}
  .logline .ic{margin-top:1px}
  .ok{color:var(--green)} .ko{color:var(--red)} .sim{color:var(--orange)}
  .hint{font-size:12.5px;color:var(--muted);margin-top:8px}
  .note{background:#F7F5FD;border-left:3px solid var(--purple);padding:10px 14px;border-radius:0 4px 4px 0;
        font-size:13px;margin-top:12px;color:var(--text)}
  .warnbox{background:#FBF5EB;border-left:3px solid var(--orange);padding:10px 14px;border-radius:0 4px 4px 0;
        font-size:13px;margin-top:10px;color:#6E4E17}
  .err{background:#FDF0EF;border-left:3px solid var(--red);padding:10px 14px;border-radius:0 4px 4px 0;
       font-size:13px;color:#8E2F2A;margin-top:10px}
  .spin{display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,.5);border-top-color:#fff;
        border-radius:50%;animation:sp .7s linear infinite;vertical-align:-2px;margin-right:6px}
  .hint .spin,.note .spin,.tempty .spin,td .spin,.dcard .spin{border-color:var(--purple-t);border-top-color:var(--purple)}
  @keyframes sp{to{transform:rotate(360deg)}}
  .jbar{height:6px;background:var(--line);border-radius:3px;overflow:hidden;margin-top:6px}
  .jbar span{display:block;height:100%;width:0;background:var(--purple);transition:width .4s}
  @keyframes pulseRing{0%{box-shadow:0 0 0 0 rgba(117,48,240,.55)}100%{box-shadow:0 0 0 12px rgba(117,48,240,0)}}
  .pulse{animation:pulseRing 1s ease-out 3}
  /* Anciens éléments de navigation du parcours Restaurer : remplacés par l'assistant */
  .stepper,#rsNextBar{display:none !important}
  .step-no{display:none}
  /* Superposition : filtre / assistant / déverrouillage au-dessus des modales HYCU,
     confirmation destructive au-dessus de tout. */
  .wiz{z-index:1050} .modal-bg{z-index:1100}
  /* Contenus existants hébergés dans les modales HYCU : sans cadre de carte, sans
     titre (le titre est dans l'en-tête de la modale). */
  .hm-body .card{box-shadow:none;padding:0;margin:0 0 14px;border-radius:0}
  .hm-body .card > h3{display:none}
  .hm-body .card > p.sub:first-of-type{margin-top:0}
  /* Assistant de restauration : une seule action principale, dans le pied de modale. */
  #mRestore #hyBatchGo,#mRestore #rsInplaceRun,#mRestore #rsContinueWrap,#mRestore #rsGo,
  #mRestore #rsFlowGuide{display:none !important}
  #mRestore #rsPlan > p.sub,#mRestore .card > p.sub{display:none}
  #rsVolCfgs .vol-cfg > .nm > span:first-of-type{display:none}   /* « (PV …) » : déjà dans la liste */
  #mRestore #rsInplaceRunWrap{border-top:none !important;padding-top:0 !important}
  #rsWizMode.sim{background:var(--purple-t);color:var(--top)} #rsWizMode.live{background:#FCE9E8;color:var(--red)}
  /* Cible du clone : choisie sur la page 2 de l'assistant -> la bascule du formulaire est masquée */
  #mRestore #rsCloneAppWrap > label.fld:first-child,#mRestore #rsCloneNsMode{display:none}
  /* Sources : une fiche de connexion à la fois (choisie dans le tableau) */
  #tab-connect > .card{border:1px solid var(--rule);box-shadow:none;padding:14px 18px 16px;border-radius:4px}
  #tab-connect > .card > h3{display:flex;margin-bottom:8px;font-size:16px}
  #srcBody tr.clk td:first-child{font-weight:500;color:var(--strong)}

  @media(max-width:1100px){.dgrid{grid-template-columns:repeat(2,minmax(0,1fr))}.span2,.span3{grid-column:1/-1}}
  @media(max-width:900px){
    body:not(.sb-open) nav.sidebar{width:64px}
    body:not(.sb-open) nav.sidebar button .nl,body:not(.sb-open) nav.sidebar .ver{display:none}
    body:not(.sb-open) nav.sidebar button{justify-content:center;padding:9px 0}
    .tb-prod,.hdrconn{display:none}
  }
  @media(max-width:600px){main.wrap{padding:14px}.dgrid{grid-template-columns:1fr}.dgrid .span2{grid-column:auto}
    .tb-link u{display:none}}
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

<!-- ===================== À PROPOS ===================== -->
<div id="aboutModal" class="wiz" style="display:none">
  <div class="wiz-card" style="max-width:560px">
    <div class="wiz-head dark">
      <div class="wiz-brand">__LOGO__</div>
      <h2 style="margin-top:10px">Protection Kubernetes sur Nutanix</h2>
      <div style="color:#B8B4FC;font-weight:700;font-size:13px;margin-top:2px">Plugin pour HYCU Enterprise Cloud</div>
      <div style="font-style:italic;margin-top:6px;font-size:12px;color:#fff">Plugin gratuit, fourni « tel quel », sans aucune garantie ni engagement de HYCU.</div>
    </div>
    <div class="wiz-body" style="font-size:13px">
      <div style="display:grid;grid-template-columns:auto 1fr;gap:6px 14px;align-items:baseline">
        <b>Version :</b><code>__VERSION__</code>
        <b>Journal d'audit :</b><code id="aboutAudit" style="word-break:break-all">…</code>
        <b>Configuration :</b><code id="aboutCfg" style="word-break:break-all">…</code>
        <b>Sauvegardes :</b><code id="aboutBk" style="word-break:break-all">…</code>
      </div>
    </div>
    <div class="wiz-foot">
      <span></span>
      <button class="btn" id="aboutClose">Fermer</button>
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

<header class="topbar">
  <a class="tb-brand" id="tbHome" href="#" title="Tableau de bord">__LOGO__<span class="tb-word">HYCU<sup>®</sup></span><span class="tb-prod">Kubernetes · Nutanix</span></a>
  <div class="tb-right">
    <span id="hdrConn" class="hdrconn" title="État des sources — cliquer pour ouvrir les Sources"></span>
    <button class="tb-link" id="ctxLink" type="button" title="Cluster Kubernetes actif — cliquer pour en choisir un autre"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="4" width="16" height="6.5" rx="1.3"/><rect x="4" y="13.5" width="16" height="6.5" rx="1.3"/><path d="M7.6 7.25h.01M7.6 16.75h.01"/></svg><u id="ctx">…</u><span id="ctxWarn"></span><svg class="caret" width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M2.5 4.5l3.5 3.5 3.5-3.5" stroke="currentColor" stroke-width="1.5" fill="none" stroke-linecap="round"/></svg></button>
    <button class="tb-ico" id="srcBtn" type="button" title="Sources & Réglages"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg></button>
    <button class="tb-ico" id="aboutBtn" type="button" title="Aide &amp; À propos"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9.4"/><path d="M9.6 9.4a2.5 2.5 0 0 1 4.9.8c0 1.7-2.5 2.1-2.5 3.8"/><circle cx="12" cy="17.1" r=".7" fill="currentColor" stroke="none"/></svg></button>
    <button id="langBtn" class="tb-lang" type="button" title="Afficher l'interface en anglais">EN</button>
  </div>
</header>
<div id="clMenu" class="clmenu" role="menu"></div>
<div id="helpMenu" class="clmenu" role="menu" style="min-width:210px">
  <a class="cli" href="/help" target="_blank" rel="noopener" role="menuitem" style="text-decoration:none"><span class="chk"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 4.5h6a2.5 2.5 0 0 1 2.5 2.5v12.5a2 2 0 0 0-2-2H5z"/><path d="M19 4.5h-5.5A2.5 2.5 0 0 0 11 7v12.5a2 2 0 0 1 2-2h6z" transform="scale(-1,1) translate(-24,0)" display="none"/><path d="M19 4.5h-6v13h6z" display="none"/></svg></span><span>Aide (guide)</span></a>
  <div class="cli" data-act="about" role="menuitem"><span class="chk"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 11v6"/><circle cx="12" cy="7.6" r=".8" fill="currentColor" stroke="none"/></svg></span><span>À propos</span></div>
</div>
<div id="gearMenu" class="clmenu" role="menu" style="min-width:210px">
  <div class="cli" data-act="sources" role="menuitem"><span class="chk"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/></svg></span><span>Sources</span></div>
  <div class="cli" data-act="settings" role="menuitem"><span class="chk"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 20v-5M5 11V4M12 20v-8M12 8V4M19 20v-3M19 13V4"/><path d="M3 15h4M10 8h4M17 17h4"/></svg></span><span>Réglages</span></div>
</div>

<div class="shell">
<nav class="sidebar" role="tablist" aria-label="Sections de l'outil">
  <button class="on" role="tab" aria-selected="true" data-tab="dashboard"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4.2 17.5a8.6 8.6 0 1 1 15.6 0"/><path d="M12 13.4l4.2-4.2"/><circle cx="12" cy="13.6" r="1.4"/></svg><span class="nl">Tableau de bord</span></button>
  <div class="sb-sep"></div>
  <button role="tab" aria-selected="false" data-tab="apps"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3.5" y="3.5" width="7" height="7" rx="1.2"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.2"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.2"/><circle cx="17" cy="17" r="3.6"/></svg><span class="nl">Applications</span></button>
  <div class="sb-sep"></div>
  <button role="tab" aria-selected="false" data-tab="policies"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l7.5 3v5.4c0 4.6-3.2 8.3-7.5 9.6-4.3-1.3-7.5-5-7.5-9.6V6z"/><path d="M8.6 12.1l2.4 2.4 4.4-4.8"/></svg><span class="nl">Politiques</span></button>
  <div class="sb-sep"></div>
  <button role="tab" aria-selected="false" data-tab="jobs"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4.5" y="3.5" width="15" height="17" rx="1.6"/><path d="M8 8.5h8M8 12h8M8 15.5h5"/></svg><span class="nl">Tâches</span></button>
  <div class="sb-foot"><button class="sb-col" id="sbCol" type="button" title="Réduire / déployer le menu"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 5l-7 7 7 7"/></svg></button><span class="ver">v__VERSION__</span></div>
</nav>
<main class="wrap">
  <div id="kubeBanner"></div>
  <div class="dry" id="dryBar">
    <label class="switch"><input type="checkbox" id="dry" checked><span class="slider"></span></label>
    <div><b id="dryLabel">Mode simulation activé</b> — aucune commande destructive n'est exécutée.
      Désactivez-le seulement quand vous êtes prêt à agir réellement.</div>
  </div>


  <!-- ===================== TABLEAU DE BORD ===================== -->
  <section id="tab-dashboard">
    <div class="dgrid">
      <div><h2 class="dtitle">Applications</h2><div class="dcard" id="dbApps"></div></div>
      <div><h2 class="dtitle">Politique</h2><div class="dcard" id="dbPolicy"></div></div>
      <div><h2 class="dtitle">Sources</h2><div class="dcard" id="dbSources"></div></div>
      <div><h2 class="dtitle">Cluster</h2><div class="dcard" id="dbCluster"></div></div>
      <div><h2 class="dtitle">Stockage</h2><div class="dcard" id="dbStorage"></div></div>
      <div><h2 class="dtitle">Tâches</h2><div class="dcard" id="dbJobs"></div></div>
      <div><h2 class="dtitle">Dernières tâches</h2><div class="dcard" id="dbLast"></div></div>
      <div><h2 class="dtitle">Santé des clusters</h2><div class="dcard" id="dbHealth"></div></div>
    </div>
  </section>
  <!-- ===================== APPLICATIONS ===================== -->
  <section id="tab-apps" style="display:none">
    <div class="pagehead"><h1 class="ptitle">Applications <button class="refresh" id="appsRefresh" type="button" title="Actualiser"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19.4 12.6a7.5 7.5 0 1 1-2.3-5.9"/><path d="M19.6 4.4v4h-4"/></svg></button></h1>
      <div class="pacts">
        <button class="pact" id="actBackup" type="button" disabled><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19.6 12.5a7.6 7.6 0 1 1-2.1-5.8"/><path d="M19.8 4.3v3.9h-3.9"/><path d="M12 8.3v4l2.6 1.9"/></svg><span>Sauvegarder</span></button>
        <button class="pact" id="actRestore" type="button" disabled><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4.4 12.5a7.6 7.6 0 1 0 2.1-5.8"/><path d="M4.2 4.3v3.9h3.9"/><path d="M12 8.3v4l2.6 1.9"/></svg><span>Restaurer</span></button>
        <button class="pact" id="actPolicy" type="button" disabled><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l7.5 3v5.4c0 4.6-3.2 8.3-7.5 9.6-4.3-1.3-7.5-5-7.5-9.6V6z"/><path d="M12 8.8v6.4M8.8 12h6.4"/></svg><span>Définir la politique</span></button>
        <button class="pact" id="actVerify" type="button" disabled><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="8.6"/><path d="M8.3 12.2l2.5 2.5 5-5.3"/></svg><span>Vérifier</span></button>
        <button class="pact" id="actBulk" type="button" title="Recréer tous les namespaces supprimés du cluster actif depuis leurs sauvegardes"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3.5" y="4" width="17" height="5" rx="1.2"/><rect x="3.5" y="11" width="17" height="5" rx="1.2"/><path d="M6 18.5h12M4.4 21a7 7 0 0 0 1.9-5.3"/><path d="M4.2 13.2v3.6h3.6"/></svg><span>Restaurer en masse</span></button>
      </div></div>
    <div class="tcard">
      <div class="tbar"><div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap"><input type="text" id="appsSearch" placeholder="Rechercher" autocomplete="off">
        <div class="seg" id="appsScope" style="display:none"><button class="on" type="button" data-scope="one">Cluster actif</button><button type="button" data-scope="all">Tous les clusters</button></div></div>
        <div style="display:flex;align-items:center;gap:14px"><span class="tinfo" id="appsInfo"></span><span class="tinfo" id="appsPager" style="display:none"></span>
          <button class="pact nsEdit" type="button" title="Filtrer la liste des namespaces"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 5h16l-6.2 7.4V19l-3.6-1.8v-4.8z"/></svg></button></div></div>
      <table class="ht" id="appsTable"><thead><tr><th class="cb"><input type="checkbox" id="appsAll" title="Tout sélectionner"></th>
        <th>Nom</th><th>Namespace</th><th class="mc">Workspace</th><th class="mc">Cluster</th><th>Type</th><th>Politique</th><th class="ctr">Conformité</th><th class="ctr">Protection</th>
        <th>Dernière sauvegarde</th><th class="ctr">Versions</th></tr></thead>
        <tbody id="appsBody"><tr><td colspan="11" class="tempty"><span class="spin"></span></td></tr></tbody></table>
    </div>
  </section>
  <!-- ===================== POLITIQUES ===================== -->
  <section id="tab-policies" style="display:none">
    <div class="pagehead"><h1 class="ptitle">Politiques</h1></div>
    <div class="tcard" style="margin-bottom:16px">
      <table class="ht"><thead><tr><th>Nom</th><th>Objet protégé</th><th>Fréquence</th><th>Rétention</th><th>Cible</th><th class="ctr">État</th></tr></thead>
        <tbody id="polBody"></tbody></table>
    </div>
    <div class="card">
      <h3><span class="step-no">⏱</span>Sauvegarde automatique de la configuration (PV/PVC)</h3>
      <p class="sub">Sauvegarde régulièrement les <b>manifestes PV/PVC</b> (la « recette » du restore) de tous les
        namespaces autorisés par le filtre — tant que l'outil est lancé. <b>Pas les données</b> des volumes :
        elles sont protégées par HYCU (<b>Applications → Définir la politique</b>).</p>
      <div class="row">
        <div style="flex:none"><label class="fld">Sauvegarde automatique</label>
          <div style="display:flex;align-items:center;gap:10px;min-height:38px">
            <label class="switch onoff"><input type="checkbox" id="abEnabled"><span class="slider"></span></label>
            <b id="abEnabledLbl" style="font-size:13px;color:var(--muted)">Désactivée</b>
          </div></div>
        <div style="flex:none;width:140px"><label class="fld">Intervalle (heures)</label>
          <input type="number" id="abInterval" min="1" step="1" value="24"></div>
        <div style="flex:none;width:150px"><label class="fld">Rétention</label>
          <select id="abRet"><option value="count">N versions</option><option value="gfs">GFS (j/sem/mois)</option></select></div>
        <div style="flex:none;width:150px" id="abKeepWrap"><label class="fld">Versions à conserver</label>
          <input type="number" id="abKeep" min="1" step="1" value="15"></div>
        <div style="flex:none;display:none;gap:8px" id="abGfsWrap">
          <div style="width:86px"><label class="fld">Jours</label><input type="number" id="abGfsD" min="0" value="7"></div>
          <div style="width:86px"><label class="fld">Semaines</label><input type="number" id="abGfsW" min="0" value="4"></div>
          <div style="width:86px"><label class="fld">Mois</label><input type="number" id="abGfsM" min="0" value="12"></div>
        </div>
        <div><label class="fld">Dossier de destination (optionnel)</label>
          <input type="text" id="abDest" placeholder="Vide = hycu-backups/"></div>
        <div style="flex:none;align-self:flex-end"><button class="btn" id="abSave">Enregistrer</button></div>
      </div>
      <div class="hint" id="abStatus" style="margin-top:8px"></div>
    </div>

    <div class="card" id="polHycuCard">
      <h3>Politiques HYCU (données des volumes)</h3>
      <p class="sub">Politiques définies dans HYCU, assignables aux Volume Groups d'une application via
        <b>Applications → Définir la politique</b>.</p>
      <div id="polHycu"></div>
    </div>
  </section>
  <!-- ===================== TÂCHES ===================== -->
  <section id="tab-jobs" style="display:none">
    <div class="pagehead"><h1 class="ptitle">Tâches <button class="refresh" id="jobsRefresh" type="button" title="Actualiser"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19.4 12.6a7.5 7.5 0 1 1-2.3-5.9"/><path d="M19.6 4.4v4h-4"/></svg></button></h1>
      <div class="pacts">
        <a class="pact" href="/api/report?format=html" download title="Rapport de conformité (HTML autonome) : applications, RPO, santé des clusters, tâches"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 3.5h9l4 4V20.5H6z"/><path d="M14.5 3.5v4.5H19"/><path d="M9 13h7M9 16.5h5"/></svg><span>Rapport HTML</span></a>
        <a class="pact" href="/api/report?format=csv" download title="Export CSV des applications (Excel)"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 3.5h9l4 4V20.5H6z"/><path d="M14.5 3.5v4.5H19"/><path d="M9 12.5l2.2 5M11.2 12.5L9 17.5M14 12.5v5h2.6"/></svg><span>CSV</span></a>
      </div></div>
    <div class="tcard" style="margin-bottom:16px;padding:14px 16px"><div class="jcounts" id="jobsCounts" style="margin-top:0"></div></div>
    <div class="tcard">
      <div class="tbar"><input type="text" id="jobsSearch" placeholder="Rechercher" autocomplete="off"><span class="tinfo" id="jobsInfo"></span></div>
      <table class="ht"><thead><tr><th>Tâche</th><th>Application</th><th>Cluster</th><th>Détail</th><th>Démarrée</th><th class="ctr">État</th></tr></thead>
        <tbody id="jobsBody"><tr><td colspan="6" class="tempty"><span class="spin"></span></td></tr></tbody></table>
    </div>
  </section>

  <!-- ===================== VÉRIFICATION ===================== -->
  <section id="tab-verify" style="display:none">
    <div class="pagehead"><h1 class="ptitle"><a class="crumb" data-go="apps">Applications</a><span class="sep">›</span>Vérification</h1></div>
    <div class="card">
      <h3><span class="step-no">3</span>Vérifier l'état d'un namespace</h3>
      <p class="sub">Confirme que les PVC sont liés (Bound) et que les pods tournent.</p>
      <label class="fld">Namespace</label>
      <div class="row">
        <div><select id="vfNs"></select></div>
        <div style="flex:none"><button class="btn ghost nsEdit" title="Filtrer la liste des namespaces">✎ Filtrer</button></div>
        <div style="flex:none"><button class="btn" id="vfRun">Vérifier</button></div>
        <div style="flex:none"><button class="btn ghost" id="vfAuto" title="Rafraîchit la vérification toutes les ~3 s et s'arrête dès que tous les PVC sont Bound et les pods Running (10 min max) ; recliquez pour arrêter">Suivi auto (jusqu'à stable)</button></div>
      </div>
      <div id="vfOut"></div>
    </div>
  </section>

  <!-- ===================== RÉGLAGES ===================== -->
  <section id="tab-settings" style="display:none">
    <div class="pagehead"><h1 class="ptitle">Réglages</h1></div>
    <div class="card">
      <h3><span class="step-no">⎈</span>Cluster local (contexte kubectl)</h3>
      <p class="sub">Choisissez explicitement le cluster, au lieu de suivre le contexte courant.
        L'outil ajoute <code>--context</code> (et <code>--kubeconfig</code>) à chaque commande kubectl.
        Les clusters <b>supplémentaires</b> (kubeconfig importé, workspaces NKP) se gèrent depuis <b>⚙ Sources</b>.</p>
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
        <div><label class="fld">Contextes / clusters autorisés (séparés par des virgules ; vide = tous)</label><input type="text" id="cfgCtx" placeholder="prod-cluster, dr-cluster"></div>
        <div><label class="fld">Namespaces autorisés — cluster local (vide = tous)</label><input type="text" id="cfgNs" placeholder="wordpress, bo-dev"></div>
      </div>
      <div class="row">
        <div><label class="fld">Sélecteur d'étiquettes des namespaces (vide = inactif ; s'applique à tous les clusters)</label><input type="text" id="cfgLabelSel" placeholder="hycu.io/backup=true  ou  env in (prod,preprod)"></div>
        <div style="flex:none;width:230px"><label class="fld">Historique des tâches (jours ; 0 = illimité)</label><input type="number" id="cfgAuditDays" min="0" step="1" placeholder="31"></div>
      </div>
      <div class="row">
        <div style="flex:none;width:250px"><label class="fld">Plancher d'espace libre (Mo ; 0 = désactivé)</label><input type="number" id="cfgMinFree" min="0" step="100" placeholder="500"></div>
        <div style="flex:none;width:280px"><label class="fld">Quota des sauvegardes (Go ; 0 = illimité)</label><input type="number" id="cfgQuota" min="0" step="1" placeholder="0"></div>
        <div style="align-self:flex-end" class="hint">Sous le plancher, toute sauvegarde est refusée ; au-delà du quota, les plus anciennes sont purgées (la plus récente de chaque application est toujours gardée).</div>
      </div>
      <div class="row">
        <div><label class="fld"><input type="checkbox" id="cfgDr" style="width:auto"> <b>Autoriser la restauration DR</b> (inter-cluster / inter-contexte)</label>
        <div class="hint">À activer le temps d'un exercice ou d'un sinistre. Chaque restauration DR reste explicite : sources lues depuis la seule sauvegarde, avertissement, re-saisie du cluster cible, audit dédié.</div></div>
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
</main>
</div>

<div id="mBackup" class="hmodal-bg" style="display:none">
  <div class="hmodal" style="max-width:640px">
    <div class="hm-head"><h2 id="mBackupTitle">Sauvegarde de configuration</h2><div class="hm-ico"><button type="button" data-close="mBackup" title="Fermer">✕</button></div></div>
    <div class="hm-body">
    <div class="card">
      <h3><span class="step-no">1</span>Sauvegarder les volumes d'un namespace</h3>
      <p class="sub">Exporte et nettoie automatiquement tous les PV et PVC du namespace.
        Équivaut aux boucles kubectl + nettoyage manuel des manifestes.</p>
      <div id="bkNsRow"><label class="fld">Namespace</label>
      <div class="row">
        <div><select id="bkNs"></select></div>
        <div style="flex:none"><button class="btn ghost nsEdit" title="Filtrer la liste des namespaces">✎ Filtrer</button></div>
        <div style="flex:none"><button class="btn" id="bkRun">Sauvegarder ce namespace</button></div>
        <div style="flex:none"><button class="btn ghost" id="bkRunAll" title="Sauvegarder tous les namespaces autorisés par le filtre (tous si aucun filtre)">Sauvegarder tous (filtrés)</button></div>
      </div></div>
      <div id="bkSelInfo" style="display:none"><label class="fld">Namespaces sélectionnés</label><div class="fbox" id="bkSelList"></div></div>
      <label class="fld" style="margin-top:10px">Dossier de destination (optionnel)</label>
      <input type="text" id="bkDest" placeholder="Vide = hycu-backups/ (à côté du programme). Ex. D:\sauvegardes\hycu  ou  /mnt/backups">
      <div class="hint" style="margin-top:4px">Chemin sur la machine qui exécute l'outil. Le sous-dossier &lt;namespace&gt;/&lt;horodatage&gt; est créé automatiquement.</div>
      <div id="bkOut"></div>
    </div>

    </div>
    <div class="hm-foot" id="mBackupFoot"><button class="lnk" type="button" data-close="mBackup">Fermer</button><button class="btn" id="bkRunSel" type="button" style="display:none">Sauvegarder la sélection</button></div>
  </div>
</div>
<div id="mBulk" class="hmodal-bg" style="display:none">
  <div class="hmodal" style="max-width:860px">
    <div class="hm-head"><h2>Restauration en masse</h2><div class="hm-ico"><button type="button" data-close="mBulk" title="Fermer">✕</button></div></div>
    <div class="hm-body">
      <div class="note">Recrée <b>tous les namespaces supprimés</b> du cluster actif (<b id="bulkCluster"></b>) depuis leur dernière sauvegarde antérieure à l'instant de référence : namespace, PV/PVC, workloads, dépendances, Secrets (coffre déverrouillé), Volume Groups restaurés par HYCU s'ils ont disparu, applications stateless. Les namespaces <b>encore présents</b> sont ignorés : une application vivante se restaure depuis sa propre ligne. Exécution séquentielle et journalisée, reprise possible ; <b>simulation obligatoire</b> avant le réel.</div>
      <div class="row" style="margin-top:10px">
        <div style="flex:none;width:230px"><label class="fld">Instant de référence</label><input type="datetime-local" id="bulkAsOf"></div>
        <div><label class="fld">Namespaces à exclure (virgules, optionnel)</label><input type="text" id="bulkExclude" placeholder="kube-system, monitoring" autocomplete="off"></div>
        <div style="flex:none;align-self:flex-end"><button class="btn ghost" id="bulkPlanBtn" type="button">Préparer le plan</button></div>
      </div>
      <div id="bulkPlanOut" style="margin-top:10px"></div>
      <div id="bulkRunOut" style="margin-top:10px"></div>
    </div>
    <div class="hm-foot"><button class="lnk" type="button" data-close="mBulk">Fermer</button>
      <button class="btn ghost" id="bulkStop" type="button" style="display:none">Arrêter</button>
      <button class="btn ghost" id="bulkResume" type="button" style="display:none">Reprendre</button>
      <button class="btn" id="bulkSim" type="button" disabled>Simuler</button>
      <button class="btn danger" id="bulkReal" type="button" disabled>Lancer (réel)</button></div>
  </div>
</div>
<div id="mPolicy" class="hmodal-bg" style="display:none">
  <div class="hmodal" style="max-width:700px">
    <div class="hm-head"><h2 id="mPolicyTitle">Définir la politique</h2><div class="hm-ico"><button type="button" data-close="mPolicy" title="Fermer">✕</button></div></div>
    <div class="hm-body">
    <div class="card" id="bkProtectCard">
      <h3><span class="step-no">2</span>Protéger les données dans HYCU</h3>
      <p class="sub">L'export ci-dessus ne sauvegarde que les <b>manifestes</b> (la « recette » du restore).
        Les <b>données</b> vivent dans les Volume Groups Nutanix : seul HYCU les sauvegarde réellement.
        Ici, on associe les PVC du namespace aux Volume Groups HYCU, on assigne une politique, et on lance
        une sauvegarde.</p>
      <div id="bkProtectOff" class="warnbox">Enregistrez la source HYCU (⚙ en haut à droite) pour activer cette section.</div>
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
    </div>
    <div class="hm-foot" id="mPolicyFoot"><button class="lnk" type="button" data-close="mPolicy">Fermer</button></div>
  </div>
</div>
<div id="mRestore" class="hmodal-bg" style="display:none">
  <div class="hmodal" style="max-width:760px">
    <div class="hm-head"><h2 id="mRestoreTitle">Restauration de l'application</h2><div class="hm-ico"><button type="button" data-close="mRestore" title="Fermer">✕</button></div></div>
    <div class="hm-body">
  <!-- ===================== RESTAURATION ===================== -->
  <section id="tab-restore">
    <div class="stepper" id="rsStepper">
      <span class="st on" data-st="1">1 · Volumes</span>
      <span class="st" data-st="2">2 · Configurer</span>
      <span class="st" data-st="3">3 · Lancer</span>
    </div>
    <div id="rsPgType">
      <div class="note" id="rsAppNote" style="display:none;margin-bottom:10px"></div>
      <div class="opt" data-kind="cloneapp"><svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="4" y="27" width="16" height="16" rx="2"/><circle cx="35.5" cy="35" r="8.5"/><path d="M27.5 12.5a8.3 8.3 0 1 1 3 6.3"/><path d="M27 6.8v5.4h5.4"/></svg><div><b>Restaurer toute l'application (copie)</b><span>Restaure le stockage et les objets de l'application (workloads, dépendances) dans le même namespace (suffixe) ou dans un autre. L'original n'est pas modifié.</span></div></div>
      <div class="opt" data-kind="inplace"><svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><ellipse cx="19" cy="10.5" rx="12" ry="4.5"/><path d="M7 10.5v25c0 2.5 5.4 4.5 12 4.5"/><path d="M31 10.5v10"/><path d="M7 23c0 2.5 5.4 4.5 12 4.5"/><path d="M27.3 36.3a8.2 8.2 0 1 0 2.4-5.8"/><path d="M27 26.6v4.9h4.9"/></svg><div><b>Restaurer le stockage sur place</b><span>Restaure les données dans les volumes d'origine. L'application est arrêtée puis redémarrée.</span></div></div>
      <div class="opt" data-kind="reattach"><svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><ellipse cx="16" cy="10.5" rx="11" ry="4.3"/><path d="M5 10.5v25c0 2.4 4.9 4.3 11 4.3s11-1.9 11-4.3v-25"/><path d="M5 23c0 2.4 4.9 4.3 11 4.3s11-1.9 11-4.3"/><path d="M32 23.5h11M38.5 18.5l5 5-5 5"/></svg><div><b>Restaurer le stockage vers de nouveaux volumes</b><span>Restaure vers de nouveaux Volume Groups et y rattache l'application. Les volumes d'origine sont conservés.</span></div></div>
      <div class="opt" data-kind="dr"><svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M24 5l17 8v10c0 10.5-7.2 18.6-17 21-9.8-2.4-17-10.5-17-21V13z"/><path d="M24 15v10M24 30.5h.01"/></svg><div><b>Restauration DR (autre cluster / contexte)</b><span>Reprise d'activité : recrée une application sur CE cluster depuis une sauvegarde d'un cluster disparu (ou importée du bucket S3). Sources lues depuis la seule sauvegarde. Nécessite le réglage « Autoriser la restauration DR ».</span></div></div>
      <div class="opt" data-kind="objects"><svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="6" width="26" height="34" rx="3"/><path d="M11 14h14M11 20h14M11 26h9"/><path d="M28.5 36.5a8.2 8.2 0 1 0 2.4-5.8"/><path d="M28.2 26.8v4.9h4.9"/></svg><div><b>Restaurer des objets de configuration</b><span>Ré-applique des objets choisis (Deployments, Services, ConfigMaps…) depuis l'instantané d'une sauvegarde, avec aperçu des différences. Ne touche ni aux volumes ni aux données.</span></div></div>
    </div>
    <div id="rsPgDr" style="display:none">
      <div id="drGate" style="display:none"><div class="warnbox">La <b>restauration DR</b> est désactivée. Activez « <b>Autoriser la restauration DR</b> » dans ⚙ → Réglages (le temps de l'exercice ou du sinistre), puis revenez ici.</div>
        <div style="margin-top:10px"><button class="btn ghost" id="drOpenCfg" type="button">Ouvrir les réglages</button></div></div>
      <div id="drForm" style="display:none">
        <div class="warnbox" id="drWarnDr">Mode <b>reprise d'activité</b> : la garde inter-cluster est levée pour CETTE opération. Toutes les sources proviennent de la sauvegarde choisie ; le cluster cible est le <b>cluster actif</b> (<b id="drCluster"></b>). Restaurez d'abord les Volume Groups dans HYCU vers le site cible, puis collez leurs UUID.</div>
        <div class="note" id="drWarnRec" style="display:none">Ce namespace n'existe plus sur le cluster <b id="drClusterRec"></b> : l'application va être <b>recréée depuis sa sauvegarde</b> (namespace, PV/PVC, workloads, dépendances non masquées), en réutilisant ses volumes d'origine — ou, s'ils ont été supprimés avec le namespace, en les restaurant automatiquement depuis HYCU (« Protected deleted »). Dans le cas courant, rien à saisir : vérifiez la sauvegarde et lancez la restauration.</div>
        <div class="row" style="margin-top:10px">
          <div><label class="fld">Sauvegarde source (tous clusters / imports S3)</label><select id="drBackupSel"></select></div>
          <div style="flex:none;width:220px"><label class="fld">Namespace cible</label><input type="text" id="drTargetNs" autocomplete="off"></div>
        </div>
        <div class="row">
          <div style="flex:none;width:260px"><label class="fld">StorageClass cible (vide = inchangée)</label><input type="text" id="drSc" placeholder="nutanix-volume" autocomplete="off"></div>
          <div style="align-self:flex-end"><label class="fld"><input type="checkbox" id="drRefs" checked style="width:auto"> Recréer les dépendances depuis la sauvegarde (Secrets non masqués, ConfigMaps, ServiceAccounts, Services)</label></div>
        </div>
        <div class="note" id="drSecretsNote" style="display:none;margin:8px 0"></div>
        <div class="note" id="drNoRes" style="display:none;margin:8px 0">Cette sauvegarde ne contient <b>que les volumes</b> (pas d'instantané des workloads/dépendances) : elle est antérieure à cette fonction, ou la sauvegarde de config étendue était désactivée. La restauration recréera <b>les volumes (PV/PVC)</b> ; recréez les workloads depuis une sauvegarde plus récente ou manuellement.</div>
        <div id="drReuseWrap" style="display:none;margin:6px 0 4px">
          <label class="fld" style="display:flex;gap:9px;align-items:flex-start;cursor:pointer;font-weight:600">
            <input type="checkbox" id="drReuse" checked style="width:auto;margin-top:2px">
            <span>Réutiliser les volumes d'origine de l'application <span class="badge sim">recommandé</span>
            <span class="hint" style="display:block;font-weight:400;margin-top:3px">Rien à saisir : l'application est rebranchée sur ses volumes Nutanix d'origine (leurs identifiants sont dans la sauvegarde). Décochez seulement si vous avez restauré les données sur de <b>nouveaux</b> volumes dans HYCU.</span></span>
          </label>
        </div>
        <label class="fld" id="drVolsLabel">Volumes — collez l'UUID du VG restauré/cloné sur le site cible</label>
        <div id="drVols"></div>
        <div id="drAutoWrap" style="display:none;margin:8px 0 2px">
          <button class="btn ghost" id="drAuto" type="button">Créer les volumes automatiquement via HYCU</button>
          <span class="hint" style="margin-left:8px">HYCU clone les Volume Groups et l'outil récupère les nouveaux identifiants — aucune saisie. En simulation, seul le plan est affiché.</span>
        </div>
        <div id="drLog" style="margin-top:10px"></div>
        <div id="drErr"></div>
      </div>
    </div>
    <div id="rsPgObjects" style="display:none">
      <div class="row" style="margin-bottom:4px">
        <div><label class="fld" style="margin-top:0">Application</label><div class="fbox" id="objApp"></div></div>
        <div><label class="fld" style="margin-top:0">Sauvegarde (instantané de config)</label><select id="objBackupSel"></select></div>
      </div>
      <div id="objPick">
        <label class="fld" style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">Objets à restaurer <span class="hint" id="objInfo"></span>
          <span id="objOnlyAppWrap" style="display:none;font-weight:400;margin-left:auto"><input type="checkbox" id="objOnlyApp" checked style="width:auto"> Seulement les objets de l'application</span></label>
        <div class="tcard" style="box-shadow:none;border:1px solid var(--rule)">
          <table class="ht"><thead><tr><th class="cb"><input type="checkbox" id="objAll"></th><th>Type</th><th>Nom</th><th>Note</th></tr></thead>
          <tbody id="objBody"></tbody></table></div>
      </div>
      <div id="objDiffWrap" style="display:none">
        <label class="fld">Aperçu des différences (live → sauvegarde)</label>
        <div id="objDiff"></div>
      </div>
      <div id="objLog" style="margin-top:10px"></div>
      <div id="objErr"></div>
    </div>
    <div id="rsPgTarget" style="display:none">
      <div class="opt" data-nsmode="same"><svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="6" y="6" width="24" height="24" rx="3"/><rect x="18" y="18" width="24" height="24" rx="3"/><path d="M25 30h10M30 25v10"/></svg><div><b>Dans le même namespace (suffixe)</b><span>La copie est créée à côté de l'application d'origine : chaque objet reçoit un suffixe (ex. <code>-clone</code>). Pratique pour vérifier une restauration sans rien déplacer.</span></div></div>
      <div class="opt" data-nsmode="other"><svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="12" width="17" height="24" rx="3"/><rect x="30" y="12" width="14" height="24" rx="3" stroke-dasharray="4 3"/><path d="M21 24h11M27.5 19.5l4.5 4.5-4.5 4.5"/></svg><div><b>Vers un autre namespace</b><span>La copie est créée dans un namespace cible (créé s'il n'existe pas), avec ses dépendances (Secrets, ConfigMaps, ServiceAccount, Services). Les noms d'origine sont conservés.</span></div></div>
    </div>
    <div id="rsPgForm" style="display:none">
      <div class="row" style="margin-bottom:4px">
        <div><label class="fld" style="margin-top:0">Application</label><div class="fbox" id="rsWizApp"></div></div>
        <div><label class="fld" style="margin-top:0">Cluster cible</label><div class="fbox" id="rsWizCluster"></div></div>
      </div>
    <div class="card">
      <h3><span class="step-no">1</span>Choisir le namespace et les volumes</h3>
      <p class="sub">Cochez le(s) volume(s) à restaurer — plusieurs volumes = une seule transaction.</p>
      <div id="rsNsRow" style="display:none"><label class="fld">Namespace</label>
      <div class="row">
        <div><select id="rsNs"></select></div>
        <div style="flex:none;align-self:flex-end"><button class="btn ghost nsEdit" title="Filtrer la liste des namespaces">✎ Filtrer</button></div>
      </div></div>
      <label class="fld" id="rsCustomDirLbl" style="margin-top:8px"><input type="checkbox" id="rsCustomDir" style="width:auto"> Lire les sauvegardes depuis un dossier personnalisé</label>
      <div id="rsCustomDirWrap" style="display:none;margin-top:4px">
        <input type="text" id="rsBackupRoot" placeholder="Ex. D:\sauvegardes\hycu  ou  /mnt/backups  (dossier contenant &lt;namespace&gt;/&lt;horodatage&gt;/)">
        <div class="hint" style="margin-top:4px">Les sauvegardes lues (et utilisées pour la restauration) seront cherchées ici, au lieu de <code>hycu-backups/</code>.</div>
      </div>
      <div id="rsBackupSelWrap" style="display:none;margin-top:8px">
        <label class="fld">Sauvegarde de configuration à restaurer</label>
        <select id="rsBackupSel"></select>
        <div class="hint" style="margin-top:4px">Manifestes PV/PVC (le « squelette ») — indépendant du point de restauration HYCU des <b>données</b>.<a id="rsBackupDl" href="#" download style="display:none;margin-left:6px;text-decoration:none">⬇ Télécharger (.zip)</a></div>
      </div>
      <div id="rsModeRow" style="display:none"><label class="fld">Type d'opération</label>
      <div class="seg" id="rsMode">
        <button class="on" data-mode="clone">Clone (nouveau VG)</button>
        <button data-mode="inplace">Restauration sur place</button>
      </div></div>
      <div id="rsCloneSubWrap">
        <label class="fld" style="display:none">Que faire du clone ?</label>
        <div class="seg" id="rsCloneSub" style="display:none">
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
      <label class="fld">Volumes à restaurer</label>
      <ul class="pvc-list" id="rsPvcs" style="margin-top:12px"></ul>
    </div>

    <div class="card" id="rsConfig" style="display:none">
      <h3><span class="step-no">2</span>Restaurer les données (Volume Groups)</h3>
      <div id="rsFlowGuide" class="rsGuide"></div>
      <div id="rsVolCfgs"></div>
      <div id="rsHyActions"></div>
      <div id="rsInplaceRunWrap" style="display:none;margin-top:14px;border-top:1px solid var(--line);padding-top:12px">
        <p class="sub" style="margin:4px 0 8px"><b>Arrêt de l'application → restore in-place HYCU → redémarrage.</b> Aucune référence à saisir.</p>
        <button class="btn" id="rsInplaceRun" disabled>Lancer la restauration sur place</button>
        <span class="hint" id="rsInplaceHint" style="margin:0"></span>
        <div id="rsInplaceLog"></div>
      </div>
      <div id="rsContinueWrap" style="margin-top:14px">
        <button class="btn" id="rsPreview">Continuer : vérifier et lancer →</button>
      </div>
      <div id="rsErr"></div>
    </div>

    <details class="rsAdv" id="rsAdvWrap"><summary class="rsAdvSum">Avancé — dossier de sauvegardes personnalisé</summary><div id="rsAdvBody"></div></details>
    </div>
    <div id="rsPgPlan" style="display:none">
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
    </div>
    <div class="nextbar" id="rsNextBar"><span id="rsNextTxt"></span><button class="btn" id="rsNextBtn"></button></div>
  </section>

    </div>
    <div class="hm-foot" id="mRestoreFoot"><span id="rsWizMode" class="badge" style="margin-right:auto"></span><button class="lnk" type="button" data-close="mRestore">Fermer</button><button class="lnk" type="button" id="rsWizBack">Retour</button><button class="btn" type="button" id="rsWizGo">Suivant</button></div>
  </div>
</div>
<div id="mSources" class="hmodal-bg" style="display:none">
  <div class="hmodal" style="max-width:860px">
    <div class="hm-head"><h2 id="mSourcesTitle">Sources</h2><div class="hm-ico"><button type="button" data-close="mSources" title="Fermer">✕</button></div></div>
    <div class="hm-body">
      <p class="hint" style="margin:0 0 12px">Enregistrez ici les systèmes utilisés par l'outil — HYCU, Nutanix et vos clusters Kubernetes. Les identifiants et kubeconfigs restent en mémoire le temps de la session (ou dans le coffre chiffré si vous le choisissez).</p>
      <div class="srctools">
        <button class="pact" id="clAddBtn" type="button"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="4" width="16" height="6.5" rx="1.3"/><rect x="4" y="13.5" width="10" height="6.5" rx="1.3"/><path d="M18.5 14.5v5M16 17h5"/></svg><span>Ajouter un cluster Kubernetes</span></button>
        <button class="pact" id="nkpBtn" type="button"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3.5" y="3.5" width="7" height="7" rx="1.2"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.2"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.2"/><circle cx="16.6" cy="16.6" r="3"/><path d="M18.8 18.8l2 2"/></svg><span>Découvrir les workspaces NKP</span></button>
      </div>
      <div class="tcard" style="box-shadow:none;border:1px solid var(--rule);margin-bottom:14px">
        <table class="ht"><thead><tr><th>Nom</th><th>Type</th><th>URL / serveur</th><th class="ctr">État</th></tr></thead><tbody id="srcBody"></tbody></table>
      </div>
  <!-- ===================== CONNEXIONS ===================== -->
  <section id="tab-connect">
    <div class="card" data-card="hycu">
      <h3><span class="step-no">H</span>HYCU — connexion</h3>
      <p class="sub">Pour lister les points de restauration et orchestrer le clone/restore d'un Volume Group
        depuis l'assistant de restauration (<b>Applications → Restaurer</b>). Les identifiants restent <b>en mémoire</b> le temps de la session — jamais écrits sur disque.</p>
      <label class="fld">URL HYCU (port 8443)</label>
      <input type="text" id="hyUrl" placeholder="https://hycu.exemple.com:8443">
      <label class="fld">Authentification</label>
      <div class="seg" id="hyAuthMode">
        <button class="on" data-mode="basic">Basic (utilisateur)</button>
        <button data-mode="apikey">Clé API</button>
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

    <div class="card" data-card="nutanix">
      <h3><span class="step-no">N</span>Nutanix Prism Element — connexion</h3>
      <p class="sub">Récupère automatiquement la référence (UUID) du Volume Group cloné (lecture seule, API v2)
        dans l'assistant de restauration. Identifiants en mémoire de session uniquement.</p>
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

    <div class="card" data-card="prismcentral">
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

    <div class="card" data-card="s3">
      <h3><span class="step-no">S3</span>Stockage objet S3 — export des sauvegardes (optionnel)</h3>
      <p class="sub">Copie chaque sauvegarde de configuration (<code>.zip</code>) vers un bucket <b>compatible S3</b>
        (Nutanix Objects, MinIO, AWS S3…) : le filet de sécurité vit alors <b>hors du cluster</b> qu'il protège.
        Clés d'accès en <b>mémoire</b> le temps de la session (coffre chiffré en option).</p>
      <div class="row">
        <div><label class="fld">Endpoint S3</label><input type="text" id="s3Url" placeholder="https://objects.exemple.com"></div>
        <div><label class="fld">Bucket</label><input type="text" id="s3Bucket" placeholder="hycu-backups" autocomplete="off"></div>
      </div>
      <div class="row">
        <div><label class="fld">Clé d'accès (Access key)</label><input type="text" id="s3Access" autocomplete="off"></div>
        <div><label class="fld">Clé secrète (Secret key)</label><input type="password" id="s3Secret" autocomplete="off"></div>
      </div>
      <div class="row">
        <div><label class="fld">Région (signature)</label><input type="text" id="s3Region" placeholder="us-east-1"></div>
        <div style="align-self:flex-end">
          <label class="fld"><input type="checkbox" id="s3PathStyle" checked style="width:auto"> URL de type chemin (Objects / MinIO)</label>
          <label class="fld"><input type="checkbox" id="s3Tls" style="width:auto"> Vérifier le certificat TLS</label>
        </div>
      </div>
      <label class="fld" style="margin-top:10px"><input type="checkbox" id="s3Auto" style="width:auto">
        <b>Export automatique</b> : envoyer chaque sauvegarde réussie (manuelle et planifiée) vers le bucket</label>
      <label class="fld"><input type="checkbox" id="s3Enc" style="width:auto">
        <b>Chiffrer les exports</b> (option) : les objets envoyés sont chiffrés — le bucket peut être un stockage non maîtrisé</label>
      <div id="s3EncWrap" style="display:none"><label class="fld">Phrase de chiffrement des exports (à conserver : elle sert au déchiffrement)</label>
        <input type="password" id="s3EncPass" autocomplete="off">
        <div class="hint" style="margin-top:4px">Déchiffrement hors interface : <code>python3 hycu_k8s_nutanix.py --decrypt fichier.zip.enc</code></div></div>
      <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <button class="btn" id="s3Connect">Tester &amp; connecter</button>
        <button class="btn ghost" id="s3Disconnect">Déconnecter</button>
        <span class="hint" id="s3Status" style="margin:0"><span class="conn-dot"></span>non connecté</span>
      </div>
      <div class="hint" style="margin-top:8px">Test en lecture seule (liste du bucket, 1 objet). Objets créés :
        <code>&lt;préfixe&gt;/&lt;cluster&gt;/&lt;namespace&gt;/&lt;horodatage&gt;.zip</code>. L'échec d'un export
        n'échoue jamais la sauvegarde locale (visible dans les Tâches).</div>
      <div id="s3Err"></div>
      <div style="margin-top:14px;border-top:1px solid var(--line);padding-top:12px">
        <button class="pact" id="s3ListBtn" type="button"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v12M7.5 10.5L12 15l4.5-4.5"/><path d="M4 17v2.5h16V17"/></svg><span>Importer depuis le bucket (reprise / DR)</span></button>
        <div id="s3ImportWrap" style="display:none;margin-top:10px">
          <div id="s3ListOut"></div>
          <div class="row" style="margin-top:8px">
            <div><label class="fld">Phrase de déchiffrement (objets .enc uniquement)</label><input type="password" id="s3ImpPass" autocomplete="off"></div>
            <div style="flex:none;align-self:flex-end"><button class="btn" id="s3ImportBtn" type="button" disabled>Importer la sélection</button></div>
          </div>
          <div class="hint" style="margin-top:4px">Les exports rapatriés vont dans <code>hycu-backups/_imports/…</code> ; ils se restaurent via la <b>Restauration DR</b> de l'assistant (ou sur leur cluster d'origine).</div>
          <div id="s3ImpRes"></div>
        </div>
      </div>
    </div>

    <div class="card" data-card="vault">
      <h3><span class="step-no">🔒</span>Mémoriser les connexions (chiffré)</h3>
      <p class="sub">Option : enregistrer les identifiants saisis (et les kubeconfigs des clusters ajoutés) dans un coffre <b>chiffré</b>
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

    <div class="card" data-card="cluster-add">
      <h3><span class="step-no">K</span>Ajouter un cluster Kubernetes</h3>
      <p class="sub">Chargez le <b>kubeconfig</b> du cluster (fichier ou copier-coller). Comme un mot de passe, il reste
        <b>en mémoire</b> le temps de la session, et n'est écrit sur disque que <b>chiffré</b> si vous utilisez le coffre.
        Les sauvegardes de chaque cluster sont rangées séparément.</p>
      <div class="row">
        <div><label class="fld">Nom du cluster</label><input type="text" id="clName" placeholder="prod-paris" autocomplete="off"></div>
        <div><label class="fld">Fichier kubeconfig</label><input type="file" id="clFile"></div>
      </div>
      <label class="fld">…ou collez son contenu (YAML ou JSON)</label>
      <textarea id="clKc" class="kc" spellcheck="false" autocomplete="off" placeholder="apiVersion: v1&#10;kind: Config&#10;clusters: …"></textarea>
      <div id="clCtxWrap" style="display:none"><label class="fld">Contexte</label><select id="clCtx"></select><div id="clCtxInfo"></div></div>
      <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <button class="btn" id="clAdd" type="button">Tester &amp; ajouter</button>
        <span class="hint" style="margin:0">Test de connexion en lecture seule (liste des namespaces, 10 s max).</span>
      </div>
      <div id="clErr"></div>
    </div>

    <div class="card" data-card="cluster">
      <h3><span class="step-no">K</span><span id="clDTitle">Cluster</span></h3>
      <div id="clDBody"></div>
      <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <button class="btn" id="clUse" type="button">Définir comme cluster actif</button>
        <button class="btn ghost" id="clLocalCfg" type="button">Ouvrir les réglages</button>
        <button class="btn danger" id="clRemove" type="button">Retirer</button>
      </div>
      <div id="clDErr"></div>
    </div>

    <div class="card" data-card="nkp">
      <h3><span class="step-no">W</span>Découverte des workspaces NKP (optionnel)</h3>
      <p class="sub">Depuis le <b>cluster de management</b> NKP, liste les <b>workspaces</b> et leurs clusters, puis importe
        leurs kubeconfigs. Cluster interrogé : <b id="nkpMgmt">—</b> (le cluster actif — choisissez le cluster de management
        dans la barre du haut).</p>
      <div class="warnbox">⚠ <b>Droits élevés requis</b> sur le cluster de management : lecture des Workspaces, des
        KommanderClusters et des <b>Secrets</b> kubeconfig des namespaces de workspace. Les kubeconfigs importés donnent
        souvent un accès <b>administrateur</b> aux clusters : ils restent en mémoire (coffre chiffré en option), jamais en clair sur disque.</div>
      <div style="margin-top:12px"><button class="btn" id="nkpDiscover" type="button">Découvrir</button></div>
      <div id="nkpOut"></div>
      <div id="nkpImportWrap" style="display:none;margin-top:10px">
        <label class="fld"><input type="checkbox" id="nkpAck" style="width:auto"> J'ai compris : importer les kubeconfigs des clusters cochés</label>
        <button class="btn" id="nkpImport" type="button" disabled>Importer la sélection</button>
      </div>
      <div id="nkpRes"></div>
    </div>
  </section>

    </div>
    <div class="hm-foot" id="mSourcesFoot"><button class="lnk" type="button" data-close="mSources">Fermer</button></div>
  </div>
</div>

<script>
const $ = s => document.querySelector(s);
const CSRF = document.querySelector('meta[name=csrf-token]').content;
const dry = () => $("#dry").checked;
let state = {selected:{}, mode:"clone", cloneSub:"reattach", cloneNsMode:"same", backup_path:null, backup_root:null, preview:null, ns:null, app:null};
let ctxInfo = {};
function isCloneApp(){ return state.mode==="clone" && state.cloneSub==="cloneapp"; }

function badge(phase){
  const p=(phase||"").toLowerCase();
  const c = p==="bound"?"b-bound":p==="lost"?"b-lost":p==="pending"?"b-pending":"b-na";
  return `<span class="badge ${c}">${esc(phase||"—")}</span>`;
}
function esc(s){return (s==null?"":String(s)).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
// Cluster Kubernetes ACTIF : chaque requête le désigne (en-tête X-HYCU-Cluster) ;
// le serveur route kubectl vers ce cluster. « local » = cluster de la configuration.
let ACTIVE_CID="local", CLUSTERS=[{id:"local", name:"local", local:true}];
// Toute panne (serveur arrêté, réseau, réponse non-JSON comme un 403 texte) devient
// une réponse {ok:false,error:…} : jamais d'exception non rattrapée qui laisserait
// un bouton désactivé avec son spinner.
async function _req(u, opts){
  try{
    const r=await fetch(u, opts);
    try{ return await r.json(); }
    catch(e){ return {ok:false, error:"Réponse inattendue du serveur ("+r.status+") — rechargez la page (Ctrl+Shift+R)."}; }
  }catch(e){ return {ok:false, error:"Serveur injoignable : "+(e && e.message || e)+". L'outil est-il toujours lancé ?"}; }
}
async function get(u, cid){return _req(u,{headers:{"X-HYCU-Cluster":cid||ACTIVE_CID}});}
async function post(u,b,cid){return _req(u,{method:"POST",
  headers:{"Content-Type":"application/json","X-CSRF-Token":CSRF,"X-HYCU-Cluster":cid||ACTIVE_CID},
  body:JSON.stringify(b)});}

// Erreurs actionnables : reconnaît les causes courantes (HYCU/Nutanix/kubectl/HTTP)
// et préfixe un conseil concret, en gardant le détail brut en dessous.
function errHint(raw){
  const e=(raw||"").toLowerCase();
  if(/401|unauthorized|identifiant|mot de passe|password|invalid cred/.test(e)) return "Identifiants refusés — vérifiez l'utilisateur/mot de passe, ou la clé API HYCU (Aide → API Keys, requise si 2FA).";
  if(/\b403\b|forbidden|interdit|rbac/.test(e)) return "Accès refusé — droits insuffisants (RBAC / rôle sur l'API).";
  if(/\b404\b|api-docs|endpoint.*not found/.test(e)) return "Endpoint introuvable — vérifiez l'URL de base et la version d'API (⚙ Réglages).";
  if(/certificat|certificate|ssl|tls|self.?signed/.test(e)) return "Certificat TLS — cochez/décochez « Vérifier le certificat TLS » dans Connexions selon votre PKI.";
  if(/stockage objet|object storage/.test(e)) return "Endpoint S3 injoignable — vérifiez le PORT (MinIO : 9000 = API S3, pas la console 9001 ; Nutanix Objects : 443), le protocole http/https, et que la machine qui exécute l'outil (le Pod, pas votre poste) atteint cet hôte.";
  if(/timeout|timed out|délai|connexion impossible|connection failed|refused|unreachable|injoignable|getaddrinfo|name or service|errno|10061|10060/.test(e)) return "Hôte injoignable — vérifiez l'URL:port (HYCU 8443, Prism 9440), le réseau et le pare-feu.";
  if(/non connecté|connectez-vous|not connected|connect to at least|connect to hycu/.test(e)) return "Enregistrez d'abord la source (⚙ en haut à droite).";
  if(/namespace.*(non autorisé|autorisé|not allowed)|(non autorisé).*namespace/.test(e)) return "Namespace hors liste autorisée — voir ⚙ Réglages → namespaces autorisés.";
  if(/contexte.*non autorisé|context.*not allowed|allowed_contexts/.test(e)) return "Contexte kubectl hors liste autorisée — voir ⚙ Réglages.";
  if(/confirmation du contexte|context confirmation/.test(e)) return "Retapez le nom exact du contexte cible pour confirmer (mode réel).";
  if(/jeton anti-csrf|csrf token/.test(e)) return "Rechargez la page (Ctrl+Shift+R) : le jeton de sécurité a expiré.";
  return "";
}
function errBox(raw){
  const h=errHint(raw);
  return `<div class="err">${h?`<b>${esc(h)}</b><div class="hint" style="margin-top:4px">${esc(raw||"")}</div>`:esc(raw||"erreur")}</div>`;
}

// Préférences mémorisées PAR NAVIGATEUR (localStorage) : namespace, type d'opération,
// dossiers. Confort uniquement — jamais d'identifiant ni de secret ici.
const PREFS_KEY="hycu_prefs";
function prefs(){ try{ return JSON.parse(localStorage.getItem(PREFS_KEY)||"{}"); }catch(e){ return {}; } }
function savePref(k,v){ try{ const p=prefs(); p[k]=v; localStorage.setItem(PREFS_KEY,JSON.stringify(p)); }catch(e){} }
function applyPrefs(){
  const p=prefs();
  if(p.bkDest) $("#bkDest").value=p.bkDest;
  if(p.backupRoot) $("#rsBackupRoot").value=p.backupRoot;
  if(p.customDir){ $("#rsCustomDir").checked=true; $("#rsCustomDirWrap").style.display="block"; }
  if(p.mode==="inplace"){ state.mode="inplace";
    document.querySelectorAll("#rsMode button").forEach(x=>x.classList.toggle("on",x.dataset.mode==="inplace"));
    $("#rsCloneSubWrap").style.display="none"; }
  if(p.ns && [...$("#bkNs").options].some(o=>o.value===p.ns)){ state.ns=p.ns; applyGlobalNs(); }
}

// Onglets
// Namespace GLOBAL synchronisé entre les 3 onglets (fluidité : un seul choix).
function applyGlobalNs(){ if(!state.ns) return; ["#bkNs","#rsNs","#vfNs"].forEach(id=>{ const e=$(id); if(e && e.value!==state.ns) e.value=state.ns; }); }
// Stepper du parcours Restaurer : surligne l'étape courante (1 Volumes, 2 Configurer, 3 Lancer).
function setRsStep(n){ document.querySelectorAll("#rsStepper .st").forEach(e=>{ const k=+e.dataset.st;
  e.classList.toggle("on",k===n); e.classList.toggle("done",k<n); }); }
// Pastilles cliquables du stepper : faire défiler vers la carte de l'étape (si affichée).
document.querySelectorAll("#rsStepper .st").forEach(s=>s.onclick=()=>{
  const n=+s.dataset.st;
  const el = n===1? document.querySelector("#tab-restore .card") : (n===2? $("#rsConfig") : $("#rsPlan"));
  if(el && el.style.display!=="none") el.scrollIntoView({behavior:"smooth",block:"start"});
});
const navBtns=[...document.querySelectorAll("nav button[data-tab]")];
// Pages (barre latérale) — navigation « à la HYCU ». Les opérations (sauvegarde,
// restauration, politique, sources) s'ouvrent en MODALES depuis une page, comme dans
// HYCU. switchTab() accepte encore les anciens noms d'onglet (backup/restore/connect)
// pour les appels programmés existants, et les redirige vers la modale correspondante.
const PAGES=["dashboard","apps","policies","jobs","verify","settings"];
let curPage="dashboard";
function switchTab(tab){
  if(tab==="connect") return openSources();
  if(tab==="restore") return openRestoreModal(state.ns);
  if(tab==="backup") return openBackupModal(state.ns?[state.ns]:[]);
  closeAllModals();
  const navTab = tab==="verify" ? "apps" : tab;     // Vérification = sous-page d'Applications
  navBtns.forEach(x=>{ const on=x.dataset.tab===navTab; x.classList.toggle("on",on); x.setAttribute("aria-selected",on?"true":"false"); });
  PAGES.forEach(t=>$("#tab-"+t).style.display="none");
  $("#tab-"+tab).style.display="block";
  applyGlobalNs();                                   // la page ouverte reflète le namespace courant
  curPage=tab; onPageShown(tab);
  window.scrollTo({top:0});
}
navBtns.forEach(b=>b.onclick=()=>switchTab(b.dataset.tab));
$("#hdrConn").onclick=()=>openSources();

// ----- Fenêtre « À propos » (bouton ? de l'en-tête) -----
// « ? » : menu Aide (guide dans un nouvel onglet) / À propos (modale existante).
async function openAbout(){
  const r=await get("/api/config");
  $("#aboutAudit").textContent=r.audit_log||"—";
  $("#aboutCfg").textContent=r.config_path||"—";
  $("#aboutBk").textContent=r.backup_root||"—";
  $("#aboutModal").style.display="flex";
}
function toggleHelpMenu(){
  const m=$("#helpMenu");
  if(m.style.display==="block"){ m.style.display="none"; return; }
  $("#clMenu").style.display="none"; $("#gearMenu").style.display="none";
  const r=$("#aboutBtn").getBoundingClientRect();
  m.style.right=Math.max(8, window.innerWidth-r.right-10)+"px";
  m.style.display="block";
}
$("#aboutBtn").onclick=e=>{ e.stopPropagation(); toggleHelpMenu(); };
document.querySelectorAll("#helpMenu .cli").forEach(el=>el.onclick=e=>{
  e.stopPropagation(); $("#helpMenu").style.display="none";
  if(el.dataset.act==="about") openAbout();
});
$("#aboutClose").onclick=()=>{ $("#aboutModal").style.display="none"; };

// ----- Barre « action suivante » du parcours Restaurer (anti-scroll) -----
// La page Restaurer est longue : cette barre flottante rend l'étape suivante
// visible en permanence (références à remplir -> prévisualiser -> lancer),
// sans que l'opérateur ait à chercher le bouton en bas de page.
function rsNext(txt, btnLabel, fn){
  $("#rsNextTxt").innerHTML=txt;
  const b=$("#rsNextBtn"); b.textContent=btnLabel; b.onclick=fn;
  $("#rsNextBar").classList.add("show");
}
function hideNextBar(){ $("#rsNextBar").classList.remove("show"); }
function scrollPulse(el){ if(!el) return; el.scrollIntoView({behavior:"smooth",block:"center"});
  el.classList.remove("pulse"); void el.offsetWidth; el.classList.add("pulse"); }
function updateNextBar(){
  if($("#tab-restore").style.display==="none") return hideNextBar();
  const chks=[...document.querySelectorAll(".rsChk:checked")];
  const slClone = typeof rsStatelessClone==="function" && rsStatelessClone();
  if(!chks.length && !slClone) return hideNextBar();
  if(slClone && $("#rsPlan").style.display==="none")
    return rsNext("Application stateless : aucun volume à choisir.","Vérifier la copie",()=>$("#rsPreview").click());
  const hyOn = conn.hycu && conn.hycu.connected;
  // Étape 3 : plan affiché et lancement possible -> guider vers le bouton Lancer.
  if($("#rsPlan").style.display!=="none" && !$("#rsGo").disabled){
    return rsNext("Plan prêt — dernière étape :", $("#rsGo").textContent, ()=>scrollPulse($("#rsGo")));
  }
  // Restauration sur place orchestrée : compte des points sélectionnés.
  if(state.mode==="inplace" && hyOn){
    const ready=chks.map(c=>c.dataset.pvc).filter(p=>rsInplaceSel[p]).length;
    if(ready===chks.length)
      return rsNext("Tous les points de restauration sont sélectionnés.","Aller au lancement",()=>scrollPulse($("#rsInplaceRun")));
    return rsNext(ready+" / "+chks.length+" point(s) de restauration sélectionné(s).","Voir les volumes",()=>scrollPulse($("#rsVolCfgs")));
  }
  // Clone / flux manuel : compte des références VG remplies.
  const items=collectItems();
  const filled=items.filter(i=>(i.new_ref||"").trim()).length;
  if(filled===items.length)
    return rsNext("Toutes les références VG sont remplies.","Continuer : vérifier et lancer",()=>$("#rsPreview").click());
  const batch=$("#hyBatchGo");   // panneau HYCU groupé disponible -> c'est l'action naturelle
  if(batch && !batch.disabled)
    return rsNext(filled+" / "+items.length+" référence(s) VG remplie(s).","Restaurer les VG depuis HYCU",()=>scrollPulse(batch));
  return rsNext(filled+" / "+items.length+" référence(s) VG remplie(s).","Voir les volumes",()=>scrollPulse($("#rsVolCfgs")));
}
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
  await loadClusters();
  ctxInfo = await get("/api/context");
  renderCtx();
  renderKubeBanner();
  const n=await get("/api/namespaces");
  const opts = (n.namespaces||[]).map(x=>`<option>${esc(x)}</option>`).join("");
  ["#bkNs","#rsNs","#vfNs"].forEach(id=>$(id).innerHTML = opts || "<option>—</option>");
  if(n.error){["#bkNs","#rsNs","#vfNs"].forEach(id=>$(id).innerHTML="<option>kubectl ?</option>");}
  applyPrefs();                               // derniers choix de CE navigateur (ns, mode, dossiers)
  loadConfig();
  loadAutoBackup();
  await loadConnStatus();                     // ATTENDRE que `conn` soit prêt (sinon la popup
  maybePromptUnlock();                        // de déverrouillage ne s'affichait jamais)
  onPageShown(curPage);                       // (re)charge les données de la page affichée
}
(async()=>{
  ACTIVE_CID = prefs().cluster || "local";
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
  const names={hycu:"HYCU", nutanix:"Prism Element", prismcentral:"Prism Central", s3:"Stockage objet S3"};
  const lst=(r.loaded||[]).map(s=>names[s]||s).join(", ");
  const cls=(r.clusters||[]).join(", ");
  $("#unlockErr").innerHTML=`<div class="note">Connexions rechargées : ${esc(lst||"aucune")}.`+
    (cls?`<br>Clusters Kubernetes rechargés : ${esc(cls)}.`:"")+`</div>`;
  await loadConnStatus();
  await afterVaultLoad();
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
      pour le générer — vous pourrez tout modifier ensuite dans la page Réglages.</p>
      <label class="fld">Langue de l'interface</label>
      <div id="wLang">${[["fr","Français"],["en","English"]].map(([code,lbl])=>
        `<span class="chip ${PAGE_LANG===code?'sel':''}" data-lang="${code}">${lbl}</span>`).join("")}</div>
      <div class="note" style="margin-top:14px">Contexte kubectl détecté : <b>${esc(ctx||"indisponible")}</b></div>`,
     enter:()=>{ document.querySelectorAll("#wLang .chip").forEach(c=>c.onclick=()=>{
        const l=c.dataset.lang; if(l===PAGE_LANG) return;              // déjà dans cette langue
        // Change la langue et recharge : le coffre de config n'existe pas encore,
        // l'assistant se rouvre entièrement dans la langue choisie.
        document.cookie="hycu_lang="+l+";path=/;max-age=31536000;SameSite=Lax"; location.reload(); }); },
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
  const u="/api/backup/download?path="+encodeURIComponent(dir)+(root?("&root="+encodeURIComponent(root)):"")+"&cluster="+encodeURIComponent(ACTIVE_CID);
  return `<a class="btn ghost" href="${u}" download style="padding:2px 8px;font-size:12px;text-decoration:none;margin-left:6px">⬇ ${esc(label||'Télécharger (.zip)')}</a>`;
}
// ----- Sauvegarde automatique de la configuration (onglet 1) -----
function abSyncLbl(){
  const on=$("#abEnabled").checked, l=$("#abEnabledLbl");
  l.textContent = on? "Activée" : "Désactivée";
  l.style.color = on? "var(--good)" : "var(--muted)";
}
$("#abEnabled").onchange=abSyncLbl;
function abRetSync(){
  const gfs=$("#abRet").value==="gfs";
  $("#abKeepWrap").style.display=gfs?"none":"";
  $("#abGfsWrap").style.display=gfs?"flex":"none";
}
$("#abRet").onchange=abRetSync;
function abRetLabel(s){
  return s.retention==="gfs"
    ? "GFS "+((s.gfs||{}).daily??7)+" j / "+((s.gfs||{}).weekly??4)+" sem / "+((s.gfs||{}).monthly??12)+" mois"
    : (s.keep===0 ? "illimitée (pas de compteur)" : (s.keep||15)+" versions");
}
async function loadAutoBackup(){
  const s=await get("/api/auto_backup");
  if(!s || !s.ok) return;
  $("#abEnabled").checked=!!s.enabled; abSyncLbl();
  $("#abInterval").value=Math.round(s.interval_hours||24);
  $("#abKeep").value=s.keep||15;
  $("#abRet").value=(s.retention==="gfs")?"gfs":"count";
  const g=s.gfs||{}; $("#abGfsD").value=g.daily??7; $("#abGfsW").value=g.weekly??4; $("#abGfsM").value=g.monthly??12;
  abRetSync();
  if(!$("#abDest").value) $("#abDest").value=s.dest||"";
  let txt = s.enabled? ("Toutes les "+Math.round(s.interval_hours||24)+" h · rétention : "+abRetLabel(s)+" par namespace.") : "";
  if(s.running) txt+=" Sauvegarde en cours…";
  if(s.last_run) txt+=" Dernière : "+new Date(s.last_run*1000).toLocaleString()+" "+(s.last_ok?"✓":"✕")+" "+(s.last_summary||"");
  if(s.enabled) txt+= s.next_due? (" · Prochaine : "+new Date(s.next_due*1000).toLocaleString()) : " · Première exécution dans moins d'une minute.";
  $("#abStatus").textContent=txt;
}
$("#abSave").onclick=async()=>{
  const cfg={auto_backup_enabled:$("#abEnabled").checked,
    auto_backup_interval_hours:Math.max(1,parseInt($("#abInterval").value)||24),
    auto_backup_keep:Math.max(1,parseInt($("#abKeep").value)||15),
    auto_backup_retention:$("#abRet").value,
    auto_backup_keep_daily:Math.max(0,parseInt($("#abGfsD").value)||0),
    auto_backup_keep_weekly:Math.max(0,parseInt($("#abGfsW").value)||0),
    auto_backup_keep_monthly:Math.max(0,parseInt($("#abGfsM").value)||0),
    auto_backup_dest:$("#abDest").value.trim()};
  const r=await post("/api/config",{config:cfg});
  $("#abStatus").textContent = r.ok? "Enregistré." : ("Erreur : "+(r.error||""));
  setTimeout(loadAutoBackup, 700);
};
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
  const resLine = (r.resources_count!=null)
    ? ` <span class="hint">+ ${r.resources_count} ressource(s) de config (Deployments, Services, Secrets…)${r.secrets==="encrypted"?" · Secrets chiffrés":r.secrets==="redacted"?" · Secrets masqués":""}</span>` : "";
  const secWarn = r.secrets_warning ? `<div class="warnbox">⚠ ${esc(r.secrets_warning)}</div>` : "";
  $("#bkOut").innerHTML=`<div class="note">${r.count} volume(s) sauvegardé(s) dans
     <code>${esc(r.dir)}</code>${resLine}${dlBackupLink(r.dir, r.root)}</div>${secWarn}<ul class="pvc-list" style="margin-top:10px">${rows}</ul>
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
  openPolicyModal(ns || $("#bkNs").value);      // HYCU : « Définir la politique » (analyse lancée d'office)
}
$("#bkNs").onchange=()=>{ state.ns=$("#bkNs").value; savePref("ns",state.ns); applyGlobalNs(); clearBkProtect(); };  // ns global + invalide l'analyse
$("#vfNs").onchange=()=>{ state.ns=$("#vfNs").value; savePref("ns",state.ns); applyGlobalNs(); };
$("#bkDest").addEventListener("change",()=>savePref("bkDest",$("#bkDest").value.trim()));
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
  if(nx+nn>0){ $("#bkProtectForm").style.display="block"; loadBkPolicies(); updateBkHint(); }
};
// Liste des politiques HYCU de la modale « Définir la politique ». NB : nom distinct de
// loadPolicies() (page Politiques) — deux déclarations homonymes se masqueraient.
async function loadBkPolicies(){
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
$("#rsNs").onchange=()=>{ state.ns=$("#rsNs").value; savePref("ns",state.ns); applyGlobalNs(); loadPvcs(); };
$("#rsCustomDir").onchange=()=>{ savePref("customDir",$("#rsCustomDir").checked); $("#rsCustomDirWrap").style.display=$("#rsCustomDir").checked?"block":"none"; if($("#rsNs").value) loadPvcs(); };
$("#rsBackupRoot").addEventListener("change",()=>{ savePref("backupRoot",$("#rsBackupRoot").value.trim()); if($("#rsCustomDir").checked && $("#rsNs").value) loadPvcs(); });
$("#rsBackupSel").onchange=applyBackupSelection;   // changer de sauvegarde de config sans re-fetch
let rsBackups = [];   // sauvegardes de config du namespace courant (la plus récente en premier)
let loadPvcsSeq=0;     // jeton anti-course : un fetch dépassé (autre namespace/cluster) est ignoré
async function loadPvcs(){
  const sel=$("#rsNs"); if(!sel.value) return;
  const ns=sel.value; state.ns=ns; state.pvcNs=ns; rsHyMatch=null; rsInplaceSel={};
  if(state.app && state.app.ns!==ns){ state.app=null; $("#rsWizApp").innerHTML=rsAppLabel(); }   // autre namespace choisi : plus d'application ciblée
  const seq=++loadPvcsSeq;
  const customRoot = $("#rsCustomDir").checked ? $("#rsBackupRoot").value.trim() : "";
  state.backup_root = customRoot || null;
  const bk=await get("/api/backups?ns="+encodeURIComponent(ns)+(customRoot?("&root="+encodeURIComponent(customRoot)):""));
  if(seq!==loadPvcsSeq || state.ns!==ns) return;   // périmé : une autre application a été ouverte entre-temps
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
    const _dl=$("#rsBackupDl"); if(_dl){ _dl.href="/api/backup/download?path="+encodeURIComponent(b.path)+(customRoot?("&root="+encodeURIComponent(customRoot)):"")+"&cluster="+encodeURIComponent(ACTIVE_CID); _dl.style.display="inline"; }
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
     : `<div class="hint">Aucun volume. Sauvegardez d'abord la configuration de cette application (Applications → Sauvegarder).</div>`;
  document.querySelectorAll(".rsChk").forEach(c=>c.onchange=rebuildVolCfgs);
  $("#rsConfig").style.display="none"; $("#rsPlan").style.display="none"; setRsStep(1);
  // Assistant de restauration : comme dans HYCU, TOUS les volumes de l'application
  // sont présélectionnés (l'opérateur peut en décocher). Application ciblée (page
  // Applications) : seuls SES volumes le sont — les autres applications du namespace
  // ne sont pas touchées par défaut.
  if(rsAutoCheck && pvcs.length){
    const only = state.app && state.app.pvcs && state.app.pvcs.length ? new Set(state.app.pvcs) : null;
    document.querySelectorAll(".rsChk").forEach(c=>c.checked = !only || only.has(c.dataset.pvc));
    if(only && ![...document.querySelectorAll(".rsChk")].some(c=>c.checked)) document.querySelectorAll(".rsChk").forEach(c=>c.checked=true);
    rebuildVolCfgs();
  }
  updateNextBar();
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
  if(!chks.length){$("#rsConfig").style.display="none";setRsStep(1);updateNextBar();return;}
  $("#rsConfig").style.display="block"; $("#rsPlan").style.display="none"; setRsStep(2);
  const ntOn = (conn.nutanix && conn.nutanix.connected) || (conn.prismcentral && conn.prismcentral.connected);
  const hyOn = conn.hycu && conn.hycu.connected;
  const inplaceOrch = hyOn && state.mode==="inplace";
  // Une carte ÉPURÉE par volume : à l'écran, seulement « volume → VG HYCU » et le
  // point de restauration (rempli en asynchrone par buildHyPanel). Tout le reste —
  // noms générés (VG cloné, nouveau PV) et saisie manuelle de la référence — vit
  // dans UN SEUL volet « Avancé » replié : ce sont des valeurs par défaut correctes.
  $("#rsVolCfgs").innerHTML = chks.map(c=>{
    const pvc=c.dataset.pvc, pv=c.dataset.pv;
    const vgNameRow = (hyOn && state.mode==="clone")
      ? `<label class="fld">Nom du VG cloné</label>
         <input type="text" class="hyVgName" data-pvc="${esc(pvc)}" value="${esc(pvc+'-'+cloneStamp())}">` : "";
    const nameRow = state.mode==="clone"
      ? `<label class="fld">Nom du nouveau PV</label>
         <input type="text" class="rsName" data-pvc="${esc(pvc)}" value="${esc(suggestName(pv))}">` : "";
    const ntRow = ntOn
      ? `<button class="btn ghost ntRefBtn" data-pvc="${esc(pvc)}" style="margin-top:6px">Rechercher le VG dans Prism</button>
         <div class="ntpick" data-pvc="${esc(pvc)}"></div>` : "";
    const advOpen = hyOn ? "" : "open";   // sans HYCU, la saisie manuelle est la seule voie -> volet ouvert
    const advSum = hyOn ? "Avancé (optionnel) — noms générés, saisie manuelle"
                        : "Référence du VG (obligatoire) & noms générés";
    return `<div class="vol-cfg" data-pvc="${esc(pvc)}">
      <div class="nm">${esc(pvc)} <span class="hint">(PV ${esc(pv||'—')})</span> <span class="hint vgLabel" data-pvc="${esc(pvc)}" style="margin:0"></span> <span class="refStat hint" data-pvc="${esc(pvc)}" style="margin:0"></span></div>
      <div class="hySlot" data-pvc="${esc(pvc)}"></div>
      <details class="rsAdv" ${advOpen}>
        <summary class="rsAdvSum">${advSum}</summary>
        ${vgNameRow}${nameRow}
        <textarea class="rsRef" data-pvc="${esc(pvc)}" placeholder="5b4d284b-7109-4e82-4c71-7d0e36ecb5ab  (UUID du VG, ou NutanixVolumes-&lt;uuid&gt;, ou IQN legacy)"></textarea>${ntRow}
      </details></div>`;
  }).join("");
  document.querySelectorAll(".ntRefBtn").forEach(b=>b.onclick=()=>ntFindRef(b.dataset.pvc));
  // Bouton global d'orchestration sur place (mode inplace + HYCU)
  $("#rsInplaceRunWrap").style.display = inplaceOrch? "block":"none";
  if(inplaceOrch) updateInplaceRunBtn();
  // « Continuer » (construit le plan) : voie principale, sauf en sur-place orchestré
  // où le lancement se fait par le bouton dédié ci-dessus.
  $("#rsContinueWrap").style.display = inplaceOrch? "none":"block";

  // Guide en UNE ligne, adapté au cas (type d'opération + HYCU connecté ou non).
  let guide;
  if(state.mode==="inplace"){
    guide = hyOn
      ? "Choisissez un <b>point de restauration</b> par volume (le plus récent est pré-sélectionné), puis <b>Lancer la restauration sur place</b>."
      : "Restaurez le VG dans HYCU, collez son UUID par volume (volet <b>Avancé</b>), puis <b>Continuer : vérifier et lancer</b>. <span class='hint'>Connectez HYCU pour automatiser.</span>";
  } else {
    guide = hyOn
      ? "Choisissez un <b>point de restauration</b> par volume (le plus récent est pré-sélectionné), puis cliquez <b>Restaurer les VG depuis HYCU</b> — références et plan s'enchaînent automatiquement."
      : "Clonez chaque VG dans HYCU, collez son UUID par volume (volet <b>Avancé</b>), puis <b>Continuer : vérifier et lancer</b>. <span class='hint'>Connectez HYCU pour automatiser.</span>";
  }
  $("#rsFlowGuide").innerHTML = guide;
  // Barre « action suivante » + état des références en direct.
  document.querySelectorAll(".rsRef").forEach(t=>t.addEventListener("input",()=>{ refreshRefStats(); syncContinueVisibility(); updateNextBar(); }));
  refreshRefStats();
  rsFullOrch=false;     // recalculé par buildHyPanel selon la couverture HYCU
  buildHyPanel();       // remplit les points de restauration (asynchrone) — rien si HYCU non connecté
  updateNextBar();
}
// « Continuer : vérifier et lancer » n'est utile que pour le flux manuel : quand
// TOUS les volumes passent par le bouton HYCU groupé (plan automatique), on le
// masque pour ne laisser qu'UNE action à l'écran. Il réapparaît si l'utilisateur
// remplit les références à la main (volet Avancé).
let rsFullOrch=false;
function syncContinueVisibility(){
  const hyOn = conn.hycu && conn.hycu.connected;
  if(state.mode==="inplace" && hyOn){ $("#rsContinueWrap").style.display="none"; return; }
  const items=collectItems();
  const allFilled=items.length && items.every(i=>(i.new_ref||"").trim());
  $("#rsContinueWrap").style.display = (rsFullOrch && !allFilled)? "none":"block";
}
// État « référence remplie / à remplir » affiché à côté de chaque volume.
// En sur-place orchestré la référence n'est pas requise -> pas d'état.
function refreshRefStats(){
  const inplaceOrch = state.mode==="inplace" && conn.hycu && conn.hycu.connected;
  document.querySelectorAll(".refStat").forEach(el=>{
    const ta=document.querySelector(`.rsRef[data-pvc="${CSS.escape(el.dataset.pvc)}"]`);
    el.innerHTML = inplaceOrch? "" :
      ((ta && ta.value.trim())? '<span class="ok">✓ référence remplie</span>' : '<span class="sim">— référence à remplir</span>');
  });
}
let rsHyMatch=null;   // cache de la correspondance PVC↔VG HYCU pour le namespace courant
let hyPanelSeq=0;     // jeton anti-rendu périmé (la sélection peut changer pendant les fetch)
// --------- Panneau HYCU groupé : TOUS les volumes cochés en un seul geste ---------
// Remplit le point de restauration DANS la carte de chaque volume (.hySlot), puis
// rend l'action globale (#rsHyActions). Clone : UN SEUL bouton « Restaurer les VG
// depuis HYCU » qui clone tout et remplit les références. Sur place : le point le
// plus récent est pré-sélectionné -> le lancement est prêt d'emblée.
async function buildHyPanel(){
  const actions=$("#rsHyActions");
  const hyOn = conn.hycu && conn.hycu.connected;
  const chks=[...document.querySelectorAll(".rsChk:checked")].map(c=>c.dataset.pvc);
  actions.innerHTML="";
  if(!hyOn || !chks.length) return;
  const seq=++hyPanelSeq;
  document.querySelectorAll("#rsVolCfgs .hySlot").forEach(s=>
    s.innerHTML='<div class="hint" style="margin-top:4px"><span class="spin"></span> Recherche du Volume Group HYCU…</div>');
  const ns=$("#rsNs").value;
  if(!rsHyMatch || rsHyMatch.ns!==ns){
    const r=await get("/api/hycu/match?ns="+encodeURIComponent(ns));
    if(seq!==hyPanelSeq) return;
    if(!r.ok){ document.querySelectorAll("#rsVolCfgs .hySlot").forEach(s=>s.innerHTML=errBox(r.error)); return; }
    rsHyMatch={ns, matches:r.matches||[]};
  }
  const rows=await Promise.all(chks.map(async pvc=>{
    const m=(rsHyMatch.matches||[]).find(x=>x.pvc===pvc);
    if(!m || !m.matched) return {pvc, matched:false};
    const rp=await get("/api/hycu/restorepoints?source="+encodeURIComponent(m.hycu_vg_uuid));
    return {pvc, matched:true, vg:m.hycu_vg_uuid, vgName:m.hycu_vg_name||"", kind:m.match_kind,
            points:(rp.ok?(rp.points||[]):[]), rpErr:(rp.ok?null:(rp.error||"points indisponibles"))};
  }));
  if(seq!==hyPanelSeq) return;
  const isClone = state.mode==="clone";
  rows.forEach(r=>{
    const slot=document.querySelector(`#rsVolCfgs .hySlot[data-pvc="${CSS.escape(r.pvc)}"]`);
    if(!slot) return;
    const card=slot.closest(".vol-cfg");
    if(!r.matched){
      slot.innerHTML='<div class="warnbox" style="margin-top:6px">Aucun Volume Group HYCU associé — collez la référence dans « Avancé ».</div>';
      const d=card&&card.querySelector("details.rsAdv"); if(d) d.open=true;
      return;
    }
    const lbl=card&&card.querySelector(".vgLabel");
    if(lbl) lbl.innerHTML='→ VG HYCU <b>'+esc(r.vgName||r.vg)+'</b>'+(r.kind!=='exact'?' <span class="sim">(correspondance '+esc(r.kind)+' — à vérifier)</span>':'');
    if(r.rpErr){ slot.innerHTML=`<div class="warnbox" style="margin-top:6px">${esc(r.rpErr)}</div>`; return; }
    if(!(r.points||[]).length){ slot.innerHTML='<div class="warnbox" style="margin-top:6px">Aucun point de restauration pour ce VG.</div>'; return; }
    const opts=r.points.map((p,i)=>`<option value="${esc(p.id)}"${i===0?' selected':''}>${esc(p.time||p.id)}${p.status?(' · '+esc(p.status)):''}${i===0?' (le plus récent)':''}</option>`).join("");
    slot.innerHTML=`<label class="fld">Point de restauration</label>
      <select class="hyRp" data-pvc="${esc(r.pvc)}" data-vg="${esc(r.vg)}" data-name="${esc(r.vgName)}">${opts}</select>
      <div class="hyStat" data-pvc="${esc(r.pvc)}"></div>`;
    // Nom du VG cloné (volet Avancé) : basé sur le VG source dès qu'on le connaît,
    // sauf si l'utilisateur a déjà touché au champ.
    const nameEl=card&&card.querySelector(".hyVgName");
    if(nameEl && !nameEl.dataset.touched && r.vgName) nameEl.value=r.vgName+"-"+cloneStamp();
  });
  document.querySelectorAll(".hyVgName").forEach(i=>i.oninput=()=>{ i.dataset.touched="1"; });
  const ready=rows.filter(r=>r.matched && !r.rpErr && (r.points||[]).length);
  if(isClone){
    if(ready.length){
      actions.innerHTML=
        `<div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
           <button class="btn" id="hyBatchGo">Restaurer les VG depuis HYCU (${ready.length} volume(s))</button>
           <span class="hint" style="margin:0">Clone les VG au point choisi et remplit les références — aucune donnée écrasée.</span>
         </div>`;
      $("#hyBatchGo").onclick=hyBatchRun;
    }
    rsFullOrch = ready.length===chks.length && ready.length>0;
    syncContinueVisibility();
  } else {
    // Sur place : pré-sélectionner le point le plus récent de chaque volume.
    rsInplaceSel={};
    ready.forEach(r=>{ rsInplaceSel[r.pvc]={source_vg_uuid:r.vg, restore_point_id:r.points[0].id, vg_name:r.vgName}; });
    document.querySelectorAll("#rsVolCfgs .hyRp").forEach(sel=>sel.onchange=()=>{
      rsInplaceSel[sel.dataset.pvc]={source_vg_uuid:sel.dataset.vg, restore_point_id:sel.value, vg_name:sel.dataset.name};
      updateInplaceRunBtn();
    });
    updateInplaceRunBtn();
  }
  updateNextBar();
}
// Remplit la référence d'un volume (textarea du volet Avancé) et rafraîchit les états.
function setRef(pvc, val){
  const ta=document.querySelector(`.rsRef[data-pvc="${CSS.escape(pvc)}"]`);
  if(ta) ta.value=val;
  refreshRefStats(); updateNextBar();
}
// UUID du VG cloné, retrouvé côté Nutanix par nom EXACT (ne jamais deviner :
// un mauvais VG = un mauvais volume attaché).
async function lookupVgUuid(vgName){
  if(!((conn.nutanix&&conn.nutanix.connected)||(conn.prismcentral&&conn.prismcentral.connected)))
    return {ok:false, err:"Connectez Nutanix (Prism) pour récupérer la référence automatiquement, ou utilisez le volet Avancé."};
  const r=await get("/api/nutanix/vgs?q="+encodeURIComponent(vgName||""));
  if(!r.ok || !(r.vgs||[]).length) return {ok:false, err:"VG « "+vgName+" » introuvable côté Nutanix — utilisez le volet Avancé."};
  const exact=r.vgs.filter(v=>(v.name||"")===vgName);
  if(exact.length!==1) return {ok:false, err:(exact.length===0?"Aucun":"Plusieurs")+" VG nommé(s) exactement « "+vgName+" » — utilisez le volet Avancé pour choisir le bon."};
  if(!exact[0].uuid) return {ok:false, err:"VG trouvé mais UUID non exposé — utilisez le volet Avancé."};
  return {ok:true, uuid:exact[0].uuid, name:exact[0].name};
}
// Clone TOUS les volumes prêts dans HYCU (séquentiel : suivi lisible ligne par ligne),
// remplit les références, puis construit le plan automatiquement.
async function hyBatchRun(){
  const rows=[...document.querySelectorAll("#rsVolCfgs .vol-cfg")].map(div=>{
    const sel=div.querySelector(".hyRp"); if(!sel || !sel.value) return null;
    const nameEl=div.querySelector(".hyVgName");
    const newName=(nameEl&&nameEl.value.trim()) || ((sel.dataset.name||div.dataset.pvc)+"-"+cloneStamp());
    return {pvc:div.dataset.pvc, vg:sel.dataset.vg, rp:sel.value,
            newName, stat:div.querySelector(".hyStat")};
  }).filter(Boolean);
  if(!rows.length) return;
  const live=!dry();
  if(live && !(await confirmDanger({title:"Clones HYCU RÉELS", lines:[
     "Déclencher dans HYCU le <b>clone</b> de <b>"+rows.length+"</b> Volume Group(s) au point choisi ?",
     "Les VG sources ne sont <b>pas</b> modifiés — de <b>nouveaux</b> VG sont créés."]}))) return;
  const b=$("#hyBatchGo"); b.disabled=true; b.innerHTML='<span class="spin"></span>Clones HYCU en cours…';
  hideNextBar();
  let failed=0;
  for(const row of rows){
    row.stat.innerHTML='<div class="hint" style="margin-top:6px"><span class="spin"></span> Clone HYCU…</div>';
    const body={namespace:rsHyMatch.ns, source_uuid:row.vg, restore_point_id:row.rp,
                mode:"clone", new_name:row.newName, dry:dry()};
    const r=await post("/api/hycu/restore",body);
    if(!r.ok){ row.stat.innerHTML=errBox(r.error); failed++; continue; }
    if(r.dry){
      row.stat.innerHTML=`<div class="warnbox" style="margin-top:6px">Simulation — appel HYCU qui serait envoyé :</div><pre class="box">${esc(JSON.stringify(r.planned,null,2))}</pre>`;
      // En simulation aucun VG n'est créé : on inscrit une référence PROVISOIRE (le VG
      // source) pour pouvoir dérouler l'aperçu du plan ; en réel elle sera remplacée
      // par l'UUID du VG cloné découvert.
      const m=((rsHyMatch&&rsHyMatch.matches)||[]).find(x=>x.pvc===row.pvc);
      if(m && m.nutanix_uuid){ setRef(row.pvc, m.nutanix_uuid);
        row.stat.innerHTML+='<div class="hint">Référence provisoire (VG source) inscrite pour la simulation — remplacée par le VG cloné en réel.</div>'; }
      continue; }
    if(!r.job_id){ row.stat.innerHTML='<div class="warnbox" style="margin-top:6px">Job HYCU non identifié — récupérez la référence via le volet Avancé une fois le clone terminé.</div>'; failed++; continue; }
    const ok=await pollJobBar(r.job_id, row.stat);
    if(!ok){ failed++; continue; }
    const lu=await lookupVgUuid(row.newName);
    if(!lu.ok){ row.stat.innerHTML+=`<div class="warnbox">${esc(lu.err)}</div>`; failed++; continue; }
    setRef(row.pvc, lu.uuid);
    row.stat.innerHTML=`<div class="note" style="margin-top:6px">✓ VG cloné — référence <code>${esc(lu.uuid)}</code> remplie.</div>`;
  }
  b.disabled=false; b.textContent="Restaurer les VG depuis HYCU ("+rows.length+" volume(s))";
  if(dry()) return;                          // simulation : rien à préparer
  const items=collectItems();
  const allFilled=items.length && items.every(i=>(i.new_ref||"").trim());
  if(!failed && allFilled){
    // Enchaîner directement : construire le plan et amener l'opérateur au lancement.
    $("#rsPreview").click();
  } else {
    updateNextBar();
  }
}
// --------- Orchestration RESTAURATION SUR PLACE (arrêt -> restore in-place -> redémarrage) ---------
let rsInplaceSel={};   // {pvc: {source_vg_uuid, restore_point_id, vg_name}}
function updateInplaceRunBtn(){
  const chosen=[...document.querySelectorAll(".rsChk:checked")].map(c=>c.dataset.pvc);
  const ready=chosen.filter(p=>rsInplaceSel[p]);
  if(!$("#rsInplaceRun")) return;
  $("#rsInplaceRun").disabled = ready.length===0;
  $("#rsInplaceHint").textContent = ready.length
    ? (ready.length+" / "+chosen.length+" volume(s) prêt(s)"+(dry()?" · simulation":" · MODE RÉEL"))
    : "Sélectionnez un point de restauration par volume.";
  updateNextBar();
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
       "Cluster ciblé : <b>"+esc(ctxInfo.context||"?")+"</b>",
       "L'application sera <b>ARRÊTÉE</b>, les volumes restaurés <b>in-place</b> dans HYCU (données écrasées par le point choisi), puis l'application <b>REDÉMARRÉE</b>."]});
    if(!res) return;
    if(typeof res==="string") confirmedCtx=res;
  }
  hideNextBar();   // pas de « prochaine action » pendant l'exécution
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
  if(!r.dry && r.ok && !r.aborted){
    $("#rsInplaceLog").insertAdjacentHTML("afterbegin",'<div class="note">Ouverture de la vérification…</div>');
    setTimeout(()=>gotoVerify(ipBody.namespace,true),1200);
  }
};
document.querySelectorAll("#rsMode button").forEach(b=>b.onclick=()=>{
  document.querySelectorAll("#rsMode button").forEach(x=>x.classList.remove("on"));
  b.classList.add("on"); state.mode=b.dataset.mode; savePref("mode",state.mode);
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
          app: rsStatelessClone() ? state.app.name : undefined,
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
  $("#rsSteps").innerHTML='<li>Créer le namespace cible (si « autre »)</li>'+(rsStatelessClone()?'':'<li>Créer les PV/PVC clonés (sur le VG cloné)</li>')+'<li>Créer les applications clonées (elles démarrent automatiquement)</li><li>L\'application d\'origine n\'est PAS modifiée ni arrêtée</li>';
  $("#rsPlan").style.display="block"; setRsStep(3);
  updateGoButton(r.ok);
  $("#rsPlan").scrollIntoView({behavior:"smooth",block:"start"});   // amener l'étape 3 sous les yeux
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
  if(!items.length && !rsStatelessClone()){$("#rsErr").innerHTML='<div class="err">Cochez au moins un PVC.</div>';return;}
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
  $("#rsPlan").scrollIntoView({behavior:"smooth",block:"start"});   // amener l'étape 3 sous les yeux
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
  updateNextBar();
}
$("#dry").addEventListener("change",()=>{ if($("#rsPlan").style.display!=="none") updateGoButton(!$("#rsGo").disabled); });

$("#rsGo").onclick=async()=>{
  hideNextBar();   // pas de « prochaine action » pendant l'exécution
  const live=!dry();
  if(state.preview && state.preview._cloneapp){
    let confirmedCtxCA="";
    if(live){
      const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||"") : null;
      const res = await confirmDanger({title:"Clone d'application RÉEL", requireText:needCtx, lines:[
         "Une <b>COPIE</b> de l'application sera créée"+(state.cloneNsMode==="same"?" dans le <b>même namespace</b> (avec suffixe)":" dans le namespace cible <b>"+esc($("#rsCloneTargetNs").value||"?")+"</b>")+".",
         "Cluster ciblé : <b>"+esc(ctxInfo.context||"?")+"</b>",
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
    if(!r.dry && r.ok){
      const tgt = state.cloneNsMode==="other" ? $("#rsCloneTargetNs").value.trim() : $("#rsNs").value;
      if((r.warnings||[]).length){   // laisser lire les avertissements ; la vérification est à un clic
        $("#rsLog").insertAdjacentHTML("beforeend",'<div style="margin-top:8px"><button class="btn" id="rsGoVerify">Vérifier l\'application maintenant →</button></div>');
        $("#rsGoVerify").onclick=()=>gotoVerify(tgt,true);
      } else {
        $("#rsLog").insertAdjacentHTML("afterbegin",'<div class="note">Ouverture de la vérification…</div>');
        setTimeout(()=>gotoVerify(tgt,true),1200);
      }
    }
    return;
  }
  let confirmedCtx="";
  if(live){
    const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||"") : null;
    const res = await confirmDanger({title:"Restauration RÉELLE", requireText:needCtx, lines:[
      "Namespace : <b>"+esc($("#rsNs").value||"?")+"</b>",
      "Cluster ciblé : <b>"+esc(ctxInfo.context||"?")+"</b>",
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
  if(!r.dry && r.ok && !r.aborted){
    if(reprot){   // ne pas quitter la page tant que la re-protection HYCU n'est pas traitée
      $("#rsLog").insertAdjacentHTML("beforeend",'<div style="margin-top:8px"><button class="btn" id="rsGoVerify">Vérifier l\'application maintenant →</button></div>');
      $("#rsGoVerify").onclick=()=>gotoVerify($("#rsNs").value,true);
    } else {
      $("#rsLog").insertAdjacentHTML("afterbegin",'<div class="note">Ouverture de la vérification…</div>');
      setTimeout(()=>gotoVerify($("#rsNs").value,true),1200);
    }
  }
};

// --------- Vérification ---------
async function runVerify(){
  const ns=$("#vfNs").value;
  const r=await get("/api/verify?ns="+encodeURIComponent(ns));
  if(r.error){
    let html=errBox(r.error);
    // Erreur actionnable : namespace hors liste blanche (ex. namespace créé par un
    // clone AVANT que l'ajout automatique n'existe) -> proposer l'ajout en un clic.
    if(r.ns_not_allowed) html+=`<div style="margin-top:8px"><button class="btn" id="vfAllowNs">Autoriser « ${esc(ns)} » et réessayer</button></div>`;
    $("#vfOut").innerHTML=html;
    const ab=$("#vfAllowNs");
    if(ab) ab.onclick=async()=>{
      const f=await get("/api/ns_filter");
      const rr=await post("/api/ns_filter",{filter:(f.filter||[]).concat([ns])});
      if(!rr.ok){ $("#vfOut").innerHTML=errBox(rr.error||"Mise à jour du filtre impossible."); return; }
      const n=await get("/api/namespaces");            // recharger les listes déroulantes
      const opts=(n.namespaces||[]).map(x=>`<option>${esc(x)}</option>`).join("");
      ["#bkNs","#rsNs","#vfNs"].forEach(id=>$(id).innerHTML=opts||"<option>—</option>");
      $("#vfNs").value=ns; state.ns=ns; applyGlobalNs();
      runVerify();
    };
    return false;
  }
  const pvcs=r.pvcs.map(p=>`<li class="logline"><span>${badge(p.phase)} <b>${esc(p.name)}</b>
     <span class="hint">→ ${esc(p.pv||'—')}</span></span></li>`).join("")||'<div class="hint">Aucun PVC.</div>';
  let allReady=r.pods.length>0;
  const pods=r.pods.map(p=>{
    const ok=p.phase==="Running"; if(!ok) allReady=false;
    const issue = p.issue ? `<div class="hint" style="color:var(--red);margin-top:3px">⚠ ${esc(p.issue.reason)}${p.issue.count>1?' (×'+p.issue.count+')':''} : ${esc(p.issue.message)}</div>` : "";
    return `<li class="logline"><span class="ic ${ok?'ok':'sim'}">${ok?'✓':'○'}</span>
     <span><b>${esc(p.name)}</b> <span class="hint">${esc(p.phase)}${p.waiting?' · '+esc(p.waiting):''} · prêts ${esc(p.ready)}</span>${issue}</span></li>`;}).join("")
     ||'<div class="hint">Aucun pod.</div>';
  $("#vfOut").innerHTML=`<div style="margin-top:12px"><b style="font-size:13px">PVC</b>
     <ul class="pvc-list">${pvcs}</ul><b style="font-size:13px">Pods</b><ul class="pvc-list">${pods}</ul></div>`;
  const allBound=r.pvcs.every(p=>(p.phase||"").toLowerCase()==="bound");
  return allBound && allReady;
}
$("#vfRun").onclick=runVerify;
// Suivi auto CONTINU : rafraîchit toutes les ~3 s jusqu'à l'état stable (tous les PVC
// Bound + pods Running), avec plafond de sécurité ~10 min. Re-cliquer arrête le suivi.
let vfTrack=false;
function vfSetBtn(){ $("#vfAuto").textContent = vfTrack? "■ Arrêter le suivi" : "Suivi auto (jusqu'à stable)"; }
async function vfAutoTrack(){
  if(vfTrack){ vfTrack=false; return; }          // stop demandé : la boucle en cours s'arrête
  vfTrack=true; vfSetBtn();
  for(let i=0;i<200 && vfTrack;i++){             // ~10 min à 3 s
    const done=await runVerify();
    if(done){ $("#vfOut").insertAdjacentHTML("afterbegin",'<div class="note">État stable : tous les PVC sont Bound et les pods Running.</div>'); break; }
    await sleep(3000);
  }
  vfTrack=false; vfSetBtn();
}
$("#vfAuto").onclick=vfAutoTrack;
// Ouvre l'onglet Vérifier sur un namespace donné (après une restauration réelle) et
// démarre le suivi. Un namespace fraîchement créé (clone d'app) est ajouté à la liste.
function gotoVerify(ns, track){
  if(ns){
    const sel=$("#vfNs");
    if(sel && ![...sel.options].some(o=>o.value===ns)) sel.insertAdjacentHTML("beforeend",`<option>${esc(ns)}</option>`);
    state.ns=ns;
  }
  switchTab("verify");
  if(track && !vfTrack) vfAutoTrack(); else runVerify();
}

// --------- Réglages ---------
async function loadConfig(){
  const r=await get("/api/config"); const c=r.config||{};
  $("#cfgKubectl").value=c.kubectl_path||""; $("#cfgVhPrefix").value=c.volume_handle_prefix||"";
  $("#cfgCtx").value=(c.allowed_contexts||[]).join(", ");
  $("#cfgNs").value=(c.namespace_filter||[]).join(", ");
  $("#cfgLabelSel").value=c.namespace_label_selector||"";
  $("#cfgAuditDays").value=(c.audit_retention_days??31);
  $("#cfgMinFree").value=(c.storage_min_free_mb??500);
  $("#cfgQuota").value=(c.storage_quota_gb??0);
  $("#cfgDr").checked=!!c.allow_dr_restore;
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
    namespace_label_selector:$("#cfgLabelSel").value.trim(),
    audit_retention_days:Math.max(0,parseInt($("#cfgAuditDays").value)||0),
    storage_min_free_mb:Math.max(0,parseInt($("#cfgMinFree").value)||0),
    storage_quota_gb:Math.max(0,parseInt($("#cfgQuota").value)||0),
    allow_dr_restore:$("#cfgDr").checked,
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
  let s = await get("/api/conn_status");
  if(!s || !s.hycu) s = {hycu:{}, nutanix:{}, prismcentral:{}, vault:(s&&s.vault)||{}};  // réponse d'erreur : ne pas casser l'init
  conn = s;
  ntAllVgs=null;   // invalide le cache des VG Nutanix après tout (dé)connexion
  const st=(x)=>connDot(x.connected)+(x.connected?"connecté":"non connecté");
  $("#hyStatus").innerHTML=st(s.hycu); $("#ntStatus").innerHTML=st(s.nutanix); $("#pcStatus").innerHTML=st(s.prismcentral);
  const s3=s.s3||{};
  $("#s3Status").innerHTML=st(s3);
  if(!$("#s3Url").value) $("#s3Url").value=s3.url||"";
  if(!$("#s3Bucket").value) $("#s3Bucket").value=s3.bucket||"";
  if(!$("#s3Region").value) $("#s3Region").value=s3.region||"";
  $("#s3Tls").checked=!!s3.verify_tls; $("#s3Auto").checked=!!s3.auto_upload;
  $("#s3Enc").checked=!!s3.encrypt; $("#s3EncWrap").style.display=s3.encrypt?"block":"none";
  if(!$("#hyUrl").value) $("#hyUrl").value = s.hycu.url||"";
  if(!$("#ntUrl").value) $("#ntUrl").value = s.nutanix.url||"";
  if(!$("#pcUrl").value) $("#pcUrl").value = s.prismcentral.url||"";
  $("#hyTls").checked=!!s.hycu.verify_tls; $("#ntTls").checked=!!s.nutanix.verify_tls; $("#pcTls").checked=!!s.prismcentral.verify_tls;
  $("#bkProtectOff").style.display = s.hycu.connected? "none":"block";
  $("#bkProtectOn").style.display = s.hycu.connected? "block":"none";
  renderHdrConn();
  loadVaultStatus();
}
// Pastilles d'état permanentes dans l'en-tête : HYCU / Prism Element / Prism Central.
// Un clic ouvre l'onglet Connexions (l'opérateur voit AVANT d'agir s'il est connecté).
function renderHdrConn(){
  $("#hdrConn").innerHTML=[["HYCU",conn.hycu],["PE",conn.nutanix],["PC",conn.prismcentral]]
    .map(([l,x])=>`<span class="hc">${connDot(!!(x&&x.connected))}${l}</span>`).join("");
  renderSourcesTable();
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
    <div class="hint" style="margin-top:6px">Les opérations <b>Sauvegarder</b>, <b>Restaurer</b> (séquence Kubernetes) et <b>Vérifier</b> nécessitent kubectl. Les connexions <b>HYCU / Nutanix</b> fonctionnent, elles, sans kubectl.${ctxInfo.error?`<br><code style="color:#7a221b">${esc(ctxInfo.error)}</code>`:''}</div></div>`;
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
  $("#vaultErr").innerHTML = r.ok? `<div class="note">Connexions chiffrées : ${esc((r.saved||[]).join(', ')||"—")}.`+
      ((r.clusters||[]).length?`<br>Clusters Kubernetes chiffrés : ${esc(r.clusters.join(', '))}.`:"")+`</div>`
                                 : errBox(r.error);
  await loadConnStatus();
};
$("#vaultLoad").onclick=async()=>{
  const r=await vaultAction("/api/creds/load", true);
  $("#vaultErr").innerHTML = r.ok? `<div class="note">Connexions chargées : ${esc((r.loaded||[]).join(', ')||"—")}.`+
      ((r.clusters||[]).length?`<br>Clusters Kubernetes chargés : ${esc(r.clusters.join(', '))}.`:"")+`</div>`
                                 : errBox(r.error);
  await loadConnStatus();
  if(r.ok) await afterVaultLoad();
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
$("#s3Connect").onclick=async()=>{
  $("#s3Err").innerHTML="";
  const b=$("#s3Connect"); b.disabled=true; b.innerHTML='<span class="spin"></span>Test du bucket…';
  const r=await post("/api/s3/connect",{s3_url:$("#s3Url").value.trim(), s3_bucket:$("#s3Bucket").value.trim(),
    s3_region:$("#s3Region").value.trim()||"us-east-1", s3_verify_tls:$("#s3Tls").checked,
    s3_path_style:$("#s3PathStyle").checked, s3_auto_upload:$("#s3Auto").checked,
    s3_encrypt:$("#s3Enc").checked, enc_passphrase:$("#s3EncPass").value,
    access:$("#s3Access").value.trim(), secret:$("#s3Secret").value});
  $("#s3Secret").value=""; $("#s3EncPass").value=""; b.disabled=false; b.textContent="Tester & connecter";
  if(!r.ok){ $("#s3Err").innerHTML=errBox(r.error); }
  else { $("#s3Err").innerHTML=`<div class="note">Bucket « ${esc(r.bucket||"")} » accessible.`+
    (r.auto_upload?" Export automatique activé.":" Export automatique désactivé (cochez la case pour l'activer).")+`</div>`; }
  await loadConnStatus();
};
$("#s3Enc").onchange=()=>{ $("#s3EncWrap").style.display=$("#s3Enc").checked?"block":"none"; };
function s3ImpSync(){ $("#s3ImportBtn").disabled = !document.querySelectorAll(".s3ImpChk:checked").length; }
$("#s3ListBtn").onclick=async()=>{
  const w=$("#s3ImportWrap");
  if(w.style.display!=="none"){ w.style.display="none"; return; }
  w.style.display="block"; $("#s3ImpRes").innerHTML="";
  $("#s3ListOut").innerHTML='<div class="hint"><span class="spin"></span>Liste du bucket…</div>';
  const r=await get("/api/s3/list");
  if(!r.ok){ $("#s3ListOut").innerHTML=errBox(r.error); return; }
  const o=r.objects||[];
  $("#s3ListOut").innerHTML = o.length? `<div class="tcard" style="box-shadow:none;border:1px solid var(--rule)"><table class="ht"><thead><tr><th class="cb"><input type="checkbox" id="s3ImpAll"></th><th>Cluster</th><th>Application</th><th>Horodatage</th><th>Taille</th><th>Chiffré</th></tr></thead><tbody>`+
    o.map((x,i)=>`<tr><td class="cb"><input type="checkbox" class="s3ImpChk" data-i="${i}"></td><td>${esc(x.cluster)}</td><td style="color:var(--strong)">${esc(x.namespace)}</td><td>${esc(x.timestamp)}</td><td>${esc(fmtBytes(x.size))}</td><td>${x.encrypted?"oui":"—"}</td></tr>`).join("")+
    `</tbody></table></div>` : '<div class="hint">Aucun export de l\'outil dans ce bucket.</div>';
  window.s3Objs=o;
  document.querySelectorAll(".s3ImpChk").forEach(c=>c.onchange=s3ImpSync);
  const all=$("#s3ImpAll"); if(all) all.onchange=()=>{ document.querySelectorAll(".s3ImpChk").forEach(c=>c.checked=all.checked); s3ImpSync(); };
  s3ImpSync();
};
$("#s3ImportBtn").onclick=async()=>{
  const items=[...document.querySelectorAll(".s3ImpChk:checked")].map(c=>({key:(window.s3Objs||[])[+c.dataset.i].key}));
  if(!items.length) return;
  const b=$("#s3ImportBtn"); b.disabled=true; b.innerHTML='<span class="spin"></span>Import…';
  const r=await post("/api/s3/import",{items, enc_passphrase:$("#s3ImpPass").value});
  $("#s3ImpPass").value=""; b.disabled=false; b.textContent="Importer la sélection"; s3ImpSync();
  const res=r.results||[];
  $("#s3ImpRes").innerHTML=(r.error&&!res.length?errBox(r.error):"")+(res.length?`<ul class="dlist" style="margin-top:10px">`+res.map(x=>
    `<li><span class="k" style="display:flex;gap:10px;align-items:center">${stIc(x.ok?"ok":"ko")}${esc(x.key)}</span>`+
    `<span class="v" style="font-weight:400">${x.ok? x.files+" fichier(s)" : esc(x.error||"")}</span></li>`).join("")+"</ul>":"");
};
$("#s3Disconnect").onclick=async()=>{ await post("/api/disconnect",{system:"s3"}); $("#s3Err").innerHTML=""; await loadConnStatus(); };
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
    if(/^(OK|DONE|SUCCESS|SUCCEEDED|COMPLETED?|FINISHED|WARNING)$/i.test(status)){ el.innerHTML+='<div class="note" style="margin-top:6px">Job terminé avec succès.</div>'; return true; }
    if(/^(FAILED|ERROR|FATAL|ABORTED?|CANCEL+ED|TIMEOUT)$/i.test(status)){ el.innerHTML+='<div class="err" style="margin-top:6px">Job en échec — vérifiez dans HYCU.</div>'; return false; }
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
  onPageShown(curPage);                          // Applications / tableau de bord à jour
};
refreshDry();

// ============================================================================
// Interface « HYCU Enterprise Cloud » : pages (Tableau de bord, Applications,
// Politiques, Tâches) et modales d'opération (Sauvegarde, Définir la politique,
// Restauration, Sources). Les blocs d'origine (mêmes IDs, même logique testée)
// sont hébergés dans ces modales : ce code se contente de les piloter.
// ============================================================================
var rsAutoCheck=false;            // assistant ouvert : volumes présélectionnés (cf. renderRsPvcs)
var pageTimer=null;
const MODALS=["mBackup","mPolicy","mRestore","mSources"];
function openModal(id){ $("#"+id).style.display="flex"; }
function closeModal(id){
  const m=$("#"+id); if(!m || m.style.display==="none") return;
  m.style.display="none";
  if(id==="mRestore") rsAutoCheck=false;
  if(id!=="mSources") onPageShown(curPage);        // l'opération a pu changer l'état affiché
}
function closeAllModals(){ MODALS.forEach(closeModal); }
document.querySelectorAll("[data-close]").forEach(b=>b.onclick=()=>closeModal(b.dataset.close));
document.addEventListener("keydown",e=>{
  if(e.key!=="Escape") return;
  if($("#dangerModal").style.display!=="none" || $("#nsFilter").style.display!=="none") return;
  const open=MODALS.filter(id=>$("#"+id).style.display!=="none");
  if(open.length) closeModal(open[open.length-1]);
});
function bindGo(root){ (root||document).querySelectorAll("[data-go]").forEach(a=>a.onclick=e=>{ e.preventDefault(); switchTab(a.dataset.go); }); }
bindGo();

// ----- Barre du haut / barre latérale -----
// Engrenage : petit menu (Sources / Réglages), même style que le menu des clusters.
function toggleGearMenu(){
  const m=$("#gearMenu");
  if(m.style.display==="block"){ m.style.display="none"; return; }
  $("#clMenu").style.display="none"; $("#helpMenu").style.display="none";
  const r=$("#srcBtn").getBoundingClientRect();
  m.style.right=Math.max(8, window.innerWidth-r.right-10)+"px";
  m.style.display="block";
}
$("#srcBtn").onclick=e=>{ e.stopPropagation(); toggleGearMenu(); };
document.querySelectorAll("#gearMenu .cli").forEach(el=>el.onclick=e=>{
  e.stopPropagation(); $("#gearMenu").style.display="none";
  if(el.dataset.act==="sources") openSources();
  else switchTab("settings");
});
$("#ctxLink").onclick=e=>{ e.stopPropagation(); toggleClMenu(); };
$("#tbHome").onclick=e=>{ e.preventDefault(); switchTab("dashboard"); };
$("#sbCol").onclick=()=>{ const m=!document.body.classList.contains("sb-min");
  document.body.classList.toggle("sb-min",m); savePref("sbMin",m); };
if(prefs().sbMin) document.body.classList.add("sb-min");

// ----- Petits formats -----
const AGO={now:"à l'instant", min:"il y a %d min", h:"il y a %d h", d:"il y a %d j"};
function fmtAgo(ts){
  if(!ts) return "";
  const s=Math.max(0, Date.now()/1000-ts);
  if(s<60) return AGO.now;
  if(s<3600) return AGO.min.replace("%d", Math.round(s/60));
  if(s<86400) return AGO.h.replace("%d", Math.round(s/3600));
  return AGO.d.replace("%d", Math.round(s/86400));
}
function fmtTs(iso){ if(!iso) return "—"; const d=new Date(iso); return isNaN(d)? String(iso) : d.toLocaleString(); }
function stIc(kind, title){
  const g={ok:"✓", ko:"✕", wn:"!", na:"?", sim:"○", run:"▸"}[kind]||"?";
  return `<span class="st ${kind}" title="${esc(title||"")}">${g}</span>`;
}
function dnums(l1, v1, l2, v2){
  return `<div class="dnums"><div><div class="l">${l1}</div><div class="v">${v1}</div></div>`+
         `<div><div class="l">${l2}</div><div class="v">${v2}</div></div></div>`;
}
// Anneaux « à la HYCU » : extérieur (épais) = première mesure, intérieur (fin) = seconde.
function donutSVG(outer, inner){
  const clamp=v=>Math.max(0, Math.min(100, v||0));
  const R1=62, R2=47, C1=2*Math.PI*R1, C2=2*Math.PI*R2, o=clamp(outer), i=clamp(inner);
  return `<svg class="donut" width="164" height="164" viewBox="0 0 164 164" aria-hidden="true">
    <circle cx="82" cy="82" r="76" fill="none" stroke="#9BDAC7" stroke-width="5"/>
    <circle cx="82" cy="82" r="${R1}" fill="none" stroke="#F6D3D1" stroke-width="15"/>
    <circle cx="82" cy="82" r="${R1}" fill="none" stroke="#05A274" stroke-width="15"
            stroke-dasharray="${(C1*o/100).toFixed(1)} ${C1.toFixed(1)}" transform="rotate(-90 82 82)"/>
    <circle cx="82" cy="82" r="${R2}" fill="none" stroke="#EEF0F5" stroke-width="5"/>
    <circle cx="82" cy="82" r="${R2}" fill="none" stroke="#9BDAC7" stroke-width="5"
            stroke-dasharray="${(C2*i/100).toFixed(1)} ${C2.toFixed(1)}" transform="rotate(-90 82 82)"/>
  </svg>`;
}

// ----- Pages : chargement des données à l'affichage (+ rafraîchissement) -----
function onPageShown(tab){
  clearInterval(pageTimer); pageTimer=null;
  const every=(fn, ms)=>{ pageTimer=setInterval(()=>{ if(document.visibilityState==="visible") fn(); }, ms); };
  if(tab==="dashboard"){ loadDashboard(); every(loadDashboard, 30000); }
  else if(tab==="apps") loadApps();
  else if(tab==="jobs"){ loadJobs(); every(loadJobs, 5000); }
  else if(tab==="policies") loadPolicies();
}

// ============================ Applications ============================
let apps=[], appsSel=new Set(), appsFresh=24, appsPolicy={}, appsScope="one", appsClErr=[];
// Clé de sélection = cluster|namespace (vue « Tous les clusters » : un même nom de
// namespace peut exister sur plusieurs clusters).
// Clé d'une ligne : cluster | namespace | application (plusieurs applications par namespace).
const appKey=a=>(a.cluster_id||ACTIVE_CID)+"|"+(a.namespace||a.name)+"|"+a.name;
const appNs=a=>a.namespace||a.name;
// Libellé du type d'application (stateful = monte des volumes ; stateless = configuration seule).
function appTypeCell(a){
  if(a.missing) return '<span class="badge b-lost">Supprimée — restaurable</span>'+(a.type==="stateless"?' <span class="hint">stateless</span>':"");
  if(a.type==="stateful") return '<span class="badge b-bound">Stateful</span> <span class="hint">'+(a.volumes||0)+' volume(s)</span>'+(a.unassigned?' <span class="hint">· sans workload</span>':"");
  if(a.type==="stateless") return '<span class="badge b-pending">Stateless</span> <span class="hint">'+((a.workloads||[]).length)+' workload(s)</span>';
  if(a.type==="empty") return '<span class="badge b-na">Vide</span>';
  return '<span class="badge b-na">Namespace</span>';
}
function updateScopeSeg(){
  const multi=CLUSTERS.length>1;
  $("#appsScope").style.display = multi ? "" : "none";
  if(!multi) appsScope="one";
  else if(prefs().appsScope==="all") appsScope="all";
  document.querySelectorAll("#appsScope button").forEach(b=>b.classList.toggle("on", b.dataset.scope===appsScope));
}
document.querySelectorAll("#appsScope button").forEach(b=>b.onclick=()=>{
  appsScope=b.dataset.scope; savePref("appsScope", appsScope); appsSel.clear();
  document.querySelectorAll("#appsScope button").forEach(x=>x.classList.toggle("on", x===b));
  loadApps();
});
// `fresh` (bouton Actualiser) : ignore le cache serveur de l'inventaire (apps_cache_ttl_s).
async function loadApps(fresh){
  $("#appsRefresh").classList.add("busy");
  const all = appsScope==="all";
  const r=await get("/api/applications?"+(all ? "scope=all" : "scope=one")+(fresh ? "&fresh=1" : ""));
  $("#appsRefresh").classList.remove("busy");
  apps=(r.apps||[]).map(a=>all ? a : Object.assign({}, a, {cluster_id:ACTIVE_CID}));
  appsFresh=r.freshness_hours||24; appsPolicy=r.policy||{};
  appsClErr = all ? (r.clusters||[]).filter(c=>!c.ok && !c.skipped) : [];
  if(all) apps.sort((x,y)=>(x.workspace||"").localeCompare(y.workspace||"") || (x.cluster||"").localeCompare(y.cluster||"") || appNs(x).localeCompare(appNs(y)) || x.name.localeCompare(y.name));
  const keys=new Set(apps.map(appKey));
  [...appsSel].forEach(k=>{ if(!keys.has(k)) appsSel.delete(k); });
  $("#appsTable").classList.toggle("multi", all);
  if(!r.ok && !apps.length){
    $("#appsBody").innerHTML=`<tr><td colspan="11">${errBox(r.error||"kubectl ?")}</td></tr>`;
    updateAppActs(); return r;
  }
  renderApps(); return r;
}
function appPolicyLabel(){
  return appsPolicy.enabled ? ("Configuration auto · "+Math.round(appsPolicy.interval_hours||24)+" h") : "Aucune";
}
function appsVisible(){
  const q=($("#appsSearch").value||"").trim().toLowerCase();
  return apps.filter(a=>!q || a.name.toLowerCase().includes(q) || appNs(a).toLowerCase().includes(q)
                           || (a.cluster||"").toLowerCase().includes(q) || (a.workspace||"").toLowerCase().includes(q));
}
// Pagination : au-delà de APPS_PAGE_SIZE lignes (grands clusters), le tableau est
// découpé en pages ; la recherche s'applique à toutes les lignes, la sélection persiste.
const APPS_PAGE_SIZE=100; let appsPage=0;
function appsPageRows(rows){
  const nPages=Math.max(1, Math.ceil(rows.length/APPS_PAGE_SIZE));
  if(appsPage>=nPages) appsPage=nPages-1;
  const pg=$("#appsPager");
  if(rows.length<=APPS_PAGE_SIZE){ pg.style.display="none"; pg.innerHTML=""; return rows; }
  const from=appsPage*APPS_PAGE_SIZE, to=Math.min(rows.length, from+APPS_PAGE_SIZE);
  pg.style.display="";
  pg.innerHTML=`<button class="pact" type="button" id="appsPrev" ${appsPage===0?"disabled":""} title="Page précédente">‹</button> `+
    `<span>${from+1}–${to} / ${rows.length}</span> `+
    `<button class="pact" type="button" id="appsNext" ${appsPage>=nPages-1?"disabled":""} title="Page suivante">›</button>`;
  $("#appsPrev").onclick=()=>{ appsPage--; renderApps(); };
  $("#appsNext").onclick=()=>{ appsPage++; renderApps(); };
  return rows.slice(from, to);
}
function renderApps(){
  const rowsAll=appsVisible(), all=appsScope==="all";
  const nNs=new Set(rowsAll.map(a=>(a.cluster_id||"")+"|"+appNs(a))).size;
  $("#appsInfo").textContent=rowsAll.length+" application(s) · "+nNs+" namespace(s)";
  const rows=appsPageRows(rowsAll);
  let h="";
  appsClErr.forEach(c=>{ h+=`<tr class="grp"><td colspan="11">${c.workspace?esc(c.workspace)+'<span class="gs">›</span>':""}${esc(c.cluster)}`+
                             `<span class="ge">${stIc("ko")} ${esc(c.error||"injoignable")}</span></td></tr>`; });
  if(!rows.length){
    h+=`<tr><td colspan="11" class="tempty">${apps.length
      ? "Aucune application ne correspond à la recherche."
      : "Aucun namespace à afficher — vérifiez le contexte kubectl ou le filtre des namespaces."}</td></tr>`;
  } else {
    let grp=null;
    h+=rows.map(a=>{
      let g="";
      const gk=(a.workspace||"")+"|"+(a.cluster_id||"");
      if(all && gk!==grp){ grp=gk;
        g=`<tr class="grp"><td colspan="11">${a.workspace?esc(a.workspace)+'<span class="gs">›</span>':""}${esc(a.cluster||"")}`+
          `${a.cluster_id===ACTIVE_CID?'<span class="tag">ACTIF</span>':''}</td></tr>`; }
      const k=appKey(a), sel=appsSel.has(k);
      const comp = a.missing ? stIc("na","Namespace supprimé du cluster")
                 : a.compliant ? stIc("ok","Sauvegarde de configuration récente")
                 : (a.protected ? stIc("ko","Dernière sauvegarde plus ancienne que "+appsFresh+" h")
                                : stIc("na","Jamais sauvegardée"));
      // Protection = sauvegardes du NAMESPACE ; un volume de l'application absent de la
      // dernière sauvegarde (PVC créé depuis) rend sa protection incomplète.
      const unb=(a.unbacked_pvcs||[]);
      const prot = !a.protected ? stIc("na","Aucune sauvegarde de configuration")
                 : (unb.length && !a.missing) ? stIc("wn", "Volume(s) absent(s) de la dernière sauvegarde : "+unb.join(", ")+" — relancez une sauvegarde")
                 : stIc("ok", a.backups+" sauvegarde(s) de configuration du namespace");
      const last = a.last_backup ? esc(fmtAgo(a.last_backup)) : '<span style="color:var(--muted)">Jamais</span>';
      const nameCell = (a.unassigned ? '<i>'+esc(a.name)+'</i>' : esc(a.name))
        + (a.whole_ns && !a.missing && a.type!=="empty" ? ' <span class="hint">(namespace entier)</span>' : '');
      return g+`<tr class="clk${sel?' sel':''}" data-k="${esc(k)}"${a.missing?' style="opacity:.75"':''}>
        <td class="cb"><input type="checkbox" tabindex="-1" ${sel?"checked":""}></td>
        <td style="color:var(--strong);font-weight:500">${nameCell}</td><td>${esc(appNs(a))}</td>
        <td class="mc">${esc(a.workspace||"—")}</td><td class="mc">${esc(a.cluster||"")}</td>
        <td>${appTypeCell(a)}</td><td>${esc(appPolicyLabel())}</td>
        <td class="ctr">${comp}</td><td class="ctr">${prot}</td><td>${last}</td>
        <td class="ctr">${a.backups||0}</td></tr>`;
    }).join("");
  }
  $("#appsBody").innerHTML=h;
  // Sélection : on met à jour LA ligne cliquée (pas de reconstruction du tableau —
  // coûteuse à 1 000 lignes), puis les actions et la case « tout ».
  document.querySelectorAll("#appsBody tr.clk").forEach(tr=>tr.onclick=()=>{
    const k=tr.dataset.k, on=!appsSel.has(k);
    on ? appsSel.add(k) : appsSel.delete(k);
    tr.classList.toggle("sel", on); const c=tr.querySelector('input[type="checkbox"]'); if(c) c.checked=on;
    $("#appsAll").checked = rows.length>0 && rows.every(a=>appsSel.has(appKey(a)));
    updateAppActs(); });
  $("#appsAll").checked = rows.length>0 && rows.every(a=>appsSel.has(appKey(a)));
  updateAppActs();
}
function selAppObjs(){ return apps.filter(a=>appsSel.has(appKey(a))); }
// Namespaces distincts de la sélection (la sauvegarde est par namespace : deux
// applications du même namespace = une seule sauvegarde).
function selNsObjs(){
  const seen=new Set(), out=[];
  selAppObjs().forEach(a=>{ const k=(a.cluster_id||ACTIVE_CID)+"|"+appNs(a); if(seen.has(k)) return; seen.add(k);
    out.push({name:appNs(a), cluster_id:a.cluster_id, cluster:a.cluster, workspace:a.workspace, missing:a.missing}); });
  return out;
}
function selApps(){ return selNsObjs().map(a=>a.name); }
function updateAppActs(){
  const objs=selAppObjs(), n=objs.length, anyMissing=objs.some(a=>a.missing), anyEmpty=objs.some(a=>a.type==="empty");
  $("#actBackup").disabled = !n || anyMissing || anyEmpty;
  ["#actPolicy","#actVerify"].forEach(id=>$(id).disabled = n!==1 || anyMissing);
  // Restaurer : une application, OU plusieurs applications du MÊME namespace (= tout le
  // namespace, ex. mariadb + wordpress séparés par leurs étiquettes). Un namespace vide
  // reste restaurable s'il a des sauvegardes (application supprimée mais namespace
  // conservé) — restaurer une app SUPPRIMÉE est le cas clé.
  const sameNs = n>=1 && new Set(objs.map(a=>(a.cluster_id||ACTIVE_CID)+"|"+appNs(a))).size===1;
  $("#actRestore").disabled = !sameNs || (anyEmpty && !objs[0].protected);
  const rs=$("#actRestore span"); if(rs){ if(!rs.dataset.lbl) rs.dataset.lbl=rs.textContent;
    rs.textContent = (sameNs && n>1) ? "Restaurer le namespace" : rs.dataset.lbl; }
}
// Opération sur UNE application d'un autre cluster (vue « Tous les clusters ») : on
// bascule d'abord le cluster actif, pour que confirmations et garde-fous le désignent.
async function ensureCluster(a){ if(a && a.cluster_id && a.cluster_id!==ACTIVE_CID) await setActiveCluster(a.cluster_id); }
$("#appsSearch").oninput=()=>{ appsPage=0; renderApps(); };
// « Tout sélectionner » porte sur la PAGE affichée (jamais 1 000 lignes d'un coup à l'insu de l'opérateur).
$("#appsAll").onchange=()=>{ const on=$("#appsAll").checked;
  appsVisible().slice(appsPage*APPS_PAGE_SIZE, (appsPage+1)*APPS_PAGE_SIZE).forEach(a=>on ? appsSel.add(appKey(a)) : appsSel.delete(appKey(a))); renderApps(); };
$("#appsRefresh").onclick=()=>loadApps(true);
$("#actBackup").onclick=async()=>{
  const objs=selNsObjs();
  const cids=[...new Set(objs.map(a=>a.cluster_id))];
  if(cids.length===1) await ensureCluster(objs[0]);
  openBackupModal(objs.map(a=>a.name), objs);
};
$("#actRestore").onclick=async()=>{ const objs=selAppObjs(), a=objs[0]; await ensureCluster(a);
  if(a.missing) return openRecoverModal(appNs(a));
  // Plusieurs applications du même namespace sélectionnées -> tout le namespace.
  openRestoreModal(appNs(a), objs.length>1 ? null : a); };
$("#actPolicy").onclick=async()=>{ const a=selAppObjs()[0]; await ensureCluster(a); openPolicyModal(appNs(a)); };
$("#actVerify").onclick=async()=>{ const a=selAppObjs()[0]; await ensureCluster(a); gotoVerify(appNs(a), false); };

// ============================ Modale Sauvegarde ============================
// Actions principales dans le pied de modale (comme HYCU) : on y DÉPLACE les boutons
// existants — leurs gestionnaires d'événements suivent l'élément.
$("#mBackupFoot").append($("#bkRunAll"), $("#bkRun"));
let bkSel=[], bkObjs=[];
function openBackupModal(list, objs){
  bkSel=(list||[]).filter(Boolean);
  bkObjs=(objs && objs.length===bkSel.length) ? objs : bkSel.map(n=>({name:n, cluster_id:ACTIVE_CID}));
  const multi=bkSel.length>1, multiCl=new Set(bkObjs.map(o=>o.cluster_id)).size>1;
  $("#bkOut").innerHTML="";
  $("#bkNsRow").style.display = multi ? "none" : "";
  $("#bkSelInfo").style.display = multi ? "" : "none";
  $("#bkRun").style.display = multi ? "none" : "";
  $("#bkRunAll").style.display = multi ? "none" : "";
  $("#bkRunSel").style.display = multi ? "" : "none";
  if(multi){ $("#bkSelList").textContent=bkObjs.map(o=>multiCl ? o.name+" ("+(o.cluster||o.cluster_id)+")" : o.name).join(", ");
             $("#bkRunSel").textContent="Sauvegarder la sélection ("+bkSel.length+")"; }
  else if(bkSel[0]){ state.ns=bkSel[0]; applyGlobalNs(); }
  openModal("mBackup");
}
$("#bkRunSel").onclick=async()=>{
  const b=$("#bkRunSel"), dest=$("#bkDest").value.trim(); b.disabled=true;
  const multiCl=new Set(bkObjs.map(o=>o.cluster_id)).size>1;
  let lines="", ok=0;
  for(const o of bkObjs){
    const lbl=multiCl ? o.name+" ("+(o.cluster||o.cluster_id)+")" : o.name;
    $("#bkOut").innerHTML=`<div class="hint"><span class="spin"></span>${esc(lbl)}…</div><ul class="dlist">${lines}</ul>`;
    const r=await post("/api/backup",{ns:o.name, dest}, o.cluster_id);
    if(r.ok) ok++;
    lines+=`<li><span class="k" style="display:flex;gap:10px;align-items:center">${stIc(r.ok?"ok":"ko")}${esc(lbl)}</span>`+
           `<span class="v" style="font-weight:400">${r.ok ? r.count+" volume(s)" : esc(r.error||"")}</span></li>`;
  }
  $("#bkOut").innerHTML=`<div class="note">${ok}/${bkObjs.length} namespace(s) sauvegardé(s).</div><ul class="dlist" style="margin-top:8px">${lines}</ul>`;
  b.disabled=false;
};

// ============================ Modale Définir la politique ============================
function openPolicyModal(ns){
  if(ns){ state.ns=ns; applyGlobalNs(); $("#bkNs").value=ns;
    if($("#bkNs").value!==ns){                 // namespace disparu / kubectl en panne
      clearBkProtect(); openModal("mPolicy");
      $("#bkMatchOut").innerHTML=errBox("Namespace « "+ns+" » introuvable dans la liste — actualisez les Applications (kubectl indisponible ?).");
      return;
    } }
  clearBkProtect();
  $("#mPolicyTitle").innerHTML=esc("Définir la politique")+(ns ? '<span class="sep">›</span>'+esc(ns) : "");
  openModal("mPolicy");
  if(conn.hycu && conn.hycu.connected) setTimeout(()=>$("#bkMatch").click(), 30);   // analyse : lecture seule
}

// ============================ Restauration en masse (même cluster) ============================
// Plan (lecture seule) -> Simuler (journal, arrière-plan) -> Lancer (réel : simulation
// du même plan exigée par le serveur, confirmation du contexte) ; suivi par polling,
// arrêt propre et reprise (les namespaces déjà recréés ne sont jamais refaits).
let bulkPlan=null, bulkStatus=null, bulkTimer=null, bulkWasRunning=false;
function bulkNowLocal(){ const d=new Date(); const p=n=>String(n).padStart(2,"0");
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`; }
function bulkExclude(){ return ($("#bulkExclude").value||"").split(",").map(s=>s.trim()).filter(Boolean); }
function openBulkModal(){
  bulkPlan=null; $("#bulkAsOf").value=bulkNowLocal(); $("#bulkPlanOut").innerHTML=""; $("#bulkRunOut").innerHTML="";
  $("#bulkCluster").textContent=ctxInfo.context||"—";
  openModal("mBulk"); bulkSyncBtns(); bulkPoll();
}
$("#actBulk").onclick=openBulkModal;
function bulkSamePlan(j){
  return !!(j && bulkPlan && j.as_of===bulkPlan.as_of_iso && j.items.length===bulkPlan.items.length
            && j.items.every((it,i)=>it.ns===bulkPlan.items[i].ns));
}
function bulkSyncBtns(){
  const running=!!(bulkStatus&&bulkStatus.running), j=bulkStatus&&bulkStatus.journal, c=bulkStatus&&bulkStatus.counts;
  const n=!!(bulkPlan&&bulkPlan.items.length);
  const simOk=!!(j && j.dry && j.done && !j.stopped && c && c.failed===0 && bulkSamePlan(j));
  $("#bulkSim").disabled = !n || running;
  $("#bulkReal").disabled = !n || running || !simOk || dry();
  $("#bulkReal").title = dry() ? "Désactivez le bandeau Simulation pour lancer le réel." : (!simOk ? "Simulez d'abord ce plan (sans échec)." : "");
  $("#bulkStop").style.display = running ? "" : "none";
  $("#bulkResume").style.display = (j && !running && !j.done && j.items.some(it=>it.status!=="done")) ? "" : "none";
}
async function bulkMakePlan(){
  const b=$("#bulkPlanBtn"); b.disabled=true;
  $("#bulkPlanOut").innerHTML='<div class="hint"><span class="spin"></span>Analyse des sauvegardes et du cluster…</div>';
  const r=await post("/api/bulk/plan",{as_of:$("#bulkAsOf").value, exclude:bulkExclude()});
  b.disabled=false;
  if(!r.ok){ bulkPlan=null; $("#bulkPlanOut").innerHTML=errBox(r.error); bulkSyncBtns(); return; }
  bulkPlan=r; $("#bulkPlanOut").innerHTML=bulkRenderPlan(r); bulkSyncBtns();
}
$("#bulkPlanBtn").onclick=bulkMakePlan;
function bulkRenderPlan(r){
  const rows=r.items.map(it=>`<tr><td style="color:var(--strong);font-weight:500">${esc(it.ns)}</td><td>${esc((it.created||it.timestamp||"").replace("T"," ").slice(0,16))}</td>
     <td>${it.stateless?'<span class="badge b-pending">Stateless</span>':(it.volumes.length+" volume(s)")}${it.partial?' <span class="badge b-lost">partielle</span>':''}</td>
     <td>${(it.warnings||[]).length?'<span class="ko">⚠ '+esc(it.warnings.join(" · "))+'</span>':'<span class="ok">✓</span>'}</td></tr>`).join("");
  const sk=(r.skipped||[]).map(s=>`<li><b>${esc(s.ns)}</b> — ${esc(s.reason)}</li>`).join("");
  const warnN=r.items.filter(it=>(it.warnings||[]).length).length;
  return `<div class="note"><b>${r.items.length}</b> namespace(s) à recréer sur <b>${esc(r.context||r.cluster||"?")}</b> · instant de référence ${esc((r.as_of_iso||"").replace("T"," "))}${warnN?` · <span class="ko">${warnN} avec avertissement</span>`:""}${r.vault_unlocked?"":' · <span class="ko">coffre verrouillé</span>'}${r.hycu?"":' · <span class="hint">HYCU non connecté : les Volume Groups disparus ne seront pas restaurés</span>'}</div>
    ${r.items.length?`<div class="tcard" style="box-shadow:none;border:1px solid var(--rule);max-height:300px;overflow:auto"><table class="ht" id="bulkPlanTable"><thead><tr><th>Namespace</th><th>Sauvegarde</th><th>Contenu</th><th>Avertissements</th></tr></thead><tbody>${rows}</tbody></table></div>`:'<div class="hint">Aucun namespace supprimé avec une sauvegarde antérieure à l\'instant de référence.</div>'}
    ${sk?`<details style="margin-top:8px"><summary class="hint">${(r.skipped||[]).length} namespace(s) ignoré(s)</summary><ul class="dlist" style="margin-top:6px">${sk}</ul></details>`:""}`;
}
async function bulkStart(dryRun){
  let confirmedCtx="";
  if(!dryRun){
    const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||"") : null;
    const res=await confirmDanger({title:"Restauration en masse RÉELLE", requireText:needCtx, lines:[
      "<b>"+bulkPlan.items.length+"</b> namespace(s) seront RECRÉÉS sur <b>"+esc(ctxInfo.context||"?")+"</b> depuis leurs sauvegardes.",
      "Exécution séquentielle et journalisée ; les Volume Groups disparus seront restaurés par HYCU (opérations réelles).",
      "Les namespaces présents ne sont pas touchés."]});
    if(!res) return; if(typeof res==="string") confirmedCtx=res;
  }
  const body={as_of:$("#bulkAsOf").value, exclude:bulkExclude(), dry:dryRun};
  if(!dryRun && ctxInfo.require_confirm) body.confirm_context=confirmedCtx;
  const r=await post("/api/bulk/run", body);
  if(!r.ok){ $("#bulkRunOut").innerHTML=errBox(r.error); return; }
  bulkPoll();
}
$("#bulkSim").onclick=()=>bulkStart(true);
$("#bulkReal").onclick=()=>bulkStart(false);
$("#dry").addEventListener("change",()=>{ if($("#mBulk").style.display!=="none") bulkSyncBtns(); });   // bandeau Simulation
$("#bulkStop").onclick=async()=>{ const r=await post("/api/bulk/stop",{}); if(!r.ok) $("#bulkRunOut").insertAdjacentHTML("afterbegin", errBox(r.error)); };
$("#bulkResume").onclick=async()=>{
  const j=bulkStatus&&bulkStatus.journal; if(!j) return;
  let confirmedCtx="";
  if(!j.dry){
    const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||"") : null;
    const res=await confirmDanger({title:"Reprendre la restauration en masse (RÉEL)", requireText:needCtx, lines:[
      "Les namespaces restants (en attente, arrêtés ou en échec) seront recréés ; ceux déjà recréés ne sont pas refaits."]});
    if(!res) return; if(typeof res==="string") confirmedCtx=res;
  }
  const body={resume:true, dry:j.dry}; if(!j.dry && ctxInfo.require_confirm) body.confirm_context=confirmedCtx;
  const r=await post("/api/bulk/run", body);
  if(!r.ok){ $("#bulkRunOut").innerHTML=errBox(r.error); return; }
  bulkPoll();
};
async function bulkPoll(){
  clearTimeout(bulkTimer);
  if($("#mBulk").style.display==="none") return;
  const st=await get("/api/bulk/status"); if(!st.ok) return;
  bulkStatus=st; bulkRenderStatus(st); bulkSyncBtns();
  if(st.running){ bulkWasRunning=true; bulkTimer=setTimeout(bulkPoll, 2000); }
  else if(bulkWasRunning){ bulkWasRunning=false; loadApps(true); }   // namespaces recréés : inventaire à jour
}
function bulkRenderStatus(st){
  const j=st.journal; if(!j){ $("#bulkRunOut").innerHTML=""; return; }
  const c=st.counts, pct=c.total?Math.round(100*(c.done+c.failed)/c.total):0;
  const IC={done:"ok",failed:"ko",running:"run",pending:"na",stopped:"wn"};
  const head = st.running ? '<span class="spin"></span> En cours' : j.stopped ? "Arrêtée" : j.done ? (c.failed ? "Terminée avec échecs" : "Terminée") : "Interrompue";
  $("#bulkRunOut").innerHTML=`<div class="${j.dry?'warnbox':'note'}" id="bulkHead"><b>${j.dry?"Simulation":"Réel"}</b> · ${head} · ${c.done+c.failed} / ${c.total} (${c.failed} échec(s)) · instant de référence ${esc((j.as_of||"").replace("T"," "))}${j.started?" · démarrée "+esc(j.started.replace("T"," ")):""}</div>
    <div style="height:6px;background:var(--rule);border-radius:3px;margin:6px 0 10px"><div style="height:6px;width:${pct}%;background:#41327C;border-radius:3px"></div></div>
    <div class="tcard" style="box-shadow:none;border:1px solid var(--rule);max-height:320px;overflow:auto"><table class="ht" id="bulkStatusTable"><thead><tr><th>Namespace</th><th>État</th><th>Détail</th></tr></thead><tbody>${
      j.items.map(it=>`<tr><td style="color:var(--strong);font-weight:500">${esc(it.ns)}</td><td>${stIc(IC[it.status]||"na", it.status)} ${esc(it.status)}</td>
        <td>${it.error?'<span class="ko">'+esc(it.error)+'</span>':''}${(it.run_warnings||[]).length?'<div class="hint">⚠ '+esc(it.run_warnings.join(" · "))+'</div>':''}${(it.log||[]).length?`<details><summary class="hint">${it.log.length} étape(s)</summary>${renderLog(it.log)}</details>`:''}</td></tr>`).join("")}</tbody></table></div>`;
}

// ============================ Modale Sources (engrenage) ============================
const SRC=[{key:"hycu", name:"HYCU", type:"Sauvegarde & restauration (API REST)"},
           {key:"nutanix", name:"Prism Element", type:"Nutanix — Volume Groups (API v2)"},
           {key:"prismcentral", name:"Prism Central", type:"Nutanix — multi-cluster (API v3/v4)"},
           {key:"s3", name:"Stockage objet S3", type:"Export des sauvegardes (optionnel)"},
           {key:"vault", name:"Coffre d'identifiants", type:"Mémorisation chiffrée (optionnel)"}];
let srcSel="hycu";
const CHK_SVG='<svg width="14" height="14" viewBox="0 0 18 18" aria-hidden="true"><path d="M4.5 9.4l3 3 6-6.4" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>';
function clById(id){ return CLUSTERS.find(c=>c.id===id); }
function clType(c){
  if(c.local) return "Kubernetes — configuration locale";
  if(c.source==="nkp") return "Kubernetes — NKP"+(c.workspace?" (workspace "+c.workspace+")":"");
  return "Kubernetes — kubeconfig importé";
}
function clStatusIc(c){
  const h=c.health;
  if(h && !h.ok) return stIc("ko","Cluster injoignable (contrôle "+fmtAgo(h.at)+") : "+(h.error||""));
  if(c.local) return c.configured ? stIc("ok","Contexte : "+(c.context||"")) : stIc("na","Non configuré");
  const a=c.auth||{}, w=(a.warnings||[]).concat(c.warning?[c.warning]:[]).join(" ");
  if(a.level==="error") return stIc("ko", w);
  if(a.level==="warn" || c.warning) return stIc("wn", w);
  if(h && h.ok) return stIc("ok","Joignable ("+fmtAgo(h.at)+") · authentification : "+(a.type||"?"));
  return stIc("ok","Authentification : "+(a.type||"?"));
}
function renderSourcesTable(){
  const body=$("#srcBody"); if(!body) return;
  const row=(key, name, type, url, st)=>`<tr class="clk${key===srcSel?' sel':''}" data-key="${esc(key)}"><td>${name}</td><td>${esc(type)}</td>`+
           `<td><code>${esc(url||"—")}</code></td><td class="ctr">${st}</td></tr>`;
  let h=`<tr class="srcsec"><td colspan="4">HYCU &amp; Nutanix</td></tr>`;
  h+=SRC.map(s=>{
    let url="—", st;
    if(s.key==="vault"){
      st = (conn.vault && conn.vault.present) ? stIc("ok","Coffre présent") : stIc("na","Aucun coffre");
    } else {
      const x=conn[s.key]||{}; url=x.url||"—";
      if(s.key==="s3" && x.url) url=x.url+"/"+(x.bucket||"");
      st = x.connected ? stIc("ok","Connecté") : (x.configured ? stIc("wn","Configuré, non connecté") : stIc("na","Non configuré"));
      if(s.key==="s3" && x.connected && !x.auto_upload) st=stIc("wn","Connecté — export automatique désactivé");
    }
    return row(s.key, esc(s.name), s.type, url, st);
  }).join("");
  h+=`<tr class="srcsec"><td colspan="4">Clusters Kubernetes</td></tr>`;
  h+=CLUSTERS.map(c=>row("cluster:"+c.id, esc(c.name)+(c.id===ACTIVE_CID?'<span class="tag">ACTIF</span>':''),
        clType(c), c.local ? (c.kubeconfig_path||"kubeconfig par défaut") : c.server, clStatusIc(c))).join("");
  body.innerHTML=h;
  body.querySelectorAll("tr.clk").forEach(tr=>tr.onclick=()=>{ srcSel=tr.dataset.key; showSourceCard(); renderSourcesTable(); });
}
function showSourceCard(){
  const card = srcSel.indexOf("cluster:")===0 ? "cluster" : srcSel;
  document.querySelectorAll("#tab-connect > .card").forEach(c=>c.style.display = c.dataset.card===card ? "" : "none");
  if(card==="cluster") renderClusterCard(srcSel.slice(8));
  if(card==="nkp") $("#nkpMgmt").textContent = ctxInfo.context || "—";
}
function openSources(i){
  if(typeof i==="number") srcSel=SRC[i].key;
  else if(typeof i==="string") srcSel=i;
  renderSourcesTable(); showSourceCard(); openModal("mSources");
}
$("#clAddBtn").onclick=()=>openSources("cluster-add");
$("#nkpBtn").onclick=()=>openSources("nkp");

// ----- Clusters Kubernetes : liste, sélecteur de la barre du haut, cluster actif -----
async function loadClusters(){
  const r=await get("/api/clusters","local");
  if(r && r.ok) CLUSTERS=r.clusters||CLUSTERS;
  if(!clById(ACTIVE_CID)) ACTIVE_CID="local";      // cluster retiré / session verrouillée
  renderClMenu(); renderSourcesTable(); updateScopeSeg();
  return CLUSTERS;
}
function renderCtx(){
  $("#ctx").textContent = ctxInfo.context || "indisponible";
  $("#ctxWarn").innerHTML = (ctxInfo.context && ctxInfo.allowed && ctxInfo.allowed.length && !ctxInfo.context_ok)
    ? ' <span class="bad">⚠ hors liste autorisée</span>'
    : ((ctxInfo.auth && ctxInfo.auth.level==="error") ? ' <span class="bad">⚠ jeton expiré</span>' : '');
  $("#ctxLink").title = "Cluster Kubernetes actif"+(ctxInfo.workspace?(" — workspace "+ctxInfo.workspace):"")+" — cliquer pour en choisir un autre";
}
function renderClMenu(){
  const m=$("#clMenu");
  m.innerHTML=CLUSTERS.map(c=>`<div class="cli${c.id===ACTIVE_CID?' on':''}" data-cid="${esc(c.id)}" role="menuitem">`+
      `<span class="chk">${c.id===ACTIVE_CID?CHK_SVG:''}</span><span>${esc(c.name)}</span>`+
      `<span class="ws">${esc(c.local ? "configuration locale" : (c.workspace || "kubeconfig importé"))}</span></div>`).join("")+
    `<div class="msep"></div><div class="cli act" data-act="add" role="menuitem"><span class="chk"></span>Ajouter un cluster Kubernetes…</div>`+
    `<div class="cli act" data-act="manage" role="menuitem"><span class="chk"></span>Gérer les clusters…</div>`;
  m.querySelectorAll(".cli").forEach(el=>el.onclick=async e=>{
    e.stopPropagation(); m.style.display="none";
    if(el.dataset.act==="add") return openSources("cluster-add");
    if(el.dataset.act==="manage") return openSources("cluster:"+ACTIVE_CID);
    if(el.dataset.cid!==ACTIVE_CID) await setActiveCluster(el.dataset.cid);
  });
}
function toggleClMenu(){
  const m=$("#clMenu");
  if(m.style.display==="block"){ m.style.display="none"; return; }
  $("#gearMenu").style.display="none"; $("#helpMenu").style.display="none";
  renderClMenu();
  const r=$("#ctxLink").getBoundingClientRect();
  m.style.right=Math.max(8, window.innerWidth-r.right-10)+"px";
  m.style.display="block";
}
document.addEventListener("click",()=>{ ["clMenu","gearMenu","helpMenu"].forEach(i=>$("#"+i).style.display="none"); });
async function setActiveCluster(cid){
  if(!clById(cid)) return;
  ACTIVE_CID=cid; savePref("cluster", cid);
  ["mBackup","mPolicy","mRestore"].forEach(closeModal);
  if(appsScope!=="all") appsSel.clear();
  state.ns=null;
  ctxInfo=await get("/api/context");
  renderCtx(); renderKubeBanner(); renderClMenu(); renderSourcesTable();
  if($("#mSources").style.display!=="none") showSourceCard();
  await refreshNamespaces();
  onPageShown(curPage);
}
// Coffre déverrouillé : les clusters mémorisés reviennent -> reprendre le cluster préféré.
async function afterVaultLoad(){
  await loadClusters();
  const p=prefs().cluster;
  if(p && p!==ACTIVE_CID && clById(p)) await setActiveCluster(p);
}
function renderClusterCard(cid){
  const c=clById(cid); $("#clDErr").innerHTML="";
  if(!c){ $("#clDTitle").textContent="Cluster"; $("#clDBody").innerHTML='<div class="hint">Cluster introuvable.</div>'; return; }
  $("#clDTitle").textContent=c.name;
  const li=(k,v)=>`<li><span class="k">${k}</span><span class="v">${v}</span></li>`;
  let h='<ul class="dlist">';
  h+=li("Type", esc(clType(c)));
  if(c.local){
    h+=li("Contexte kubectl", c.context?`<code>${esc(c.context)}</code>`:"—");
    h+=li("Kubeconfig", `<code>${esc(c.kubeconfig_path||"kubeconfig par défaut")}</code>`);
  } else {
    h+=li("Contexte kubectl", `<code>${esc(c.context)}</code>`);
    h+=li("Serveur API", `<code>${esc(c.server||"—")}</code>`);
    if(c.workspace) h+=li("Workspace NKP", esc(c.workspace));
    if(c.management) h+=li("Cluster de management", esc(c.management));
    h+=li("Authentification", esc((c.auth||{}).type||"?")+" "+clStatusIc(c));
  }
  h+=li("Sauvegardes", c.local ? `<code>hycu-backups/_contexts/${esc(c.context||"…")}/&lt;namespace&gt;/</code>` : `<code>hycu-backups/_clusters/${esc(c.id)}/&lt;namespace&gt;/</code>`);
  if(c.health) h+=li("Dernier contrôle de santé", (c.health.ok?stIc("ok","Joignable"):stIc("ko",esc(c.health.error||"")))+" "+esc(fmtAgo(c.health.at)));
  h+='</ul>';
  if(c.health && !c.health.ok) h+=`<div class="err" style="margin-top:10px">Cluster injoignable au dernier contrôle : ${esc(c.health.error||"")}</div>`;
  const w=((c.auth||{}).warnings||[]).concat(c.warning?[c.warning]:[]);
  if(w.length) h+=`<div class="warnbox" style="margin-top:10px">⚠ ${w.map(esc).join("<br>")}</div>`;
  if(c.local && !c.configured) h+=`<div class="warnbox" style="margin-top:10px">Aucun contexte kubectl local : ajoutez un cluster avec son kubeconfig, ou configurez kubectl (Réglages).</div>`;
  $("#clDBody").innerHTML=h;
  $("#clUse").disabled = c.id===ACTIVE_CID;
  $("#clUse").textContent = c.id===ACTIVE_CID ? "Cluster actif" : "Définir comme cluster actif";
  $("#clRemove").style.display = c.local ? "none" : "";
  $("#clLocalCfg").style.display = c.local ? "" : "none";
  $("#clUse").onclick=()=>setActiveCluster(c.id);
  $("#clLocalCfg").onclick=()=>{ closeModal("mSources"); switchTab("settings"); };
  $("#clRemove").onclick=async()=>{
    if(!confirm("Retirer le cluster « "+c.name+" » ? Son kubeconfig est oublié ; ses sauvegardes restent sur disque.")) return;
    const r=await post("/api/clusters/remove",{id:c.id},"local");
    if(!r.ok){ $("#clDErr").innerHTML=errBox(r.error); return; }
    const wasActive = c.id===ACTIVE_CID;
    await loadClusters();
    srcSel="cluster:"+(wasActive?"local":ACTIVE_CID);
    if(wasActive) await setActiveCluster("local");
    showSourceCard(); renderSourcesTable();
  };
}

// ----- Ajout d'un cluster (kubeconfig fichier / collé) -----
let clInspectT=null, clCtxs=[];
function clCtxInfo(){
  const c=clCtxs.find(x=>x.name===$("#clCtx").value); if(!c){ $("#clCtxInfo").innerHTML=""; return; }
  const a=c.auth||{};
  $("#clCtxInfo").innerHTML=`<ul class="dlist" style="margin-top:8px"><li><span class="k">Serveur API</span><span class="v"><code>${esc(c.server||"—")}</code></span></li>`+
    `<li><span class="k">Authentification</span><span class="v">${esc(a.type||"?")} ${a.level==="error"?stIc("ko"):a.level==="warn"?stIc("wn"):stIc("ok")}</span></li></ul>`+
    ((a.warnings||[]).length?`<div class="warnbox" style="margin-top:8px">⚠ ${a.warnings.map(esc).join("<br>")}</div>`:"");
  if(!$("#clName").value.trim() || $("#clName").dataset.auto==="1"){
    $("#clName").value=(c.cluster||c.name||"").replace(/[^A-Za-z0-9._-]+/g,"-").slice(0,63); $("#clName").dataset.auto="1"; }
}
async function clInspect(){
  const kc=$("#clKc").value; $("#clErr").innerHTML="";
  if(!kc.trim()){ $("#clCtxWrap").style.display="none"; clCtxs=[]; return; }
  const r=await post("/api/clusters/inspect",{kubeconfig:kc},"local");
  if(!r.ok){ $("#clCtxWrap").style.display="none"; clCtxs=[]; $("#clErr").innerHTML=errBox(r.error); return; }
  clCtxs=r.contexts||[];
  $("#clCtx").innerHTML=clCtxs.map(c=>`<option value="${esc(c.name)}">${esc(c.name)}</option>`).join("");
  $("#clCtx").value=r.current||(clCtxs[0]||{}).name||"";
  $("#clCtxWrap").style.display="block"; clCtxInfo();
}
$("#clKc").oninput=()=>{ clearTimeout(clInspectT); clInspectT=setTimeout(clInspect, 500); };
$("#clCtx").onchange=clCtxInfo;
$("#clName").oninput=()=>{ $("#clName").dataset.auto=""; };
$("#clFile").onchange=()=>{
  const f=$("#clFile").files[0]; if(!f) return;
  if(f.size>1024*1024){ $("#clErr").innerHTML=errBox("Kubeconfig trop volumineux (1 Mo max)."); return; }
  const rd=new FileReader(); rd.onload=()=>{ $("#clKc").value=rd.result; $("#clFile").value=""; clInspect(); }; rd.readAsText(f);
};
$("#clAdd").onclick=async()=>{
  const b=$("#clAdd"); $("#clErr").innerHTML="";
  if(!$("#clKc").value.trim()){ $("#clErr").innerHTML=errBox("Chargez ou collez d'abord un kubeconfig."); return; }
  b.disabled=true; b.innerHTML='<span class="spin"></span>Test de connexion…';
  const r=await post("/api/clusters/add",{name:$("#clName").value.trim(), kubeconfig:$("#clKc").value,
                                          context:$("#clCtx").value||""},"local");
  b.disabled=false; b.textContent="Tester & ajouter";
  if(!r.ok){ $("#clErr").innerHTML=errBox(r.error); if(r.need_context) clInspect(); return; }
  $("#clKc").value=""; $("#clName").value=""; $("#clName").dataset.auto=""; $("#clCtxWrap").style.display="none"; clCtxs=[];
  await loadClusters();
  srcSel="cluster:"+r.cluster.id; renderSourcesTable(); showSourceCard();
  $("#clDErr").innerHTML=`<div class="note">Cluster ajouté. Choisissez « Définir comme cluster actif » pour l'utiliser, ou sélectionnez-le dans la barre du haut.</div>`;
};

// ----- Découverte NKP (workspaces -> clusters) depuis le cluster de management actif -----
let nkpData=null;
function nkpSync(){
  const n=document.querySelectorAll(".nkpChk:checked").length;
  $("#nkpImport").disabled = !(n && $("#nkpAck").checked);
  $("#nkpImport").textContent = n ? "Importer la sélection ("+n+")" : "Importer la sélection";
}
$("#nkpAck").onchange=nkpSync;
$("#nkpDiscover").onclick=()=>nkpLoad(false);
async function nkpLoad(keepRes){
  const b=$("#nkpDiscover"); if(!keepRes) $("#nkpRes").innerHTML=""; $("#nkpImportWrap").style.display="none";
  b.disabled=true; $("#nkpOut").innerHTML='<div class="hint"><span class="spin"></span>Lecture des workspaces…</div>';
  const r=await get("/api/nkp/discover"); b.disabled=false; nkpData=r;
  if(!r.ok){ $("#nkpOut").innerHTML=errBox(r.error); return; }
  const cl=r.clusters||[];
  if(!cl.length){ $("#nkpOut").innerHTML='<div class="hint">Aucun cluster trouvé dans les workspaces.</div>'; return; }
  let h=`<div class="tcard" style="box-shadow:none;border:1px solid var(--rule);margin-top:12px"><table class="ht"><thead><tr><th class="cb"></th><th>Cluster</th><th>Phase</th><th>État</th></tr></thead><tbody>`, ws=null;
  cl.forEach((c,i)=>{
    if(c.workspace!==ws){ ws=c.workspace; h+=`<tr class="grp"><td colspan="4">Workspace <span class="gs">›</span>${esc(ws)}</td></tr>`; }
    const dis=c.host||!!c.registered;
    const st=c.host ? "Cluster de management (actif)" : (c.registered ? "Déjà importé ("+c.registered+")" : "—");
    h+=`<tr><td class="cb"><input type="checkbox" class="nkpChk" data-i="${i}" ${dis?"disabled":""}></td>`+
       `<td style="color:var(--strong)">${esc(c.name)}</td><td>${esc(c.phase||"—")}</td><td>${esc(st)}</td></tr>`;
  });
  $("#nkpOut").innerHTML=h+"</tbody></table></div>";
  document.querySelectorAll(".nkpChk").forEach(x=>x.onchange=nkpSync);
  $("#nkpImportWrap").style.display="block"; $("#nkpAck").checked=false; nkpSync();
}
$("#nkpImport").onclick=async()=>{
  const items=[...document.querySelectorAll(".nkpChk:checked")].map(x=>nkpData.clusters[+x.dataset.i])
    .map(c=>({namespace:c.namespace, name:c.name, secret:c.secret, workspace:c.workspace}));
  if(!items.length) return;
  const b=$("#nkpImport"); b.disabled=true; b.innerHTML='<span class="spin"></span>Import…';
  const r=await post("/api/nkp/import",{ack:$("#nkpAck").checked, items});
  nkpSync();
  const res=r.results||[];
  $("#nkpRes").innerHTML=(r.error&&!res.length?errBox(r.error):"")+(res.length?`<ul class="dlist" style="margin-top:10px">`+res.map(x=>
    `<li><span class="k" style="display:flex;gap:10px;align-items:center">${stIc(x.ok?"ok":"ko")}${esc(x.cluster)}</span>`+
    `<span class="v" style="font-weight:400">${x.ok ? "Importé sous « "+esc(x.name)+" »"+(x.warning?" — "+esc(x.warning):"") : esc(x.error||"")}</span></li>`).join("")+"</ul>":"");
  await loadClusters();
  if(r.imported) await nkpLoad(true);
};

// ============================ Politiques ============================
async function loadPolicies(){
  await loadAutoBackup();
  const s=await get("/api/auto_backup")||{};
  const on=!!s.enabled;
  $("#polBody").innerHTML=`<tr class="clk" id="polRow">
    <td style="color:var(--strong);font-weight:500">Configuration Kubernetes</td>
    <td>Manifestes PV/PVC et ressources des namespaces du filtre</td>
    <td>${on ? "Toutes les "+Math.round(s.interval_hours||24)+" h" : "—"}</td>
    <td>${abRetLabel(s)}</td>
    <td><code>${esc(s.dest||"hycu-backups/")}</code></td>
    <td class="ctr">${on ? stIc("ok","Activée") : stIc("na","Désactivée")}</td></tr>`;
  $("#polRow").onclick=()=>$("#abEnabled").scrollIntoView({behavior:"smooth", block:"center"});
  if(conn.hycu && conn.hycu.connected){
    $("#polHycu").innerHTML='<div class="hint"><span class="spin"></span></div>';
    const p=await get("/api/hycu/policies");
    $("#polHycu").innerHTML = !p.ok ? errBox(p.error) : ((p.policies||[]).length
      ? `<div class="tcard" style="box-shadow:none;border:1px solid var(--rule)"><table class="ht"><thead><tr><th>Nom</th><th>UUID</th></tr></thead><tbody>`+
        p.policies.map(x=>`<tr><td>${esc(x.name||"—")}</td><td><code>${esc(x.uuid||"")}</code></td></tr>`).join("")+`</tbody></table></div>`
      : '<div class="hint">Aucune politique HYCU.</div>');
  } else {
    $("#polHycu").innerHTML='<div class="warnbox">Enregistrez la source HYCU (⚙ en haut à droite) pour afficher ses politiques.</div>';
  }
}
$("#abSave").addEventListener("click", ()=>setTimeout(()=>{ if(curPage==="policies") loadPolicies(); }, 900));

// ============================ Tâches ============================
const JOB_LBL={backup:"Sauvegarde de configuration", backup_all:"Sauvegarde de configuration (lot)",
  auto_backup:"Sauvegarde automatique", restore_end:"Restauration Kubernetes (PV/PVC)",
  clone_app:"Clone d'application", orchestrate_inplace:"Restauration sur place",
  hycu_restore:"Restauration HYCU (Volume Group)", hycu_protect:"Protection HYCU",
  s3_upload:"Export S3 (stockage objet)", s3_import:"Import S3 (rapatriement)",
  restore_objects:"Restauration d'objets de configuration"};
const JOB_ST={success:["ok","Succès"], failed:["ko","Échec"], simulation:["sim","Simulation"]};
let jobsData=null;
async function loadJobs(){
  $("#jobsRefresh").classList.add("busy");
  const r=await get("/api/jobs");
  $("#jobsRefresh").classList.remove("busy");
  jobsData=r; renderJobs(); return r;
}
function jobCounts(r){
  const c=(r&&r.counts)||{};
  const cell=(n, ic, l)=>`<div><div class="n">${n}</div>${ic}<div class="l">${l}</div></div>`;
  return cell(c.success||0, stIc("ok"), "Succès") + cell(c.failed||0, stIc("ko"), "Échec") +
         cell(c.simulation||0, stIc("sim"), "Simulation") +
         cell((r&&r.running)||0, stIc("run"), "En cours");
}
function jobRowData(j){
  const st=JOB_ST[j.status]||["na", j.status];
  const app = (j.target_namespace && j.target_namespace!==j.namespace)
    ? esc(j.namespace)+" → "+esc(j.target_namespace) : esc(j.namespace||"—");
  const det = j.volumes!=null ? j.volumes+" volume(s)" : (j.detail||"");
  return {st, app, det, lbl: JOB_LBL[j.event]||j.event};
}
function renderJobs(){
  const r=jobsData||{};
  $("#jobsCounts").innerHTML=jobCounts(r);
  const q=($("#jobsSearch").value||"").trim().toLowerCase();
  const rows=(r.jobs||[]).filter(j=>!q || (JOB_LBL[j.event]||j.event).toLowerCase().includes(q)
                                        || (j.namespace||"").toLowerCase().includes(q)
                                        || (j.cluster||"").toLowerCase().includes(q));
  $("#jobsInfo").textContent=rows.length+" tâche(s)"
    +((r.total||0)>(r.jobs||[]).length? " · les "+(r.jobs||[]).length+" plus récentes affichées sur "+r.total:"")
    +((r.retention_days||0)>0? " · historique conservé "+r.retention_days+" j (Réglages)":"");
  $("#jobsBody").innerHTML = rows.length ? rows.map(j=>{ const d=jobRowData(j);
      return `<tr><td style="color:var(--strong)">${esc(d.lbl)}</td><td>${d.app}</td><td>${esc(j.cluster==="*"?"Tous":(j.cluster||"—"))}</td><td>${esc(d.det)}</td>`+
             `<td>${esc(fmtTs(j.ts))}</td><td class="ctr">${stIc(d.st[0], d.st[1])}</td></tr>`; }).join("")
    : `<tr><td colspan="6" class="tempty">Aucune tâche enregistrée pour l'instant.</td></tr>`;
}
$("#jobsSearch").oninput=renderJobs;
$("#jobsRefresh").onclick=()=>loadJobs();

// ============================ Tableau de bord ============================
function jobsChart(days){
  if(!days || !days.length) return "";
  const W=560, H=170, pl=30, pr=26, pt=10, pb=24, n=days.length;
  const mx=Math.max(4, ...days.map(d=>Math.max(d.success, d.failed, d.simulation)));
  const top=Math.ceil(mx/4)*4;
  const X=i=>pl+i*(W-pl-pr)/Math.max(1, n-1), Y=v=>pt+(H-pt-pb)*(1-v/top);
  let g="";
  for(let k=0;k<=4;k++){ const v=top*k/4, y=Y(v).toFixed(1);
    g+=`<line x1="${pl}" y1="${y}" x2="${W-pr}" y2="${y}" stroke="#D5DAE3" stroke-dasharray="4 4"/>`+
       `<text x="${pl-7}" y="${(+y+4).toFixed(1)}" text-anchor="end" font-size="10" fill="#6B7089">${Math.round(v)}</text>`; }
  const serie=(key, col)=>`<polyline points="${days.map((d,i)=>X(i).toFixed(1)+","+Y(d[key]).toFixed(1)).join(" ")}" fill="none" stroke="${col}" stroke-width="1.6"/>`+
    days.map((d,i)=>`<circle cx="${X(i).toFixed(1)}" cy="${Y(d[key]).toFixed(1)}" r="3" fill="${col}"/>`).join("");
  const lbl=days.map((d,i)=>`<text x="${X(i).toFixed(1)}" y="${H-6}" text-anchor="middle" font-size="10" fill="#6B7089">${d.date.slice(8,10)}/${d.date.slice(5,7)}</text>`).join("");
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" style="display:block;max-height:240px;margin:0 auto" aria-hidden="true">${g}${serie("simulation","#6688FF")}${serie("failed","#E9605A")}${serie("success","#05A274")}${lbl}</svg>`;
}
function fmtBytes(n){
  if(n==null) return "—";
  const u=["o","Ko","Mo","Go","To"]; let i=0;
  while(n>=1024 && i<u.length-1){ n/=1024; i++; }
  return (i? n.toFixed(1) : n)+" "+u[i];
}
function storageBar(pct){
  const col = pct>=90? "var(--red)" : pct>=80? "var(--orange)" : "var(--green)";
  return `<div style="height:8px;border-radius:4px;background:#EEF0F5;overflow:hidden;margin:4px 0 2px">
    <div style="width:${Math.min(100,pct)}%;height:100%;background:${col}"></div></div>`;
}
async function loadDashboard(){
  const [a, j, ab, st]=await Promise.all([get("/api/applications"), get("/api/jobs"), get("/api/auto_backup"), get("/api/storage")]);
  const alive=(a.apps||[]).filter(x=>!x.missing), n=alive.length;
  const prot=n ? Math.round(100*alive.filter(x=>x.protected).length/n) : 0;
  const comp=n ? Math.round(100*alive.filter(x=>x.compliant).length/n) : 0;
  const list=a.apps||[];
  $("#dbApps").innerHTML=donutSVG(prot, comp)+dnums("Protection", prot+"%", "Conformité", comp+"%");

  const on=!!ab.enabled;
  $("#dbPolicy").innerHTML=`<div style="display:flex;align-items:center;gap:10px;margin:4px 0 10px">${on ? stIc("ok") : stIc("na")}
      <span class="dbig" style="margin:0">${on ? "Activée" : "Désactivée"}</span></div>
    <ul class="dlist">
      <li><span class="k">Fréquence</span><span class="v">${on ? "Toutes les "+Math.round(ab.interval_hours||24)+" h" : "—"}</span></li>
      <li><span class="k">Rétention</span><span class="v">${esc(abRetLabel(ab))}</span></li>
      <li><span class="k">Dernière exécution</span><span class="v">${ab.last_run ? esc(fmtAgo(ab.last_run))+" "+stIc(ab.last_ok?"ok":"ko") : "—"}</span></li>
      <li><span class="k">Prochaine exécution</span><span class="v">${ab.next_due ? esc(new Date(ab.next_due*1000).toLocaleString()) : "—"}</span></li>
    </ul>`;

  const keys=["hycu","nutanix","prismcentral"];
  const nConn=keys.filter(k=>conn[k] && conn[k].connected).length;
  const nConf=keys.filter(k=>conn[k] && conn[k].configured).length;
  $("#dbSources").innerHTML=donutSVG(Math.round(100*nConn/3), Math.round(100*nConf/3))+
    dnums("Connectées", nConn+"/3", "Configurées", nConf+"/3");
  $("#dbSources").style.cursor="pointer"; $("#dbSources").onclick=()=>openSources();
  $("#dbCluster").style.cursor="pointer"; $("#dbCluster").onclick=()=>openSources("cluster:"+ACTIVE_CID);

  $("#dbCluster").innerHTML=`<div class="dbig" style="font-size:21px;word-break:break-all">${esc(ctxInfo.context||"—")}</div>
    <div class="hint" style="margin:0 0 8px">${ctxInfo.workspace ? "Workspace "+esc(ctxInfo.workspace) : "Cluster actif"}</div>
    <ul class="dlist">
      <li><span class="k">kubectl</span><span class="v">${ctxInfo.kubectl_ok ? stIc("ok","Opérationnel") : stIc("ko","Indisponible")}</span></li>
      <li><span class="k">Clusters enregistrés</span><span class="v">${CLUSTERS.length}</span></li>
      <li><span class="k">Applications</span><span class="v">${n}</span></li>
      <li><span class="k">Namespaces</span><span class="v">${new Set(alive.map(x=>x.namespace||x.name)).size}</span></li>
      <li><span class="k">Filtre des namespaces</span><span class="v">${a.filtered ? "Actif" : "Aucun"}</span></li>
      <li><span class="k">Mode</span><span class="v">${dry() ? "Simulation" : '<span class="ko">Réel</span>'}</span></li>
    </ul>`;

  const roots=(st&&st.roots)||[];
  $("#dbStorage").innerHTML = roots.length? roots.map(x=>{
    if(!x.exists) return `<div class="hint">Dossier absent : <code>${esc(x.path)}</code></div>`;
    const pct=x.disk_used_pct||0;
    const alert = pct>=90? ' <span class="bad" style="background:var(--red);color:#fff;border-radius:3px;padding:0 6px;font-size:11px">disque presque plein</span>'
                : pct>=80? ' '+stIc("wn","Disque rempli à "+pct+"%") : "";
    return `<div style="margin-bottom:10px">
      <div class="hint" style="margin:0" title="${esc(x.path)}"><code>${esc(x.path.length>34? "…"+x.path.slice(-33):x.path)}</code>${alert}</div>
      ${storageBar(pct)}
      <div class="hint" style="margin:0">${pct}% utilisé · ${esc(fmtBytes(x.disk_free))} libres sur ${esc(fmtBytes(x.disk_total))}</div>
      <ul class="dlist" style="margin-top:6px">
        <li><span class="k">Sauvegardes</span><span class="v">${x.backups_count||0} versions · ${esc(fmtBytes(x.backups_bytes))}</span></li>
        <li><span class="k">Journal d'audit</span><span class="v">${esc(fmtBytes(x.audit_bytes))}</span></li>
        ${(st.quota_gb||0)>0? `<li><span class="k">Quota</span><span class="v">${(x.backups_bytes/1024/1024/1024).toFixed(1)} / ${st.quota_gb} Go${x.backups_bytes>st.quota_gb*1073741824? ' '+stIc("wn","Quota dépassé : purge des plus anciennes au prochain passage"):''}</span></li>`:''}
      </ul></div>`;
  }).join("") : '<div class="tempty">—</div>';
  $("#dbStorage").innerHTML += (st.min_free_mb||0)>0? `<div class="hint" style="margin-top:2px">Garde-fou : sauvegarde refusée sous ${st.min_free_mb} Mo libres.</div>` : "";
  $("#dbJobs").innerHTML=jobsChart(j.days)+`<div class="jcounts">${jobCounts(j)}</div>`;
  const last=(j.jobs||[]).slice(0, 5);
  $("#dbLast").innerHTML = last.length
    ? `<ul class="dlist">`+last.map(x=>{ const d=jobRowData(x);
        const ep=Date.parse(x.ts||"")/1000;
        return `<li><span class="k" style="display:flex;align-items:center;gap:8px;min-width:0">${stIc(d.st[0], d.st[1])}<span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(d.lbl)}`+
               `${x.namespace ? ' <span style="color:var(--muted)">· '+d.app+'</span>' : ''}</span></span>`+
               `<span class="v" style="font-weight:400;color:var(--muted);white-space:nowrap">${esc(isNaN(ep)?"":fmtAgo(ep))}</span></li>`; }).join("")+
      `</ul><div style="margin-top:8px"><a href="#" class="lnk" data-go="jobs">Voir toutes les tâches</a></div>`
    : `<div class="tempty">Aucune tâche enregistrée pour l'instant.</div>`;
  bindGo($("#dbLast"));
  $("#dbHealth").innerHTML = CLUSTERS.length
    ? `<ul class="dlist">`+CLUSTERS.map(c=>{
        const h=c.health;
        const ic = h? (h.ok? stIc("ok","Joignable") : stIc("ko",h.error||"")) : stIc("na","Pas encore contrôlé");
        return `<li><span class="k" style="display:flex;align-items:center;gap:8px">${ic}<span>${esc(c.name)}</span></span>`+
               `<span class="v" style="font-weight:400;color:var(--muted)">${h? esc(fmtAgo(h.at)) : "—"}</span></li>`;}).join("")+
      `</ul><div style="margin-top:8px"><a href="#" class="lnk" id="dbHealthLnk">Gérer les clusters</a></div>`
    : '<div class="tempty">—</div>';
  const hl=$("#dbHealthLnk"); if(hl) hl.onclick=e=>{ e.preventDefault(); openSources("cluster:"+ACTIVE_CID); };
}

// ============================ Assistant de restauration ============================
const RS_TITLE="Restauration de l'application";
const RS_KINDS={cloneapp:"Restaurer toute l'application (copie)",
                inplace:"Restaurer le stockage sur place",
                reattach:"Restaurer le stockage vers de nouveaux volumes",
                objects:"Restaurer des objets de configuration",
                dr:"Restauration DR (autre cluster / contexte)"};
var rsWizPage="type", rsWizKind=null, rsWizAct=null, rsWizHtml="", rsTgtMode=null;
$("#rsAdvBody").append($("#rsCustomDirLbl"), $("#rsCustomDirWrap"));   // options avancées repliées
function rsKindFromState(){ return state.mode==="inplace" ? "inplace" : (state.cloneSub==="cloneapp" ? "cloneapp" : "reattach"); }
function rsSyncOpts(){ document.querySelectorAll("#rsPgType .opt").forEach(o=>o.classList.toggle("sel", o.dataset.kind===rsWizKind)); }
function rsSyncTgtOpts(){ document.querySelectorAll("#rsPgTarget .opt").forEach(o=>o.classList.toggle("sel", o.dataset.nsmode===rsTgtMode)); }
// « Suivant » depuis la page Type : le clone d'application passe d'abord par la page
// « cible du clone » (2 cartes) ; les autres types vont directement au formulaire.
function rsNextFromType(){
  if(rsWizKind==="cloneapp") return rsShowPage("target");
  if(rsWizKind==="objects") return objOpen();
  if(rsWizKind==="dr") return drOpen("dr");
  if(rsWizKind==="recover") return drOpen("recover", drRecoverNs);
  return rsToForm();
}
function rsTargetToForm(){
  if(!rsTgtMode) return;
  const b=document.querySelector('#rsCloneNsMode button[data-nsmode="'+rsTgtMode+'"]');
  if(b) b.click();                       // synchronise state.cloneNsMode + champs affichés
  return rsToForm();
}
document.querySelectorAll("#rsPgType .opt").forEach(o=>{
  o.onclick=()=>{ rsWizKind=o.dataset.kind; rsSyncOpts(); rsWizSync(); };
  o.ondblclick=()=>{ rsWizKind=o.dataset.kind; rsSyncOpts(); rsNextFromType(); };
});
document.querySelectorAll("#rsPgTarget .opt").forEach(o=>{
  o.onclick=()=>{ rsTgtMode=o.dataset.nsmode; rsSyncTgtOpts(); rsWizSync(); };
  o.ondblclick=()=>{ rsTgtMode=o.dataset.nsmode; rsSyncTgtOpts(); rsTargetToForm(); };
});
function rsShowPage(p){
  rsWizPage=p;
  if(p==="target"){ rsTgtMode=state.cloneNsMode||"same"; rsSyncTgtOpts(); }
  $("#rsPgType").style.display = p==="type" ? "block" : "none";
  $("#rsPgTarget").style.display = p==="target" ? "block" : "none";
  $("#rsPgObjects").style.display = p==="objects" ? "block" : "none";
  $("#rsPgDr").style.display = p==="dr" ? "block" : "none";
  $("#rsPgForm").style.display = p==="form" ? "block" : "none";
  $("#rsPgPlan").style.display = p==="plan" ? "block" : "none";
  // Retour vers le formulaire : re-masquer #rsPlan, sinon le prochain « Suivant »
  // (qui re-affiche le plan avec la MÊME valeur display:block) ne déclenche aucune
  // mutation -> l'observer ne bascule jamais sur la page 3 (bouton muet).
  if(p!=="plan") $("#rsPlan").style.display="none";
  $("#mRestoreTitle").innerHTML = p==="type" ? esc(RS_TITLE)
    : esc(RS_TITLE)+'<span class="sep">›</span>'+esc(RS_KINDS[rsWizKind]||"");
  $("#rsWizBack").style.display = p==="type" ? "none" : "";
  const b=$("#mRestore .hm-body"); if(b) b.scrollTop=0;
  rsWizSync();
}
// Libellé « namespace › application » de l'assistant (application ciblée, ou namespace entier).
function rsAppLabel(){
  const a=state.app;
  if(!a || a.whole_ns) return esc(state.ns||"—");
  // Lien « tout le namespace » : élargit la restauration à toutes les applications du
  // namespace (visible sur chaque page de l'assistant, pas seulement la page Type).
  return esc(state.ns||"—")+' <span class="sep">›</span> '+esc(a.name)+
    (a.type==="stateless" ? ' <span class="badge b-pending">Stateless</span>' : a.type==="stateful" ? ' <span class="badge b-bound">Stateful</span>' : "")+
    ' <a href="#" class="rsWholeNs" style="margin-left:8px;font-weight:400;font-size:12px">tout le namespace</a>';
}
document.addEventListener("click", e=>{ const a=e.target.closest && e.target.closest(".rsWholeNs, #rsWholeNs");
  if(a){ e.preventDefault(); rsTargetWholeNs(); } });
function openRestoreModal(ns, app){
  ns = ns || state.ns || $("#rsNs").value; if(!ns) return;
  state.ns=ns; applyGlobalNs();
  // Application ciblée (page Applications) : {name, type, pvcs, whole_ns}. Sans
  // application (namespace entier), l'assistant se comporte comme avant.
  state.app = (app && app.name && !app.whole_ns) ? {ns:ns, name:app.name, type:app.type, pvcs:app.pvcs||[], workloads:app.workloads||[], unassigned:!!app.unassigned} : null;
  rsWizKind=rsKindFromState(); rsSyncOpts();
  $("#rsWizApp").innerHTML=rsAppLabel();
  $("#rsWizCluster").innerHTML=`<b>${esc(ctxInfo.context||"—")}</b>`;
  ["#rsLog","#rsInplaceLog","#rsErr"].forEach(id=>$(id).innerHTML="");
  if($("#rsCustomDir").checked) $("#rsAdvWrap").open=true;
  rsRenderAppNote();
  openModal("mRestore");
  // Application STATELESS : les parcours de stockage n'ont pas de sens -> seules les cartes
  // « copie » (clone des workloads + dépendances) et « objets de configuration » restent,
  // la seconde présélectionnée (restauration = ré-appliquer ses objets).
  const sl = !!(state.app && state.app.type==="stateless");
  document.querySelectorAll('#rsPgType .opt').forEach(o=>{ o.style.display = (sl && (o.dataset.kind==="inplace"||o.dataset.kind==="reattach"||o.dataset.kind==="dr")) ? "none" : ""; });
  if(sl){ rsWizKind="objects"; rsSyncOpts(); }
  rsShowPage("type");
}
// Clone d'une application STATELESS (aucun volume) : le formulaire n'a pas de volumes à
// cocher ; le serveur copie les workloads de l'application (+ dépendances).
function rsStatelessClone(){ return !!(state.app && state.app.type==="stateless" && rsWizKind==="cloneapp"); }
// Note « application ciblée » de l'assistant, avec le lien « tout le namespace » : quand
// une application fonctionnelle est découpée en plusieurs applications par ses étiquettes
// (ex. mariadb + wordpress), l'opérateur élargit la restauration à tout le namespace.
function rsRenderAppNote(){
  const note=$("#rsAppNote"); if(!note) return;
  note.style.display = state.app ? "block" : "none";
  const link=`<div style="margin-top:6px"><a href="#" id="rsWholeNs">Restaurer plutôt <b>tout le namespace « ${esc(state.ns||"")} »</b> (toutes ses applications)</a></div>`;
  note.innerHTML = !state.app ? "" : (state.app.type==="stateless"
    ? `Application <b>${esc(state.app.name)}</b> : <b>stateless</b> (aucun volume). Sa restauration = ré-appliquer ses objets de configuration (workloads, Services, ConfigMaps…) depuis l'instantané d'une sauvegarde — parcours <b>« objets de configuration »</b>, présélectionné.`
    : `Application <b>${esc(state.app.name)}</b> : <b>stateful</b> — ses volumes (${esc(state.app.pvcs.join(", ")||"—")}) seront présélectionnés ; les autres volumes du namespace restent décochés.`)+link;
}
function rsTargetWholeNs(){
  state.app=null; rsRenderAppNote();
  document.querySelectorAll('#rsPgType .opt').forEach(o=>o.style.display="");   // tous les parcours de nouveau
  $("#rsWizApp").innerHTML=rsAppLabel(); const oa=$("#objApp"); if(oa) oa.innerHTML=rsAppLabel();
  if(rsWizPage==="form"){ rsAutoCheck=true; document.querySelectorAll(".rsChk").forEach(c=>c.checked=true); rebuildVolCfgs(); }
  else if(rsWizPage==="objects"){ objLoadList(); }
  rsWizSync();
}
async function rsToForm(){
  if(!rsWizKind) return;
  const k=rsWizKind, clk=sel=>{ const b=document.querySelector(sel); if(b) b.click(); };
  if(k==="inplace") clk('#rsMode button[data-mode="inplace"]');
  else { clk('#rsMode button[data-mode="clone"]');
         clk('#rsCloneSub button[data-sub="'+(k==="cloneapp" ? "cloneapp" : "reattach")+'"]'); }
  rsShowPage("form");
  rsAutoCheck=true;
  $("#rsPlan").style.display="none";
  if(rsStatelessClone()){
    state.ns=$("#rsNs").value||state.ns; state.backup_path=null; state.selected={};
    $("#rsPvcs").innerHTML=`<div class="note">Application <b>${esc(state.app.name)}</b> : <b>stateless</b>, aucun volume à restaurer. La copie recrée ses workloads (${esc((state.app.workloads||[]).map(w=>w.kind+"/"+w.name).join(", ")||"—")}) et leurs dépendances depuis le cluster.</div>`;
    $("#rsConfig").style.display="none"; setRsStep(2); rsWizSync(); return;
  }
  $("#rsPvcs").innerHTML='<div class="hint"><span class="spin"></span>Chargement des volumes…</div>';
  await loadPvcs();
  rsWizSync();
}
// Le récapitulatif s'affiche (plan construit) -> page 3 de l'assistant.
new MutationObserver(()=>{
  if($("#mRestore").style.display!=="none" && rsWizPage==="form" && $("#rsPlan").style.display!=="none") rsShowPage("plan");
}).observe($("#rsPlan"), {attributes:true, attributeFilter:["style"]});
// UNE action principale dans le pied de modale, qui relaie le bouton d'origine adapté
// à l'étape (clone HYCU groupé, restauration sur place, construction du plan, lancement).
function rsWizSync(){
  const go=$("#rsWizGo"); let lbl="Suivant", dis=false, act=null, src=null;
  if(rsWizPage==="type"){ dis=!rsWizKind; act=rsNextFromType; }
  else if(rsWizPage==="dr"){
    const n=document.querySelectorAll(".drRef").length;
    const filled=[...document.querySelectorAll(".drRef")].filter(t=>t.value.trim()).length;
    // Réutilisation des volumes d'origine : aucun UUID requis (le serveur les déduit
    // de la sauvegarde). Sinon, tous les volumes doivent avoir une référence. Une
    // sauvegarde STATELESS (aucun volume, workloads dans l'instantané) se restaure sans volume.
    const needRefs = !drRecoverReuse();
    const b=drSel(), noVol = !n && !!(b && b.stateless);
    lbl=dry()? "Restaurer (simulation)" : "Restaurer (réel)";
    dis=!drAllowed || (!n && !noVol) || (needRefs && filled<n) || drBusy || !$("#drTargetNs").value.trim();
    act=drRun;
  }
  else if(rsWizPage==="objects"){
    const n=document.querySelectorAll(".objChk:checked").length;
    if(objPhase==="pick"){ lbl="Prévisualiser les différences"; dis=!n || objBusy; act=objToDiff; }
    else { lbl=dry()? "Appliquer (simulation)" : "Appliquer (réel)"; dis=!n || objBusy; act=objApply; }
  }
  else if(rsWizPage==="target"){ dis=!rsTgtMode; act=rsTargetToForm; }
  else if(rsWizPage==="form"){
    const n=document.querySelectorAll(".rsChk:checked").length;
    const hyOn=!!(conn.hycu && conn.hycu.connected);
    if(rsStatelessClone()){ lbl="Vérifier la copie"; act=()=>$("#rsPreview").click(); }
    else if(state.mode==="inplace" && hyOn){ src=$("#rsInplaceRun"); lbl="Restaurer"; }
    else {
      const items=collectItems(), filled=items.length>0 && items.every(i=>(i.new_ref||"").trim());
      const batch=$("#hyBatchGo");
      if(batch && !filled){ src=batch; lbl="Restaurer"; }
      else { dis=!n; act=()=>$("#rsPreview").click(); }
    }
    if(src){ dis=!n || src.disabled; act=()=>src.click(); }
  } else { src=$("#rsGo"); lbl=(src.textContent||"").trim() || "Lancer"; dis=src.disabled; act=()=>src.click(); }
  const busy = src && src.querySelector(".spin");
  const html = busy ? '<span class="spin"></span>'+esc((src.textContent||"").trim()) : esc(lbl);
  if(html!==rsWizHtml){ go.innerHTML=html; rsWizHtml=html; }
  go.disabled=dis; rsWizAct=act;
  const live=!dry(), m=$("#rsWizMode");
  m.textContent = live ? "Mode réel" : "Simulation";
  m.className="badge "+(live ? "live" : "sim");
}
$("#rsWizGo").onclick=()=>{ if(rsWizAct && !$("#rsWizGo").disabled) rsWizAct(); };
$("#rsWizBack").onclick=()=>{
  if(rsWizPage==="dr") return rsShowPage("type");
  if(rsWizPage==="objects"){
    if(objPhase==="diff"){ objPhase="pick"; $("#objDiffWrap").style.display="none"; $("#objPick").style.display="block"; $("#objLog").innerHTML=""; rsWizSync(); return; }
    return rsShowPage("type");
  }
  rsShowPage(rsWizPage==="plan" ? "form"
    : (rsWizPage==="form" && rsWizKind==="cloneapp") ? "target" : "type");
};

// ----- Restauration DR : reprise sur CE cluster depuis une sauvegarde étrangère -----
var drAllowed=false, drBusy=false, drBackups=[], drMode="dr", drRecoverNs=null;
// Application SUPPRIMÉE du cluster : récupération sur le MÊME cluster/contexte —
// mêmes mécanismes que la page DR (sources depuis la sauvegarde seule), mais SANS
// la dérogation allow_dr_restore (le serveur vérifie que la sauvegarde est d'ici).
function openRecoverModal(ns){
  state.ns=ns; state.app=null;         // la récupération recrée tout le namespace
  const note=$("#rsAppNote"); if(note){ note.style.display="none"; note.innerHTML=""; }
  rsWizKind="recover"; rsSyncOpts();   // kind dédié : « Retour » puis « Suivant » ne devient jamais une DR
  ["#rsLog","#rsInplaceLog","#rsErr"].forEach(id=>{ const e=$(id); if(e) e.innerHTML=""; });
  openModal("mRestore");
  drOpen("recover", ns);
}
$("#drOpenCfg").onclick=()=>{ closeModal("mRestore"); switchTab("settings"); };
async function drOpen(mode, recoverNs){
  drMode = mode==="recover" ? "recover" : "dr";
  drRecoverNs = drMode==="recover" ? (recoverNs||null) : null;
  // Rien de l'ouverture précédente ne doit rester cliquable pendant le chargement :
  // occupé + listes vidées, jusqu'au rendu des sauvegardes fraîches.
  drBusy=true; drBackups=[]; $("#drVols").innerHTML=""; $("#drBackupSel").innerHTML=""; $("#drTargetNs").value="";
  $("#drLog").innerHTML=""; $("#drErr").innerHTML="";
  $("#drSc").value="";                 // jamais de remap hérité d'un parcours précédent
  $("#drRefs").checked=true;
  rsShowPage("dr");
  if(drMode==="recover"){
    $("#mRestoreTitle").innerHTML=esc(RS_TITLE)+'<span class="sep">›</span>'+esc("Restaurer l'application supprimée « "+recoverNs+" »");
    $("#drWarnDr").style.display="none"; $("#drWarnRec").style.display="block";
    $("#drReuseWrap").style.display="block"; $("#drReuse").checked=true;
  } else {
    $("#drWarnDr").style.display="block"; $("#drWarnRec").style.display="none";
    $("#drReuseWrap").style.display="none";
  }
  $("#drCluster").textContent=ctxInfo.context||"—";
  $("#drClusterRec").textContent=ctxInfo.context||"—";
  const r=await get("/api/dr/backups");
  // Récupération même-cluster : pas de dérogation requise — le serveur re-vérifie.
  drAllowed = drMode==="recover" ? !!r.ok : !!(r.ok && r.allowed);
  $("#drGate").style.display = drAllowed? "none":"block";
  $("#drForm").style.display = drAllowed? "block":"none";
  if(!drAllowed){ drBusy=false; rsWizSync(); return; }
  drBackups=(r.backups||[]).filter(b=> drMode==="recover"
    ? (b.restorable_here && b.namespace===drRecoverNs) : true);
  $("#drBackupSel").innerHTML = drBackups.length? drBackups.map((b,i)=>
    `<option value="${i}">${esc(b.cluster)}${b.context&&b.cluster_id==="local"?" ("+esc(b.context)+")":""} › ${esc(b.namespace)} › ${esc(b.timestamp)}${b.imported?" · import S3":""}</option>`).join("")
    : '<option value="">(aucune sauvegarde)</option>';
  drBusy=false;
  drRenderVols();
  rsWizSync();
}
$("#drBackupSel").onchange=()=>drRenderVols();
function drSel(){ return drBackups[+$("#drBackupSel").value]||null; }
// Récupération : par défaut on réutilise les volumes d'origine (case cochée) -> aucune
// saisie. La grille d'UUID n'apparaît que pour la reprise d'activité, ou si l'humain a
// restauré les données sur de NOUVEAUX volumes (case décochée).
function drRecoverReuse(){ return drMode==="recover" && $("#drReuse").checked; }
function drRenderVols(){
  const b=drSel();
  $("#drTargetNs").value=b? b.namespace : "";
  // Honnêteté : sauvegarde sans instantané de ressources -> volumes uniquement.
  $("#drNoRes").style.display = (b && b.has_resources===false)? "block":"none";
  // Secrets de la sauvegarde : masqués (non recréés) ou chiffrés (coffre à déverrouiller).
  const sn=$("#drSecretsNote"), sm=b&&b.secrets;
  if(sn){ sn.style.display = (sm==="redacted"||sm==="encrypted") ? "block" : "none";
    sn.innerHTML = sm==="redacted" ? "Les <b>Secrets</b> de cette sauvegarde sont <b>masqués</b> : ils ne seront pas recréés (à recréer à la main après la restauration)."
      : sm==="encrypted" ? "Les <b>Secrets</b> de cette sauvegarde sont <b>chiffrés</b> avec la phrase du coffre : déverrouillez le coffre (⚙ → Sources) avant de lancer, sinon ils ne seront pas recréés." : ""; }
  const refs=(b&&b.vol_refs)||{};
  // En récupération, chaque champ est PRÉ-REMPLI avec l'UUID d'origine (issu de la
  // sauvegarde) : l'humain n'a rien à taper. En DR, les champs restent vides (nouveaux VG).
  $("#drVols").innerHTML = b && b.volumes.length? b.volumes.map(v=>
    `<div class="drVol"><div class="drVolNm">${esc(v)}</div>
     <input type="text" class="drRef" data-pvc="${esc(v)}" spellcheck="false" autocomplete="off"
       value="${drMode==="recover"&&refs[v]?esc(refs[v]):""}"
       placeholder="${esc(drMode==="recover"?"UUID du Volume Group (8-4-4-4-12)":"UUID du VG restauré/cloné sur le site cible (8-4-4-4-12)")}"></div>`).join("")
    : (b && b.stateless ? '<div class="note">Sauvegarde <b>stateless</b> (aucun volume) : les workloads'+((b.apps||[]).length?' ('+esc((b.apps||[]).join(", "))+')':'')+' et leurs dépendances seront recréés depuis l\'instantané.</div>'
                        : '<div class="hint">Aucun volume dans cette sauvegarde.</div>');
  document.querySelectorAll(".drRef").forEach(t=>t.oninput=rsWizSync);
  drSyncReuse();
}
// Bascule d'affichage de la grille selon « réutiliser les volumes d'origine ».
function drSyncReuse(){
  const reuse=drRecoverReuse();
  $("#drVols").style.display = reuse? "none":"block";
  $("#drVolsLabel").style.display = (drMode==="recover")? (reuse?"none":"block") : "block";
  if(drMode==="recover") $("#drVolsLabel").textContent="Nouveaux volumes — collez l'identifiant (UUID) fourni par HYCU";
  else $("#drVolsLabel").textContent="Volumes — collez l'UUID du VG restauré/cloné sur le site cible";
  // Bouton « auto HYCU » : seulement quand la grille est visible ET HYCU + Prism connectés.
  const autoOk = !reuse && (conn.hycu&&conn.hycu.connected)
                 && ((conn.prismcentral&&conn.prismcentral.connected)||(conn.nutanix&&conn.nutanix.connected));
  $("#drAutoWrap").style.display = autoOk? "block":"none";
  rsWizSync();
}
$("#drReuse").onchange=drSyncReuse;
// Auto-provisionnement : HYCU clone les VG et l'outil découvre leurs nouveaux UUID,
// qu'il inscrit dans la grille (aucune saisie). Simulation = plan seulement.
$("#drAuto").onclick=async()=>{
  const b=drSel(); if(!b) return;
  const refs=(b&&b.vol_refs)||{}, hy=(b&&b.vol_hycu)||{}, names=(b&&b.vol_names)||{};
  // Source pour HYCU = l'identité HYCU du VG (contrat) si disponible, sinon l'UUID Nutanix ;
  // le nom du VG aide à retrouver un VG SUPPRIMÉ du cluster dans le catalogue HYCU.
  const volumes=[...document.querySelectorAll(".drRef")].map(t=>({pvc:t.dataset.pvc,
    source_vg_uuid:hy[t.dataset.pvc]||refs[t.dataset.pvc]||"", vg_name:names[t.dataset.pvc]||""}));
  if(!volumes.length || volumes.some(v=>!v.source_vg_uuid)){
    $("#drErr").innerHTML=errBox("UUID du VG source absent de la sauvegarde : automatisation impossible, saisissez les UUID manuellement."); return; }
  if(!dry() && !(await confirmDanger({title:"Clones HYCU RÉELS", lines:[
      "Déclencher dans HYCU le <b>clone</b> de <b>"+volumes.length+"</b> Volume Group(s) (nouveaux VG créés) ?",
      "Les nouveaux identifiants seront inscrits automatiquement dans la grille."]}))) return;
  const btn=$("#drAuto"); btn.disabled=true; drBusy=true; rsWizSync();
  $("#drErr").innerHTML=""; $("#drLog").innerHTML='<div class="hint"><span class="spin"></span>HYCU : création des volumes…</div>';
  try{
    const r=await post("/api/hycu/provision_clone", {volumes, dry:dry()});
    if(!r.ok){ $("#drErr").innerHTML=errBox(r.error); $("#drLog").innerHTML=renderLog(r.log||[]); return; }
    if(!r.dry){ (r.items||[]).forEach(it=>{ const el=document.querySelector('.drRef[data-pvc="'+(window.CSS&&CSS.escape?CSS.escape(it.pvc):it.pvc)+'"]'); if(el && it.new_ref) el.value=it.new_ref; }); }
    $("#drLog").innerHTML=renderLog(r.log||[]);
  } finally { btn.disabled=false; drBusy=false; rsWizSync(); }
};
$("#drTargetNs").oninput=()=>rsWizSync();
async function drRun(){
  const b=drSel(); if(!b) return;
  // Réutilisation des volumes d'origine : on n'envoie PAS d'UUID, le serveur le déduit
  // de la sauvegarde (source de vérité). Sinon on transmet ce que l'humain a saisi.
  const reuse=drRecoverReuse();
  const items=[...document.querySelectorAll(".drRef")].map(t=>({pvc:t.dataset.pvc, new_ref:reuse?"":t.value.trim()}));
  const live=!dry();
  let confirmedCtx="";
  if(live){
    const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||"") : null;
    const res=await confirmDanger({title:(drMode==="recover"?"Restauration d'une application SUPPRIMÉE":"Restauration DR RÉELLE"), requireText:needCtx, lines:[
      "Sauvegarde source : <b>"+esc(b.cluster)+" › "+esc(b.namespace)+" › "+esc(b.timestamp)+"</b>",
      "Cluster CIBLE : <b>"+esc(ctxInfo.context||"?")+"</b> · namespace cible : <b>"+esc($("#drTargetNs").value)+"</b>",
      drMode==="recover"
        ? "L'application sera RECRÉÉE sur ce cluster depuis la sauvegarde (namespace, PV/PVC, workloads, dépendances non masquées)."
        : "La garde inter-cluster est LEVÉE pour cette opération : l'application sera recréée sur ce cluster depuis la sauvegarde (PV/PVC, workloads, dépendances non masquées).",
      ...((drMode==="recover" && drRecoverReuse() && conn.hycu && conn.hycu.connected)
        ? ["Si un volume d'origine a disparu du cluster, HYCU le RESTAURERA automatiquement (opération HYCU réelle) avant la recréation."] : [])]});
    if(!res) return;
    if(typeof res==="string") confirmedCtx=res;
  }
  drBusy=true; rsWizSync();
  $("#drLog").innerHTML='<div class="hint"><span class="spin"></span>Restauration DR…</div>';
  const body={namespace:b.namespace, target_namespace:$("#drTargetNs").value.trim(),
              backup_path:b.path, items, dry:dry(),
              dr_storageclass:$("#drSc").value.trim(), clone_refs:$("#drRefs").checked};
  if(drMode==="recover") body.from_backup_only=true; else body.dr_restore=true;
  if(live && ctxInfo.require_confirm) body.confirm_context=confirmedCtx;
  const r=await runOp("/api/clone_app", body, log=>{ $("#drLog").innerHTML=renderLog(log); });
  drBusy=false; rsWizSync();
  const head = r.ok? (r.dry? '<div class="warnbox">Simulation — séquence qui serait exécutée.</div>'
                           : '<div class="note">Restauration DR terminée. Vérifiez l\'application, puis re-protégez ses Volume Groups dans HYCU.</div>')
                   : errBox(r.error);
  $("#drLog").innerHTML=head+((r.warnings||[]).length?`<div class="warnbox" style="margin-top:8px">${r.warnings.map(esc).join("<br>")}</div>`:"")+renderLog(r.log);
}

// ----- Restauration guidée des OBJETS de configuration (resources.json) -----
var objItems=[], objPhase="pick", objBusy=false, objBackups=[];
function objBody_(){ return {namespace:$("#rsNs").value||state.ns,
  backup_path:($("#objBackupSel").value||null), backup_root:state.backup_root||null,
  app:(state.app && !state.app.unassigned) ? state.app.name : null}; }
async function objOpen(){
  objPhase="pick"; objBusy=true; objItems=[];
  $("#objApp").innerHTML=rsAppLabel();
  $("#objErr").innerHTML=""; $("#objLog").innerHTML=""; $("#objDiffWrap").style.display="none";
  $("#objPick").style.display="block";
  $("#objBody").innerHTML='<tr><td colspan="4" class="tempty"><span class="spin"></span></td></tr>';
  rsShowPage("objects");
  const ns=state.ns||$("#rsNs").value;
  const b=await get("/api/backups?ns="+encodeURIComponent(ns)+(state.backup_root?("&root="+encodeURIComponent(state.backup_root)):""));
  objBackups=(b.backups||[]);
  $("#objBackupSel").innerHTML=objBackups.map(x=>`<option value="${esc(x.path)}">${esc(x.timestamp)} — ${((x.index||{}).volumes||[]).length} volume(s)${(x.index||{}).resources_count!=null?(" · "+(x.index||{}).resources_count+" objets"):""}</option>`).join("")
    || '<option value="">(aucune sauvegarde)</option>';
  await objLoadList();
}
$("#objBackupSel").onchange=()=>objLoadList();
async function objLoadList(){
  objBusy=true; rsWizSync();
  $("#objErr").innerHTML=""; $("#objLog").innerHTML="";
  if(!$("#objBackupSel").value){
    $("#objBody").innerHTML='<tr><td colspan="4" class="tempty">Aucune sauvegarde pour ce namespace — lancez d\'abord une sauvegarde (Applications → Sauvegarder).</td></tr>';
    objItems=[]; objBusy=false; rsWizSync(); return;
  }
  const r=await post("/api/objects/list", objBody_());
  objBusy=false;
  if(!r.ok){ $("#objBody").innerHTML=""; $("#objErr").innerHTML=errBox(r.error); objItems=[]; rsWizSync(); return; }
  objItems=r.items||[];
  // Application ciblée : ses objets sont marqués (in_app) et PRÉCOCHÉS ; les objets des
  // autres applications du namespace sont masqués par défaut (case « seulement… »).
  const appOn = !!(r.app);
  $("#objOnlyAppWrap").style.display = appOn ? "" : "none";
  $("#objInfo").textContent="("+objItems.length+" objet(s) dans l'instantané"+(appOn?(" · "+(r.app_count||0)+" de l'application « "+r.app+" »"):"")+")";
  $("#objBody").innerHTML=objItems.length? objItems.map(o=>`<tr class="clk${o.redacted?'':' '}${appOn&&!o.in_app?' objOther':''}" data-i="${o.i}">
     <td class="cb"><input type="checkbox" class="objChk" data-i="${o.i}" ${o.redacted?"disabled":""} ${appOn&&o.in_app&&!o.redacted?"checked":""}></td>
     <td>${esc(o.kind)}</td><td style="color:var(--strong);font-weight:500">${esc(o.name)}</td>
     <td>${o.encrypted?'<span class="badge b-pending">Secret chiffré — déverrouillez le coffre</span>':o.redacted?'<span class="badge b-pending">Secret masqué — non restaurable</span>':(appOn&&!o.in_app?'<span class="hint">autre application / partagé</span>':"")}</td></tr>`).join("")
    : '<tr><td colspan="4" class="tempty">Instantané vide.</td></tr>';
  document.querySelectorAll("#objBody tr.clk").forEach(tr=>tr.onclick=e=>{
    if(e.target.classList.contains("objChk")) return rsWizSync();
    const c=tr.querySelector(".objChk"); if(c && !c.disabled){ c.checked=!c.checked; rsWizSync(); } });
  document.querySelectorAll(".objChk").forEach(c=>c.onchange=rsWizSync);
  $("#objAll").checked=false; objSyncOnlyApp(); rsWizSync();
}
function objSyncOnlyApp(){
  const only = $("#objOnlyAppWrap").style.display!=="none" && $("#objOnlyApp").checked;
  document.querySelectorAll("#objBody tr.objOther").forEach(tr=>{ tr.style.display = only ? "none" : "";
    if(only){ const c=tr.querySelector(".objChk"); if(c) c.checked=false; } });
}
$("#objOnlyApp").onchange=()=>{ objSyncOnlyApp(); rsWizSync(); };
$("#objAll").onchange=()=>{ const on=$("#objAll").checked;
  document.querySelectorAll("#objBody tr").forEach(tr=>{ if(tr.style.display==="none") return;
    const c=tr.querySelector(".objChk:not([disabled])"); if(c) c.checked=on; }); rsWizSync(); };
function objSelIdx(){ return [...document.querySelectorAll(".objChk:checked")].map(c=>+c.dataset.i); }
async function objToDiff(){
  objBusy=true; rsWizSync();
  $("#objErr").innerHTML="";
  $("#objDiff").innerHTML='<div class="hint"><span class="spin"></span>Comparaison avec l\'état live…</div>';
  $("#objDiffWrap").style.display="block";
  const r=await post("/api/objects/diff", Object.assign(objBody_(), {indexes:objSelIdx()}));
  objBusy=false;
  if(!r.ok){ $("#objDiffWrap").style.display="none"; $("#objErr").innerHTML=errBox(r.error); rsWizSync(); return; }
  const ST={identical:["ok","Identique au live — apply sans effet"], differs:["wn","Diffère du live"],
            absent:["run","Absent du live — sera (re)créé"], error:["ko","Lecture du live impossible"],
            redacted:["ko","Secret masqué"]};
  $("#objDiff").innerHTML=(r.results||[]).map(x=>{
    const st=ST[x.status]||["na",x.status];
    const body = x.status==="differs" ? `<pre class="box" style="margin:6px 0 0;max-height:260px;overflow:auto">${esc(x.diff)}</pre>`
      : (x.error? `<div class="hint" style="color:var(--red)">${esc(x.error)}</div>` : "");
    return `<div class="repl" style="margin-bottom:10px"><div class="nm" style="display:flex;gap:10px;align-items:center">${stIc(st[0],st[1])}<b>${esc(x.kind)}/${esc(x.name)}</b><span class="hint">${esc(st[1])}</span></div>${body}</div>`;
  }).join("") || '<div class="hint">Rien à comparer.</div>';
  $("#objPick").style.display="none"; objPhase="diff"; rsWizSync();
}
async function objApply(){
  const live=!dry();
  let confirmedCtx="";
  if(live){
    const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||"") : null;
    const res=await confirmDanger({title:"Restauration d'objets RÉELLE", requireText:needCtx, lines:[
      "Namespace : <b>"+esc($("#rsNs").value||state.ns||"?")+"</b>",
      "Cluster ciblé : <b>"+esc(ctxInfo.context||"?")+"</b>",
      "<b>"+objSelIdx().length+"</b> objet(s) de configuration seront ÉCRASÉS par la version de la sauvegarde (kubectl apply). Les volumes et les données ne sont pas touchés."]});
    if(!res) return;
    if(typeof res==="string") confirmedCtx=res;
  }
  objBusy=true; rsWizSync();
  $("#objLog").innerHTML='<div class="hint"><span class="spin"></span>Application…</div>';
  const body=Object.assign(objBody_(), {indexes:objSelIdx(), dry:dry()});
  if(live && ctxInfo.require_confirm) body.confirm_context=confirmedCtx;
  const r=await post("/api/objects/restore", body);
  objBusy=false; rsWizSync();
  const head = r.ok? (r.dry? '<div class="warnbox">Simulation — commandes qui seraient exécutées.</div>'
                           : `<div class="note">${r.applied} objet(s) appliqué(s)${r.skipped?(" · "+r.skipped+" ignoré(s)"):""}.</div>`)
                   : errBox(r.error);
  $("#objLog").innerHTML=head+renderLog(r.log);
}
setInterval(()=>{ if($("#mRestore").style.display!=="none") rsWizSync(); }, 300);

// ----- Langue FR/EN : cookie lu par le serveur, page + messages retraduits au rechargement -----
const PAGE_LANG="fr";
$("#langBtn").onclick=()=>{
  document.cookie="hycu_lang="+(PAGE_LANG==="fr"?"en":"fr")+";path=/;max-age=31536000;SameSite=Lax";
  location.reload();
};
</script>
</body>
</html>
"""

# Édition assistée en dev : si un fichier `ui.html` est présent à côté du programme,
# il REMPLACE l'UI embarquée (coloration/lint/autocomplétion dans l'éditeur). Le `.py`
# reste 100 % autonome : sans `ui.html`, l'UI embarquée ci-dessus est utilisée.
# (Pour créer le point de départ : dumper la constante HTML dans ui.html.)
# Interface de développement : un ui.html À CÔTÉ DU PROGRAMME remplace l'interface
# embarquée — uniquement si HYCU_DEV_UI=1 (jamais en production : un fichier déposé dans
# le répertoire courant d'un conteneur ne doit pas substituer l'UI).
_UI_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui.html")
if os.environ.get("HYCU_DEV_UI") == "1" and os.path.isfile(_UI_PATH):
    try:
        with open(_UI_PATH, encoding="utf-8") as _f:
            HTML = _f.read()
        print("UI chargée depuis ui.html (mode développement).")
    except Exception as _e:                      # pragma: no cover
        print("ui.html illisible (%s) : UI embarquée utilisée." % _e)


# ------------------------------------------------------------------------------
# i18n — interface bilingue FR/EN (cookie « hycu_lang », bouton EN/FR dans l'en-tête)
# ------------------------------------------------------------------------------
# Principe : le FRANÇAIS reste la langue canonique du code (HTML, JS, messages).
# La traduction est purement une couche de PRÉSENTATION, appliquée à deux endroits :
#   1. la page servie sur « / » : le source HTML/JS est traduit par remplacement de
#      fragments (les plus longs d'abord), puis mis en cache — les chaînes construites
#      dynamiquement par le JS sont couvertes puisque le source lui-même est traduit ;
#   2. les réponses JSON (_json) : seules les clés textuelles connues (error, label,
#      warnings…) sont traduites — les données (noms, UUID, manifestes) sont intactes.
# La logique interne (regex sur les messages, audit.log, hints kubectl) travaille
# toujours sur les textes français d'origine : aucune incidence fonctionnelle.
# Chaque fragment FR doit être un extrait EXACT d'une ligne du source ou d'un message.
I18N_EN = []

# --- Page : <head>, modale de confirmation, assistant, déverrouillage, filtre ns ---
I18N_EN += [
    ('<html lang="fr">', '<html lang="en">'),
    ("<title>HYCU · Kubernetes sur Nutanix</title>", "<title>HYCU · Kubernetes on Nutanix</title>"),
    ("Confirmer l'action réelle", "Confirm the real action"),
    ("Pour confirmer, retapez <b", "To confirm, retype <b"),
    (">Annuler<", ">Cancel<"),
    ("Confirmer en mode réel", "Confirm in real mode"),
    ("Configuration initiale", "Initial setup"),
    (">Précédent<", ">Back<"),
    ("Suivant", "Next"),
    ("Déverrouiller les connexions", "Unlock saved connections"),
    ("Un coffre d'identifiants chiffré a été trouvé. Saisissez la phrase secrète maîtresse",
     "An encrypted credentials vault was found. Enter the master passphrase"),
    ("pour reconnecter automatiquement HYCU / Nutanix.", "to reconnect HYCU / Nutanix automatically."),
    ("Phrase secrète (≥ 8 caractères)", "Passphrase (≥ 8 characters)"),
    ("Phrase secrète", "Passphrase"),
    (">Plus tard<", ">Later<"),
    ("Déverrouiller", "Unlock"),
    ("Connexions rechargées : ", "Connections reloaded: "),
    ("Filtrer les namespaces", "Filter namespaces"),
    ("Toutes les namespaces (aucun filtre)", "All namespaces (no filter)"),
    ("Affiche toutes les namespaces, y compris celles créées plus tard.",
     "Shows every namespace, including ones created later."),
    ("rechercher une namespace…", "search for a namespace…"),
    ("Tout cocher (visibles)", "Check all (visible)"),
    ("Tout décocher (visibles)", "Uncheck all (visible)"),
    ("Enregistrer le filtre", "Save filter"),
    ('textContent="toutes"', 'textContent="all"'),
    ('" sélectionnée(s)"', '" selected"'),
    ('" · futures namespaces exclues (cochez « Toutes »)"', '" · future namespaces excluded (tick « All »)"'),
    ("Aucune namespace ne correspond.", "No namespace matches."),
    (" — impossible de charger la liste ; sauvegarde désactivée.",
     " — could not load the list; saving disabled."),
    ("'kubectl indisponible'", "'kubectl unavailable'"),
    ("||'erreur'", "||'error'"),
    # --- En-tête, bandeau simulation, navigation ---
    ("Protection Kubernetes sur Nutanix", "Kubernetes Protection on Nutanix"),
    ("Contexte kubectl détecté : <b>", "Detected kubectl context: <b>"),
    ('title="Afficher l\'interface en anglais">EN</button>', 'title="Passer en français / Switch to French">FR</button>'),
    ('const PAGE_LANG="fr"', 'const PAGE_LANG="en"'),
    ("⚠ hors liste autorisée", "⚠ not in allowed list"),
    ("Mode simulation activé", "Simulation mode on"),
    (" — aucune commande destructive n'est exécutée.", " — no destructive command is executed."),
    ("Désactivez-le seulement quand vous êtes prêt à agir réellement.",
     "Turn it off only when you are ready to act for real."),
    ('"MODE RÉEL — les commandes seront exécutées"', '"REAL MODE — commands will be executed"'),
    ('aria-label="Sections de l\'outil"', 'aria-label="Tool sections"'),
]

# --- Onglet Sauvegarder (HTML + JS) et protection HYCU ---
I18N_EN += [
    ("Sauvegarder les volumes d'un namespace", "Back up a namespace's volumes"),
    ("Exporte et nettoie automatiquement tous les PV et PVC du namespace.",
     "Automatically exports and cleans all PVs and PVCs in the namespace."),
    ("Équivaut aux boucles kubectl + nettoyage manuel des manifestes.",
     "Equivalent to the kubectl loops + manual manifest cleanup."),
    ('title="Filtrer la liste des namespaces"', 'title="Filter the namespace list"'),
    (">✎ Filtrer<", ">✎ Filter<"),
    ("Sauvegarder ce namespace", "Back up this namespace"),
    ("Sauvegarder tous les namespaces autorisés par le filtre (tous si aucun filtre)",
     "Back up all namespaces allowed by the filter (all if no filter)"),
    ("Sauvegarder tous (filtrés)", "Back up all (filtered)"),
    ("Dossier de destination (optionnel)", "Destination folder (optional)"),
    ("Vide = hycu-backups/ (à côté du programme). Ex. D:\\sauvegardes\\hycu  ou  /mnt/backups",
     "Empty = hycu-backups/ (next to the program). E.g. D:\\backups\\hycu  or  /mnt/backups"),
    ("Chemin sur la machine qui exécute l'outil. Le sous-dossier &lt;namespace&gt;/&lt;horodatage&gt; est créé automatiquement.",
     "Path on the machine running the tool. The &lt;namespace&gt;/&lt;timestamp&gt; subfolder is created automatically."),
    ("Protéger les données dans HYCU", "Protect the data in HYCU"),
    ("L'export ci-dessus ne sauvegarde que les <b>manifestes</b> (la « recette » du restore).",
     "The export above only saves the <b>manifests</b> (the restore “recipe”)."),
    ("Les <b>données</b> vivent dans les Volume Groups Nutanix : seul HYCU les sauvegarde réellement.",
     "The <b>data</b> lives in Nutanix Volume Groups: only HYCU actually backs it up."),
    ("Ici, on associe les PVC du namespace aux Volume Groups HYCU, on assigne une politique, et on lance",
     "Here we match the namespace's PVCs to HYCU Volume Groups, assign a policy, and trigger"),
    ("une sauvegarde.</p>", "a backup.</p>"),
    ("Enregistrez la source HYCU (⚙ en haut à droite) pour activer cette section.",
     "Register the HYCU source (⚙ at the top right) to enable this section."),
    ("Analyser la correspondance PVC ↔ Volume Group HYCU", "Analyze the PVC ↔ HYCU Volume Group mapping"),
    ("Politique HYCU à assigner (optionnel)", "HYCU policy to assign (optional)"),
    ("Sauvegarde complète (forceFull)", "Full backup (forceFull)"),
    ("Assigner + sauvegarder maintenant", "Assign + back up now"),
    ("</span>Sauvegarde…", "</span>Backing up…"),
    (" volume(s) sauvegardé(s) dans", " volume(s) backed up to"),
    (" ressource(s) de config (Deployments, Services, Secrets…)",
     " config resource(s) (Deployments, Services, Secrets…)"),
    ("(IQN détecté)", "(IQN detected)"),
    ("⚠ Récupérez cette sauvegarde <b>hors du cluster</b> via ⬇ Télécharger (.zip) — ou copiez le dossier vers un autre stockage : c'est votre filet de sécurité en cas de sinistre.",
     "⚠ Get this backup <b>off the cluster</b> via ⬇ Download (.zip) — or copy the folder to other storage: it is your safety net in a disaster."),
    ("⚠ Récupérez ces sauvegardes <b>hors du cluster</b> via ⬇ Télécharger — ou copiez les dossiers vers un autre stockage : c'est votre filet de sécurité en cas de sinistre.",
     "⚠ Get these backups <b>off the cluster</b> via ⬇ Download — or copy the folders to other storage: it is your safety net in a disaster."),
    ("'Tout télécharger (.zip)'", "'Download all (.zip)'"),
    ("'Télécharger (.zip)'", "'Download (.zip)'"),
    ("⬇ Télécharger (.zip)", "⬇ Download (.zip)"),
    ("'Télécharger'", "'Download'"),
    (" — aucun PVC (ignoré)", " — no PVC (skipped)"),
    ("||'échec'", "||'failed'"),
    (" namespace(s) sauvegardé(s) · ", " namespace(s) backed up · "),
    (" volume(s) au total ", " volume(s) in total "),
    ('"namespaces du filtre"', '"namespaces in the filter"'),
    ('"tous les namespaces du cluster"', '"all cluster namespaces"'),
    ("Mode simulation (bandeau du haut) : montre les appels HYCU.",
     "Simulation mode (banner at top): shows the HYCU calls."),
    ("Mode réel : exécute sur HYCU.", "Real mode: executes on HYCU."),
    ("Cochez au moins un Volume Group (les correspondances « par nom » doivent être confirmées).",
     "Check at least one Volume Group (“by name” matches must be confirmed)."),
    ("Protection HYCU RÉELLE", "REAL HYCU protection"),
    ("Assigner la politique puis <b>sauvegarder</b>", "Assign the policy then <b>back up</b>"),
    (':"<b>Sauvegarder</b>")', ':"<b>Back up</b>")'),
    ('" ces Volume Groups :"', '" these Volume Groups:"'),
    ("Simulation — appels qui seraient envoyés à HYCU :", "Simulation — calls that would be sent to HYCU:"),
    ("Politique assignée / sauvegarde HYCU déclenchée.", "Policy assigned / HYCU backup triggered."),
    ("Échec — voir le détail.", "Failed — see details."),
    ("par nom — à confirmer", "by name — to be confirmed"),
    ("ambigu : plusieurs Volume Groups correspondent — vérifiez dans HYCU",
     "ambiguous: several Volume Groups match — check in HYCU"),
    ("aucun Volume Group HYCU trouvé", "no HYCU Volume Group found"),
    (">conforme<", ">compliant<"),
    (">non conforme<", ">non-compliant<"),
    (">à sauvegarder<", ">to back up<"),
    (">non protégé<", ">not protected<"),
    ("· politique : <b>", "· policy: <b>"),
    ("· backups : ", "· backups: "),
    ("?'oui':'non'", "?'yes':'no'"),
    ("Aucun PVC dans ce namespace.", "No PVC in this namespace."),
    (" par nom (à confirmer) · ", " by name (to confirm) · "),
    (" ambigu(s) · ", " ambiguous · "),
    (" non trouvé(s)", " not found"),
    ("(ne pas changer la politique)", "(do not change the policy)"),
    ("Analyse en cours…", "Analyzing…"),
]

# --- Onglet Restaurer : HTML statique + guides de flux ---
I18N_EN += [
    (">2 · Configurer<", ">2 · Configure<"),
    (">3 · Lancer<", ">3 · Launch<"),
    ("Choisir le namespace et les volumes", "Choose the namespace and volumes"),
    ("Lire les sauvegardes depuis un dossier personnalisé", "Read backups from a custom folder"),
    ("Ex. D:\\sauvegardes\\hycu  ou  /mnt/backups  (dossier contenant &lt;namespace&gt;/&lt;horodatage&gt;/)",
     "E.g. D:\\backups\\hycu  or  /mnt/backups  (folder containing &lt;namespace&gt;/&lt;timestamp&gt;/)"),
    ("Les sauvegardes lues (et utilisées pour la restauration) seront cherchées ici, au lieu de <code>hycu-backups/</code>.",
     "Backups will be read (and used for the restore) from here instead of <code>hycu-backups/</code>."),
    ("Sauvegarde de configuration à restaurer", "Configuration backup to restore"),
    (">Clone (nouveau VG)<", ">Clone (new VG)<"),
    (">Restauration sur place<", ">Restore in place<"),
    ("Que faire du clone ?", "What to do with the clone?"),
    (">Rattacher à l'app existante<", ">Reattach to the existing app<"),
    (">Cloner l'application<", ">Clone the application<"),
    ("Cible du clone d'application", "Application clone target"),
    (">Même namespace (suffixe)<", ">Same namespace (suffix)<"),
    (">Autre namespace<", ">Other namespace<"),
    ("Suffixe appliqué aux copies", "Suffix applied to the copies"),
    ("Namespace cible", "Target namespace"),
    ("Cloner aussi les dépendances (Secrets, ConfigMaps, ServiceAccount, Services qui ciblent l'app)",
     "Also clone the dependencies (Secrets, ConfigMaps, ServiceAccount, Services targeting the app)"),
    ("— nécessaire pour que les pods démarrent dans l'autre namespace",
     "— required for the pods to start in the other namespace"),
    ("Restauration sur place orchestrée", "Orchestrated in-place restore"),
    ("Lancer la restauration sur place", "Launch the in-place restore"),
    ("Vérifier puis lancer", "Review then launch"),
    ("Vérifiez les remplacements dérivés et la séquence, puis lancez.",
     "Review the derived replacements and the sequence, then launch."),
    ("Séquence prévue", "Planned sequence"),
    ("Confirmation du contexte cible (mode réel)", "Target context confirmation (real mode)"),
    ("retapez le nom du contexte kubectl", "retype the kubectl context name"),
    ("Lancer la restauration", "Launch the restore"),
    # Guides de flux (lignes complètes, remplacées avant les fragments plus courts)
]

# --- Onglet Restaurer : JS (volumes, orchestration HYCU, in-place, clone d'app) ---
I18N_EN += [
    (" (la plus récente)", " (most recent)"),
    ('"dossier personnalisé"', '"custom folder"'),
    ('"sauvegarde (dossier perso)"', '"backup (custom folder)"'),
    ('"dernière sauvegarde"', '"latest backup"'),
    ('"sauvegarde choisie"', '"selected backup"'),
    ('phase:"sauvegardé"', 'phase:"backed up"'),
    ("Aucun volume. Sauvegardez d'abord la configuration de cette application (Applications → Sauvegarder).",
     "No volume. First back up this application's configuration (Applications → Back up)."),
    ("· source : ", "· source: "),
    ("Rechercher le VG dans Prism", "Search for the VG in Prism"),
    ("(UUID du VG, ou NutanixVolumes-&lt;uuid&gt;, ou IQN legacy)", "(VG UUID, or NutanixVolumes-&lt;uuid&gt;, or legacy IQN)"),
    ("Recherche du Volume Group HYCU…", "Searching for the HYCU Volume Group…"),
    ("(correspondance '", "(match '"),
    ("' — à vérifier)<", "' — to verify)<"),
    ('placeholder="auto-détecté"', 'placeholder="auto-detected"'),
    ("Point de restauration", "Restore point"),
    ("Nom du VG cloné", "Cloned VG name"),
    ("Simulation — appel HYCU qui serait envoyé :", "Simulation — HYCU call that would be sent:"),
    (" volume(s) prêt(s)", " volume(s) ready"),
    ('" · MODE RÉEL"', '" · REAL MODE"'),
    ("Sélectionnez un point de restauration par volume.", "Select a restore point for each volume."),
    ("Restauration SUR PLACE RÉELLE", "REAL IN-PLACE restore"),
    ('"Namespace : <b>"', '"Namespace: <b>"'),
    ("L'application sera <b>ARRÊTÉE</b>, les volumes restaurés <b>in-place</b> dans HYCU (données écrasées par le point choisi), puis l'application <b>REDÉMARRÉE</b>.",
     "The application will be <b>STOPPED</b>, the volumes restored <b>in-place</b> in HYCU (data overwritten by the chosen point), then the application <b>RESTARTED</b>."),
    ("</span>Orchestration…", "</span>Orchestrating…"),
    ("</span> Démarrage…", "</span> Starting…"),
    ("</span> Orchestration en cours…", "</span> Orchestration in progress…"),
    ("Simulation — séquence et appels HYCU qui seraient exécutés.",
     "Simulation — sequence and HYCU calls that would be executed."),
    (r"<b>Séquence interrompue</b> — l\'application est restée arrêtée. Voir le détail.",
     r"<b>Sequence aborted</b> — the application was left stopped. See details."),
    ("Restauration sur place terminée.", "In-place restore complete."),
    ("Des étapes ont échoué — voir le détail.", "Some steps failed — see details."),
    (">Des étapes ont échoué.<", ">Some steps failed.<"),
]

# --- Onglet Restaurer : plan, clone d'app, lancement · Vérifier · Réglages ---
I18N_EN += [
    ("Aperçu prêt. Vérifiez ci-dessous, puis cliquez « <b>Lancer le clone de l'application (réel)</b> » en bas pour créer la copie.",
     "Preview ready. Review below, then click “<b>Launch the application clone (real)</b>” at the bottom to create the copy."),
    ("L'application d'origine n'est pas touchée.", "The original application is untouched."),
    ("Clone d'application → namespace <b>", "Application clone → namespace <b>"),
    ("'(même namespace, suffixe)':'(autre namespace)'", "'(same namespace, suffix)':'(other namespace)'"),
    (">PV créés</span>", ">PVs created</span>"),
    (">PVC créés</span>", ">PVCs created</span>"),
    (">Applications clonées</span>", ">Cloned applications</span>"),
    (">Dépendances clonées</span>", ">Cloned dependencies</span>"),
    ("||'aucune'", "||'none'"),
    ('||"aucune"', '||"none"'),
    ("Voir les manifestes des applications clonées", "View the cloned applications' manifests"),
    (r"<li>Créer le namespace cible (si « autre »)</li><li>Créer les PV/PVC clonés (sur le VG cloné)</li><li>Créer les applications clonées (elles démarrent automatiquement)</li><li>L\'application d\'origine n\'est PAS modifiée ni arrêtée</li>",
     r"<li>Create the target namespace (if “other”)</li><li>Create the cloned PVs/PVCs (on the cloned VG)</li><li>Create the cloned applications (they start automatically)</li><li>The original application is NOT modified or stopped</li>"),
    ("Cochez au moins un PVC.", "Tick at least one PVC."),
    ("Indiquez le namespace cible.", "Provide the target namespace."),
    ("Aucun changement de chaîne.", "No string change."),
    ("volumeHandle dérivé", "derived volumeHandle"),
    ("Voir le manifeste complet du nouveau PV", "View the full manifest of the new PV"),
    ("Corrigez les volumes en erreur avant de lancer.", "Fix the volumes in error before launching."),
    ('"Mode réel : ces opérations seront exécutées sur le cluster."',
     '"Real mode: these operations will be executed on the cluster."'),
    ('"Mode simulation : rien ne sera modifié."', '"Simulation mode: nothing will be changed."'),
    ('"la restauration sur place (flux manuel)"', '"the in-place restore (manual flow)"'),
    ('"le clone de l\'application"', '"the application clone"'),
    ('= "le clone";', '= "the clone";'),
    ('"Lancer " : "Simuler "', '"Launch " : "Simulate "'),
    ('" (réel)"', '" (real)"'),
    ("Clone d'application RÉEL", "REAL application clone"),
    ("Une <b>COPIE</b> de l'application sera créée", "A <b>COPY</b> of the application will be created"),
    ('" dans le <b>même namespace</b> (avec suffixe)"', '" in the <b>same namespace</b> (with a suffix)"'),
    ('" dans le namespace cible <b>"', '" in the target namespace <b>"'),
    ("L'application d'origine n'est <b>PAS</b> modifiée ni arrêtée.",
     "The original application is <b>NOT</b> modified or stopped."),
    ("</span> Clonage en cours…", "</span> Cloning in progress…"),
    (r"Simulation — ressources qui seraient créées (l\'app d\'origine reste intacte).",
     r"Simulation — resources that would be created (the original app stays intact)."),
    (r"Clone d\'application créé. L\'application d\'origine est intacte.",
     r"Application clone created. The original application is intact."),
    ("Restauration RÉELLE", "REAL restore"),
    ("L'application sera <b>arrêtée</b>, les anciens PVC/PV <b>supprimés</b> puis recréés sur le(s) Volume Group(s) restauré(s).",
     "The application will be <b>stopped</b>, the old PVCs/PVs <b>deleted</b> then recreated on the restored Volume Group(s)."),
    ("</span>Exécution…", "</span>Executing…"),
    ("</span> Exécution en cours…", "</span> Execution in progress…"),
    ("Simulation terminée — voici ce qui serait exécuté en mode réel.",
     "Simulation complete — here is what would be executed in real mode."),
    (r"<b>Séquence interrompue</b> — l\'application est restée arrêtée pour éviter un redémarrage incohérent. Voir le détail.",
     r"<b>Sequence aborted</b> — the application was left stopped to avoid an inconsistent restart. See details."),
    ("Restauration terminée.", "Restore complete."),
    ("Des étapes ont échoué — voir ci-dessous.", "Some steps failed — see below."),
    ("⚠ <b>Re-protection HYCU requise.</b> Le(s) Volume Group(s) cloné(s) ci-dessous",
     "⚠ <b>HYCU re-protection required.</b> The cloned Volume Group(s) below"),
    ("ne sont <b>pas encore protégés</b> par HYCU (la politique de l'app pointait l'ancien VG).",
     "are <b>not yet protected</b> by HYCU (the app's policy pointed at the old VG)."),
    ("Re-protéger maintenant dans HYCU", "Re-protect now in HYCU"),
    # Vérifier
    ("Vérifier l'état d'un namespace", "Verify a namespace's state"),
    ("Confirme que les PVC sont liés (Bound) et que les pods tournent.",
     "Confirms that the PVCs are Bound and the pods are running."),
    (">Vérifier<", ">Verify<"),
    ("Rafraîchit la vérification toutes les ~3 s et s'arrête dès que tous les PVC sont Bound et les pods Running (10 min max) ; recliquez pour arrêter",
     "Re-runs the check every ~3 s and stops as soon as all PVCs are Bound and pods are Running (10 min max); click again to stop"),
    ("Suivi auto (jusqu'à stable)", "Auto-track (until stable)"),
    ("■ Arrêter le suivi", "■ Stop tracking"),
    ("État stable : tous les PVC sont Bound et les pods Running.",
     "Stable state: all PVCs are Bound and pods are Running."),
    (">Aucun PVC.<", ">No PVC.<"),
    ("· prêts ", "· ready "),
    (">Aucun pod.<", ">No pods.<"),
    # Réglages
    ("Choisissez explicitement le cluster, au lieu de suivre le contexte courant.",
     "Choose the cluster explicitly instead of following the current context."),
    ("L'outil ajoute <code>--context</code> (et <code>--kubeconfig</code>) à chaque commande kubectl.",
     "The tool adds <code>--context</code> (and <code>--kubeconfig</code>) to every kubectl command."),
    ("Fichier kubeconfig (vide = défaut ~/.kube/config)", "kubeconfig file (empty = default ~/.kube/config)"),
    (">Contexte<", ">Context<"),
    ("Lister les contextes", "List contexts"),
    ("Utiliser ce contexte", "Use this context"),
    ("Réglages (adaptation par client)", "Settings (per-customer adaptation)"),
    ("Ces réglages sont enregistrés dans <code>hycu_config.json</code> à côté du programme.",
     "These settings are saved in <code>hycu_config.json</code> next to the program."),
    ("Laissez vide ce que vous ne voulez pas contraindre.", "Leave blank anything you don't want to constrain."),
    ("Binaire kubectl", "kubectl binary"),
    ("Préfixe volumeHandle (vide = auto)", "volumeHandle prefix (empty = auto)"),
    ("Timeout d'attente (s)", "Wait timeout (s)"),
    ("Suffixe de nom de clone", "Clone name suffix"),
    ("Exiger la confirmation du contexte avant toute action réelle",
     "Require context confirmation before any real action"),
    ("Retirer entièrement claimRef du PV (laisser le PVC rebinder)",
     "Strip claimRef entirely from the PV (let the PVC rebind)"),
    ("Enregistrer les réglages", "Save settings"),
    ("(contexte courant du kubeconfig)", "(current kubeconfig context)"),
    (" contexte(s) trouvé(s)", " context(s) found"),
    ('"Contexte « "', '"Context « "'),
    ('" » appliqué."', '" » applied."'),
    ('"Contexte courant utilisé."', '"Current context in use."'),
    ('"Enregistré."', '"Saved."'),
    ('"Erreur : "', '"Error: "'),
]

# --- Connexions, assistant (JS), bannière kubectl, coffre, VG picker, jobs ---
I18N_EN += [
    ("HYCU — connexion", "HYCU — connection"),
    ("Pour lister les points de restauration et orchestrer le clone/restore d'un Volume Group",
     "To list restore points and orchestrate the clone/restore of a Volume Group"),
    ("depuis l'assistant de restauration (<b>Applications → Restaurer</b>). Les identifiants restent <b>en mémoire</b> le temps de la session — jamais écrits sur disque.",
     "from the restore wizard (<b>Applications → Restore</b>). Credentials stay <b>in memory</b> for the session — never written to disk."),
    ("URL HYCU (port 8443)", "HYCU URL (port 8443)"),
    ("Authentification", "Authentication"),
    (">Basic (utilisateur)<", ">Basic (user)<"),
    (">Clé API<", ">API key<"),
    (">Identifiant<", ">Username<"),
    (">Mot de passe<", ">Password<"),
    (">Clé API <", ">API key <"),
    ("(HYCU : Aide → API Keys)", "(HYCU: Help → API Keys)"),
    ("Vérifier le certificat TLS (décoché = certificat auto-signé accepté)",
     "Verify the TLS certificate (unchecked = self-signed accepted)"),
    ("Vérifier le certificat TLS", "Verify the TLS certificate"),
    ("Tester &amp; connecter", "Test &amp; connect"),
    (">Déconnecter<", ">Disconnect<"),
    ("</span>non connecté", "</span>not connected"),
    ('?"connecté":"non connecté"', '?"connected":"not connected"'),
    ("Nutanix Prism Element — connexion", "Nutanix Prism Element — connection"),
    ("Récupère automatiquement la référence (UUID) du Volume Group cloné (lecture seule, API v2)",
     "Automatically fetches the cloned Volume Group's reference (UUID) (read-only, API v2)"),
    ("dans l'assistant de restauration. Identifiants en mémoire de session uniquement.",
     "in the restore wizard. Credentials kept in session memory only."),
    ("URL Prism Element", "Prism Element URL"),
    ("Nutanix Prism Central — connexion", "Nutanix Prism Central — connection"),
    ("Alternative multi-cluster (API v3). Sert aussi à récupérer la référence (UUID) du Volume Group",
     "Multi-cluster alternative (API v3). Also used to fetch the reference (UUID) of the Volume Group"),
    ("cloné si vous n'utilisez pas Prism Element. Identifiants en mémoire de session uniquement.",
     "cloned if you do not use Prism Element. Credentials kept in session memory only."),
    ("URL Prism Central", "Prism Central URL"),
    ("exemple.com", "example.com"),
    ("Mémoriser les connexions (chiffré)", "Remember connections (encrypted)"),
    ("(<code>hycu_secrets.enc</code>), protégé par une <b>phrase secrète maîtresse</b> — jamais stockée.",
     "(<code>hycu_secrets.enc</code>), protected by a <b>master passphrase</b> — never stored."),
    ("Par défaut, rien n'est écrit (RAM seulement), le choix le plus sûr.",
     "By default nothing is written (RAM only), the safest choice."),
    ("Enregistrer (chiffrer)", "Save (encrypt)"),
    ("Charger (déchiffrer)", "Load (decrypt)"),
    (">Oublier<", ">Forget<"),
    ("</span>aucun coffre", "</span>no vault"),
    ('"coffre présent"', '"vault present"'),
    ('"aucun coffre"', '"no vault"'),
    ("MD5 n'étant pas réversible, le coffre utilise un chiffrement",
     "The vault uses passphrase-based encryption"),
    ("par phrase secrète (PBKDF2-HMAC-SHA256 + scellé d'intégrité).",
     "(PBKDF2-HMAC-SHA256 + integrity seal)."),
    ("Supprimer le coffre chiffré du disque ?", "Delete the encrypted vault from disk?"),
    ("Connexions chiffrées : ", "Connections encrypted: "),
    ("Connexions chargées : ", "Connections loaded: "),
    ("Coffre supprimé.", "Vault deleted."),
    (r"Renseignez l\'URL.", r"Enter the URL."),
    # Assistant (étapes JS)
    ("Première configuration", "First-time setup"),
    ("Langue de l'interface", "Interface language"),
    ("Aucun fichier <code>hycu_config.json</code> n'a été trouvé. Quelques questions",
     "No <code>hycu_config.json</code> file was found. A few questions"),
    ("pour le générer — vous pourrez tout modifier ensuite dans la page Réglages.",
     "to generate it — you can change everything later in the Settings page."),
    ("Quel binaire kubectl utiliser ?", "Which kubectl binary should be used?"),
    ("Choisissez la distribution, ou saisissez une commande / un chemin personnalisé.",
     "Pick the distribution, or enter a custom command / path."),
    ("Commande kubectl", "kubectl command"),
    ("Verrouiller le(s) cluster(s) ?", "Lock down the cluster(s)?"),
    ("Restreindre l'outil à des contextes kubectl précis évite d'agir par erreur sur le mauvais cluster.",
     "Restricting the tool to specific kubectl contexts avoids acting on the wrong cluster by mistake."),
    (">Tous les contextes</b>", ">All contexts</b>"),
    ("Aucune restriction.", "No restriction."),
    (">Restreindre</b>", ">Restrict</b>"),
    ("N'autoriser que les contextes listés.", "Allow only the listed contexts."),
    ("Contextes autorisés (virgules)", "Allowed contexts (commas)"),
    ("Limiter aux namespaces concernés ?", "Limit to the relevant namespaces?"),
    ("Vous pouvez n'exposer que les namespaces applicatifs protégés par HYCU.",
     "You can expose only the application namespaces protected by HYCU."),
    (">Tous les namespaces</b>", ">All namespaces</b>"),
    ("Lister tous les namespaces du cluster.", "List every namespace in the cluster."),
    ("N'afficher que les namespaces listés.", "Show only the listed namespaces."),
    ("Namespaces autorisés (virgules)", "Allowed namespaces (commas)"),
    ("Garde-fou avant action réelle", "Safety check before real actions"),
    ("Recommandé : exiger de retaper le nom du contexte avant toute restauration réelle.",
     "Recommended: require retyping the context name before any real restore."),
    ("Exiger la confirmation du contexte", "Require context confirmation"),
    ("L'opérateur retape le contexte cible avant d'agir.", "The operator retypes the target context before acting."),
    ("Réglages avancés (facultatif)", "Advanced settings (optional)"),
    ("Les valeurs par défaut conviennent à la plupart des environnements.",
     "The defaults suit most environments."),
    ("Suffixe nom de clone", "Clone name suffix"),
    ("Préfixe volumeHandle (vide = auto-détecté)", "volumeHandle prefix (empty = auto-detected)"),
    ("auto-détecté depuis le PV existant", "auto-detected from the existing PV"),
    ("Créer la configuration", "Create the configuration"),
    ("Vérifiez puis créez <code>hycu_config.json</code> (modifiable ensuite dans ⚙ Réglages).",
     "Review then create <code>hycu_config.json</code> (editable later in ⚙ Settings)."),
    ("Étape ${wizStep+1} / ${wizSteps.length}", "Step ${wizStep+1} / ${wizSteps.length}"),
    ("</span>Création…", "</span>Creating…"),
    (">Échec : ", ">Failed: "),
    ('|| "indisponible"', '|| "unavailable"'),
    ('||"indisponible"', '||"unavailable"'),
    # Bannière kubectl
    ("<b>kubectl introuvable.</b> Installez kubectl et ajoutez-le au PATH, ou indiquez son binaire/chemin dans ⚙ Réglages (ex. « microk8s kubectl »).",
     "<b>kubectl not found.</b> Install kubectl and add it to PATH, or set its binary/path in ⚙ Settings (e.g. “microk8s kubectl”)."),
    ("<b>Aucun contexte kubectl sélectionné.</b> Choisissez le cluster cible : <code>kubectl config use-context &lt;nom&gt;</code>, puis rechargez la page.",
     "<b>No kubectl context selected.</b> Choose the target cluster: <code>kubectl config use-context &lt;name&gt;</code>, then reload the page."),
    ("<b>Aucune configuration kubectl trouvée.</b> Vérifiez <code>%USERPROFILE%\\\\.kube\\\\config</code> (ou la variable <code>KUBECONFIG</code>), puis rechargez.",
     "<b>No kubectl configuration found.</b> Check <code>%USERPROFILE%\\\\.kube\\\\config</code> (or the <code>KUBECONFIG</code> variable), then reload."),
    ("<b>Cluster injoignable via kubectl.</b> Vérifiez la connectivité réseau et vos droits (RBAC) sur l'API server.",
     "<b>Cluster unreachable via kubectl.</b> Check network connectivity and your RBAC rights on the API server."),
    ("Les opérations <b>Sauvegarder</b>, <b>Restaurer</b> (séquence Kubernetes) et <b>Vérifier</b> nécessitent kubectl. Les connexions <b>HYCU / Nutanix</b> fonctionnent, elles, sans kubectl.",
     "The <b>Back up</b>, <b>Restore</b> (Kubernetes sequence) and <b>Verify</b> operations require kubectl. The <b>HYCU / Nutanix</b> connections work without kubectl."),
    # Recherche de VG Nutanix + suivi de job
    ("Chargement des Volume Groups…", "Loading Volume Groups…"),
    ("rechercher le VG cloné par nom…", "search the cloned VG by name…"),
    ("Aucun Volume Group ne correspond.", "No Volume Group matches."),
    ("} sur ${ntAllVgs.length}", "} of ${ntAllVgs.length}"),
    ("' (200 affichés — affinez)'", "' (200 shown — refine the search)'"),
    ("UUID du VG indisponible.", "VG UUID unavailable."),
    ("Référence du VG (UUID) remplie depuis Nutanix.", "VG reference (UUID) filled from Nutanix."),
    ("Suivi du job indisponible : ", "Job tracking unavailable: "),
    ("Job terminé avec succès.", "Job finished successfully."),
    ("Job en échec — vérifiez dans HYCU.", "Job failed — check in HYCU."),
    ("Suivi interrompu (délai) — le job continue côté HYCU.",
     "Tracking stopped (timeout) — the job continues on the HYCU side."),
    # runOp + errHint (JS)
    ('"Démarrage de l\'opération impossible."', '"Could not start the operation."'),
    ('"Suivi de l\'opération interrompu."', '"Operation tracking interrupted."'),
    ('"Opération terminée sans résultat."', '"Operation finished with no result."'),
    ('"Délai de suivi dépassé (l\'opération continue peut-être côté serveur)."',
     '"Tracking timed out (the operation may still be running server-side)."'),
    ("Identifiants refusés — vérifiez l'utilisateur/mot de passe, ou la clé API HYCU (Aide → API Keys, requise si 2FA).",
     "Credentials rejected — check the username/password, or the HYCU API key (Help → API Keys, required with 2FA)."),
    ("Accès refusé — droits insuffisants (RBAC / rôle sur l'API).",
     "Access denied — insufficient rights (RBAC / API role)."),
    ("Endpoint introuvable — vérifiez l'URL de base et la version d'API (⚙ Réglages).",
     "Endpoint not found — check the base URL and the API version (⚙ Settings)."),
    ("Certificat TLS — cochez/décochez « Vérifier le certificat TLS » dans Connexions selon votre PKI.",
     "TLS certificate — tick/untick “Verify the TLS certificate” in Connections to match your PKI."),
    ("Hôte injoignable — vérifiez l'URL:port (HYCU 8443, Prism 9440), le réseau et le pare-feu.",
     "Host unreachable — check the URL:port (HYCU 8443, Prism 9440), the network and the firewall."),
    ("Enregistrez d'abord la source (⚙ en haut à droite).", "Register the source first (⚙ at the top right)."),
    ("Namespace hors liste autorisée — voir ⚙ Réglages → namespaces autorisés.",
     "Namespace not in the allowed list — see ⚙ Settings → allowed namespaces."),
    ("Contexte kubectl hors liste autorisée — voir ⚙ Réglages.",
     "kubectl context not in the allowed list — see ⚙ Settings."),
    ("Retapez le nom exact du contexte cible pour confirmer (mode réel).",
     "Retype the exact target context name to confirm (real mode)."),
    ("Rechargez la page (Ctrl+Shift+R) : le jeton de sécurité a expiré.",
     "Reload the page (Ctrl+Shift+R): the security token has expired."),
]

# --- Messages backend (JSON) : générique, sauvegarde, préparation & exécution restore ---
I18N_EN += [
    ("Une autre opération est déjà en cours. Réessayez.", "Another operation is already running. Try again."),
    ("Opération inconnue ou expirée.", "Unknown or expired operation."),
    ("Erreur interne : ", "Internal error: "),
    ("Erreur interne.", "Internal error."),
    ("Commande introuvable : '", "Command not found: '"),
    ("' est-il installé et dans le PATH ?", "' — is it installed and in the PATH?"),
    ("Délai dépassé (", "Timeout exceeded ("),
    ("s) — le job continue côté HYCU.", "s) — the job continues on the HYCU side."),
    ("Réponse JSON illisible : ", "Unreadable JSON response: "),
    ("Référence de volume invalide : impossible d'en extraire l'UUID du Volume Group.",
     "Invalid volume reference: could not extract the Volume Group UUID from it."),
    ("Collez l'UUID du VG (8-4-4-4-12), un volumeHandle « NutanixVolumes-<uuid> »,",
     "Paste the VG UUID (8-4-4-4-12), a volumeHandle « NutanixVolumes-<uuid> »,"),
    ("ou (clusters iSCSI hérités) l'IQN complet du VG cloné.",
     "or (legacy iSCSI clusters) the full IQN of the cloned VG."),
    ("UUID du VG", "VG UUID"),
    ("Nom de PV invalide : '", "Invalid PV name: '"),
    ("' (RFC 1123 attendu).", "' (RFC 1123 expected)."),
    ("nom du PV", "PV name"),
    ("Dossier de destination inutilisable (", "Unusable destination folder ("),
    ("Le chemin de destination n'est pas un dossier : ", "The destination path is not a folder: "),
    (" » introuvable dans le kubeconfig.", " » not found in the kubeconfig."),
    ("' non autorisé par la configuration.", "' not allowed by the configuration."),
    ("' non autorisé.", "' not allowed."),
    ("Aucun PVC trouvé dans le namespace '", "No PVC found in namespace '"),
    ("Liste des namespaces indisponible.", "Namespace list unavailable."),
    ("Aucun namespace à sauvegarder.", "No namespace to back up."),
    ("Sauvegarde introuvable.", "Backup not found."),
    ("Sauvegarde trop volumineuse pour un téléchargement direct.", "Backup too large for a direct download."),
    ("Erreur lors de la création de l'archive.", "Error while creating the archive."),
    ("Jeton anti-CSRF invalide ou absent.", "CSRF token invalid or missing."),
    ("Charge trop volumineuse.", "Payload too large."),
    ("JSON invalide", "Invalid JSON"),
    # Workloads / suppression / attente
    ("Arrêt ", "Stopping "),
    ("arrêt de ", "stopping of "),
    ("Redémarrage ", "Restarting "),
    ("aucun contrôleur", "no controller"),
    ("Pods arrêtés", "Pods stopped"),
    ("(attente) pods montant les PVC", "(waiting) pods mounting the PVCs"),
    ("aucun pod ne monte les volumes ciblés", "no pod mounts the targeted volumes"),
    ("Pods encore présents", "Pods still present"),
    ("Délai dépassé, pods encore actifs : ", "Timeout exceeded, pods still active: "),
    (" déjà absent", " already absent"),
    ("rien à supprimer", "nothing to delete"),
    ("Attente suppression ", "Waiting for deletion of "),
    ("Déblocage finalizer ", "Unblocking finalizer "),
    (" non supprimé", " not deleted"),
    ("État : ", "State: "),
    ("Attente PVC ", "Waiting for PVC "),
    (" lié (Bound)", " to bind (Bound)"),
    ("Suppression PVC ", "Deleting PVC "),
    ("Suppression PV ", "Deleting PV "),
    ("Suppression ", "Deleting "),
    ("suppression du PVC ", "deletion of PVC "),
    ("suppression du PV ", "deletion of PV "),
    # Préparation du restore
    ("PVC manquant.", "Missing PVC."),
    ("Indiquez la référence du Volume Group cloné/restauré pour « ",
     "Provide the reference of the cloned/restored Volume Group for « "),
    ("(UUID du VG, volumeHandle, ou IQN).", "(VG UUID, volumeHandle, or IQN)."),
    ("Référence invalide pour « ", "Invalid reference for « "),
    (" » : aucun UUID détecté. Collez l'UUID du VG ", " »: no UUID detected. Paste the VG UUID "),
    ("(8-4-4-4-12), un volumeHandle « NutanixVolumes-<uuid> », ou l'IQN complet.",
     "(8-4-4-4-12), a volumeHandle « NutanixVolumes-<uuid> », or the full IQN."),
    ("Manifeste du PV introuvable pour « ", "PV manifest not found for « "),
    (" ». Sauvegardez d'abord ce namespace, ", " ». Back up this namespace first, "),
    ("ou vérifiez que le PV existe encore.", "or check that the PV still exists."),
    ("L'UUID fourni correspond au NOM du VG (« pvc-<uuid> », = UUID du PVC) et non à l'UUID",
     "The provided UUID matches the VG NAME (« pvc-<uuid> », = the PVC's UUID), not the UUID"),
    ("du Volume Group. Vous avez probablement saisi le nom du VG au lieu de son UUID —",
     "of the Volume Group. You probably entered the VG name instead of its UUID —"),
    ("utilisez « Rechercher le VG dans Prism » ou copiez l'UUID du VG (suffixe de NutanixVolumes-… / ntnx-k8s-…).",
     "use “Search for the VG in Prism” or copy the VG UUID (the suffix of NutanixVolumes-… / ntnx-k8s-…)."),
    ("L'UUID est identique à l'ancien : le clone n'a peut-être pas produit de nouveau VG",
     "The UUID is identical to the old one: the clone may not have produced a new VG"),
    ("(UUID du VG source saisi au lieu du VG cloné ?).", "(source VG UUID entered instead of the cloned VG?)."),
    ("Aucun changement détecté dans le manifeste : en restauration sur place avec le même VG,",
     "No change detected in the manifest: for an in-place restore with the same VG,"),
    ("un simple redémarrage des pods suffit à remonter les données restaurées.",
     "simply restarting the pods is enough to mount the restored data."),
    ("Un ou plusieurs volumes n'ont pas pu être préparés.", "One or more volumes could not be prepared."),
    # Plan
    ("Arrêter l'application (tous les Deployments/StatefulSets du namespace -> 0 réplica)",
     "Stop the application (all Deployments/StatefulSets in the namespace -> 0 replicas)"),
    ("Attendre l'arrêt effectif des pods qui montent les volumes ciblés",
     "Wait for the pods mounting the targeted volumes to actually stop"),
    ("Supprimer l'ancien PVC « ", "Delete the old PVC « "),
    ("Supprimer l'ancien PV « ", "Delete the old PV « "),
    (" » (+ déblocage finalizer si nécessaire)", " » (+ finalizer unblock if needed)"),
    ("Créer le nouveau PV « ", "Create the new PV « "),
    ("Recréer le PVC « ", "Recreate the PVC « "),
    (" » et le lier au nouveau PV, attendre l'état Bound", " » and bind it to the new PV, wait for Bound"),
    ("Redémarrer l'application (réplicas d'origine restaurés)", "Restart the application (original replicas restored)"),
    ("Vérifier : tous les PVC liés (Bound) et pods démarrés", "Verify: all PVCs Bound and pods started"),
    ("APRÈS : re-protéger le(s) nouveau(x) Volume Group(s) dans HYCU",
     "AFTER: re-protect the new Volume Group(s) in HYCU"),
    ("(politique / catégorie Prism) — non automatisé par cet outil",
     "(Prism policy / category) — not automated by this tool"),
    # Garde contexte + exécution
    ("Contexte kubectl « ", "kubectl context « "),
    (" » non autorisé par la configuration", " » not allowed by the configuration"),
    ("Confirmation du contexte requise : retapez le nom du contexte ciblé",
     "Context confirmation required: retype the targeted context name"),
    (" ») pour confirmer.", " ») to confirm."),
    ("Reprise d'une restauration interrompue", "Resuming an interrupted restore"),
    ("Démarrée ", "Started "),
    ("). Sauvegarde de sécurité initiale réutilisée ;", "). Initial safety backup reused;"),
    ("les étapes déjà faites sont rejouées sans dommage.", "steps already done are safely replayed."),
    ("Sauvegarde de sécurité du namespace avant restauration", "Safety backup of the namespace before the restore"),
    ("Sauvegarde de sécurité impossible (", "Safety backup failed ("),
    (") — restauration annulée pour ne pas", ") — restore cancelled so as not to"),
    ("détruire sans filet. Corrigez puis relancez.", "destroy without a safety net. Fix the issue then retry."),
    ("Réplicas mémorisés", "Replicas recorded"),
    ("(lecture) réplicas cibles", "(read) target replicas"),
    ("⚠ Pod(s) NON géré(s) par un Deployment/StatefulSet montant les volumes ciblés",
     "⚠ Pod(s) NOT managed by a Deployment/StatefulSet mounting the targeted volumes"),
    (" (contrôleur : ", " (controller: "),
    (". Le scale-down ne les arrêtera pas — arrêtez-les manuellement",
     ". The scale-down will not stop them — stop them manually"),
    ("(DaemonSet/Job/Operator/pod nu) avant de continuer.", "(DaemonSet/Job/Operator/bare pod) before continuing."),
    ("attente de l'arrêt des pods", "waiting for the pods to stop"),
    ("Protection du VG source : PV ", "Protecting the source VG: PV "),
    ("Protection du VG : PV ", "Protecting the VG: PV "),
    ("Évite que la suppression du PV/PVC ne supprime le Volume Group Nutanix",
     "Prevents the PV/PVC deletion from deleting the Nutanix Volume Group"),
    ("(reclaimPolicy=Delete par défaut).", "(reclaimPolicy=Delete by default)."),
    ("(+ finalizer si besoin)", "(+ finalizer if needed)"),
    ("Création du nouveau PV ", "Creating the new PV "),
    ("protection (Retain) du PV source ", "protection (Retain) of the source PV "),
    ("protection (Retain) du PV ", "protection (Retain) of PV "),
    (" — suppression annulée pour", " — deletion cancelled to"),
    ("ne pas risquer la perte du Volume Group", "avoid risking the loss of the Volume Group"),
    ("création du nouveau PV ", "creation of the new PV "),
    ("Recréation du PVC ", "Recreating PVC "),
    ("recréation du PVC ", "recreation of PVC "),
    ("liaison (Bound) du PVC ", "binding (Bound) of PVC "),
    (" non recréé", " not recreated"),
    ("Manifeste du PVC introuvable (ni sauvegarde ni live) : le PVC sera recréé",
     "PVC manifest not found (neither backup nor live): the PVC will be recreated"),
    ("par votre déploiement applicatif (vérifiez ensuite qu'il devient Bound).",
     "by your application deployment (check afterwards that it becomes Bound)."),
    ("SÉQUENCE INTERROMPUE", "SEQUENCE ABORTED"),
    ("Échec à l'étape : ", "Failed at step: "),
    ("L'application reste ARRÊTÉE (réplicas à 0) pour éviter de redémarrer sur des",
     "The application stays STOPPED (replicas at 0) to avoid restarting on"),
    ("volumes incohérents. Corrigez la cause, puis relancez la restauration (les",
     "inconsistent volumes. Fix the cause, then rerun the restore (the"),
    ("réplicas d'origine sont mémorisés), ou redémarrez manuellement :",
     "original replicas are recorded), or restart manually:"),
    (" lié à ", " bound to "),
    (" au lieu de ", " instead of "),
    ("⚠ volumeHandle INATTENDU — vérifiez le volume réellement monté",
     "⚠ UNEXPECTED volumeHandle — check the volume actually mounted"),
    ("Incohérence(s) : ", "Inconsistency(ies): "),
    (". Le pod tourne peut-être sur le mauvais Volume Group.",
     ". The pod may be running on the wrong Volume Group."),
    ("volumeHandle conforme au VG attendu pour tous les volumes",
     "volumeHandle matches the expected VG for all volumes"),
    ("Vérification finale", "Final verification"),
]

# --- Messages backend (JSON) : connexions, coffre, Nutanix, HYCU, clone d'app ---
I18N_EN += [
    ("Schéma d'URL refusé (", "URL scheme refused ("),
    (") : seuls http/https sont autorisés.", "): only http/https are allowed."),
    ("HTTP %s", "HTTP %s"),
    ("Connexion impossible : ", "Connection failed: "),
    ("Erreur TLS : ", "TLS error: "),
    (" non configurée (⚙ Sources).", " not configured (⚙ Sources)."),
    ("Non connecté à ", "Not connected to "),
    ("Système inconnu.", "Unknown system."),
    ("Clé API requise.", "API key required."),
    ("Identifiant et mot de passe requis.", "Username and password required."),
    ("Authentification ", "Authentication "),
    (" refusée (HTTP ", " refused (HTTP "),
    ("Vérifiez les identifiants", "Check the credentials"),
    ("ou utilisez une clé API si le 2FA est activé", "or use an API key if 2FA is enabled"),
    ("la version de l'API v3/v4", "the API version v3/v4"),
    ("Connecté, mais l'endpoint de test « ", "Connected, but the test endpoint « "),
    (" » est introuvable (HTTP 404).", " » was not found (HTTP 404)."),
    ("Les chemins REST dépendent de la version : vérifiez ", "REST paths depend on the version: check "),
    (" et ajustez si besoin.", " and adjust if needed."),
    ("Échec de connexion ", "Connection failed for "),
    ("Cette URL est identique à celle de ", "This URL is identical to the one for "),
    ("Prism Element et Prism Central doivent pointer vers des hôtes différents.",
     "Prism Element and Prism Central must point to different hosts."),
    ("Attention : cette URL semble être un ", "Warning: this URL looks like a "),
    (", pas un ", ", not a "),
    (" — vérifiez de ne pas avoir", " — make sure you did not"),
    ("inversé les deux connecteurs. La connexion est tout de même établie.",
     "swap the two connectors. The connection was still established."),
    ("Certificat TLS NON vérifié — les identifiants transitent vers un hôte non",
     "TLS certificate NOT verified — credentials are sent to an unauthenticated"),
    ("authentifié. N'utilisez ce mode que sur un réseau de gestion de confiance.",
     "host. Use this mode only on a trusted management network."),
    ("Choisissez une phrase secrète d'au moins 8 caractères.", "Choose a passphrase of at least 8 characters."),
    ("Connectez-vous d'abord à au moins un système.", "Connect to at least one system first."),
    ("Écriture du coffre impossible : ", "Could not write the vault: "),
    ("Aucune connexion mémorisée.", "No saved connections."),
    ("Lecture du coffre impossible : ", "Could not read the vault: "),
    ("Phrase secrète incorrecte (ou fichier altéré).", "Incorrect passphrase (or corrupted file)."),
    ("Données déchiffrées illisibles.", "Decrypted data unreadable."),
    ("Suppression impossible : ", "Deletion failed: "),
    ("Aucune connexion Nutanix (Prism Element ou Central).", "No Nutanix connection (Prism Element or Central)."),
    ("Erreur Nutanix.", "Nutanix error."),
    ("UUID de Volume Group manquant.", "Missing Volume Group UUID."),
    ("UUID introuvable dans la réponse Nutanix pour ce VG.", "UUID not found in the Nutanix response for this VG."),
    ("Le détachement automatique requiert Prism Element (API v2).",
     "Automatic detach requires Prism Element (API v2)."),
    ("Connectez Prism Element, ou détachez le VG de sa VM dans Prism.",
     "Connect Prism Element, or detach the VG from its VM in Prism."),
    ("Connectez Prism Central : l'API v4 Volumes (et le CSI) y sont servies.",
     "Connect Prism Central: the v4 Volumes API (and the CSI) are served there."),
    ("Renseigner hypervisorAttachedDiskUUIDs (disque du VG cloné ",
     "Set hypervisorAttachedDiskUUIDs (cloned VG disk "),
    ("Lu via Prism Central v4 ; sans lui le CSI tente l'attach iSCSI (échec).",
     "Read via Prism Central v4; without it the CSI attempts the iSCSI attach (fails)."),
    ("Aligner l'IQN du PV sur la cible iSCSI réelle du VG ", "Align the PV's IQN with the VG's real iSCSI target "),
    ("Lu via Prism Central v4 (un VG créé par HYCU porte une cible « hycu-clone-vg-… »).", "Read through Prism Central v4 (a VG created by HYCU carries a “hycu-clone-vg-…” target)."),
    ("IQN du PV non vérifié (Prism Central non connecté)", "PV IQN not checked (Prism Central not connected)"),
    ("Si le pod reste en FailedMount (« iscsiadm: No records found »), connectez Prism Central et relancez : la cible iSCSI du VG restauré peut différer de l'IQN dérivé.",
     "If the pod stays in FailedMount (“iscsiadm: No records found”), connect Prism Central and retry: the restored VG's iSCSI target may differ from the derived IQN."),
    ("IQN du PV non vérifié (cible iSCSI du VG ", "PV IQN not checked (iSCSI target of VG "),
    (" illisible)", " unreadable)"),
    ("Prism Central n'a pas renvoyé le targetName du VG.", "Prism Central did not return the VG's targetName."),
    ("IQN du PV aligné sur la cible iSCSI réelle du VG", "PV IQN aligned with the VG's real iSCSI target"),
    ("IQN du PV conforme à la cible iSCSI du VG", "PV IQN matches the VG's iSCSI target"),
    ("VG modifié par le restore in-place — rafraîchissement du PV ", "VG changed by the in-place restore — refreshing PV "),
    (" avec les attributs à jour (Retain -> delete -> apply)", " with up-to-date attributes (Retain -> delete -> apply)"),
    ("hypervisorAttachedDiskUUIDs non ajouté (le PV source ne le porte pas)",
     "hypervisorAttachedDiskUUIDs not added (the source PV does not carry it)"),
    ("Le CSI de ce cluster attache le Volume Group sans cet attribut, comme pour le PV d'origine : forme du PV source reproduite.",
     "This cluster's CSI attaches the Volume Group without this attribute, as for the original PV: the source PV's shape is reproduced."),
    ("hypervisorAttachedDiskUUIDs NON renseigné (Prism Central non connecté)",
     "hypervisorAttachedDiskUUIDs NOT set (Prism Central not connected)"),
    ("Le CSI tentera l'attach iSCSI et l'attachement échouera. Connectez Prism Central.",
     "The CSI will attempt the iSCSI attach and the attachment will fail. Connect Prism Central."),
    ("hypervisorAttachedDiskUUIDs renseigné depuis le VG cloné",
     "hypervisorAttachedDiskUUIDs set from the cloned VG"),
    ("Disque(s) du VG cloné : ", "Cloned VG disk(s): "),
    ("hypervisorAttachedDiskUUIDs NON renseigné (disque introuvable)",
     "hypervisorAttachedDiskUUIDs NOT set (disk not found)"),
    ("Aucun disque lu pour le VG ", "No disk read for VG "),
    ("Le CSI tentera l'attach iSCSI ; vérifiez le VG cloné dans Prism.",
     "The CSI will attempt the iSCSI attach; check the cloned VG in Prism."),
    ("Disque du PV ", "Disk of PV "),
    (" non vérifié (Prism Central non connecté)", " not verified (Prism Central not connected)"),
    ("Si le pod reste en FailedMount («failed to get symlink»), connectez",
     "If the pod stays in FailedMount (“failed to get symlink”), connect"),
    ("Prism Central et relancez la restauration sur place.", "Prism Central and rerun the in-place restore."),
    ("Disque du VG remplacé par le restore in-place — rafraîchissement du PV ",
     "VG disk replaced by the in-place restore — refreshing PV "),
    ("Recréer le PV ", "Recreate PV "),
    (" avec le disque à jour (Retain -> delete -> apply)", " with the up-to-date disk (Retain -> delete -> apply)"),
    ("Rafraîchissement du PV interrompu : ", "PV refresh interrupted: "),
    ("Rafraîchissement du PV ", "Refresh of PV "),
    (" annulé : état du PV indéterminé (", " cancelled: PV state undetermined ("),
    (" — suppression refusée pour ne pas risquer la perte du",
     " — deletion refused to avoid risking the loss of the"),
    ("Volume Group. Vérifiez l'accès kubectl puis relancez.", "Volume Group. Check kubectl access then retry."),
    ("vérification de l'état du PV ", "checking the state of PV "),
    (" avant suppression", " before deletion"),
    ("Recréation du PV ", "Recreating PV "),
    (" (disque rafraîchi)", " (refreshed disk)"),
    ("recréation du PV ", "recreation of PV "),
    # HYCU
    ("Point de restauration requis.", "Restore point required."),
    ("Simulation : aucun appel HYCU envoyé. Vérifiez l'appel ci-dessus,",
     "Simulation: no HYCU call sent. Review the call above,"),
    ("puis désactivez la simulation pour lancer réellement.", "then turn off simulation to launch for real."),
    ("Identifiant de job manquant.", "Missing job identifier."),
    ("Re-vérification de la correspondance impossible : ", "Could not re-verify the mapping: "),
    ("Volume Group(s) hors de la correspondance actuelle du namespace « ",
     "Volume Group(s) outside the current mapping of namespace « "),
    ("Aucun Volume Group HYCU à protéger", "No HYCU Volume Group to protect"),
    ("Assigner la politique", "Assign the policy"),
    ("Échec de l'assignation de politique : ", "Policy assignment failed: "),
    ("Lancer la sauvegarde maintenant", "Start the backup now"),
    ("Job HYCU non identifié — fin non confirmable.", "HYCU job not identified — completion cannot be confirmed."),
    (" terminé", " finished"),
    (" en échec", " failed"),
    ("Connectez-vous à HYCU pour orchestrer la restauration sur place.",
     "Connect to HYCU to orchestrate the in-place restore."),
    ("Aucun volume avec un point de restauration sélectionné.", "No volume with a selected restore point."),
    ("Une étape a échoué. L'application reste ARRÊTÉE pour éviter de redémarrer sur",
     "A step failed. The application stays STOPPED to avoid restarting on"),
    ("des données incohérentes. Corrigez puis relancez, ou redémarrez :",
     "inconsistent data. Fix the issue then retry, or restart manually:"),
    # Clone d'application
    ("Un suffixe est requis pour cloner dans le même namespace.",
     "A suffix is required to clone within the same namespace."),
    ("Nom de namespace cible invalide : '", "Invalid target namespace name: '"),
    ("Aucun volume sélectionné.", "No volume selected."),
    ("Référence du VG cloné manquante/invalide pour « ", "Missing/invalid cloned VG reference for « "),
    (" » : la référence est identique au volume SOURCE — le clone",
     " »: the reference is identical to the SOURCE volume — the clone"),
    ("pointerait vers le même disque Nutanix que l'application d'origine (risque de",
     "would point to the same Nutanix disk as the original application (risk of"),
    ("multi-attach/corruption). Collez l'UUID du VG CLONÉ.", "multi-attach/corruption). Paste the UUID of the CLONED VG."),
    (" » : la référence correspond au NOM du Volume Group", " »: the reference matches the Volume Group NAME"),
    ("(« pvc-<uuid-du-PVC> ») et non à son UUID. Collez l'UUID du VG cloné.",
     "(« pvc-<PVC-uuid> ») and not its UUID. Paste the cloned VG UUID."),
    ("Manifeste du PVC introuvable pour « ", "PVC manifest not found for « "),
    ("Le nom du PV cloné doit différer de l'original « ", "The cloned PV name must differ from the original « "),
    ("Le workload « ", "The workload « "),
    (" » monte aussi le(s) PVC ", " » also mounts the PVC(s) "),
    (" non sélectionné(s) : ", " not selected: "),
    ("sélectionnez TOUS les volumes de cette application pour la cloner.",
     "select ALL the volumes of this application to clone it."),
    (" » utilise un sélecteur matchExpressions : le clone dans",
     " » uses a matchExpressions selector: cloning within"),
    ("le même namespace n'est pas supporté (risque de collision de pods). Choisissez « Autre namespace ».",
     "the same namespace is not supported (pod collision risk). Choose “Other namespace”."),
    (" » utilise des volumeClaimTemplates : son clone provisionnera de",
     " » uses volumeClaimTemplates: its clone will provision"),
    ("NOUVEAUX volumes (pas le VG cloné). À adapter manuellement.",
     "NEW volumes (not the cloned VG). Adapt it manually."),
    ("Dépendances clonées automatiquement vers « ", "Dependencies automatically cloned to « "),
    ("Référencé(s) par l'app mais INTROUVABLE(S) dans « ", "Referenced by the app but NOT FOUND in « "),
    (" » — à créer à la main : ", " » — create manually: "),
    ("Non clonés automatiquement : Ingress, NetworkPolicies et les liaisons RBAC",
     "Not cloned automatically: Ingress, NetworkPolicies and the RBAC bindings"),
    ("(RoleBindings) des ServiceAccounts — à recréer si l'app en dépend.",
     "(RoleBindings) of the ServiceAccounts — recreate them if the app depends on them."),
    ("Clone des dépendances DÉSACTIVÉ : à recréer manuellement dans « ",
     "Dependency cloning DISABLED: recreate manually in « "),
    ("Same-namespace : les Services / Ingress / NetworkPolicies de l'app NE sont PAS clonés et",
     "Same-namespace: the app's Services / Ingress / NetworkPolicies are NOT cloned and"),
    ("peuvent router vers les pods d'origine (labels hors-sélecteur conservés). À cloner/éditer séparément.",
     "may route to the original pods (non-selector labels kept). Clone/edit them separately."),
    ("Aucun Deployment/StatefulSet ne monte ces PVC : seuls le PV et le PVC clonés seront",
     "No Deployment/StatefulSet mounts these PVCs: only the cloned PV and PVC will be"),
    ("créés (déployez votre application dessus).", "created (deploy your application on top of them)."),
    ("Objet(s) déjà présent(s) — refus pour ne rien écraser : ",
     "Object(s) already present — refusing to overwrite anything: "),
    ("Changez le suffixe ou le namespace cible.", "Change the suffix or the target namespace."),
    ("rien n'a été créé.", "nothing was created."),
    ("Namespace cible « ", "Target namespace « "),
    (" déjà présent — conservé", " already present — kept"),
    ("Non écrasé (la version existante de « ", "Not overwritten (the existing version of « "),
    (" » est gardée).", " » is kept)."),
    ("Dépendance clonée ", "Cloned dependency "),
    ("PV cloné ", "Cloned PV "),
    ("PVC cloné ", "Cloned PVC "),
    ("Application clonée ", "Cloned application "),
]

# --- Fluidité du parcours : pastilles d'en-tête, barre « action suivante », suivi auto ---
I18N_EN += [
    ("État des sources — cliquer pour ouvrir les Sources",
     "Source status — click to open Sources"),
    ("Plan prêt — dernière étape :", "Plan ready — final step:"),
    ("Tous les points de restauration sont sélectionnés.", "All restore points are selected."),
    (" point(s) de restauration sélectionné(s).", " restore point(s) selected."),
    ("Toutes les références VG sont remplies.", "All VG references are filled."),
    (" référence(s) VG remplie(s).", " VG reference(s) filled."),
    ("Aller au lancement", "Go to launch"),
    ("Voir les volumes", "Show the volumes"),
    (r"Vérifier l\'application maintenant →", r"Verify the application now →"),
    ("Ouverture de la vérification…", "Opening the verification…"),
]

# --- Parcours Restaurer simplifié : panneau HYCU groupé, textes allégés ---
I18N_EN += [
    ("Cochez le(s) volume(s) à restaurer — plusieurs volumes = une seule transaction.",
     "Tick the volume(s) to restore — several volumes = a single transaction."),
    ("Manifestes PV/PVC (le « squelette ») — indépendant du point de restauration HYCU des <b>données</b>.",
     "PV/PVC manifests (the “skeleton”) — independent from the HYCU restore point of the <b>data</b>."),
    ("Type d'opération", "Operation type"),
    ("Restaurer les données (Volume Groups)", "Restore the data (Volume Groups)"),
    ("Arrêt de l'application → restore in-place HYCU → redémarrage.</b> Aucune référence à saisir.",
     "Stop the application → HYCU in-place restore → restart.</b> No reference to enter."),
    ("Continuer : vérifier et lancer", "Continue: review and launch"),
    ("Nom du nouveau PV", "New PV name"),
    ("Avancé (optionnel) — noms générés, saisie manuelle", "Advanced (optional) — generated names, manual entry"),
    ("Référence du VG (obligatoire) & noms générés", "VG reference (required) & generated names"),
    ("✓ référence remplie", "✓ reference filled"),
    ("— référence à remplir", "— reference to fill"),
    ("Choisissez un <b>point de restauration</b> par volume (le plus récent est pré-sélectionné), puis <b>Lancer la restauration sur place</b>.",
     "Choose a <b>restore point</b> per volume (the most recent is pre-selected), then <b>Launch the in-place restore</b>."),
    ("Restaurez le VG dans HYCU, collez son UUID par volume (volet <b>Avancé</b>), puis <b>",
     "Restore the VG in HYCU, paste its UUID per volume (<b>Advanced</b> section), then <b>"),
    ("Clonez chaque VG dans HYCU, collez son UUID par volume (volet <b>Avancé</b>), puis <b>",
     "Clone each VG in HYCU, paste its UUID per volume (<b>Advanced</b> section), then <b>"),
    ("Connectez HYCU pour automatiser.", "Connect HYCU to automate."),
    ("Choisissez un <b>point de restauration</b> par volume (le plus récent est pré-sélectionné), puis cliquez <b>Restaurer les VG depuis HYCU</b> — références et plan s'enchaînent automatiquement.",
     "Choose a <b>restore point</b> per volume (the most recent is pre-selected), then click <b>Restore the VGs from HYCU</b> — references and plan follow automatically."),
    ("points indisponibles", "restore points unavailable"),
    ("Aucun Volume Group HYCU associé — collez la référence dans « Avancé ».",
     "No HYCU Volume Group matched — paste the reference under “Advanced”."),
    (" (le plus récent)", " (most recent)"),
    ("Aucun point de restauration pour ce VG.", "No restore point for this VG."),
    ("→ VG HYCU <b>", "→ HYCU VG <b>"),
    ("Restaurer les VG depuis HYCU", "Restore the VGs from HYCU"),
    ("Clone les VG au point choisi et remplit les références — aucune donnée écrasée.",
     "Clones the VGs at the chosen point and fills the references — no data overwritten."),
    ("Connectez Nutanix (Prism) pour récupérer la référence automatiquement, ou utilisez le volet Avancé.",
     "Connect Nutanix (Prism) to fetch the reference automatically, or use the Advanced section."),
    (" » introuvable côté Nutanix — utilisez le volet Avancé.",
     " » not found on the Nutanix side — use the Advanced section."),
    ('?"Aucun":"Plusieurs")+" VG nommé(s) exactement « ', '?"No":"Multiple")+" VG named exactly « '),
    (" » — utilisez le volet Avancé pour choisir le bon.",
     " » — use the Advanced section to pick the right one."),
    ("VG trouvé mais UUID non exposé — utilisez le volet Avancé.",
     "VG found but UUID not exposed — use the Advanced section."),
    ("Clones HYCU RÉELS", "REAL HYCU clones"),
    ("Déclencher dans HYCU le <b>clone</b> de <b>", "Trigger in HYCU the <b>clone</b> of <b>"),
    ("</b> Volume Group(s) au point choisi ?", "</b> Volume Group(s) at the chosen point?"),
    ("Les VG sources ne sont <b>pas</b> modifiés — de <b>nouveaux</b> VG sont créés.",
     "The source VGs are <b>not</b> modified — <b>new</b> VGs are created."),
    ("Clones HYCU en cours…", "HYCU clones in progress…"),
    ("Clone HYCU…", "HYCU clone…"),
    ("Job HYCU non identifié — récupérez la référence via le volet Avancé une fois le clone terminé.",
     "HYCU job not identified — fetch the reference via the Advanced section once the clone completes."),
    ("✓ VG cloné — référence <code>", "✓ VG cloned — reference <code>"),
    ("</code> remplie.", "</code> filled."),
    # Namespace créé par un clone : ajout automatique au filtre + bouton de secours.
    (" » ajouté aux namespaces autorisés", " » added to the allowed namespaces"),
    ("Filtre mis à jour (⚙ Réglages) pour que Vérifier/Restaurer acceptent ce namespace.",
     "Filter updated (⚙ Settings) so Verify/Restore accept this namespace."),
    ("Autoriser « ", "Allow « "),
    (" » et réessayer", " » and retry"),
    ("Mise à jour du filtre impossible.", "Could not update the filter."),
    # Sauvegarde automatique de la configuration (onglet 1).
    ("Sauvegarde automatique de la configuration (PV/PVC)",
     "Automatic configuration backup (PV/PVC manifests)"),
    ("Sauvegarde régulièrement les <b>manifestes PV/PVC</b> (la « recette » du restore) de tous les",
     "Regularly backs up the <b>PV/PVC manifests</b> (the restore “recipe”) of all"),
    ("namespaces autorisés par le filtre — tant que l'outil est lancé. <b>Pas les données</b> des volumes :",
     "namespaces allowed by the filter — while the tool is running. <b>Not the data</b> of the volumes:"),
    ("Sauvegarde automatique</label>", "Automatic backup</label>"),
    ("Intervalle (heures)", "Interval (hours)"),
    ("Versions à conserver", "Versions to keep"),
    ('? "Activée" : "Désactivée"', '? "Enabled" : "Disabled"'),
    (">Désactivée</b>", ">Disabled</b>"),
    ('"Toutes les "', '"Every "'),
    ("Sauvegarde en cours…", "Backup in progress…"),
    ('" Dernière : "', '" Last: "'),
    ('" · Prochaine : "', '" · Next: "'),
    ('" · Première exécution dans moins d\'une minute."', '" · First run in less than a minute."'),
    (" namespace(s) sauvegardé(s), ", " namespace(s) backed up, "),
    (" ancienne(s) version(s) supprimée(s)", " old version(s) deleted"),
    # Fenêtre « À propos » (bouton ? de l'en-tête).
    ("Plugin pour HYCU Enterprise Cloud", "Plugin for HYCU Enterprise Cloud"),
    ("Plugin gratuit, fourni « tel quel », sans aucune garantie ni engagement de HYCU.",
     "This is a free plugin, provided as-is, without any warranty or engagement from HYCU."),
    ("<b>Version :</b>", "<b>Version:</b>"),
    ("<b>Journal d'audit :</b>", "<b>Audit log:</b>"),
    ("<b>Configuration :</b>", "<b>Configuration:</b>"),
    ("<b>Sauvegardes :</b>", "<b>Backups:</b>"),
    (">Fermer</button>", ">Close</button>"),
]

# --- Interface « HYCU Enterprise Cloud » : pages, modales, assistant de restauration ---
I18N_EN += [
    # Barre du haut / barre latérale
    ('title="Tableau de bord"', 'title="Dashboard"'),
    ('<span class="nl">Tableau de bord</span>', '<span class="nl">Dashboard</span>'),
    ('<span class="nl">Politiques</span>', '<span class="nl">Policies</span>'),
    ('<span class="nl">Tâches</span>', '<span class="nl">Jobs</span>'),
    ("Réduire / déployer le menu", "Collapse / expand the menu"),
    ("Sections de l'outil", "Tool sections"),
    ('title="Fermer"', 'title="Close"'),
    ('title="Actualiser"', 'title="Refresh"'),
    ('placeholder="Rechercher"', 'placeholder="Search"'),
    ('title="Tout sélectionner"', 'title="Select all"'),
    # Tableau de bord
    ('<h2 class="dtitle">Dernières tâches</h2>', '<h2 class="dtitle">Recent jobs</h2>'),
    ('dnums("Protection"', 'dnums("Protection"'),
    ('"Conformité"', '"Compliance"'),
    ('"Connectées"', '"Connected"'),
    ('"Configurées"', '"Configured"'),
    ('<span class="k">Fréquence</span>', '<span class="k">Frequency</span>'),
    ('<span class="k">Rétention</span>', '<span class="k">Retention</span>'),
    ('<span class="k">Dernière exécution</span>', '<span class="k">Last run</span>'),
    ('<span class="k">Prochaine exécution</span>', '<span class="k">Next run</span>'),
    ('"Opérationnel"', '"Operational"'),
    ('"Indisponible"', '"Unavailable"'),
    ('<span class="k">Filtre des namespaces</span>', '<span class="k">Namespace filter</span>'),
    ('? "Actif" : "Aucun"', '? "Active" : "None"'),
    ('<span class="ko">Réel</span>', '<span class="ko">Real</span>'),
    ("Voir toutes les tâches", "View all jobs"),
    ("à l'instant", "just now"),
    ('"il y a %d min"', '"%d min ago"'),
    ('"il y a %d h"', '"%d h ago"'),
    ('"il y a %d j"', '"%d d ago"'),
    # Applications
    ('<span>Sauvegarder</span>', '<span>Back up</span>'),
    ('<span>Restaurer</span>', '<span>Restore</span>'),
    ('<span>Vérifier</span>', '<span>Verify</span>'),
    ("Définir la politique", "Set Policy"),
    ('<th>Nom</th>', '<th>Name</th>'),
    ('<th>Politique</th>', '<th>Policy</th>'),
    ('<th class="ctr">Conformité</th>', '<th class="ctr">Compliance</th>'),
    ('<th>Dernière sauvegarde</th>', '<th>Last backup</th>'),
    ('"Configuration auto · "', '"Automatic configuration · "'),
    (': "Aucune";', ': "None";'),
    ("Aucune application ne correspond à la recherche.", "No application matches the search."),
    ("Aucun namespace à afficher — vérifiez le contexte kubectl ou le filtre des namespaces.",
     "No namespace to display — check the kubectl context or the namespace filter."),
    ("Sauvegarde de configuration récente", "Recent configuration backup"),
    ("Dernière sauvegarde plus ancienne que ", "Last backup older than "),
    ("Jamais sauvegardée", "Never backed up"),
    (" sauvegarde(s) de configuration", " configuration backup(s)"),
    ("Aucune sauvegarde de configuration", "No configuration backup"),
    ('>Jamais</span>', '>Never</span>'),
    # Politiques
    ('<h1 class="ptitle">Politiques</h1>', '<h1 class="ptitle">Policies</h1>'),
    ('<th>Objet protégé</th>', '<th>Protected object</th>'),
    ('<th>Fréquence</th>', '<th>Frequency</th>'),
    ('<th>Rétention</th>', '<th>Retention</th>'),
    ('<th>Cible</th>', '<th>Target</th>'),
    ('<th class="ctr">État</th>', '<th class="ctr">Status</th>'),
    ("Configuration Kubernetes", "Kubernetes configuration"),
    ("Manifestes PV/PVC et ressources des namespaces du filtre", "PV/PVC manifests and resources of the filtered namespaces"),
    ('"Activée")', '"Enabled")'),
    ('"Désactivée")', '"Disabled")'),
    ("Politiques HYCU (données des volumes)", "HYCU policies (volume data)"),
    ("Politiques définies dans HYCU, assignables aux Volume Groups d'une application via",
     "Policies defined in HYCU, assignable to an application's Volume Groups via"),
    ("elles sont protégées par HYCU (<b>Applications", "they are protected by HYCU (<b>Applications"),
    ("Aucune politique HYCU.", "No HYCU policy."),
    ("Enregistrez la source HYCU (⚙ en haut à droite) pour afficher ses politiques.",
     "Register the HYCU source (⚙ at the top right) to display its policies."),
    # Tâches
    ('<h1 class="ptitle">Tâches ', '<h1 class="ptitle">Jobs '),
    ('<th>Tâche</th>', '<th>Job</th>'),
    ('<th>Détail</th>', '<th>Details</th>'),
    ('<th>Démarrée</th>', '<th>Started</th>'),
    ('"Sauvegarde de configuration (lot)"', '"Configuration backup (batch)"'),
    ("Sauvegarde de configuration", "Configuration backup"),
    ('"Sauvegarde automatique"', '"Automatic backup"'),
    ('"Restauration Kubernetes (PV/PVC)"', '"Kubernetes restore (PV/PVC)"'),
    ('"Clone d\'application"', '"Application clone"'),
    ('"Restauration sur place"', '"In-place restore"'),
    ('"Restauration HYCU (Volume Group)"', '"HYCU restore (Volume Group)"'),
    ('"Protection HYCU"', '"HYCU protection"'),
    ('"Succès"', '"Success"'),
    ('"Échec"', '"Failed"'),
    ('"En cours"', '"In progress"'),
    ('" tâche(s)"', '" job(s)"'),
    ("Aucune tâche enregistrée pour l'instant.", "No job recorded yet."),
    # Vérification / Réglages
    ('<span class="sep">›</span>Vérification</h1>', '<span class="sep">›</span>Verification</h1>'),
    ('<h1 class="ptitle">Réglages</h1>', '<h1 class="ptitle">Settings</h1>'),
    # Modales
    ("Restauration de l'application", "Application restore"),
    ("Sauvegarder la sélection", "Back up the selection"),
    ('<label class="fld">Namespaces sélectionnés</label>', '<label class="fld">Selected namespaces</label>'),
    (" namespace(s) sauvegardé(s).</div>", " namespace(s) backed up.</div>"),
    ('id="rsWizBack">Retour</button>', 'id="rsWizBack">Back</button>'),
    ('id="rsWizGo">Suivant</button>', 'id="rsWizGo">Next</button>'),
    ('"Suivant"', '"Next"'),
    ('lbl="Restaurer"', 'lbl="Restore"'),
    ('|| "Lancer"', '|| "Launch"'),
    ('"Mode réel"', '"Real mode"'),
    # Assistant de restauration : types
    ("Restaurer toute l'application (copie)", "Restore the whole application (copy)"),
    ("Restaurer le stockage sur place", "Restore storage in place"),
    ("Restaurer le stockage vers de nouveaux volumes", "Restore storage to new volumes"),
    ("Restaure le stockage et les objets de l'application (workloads, dépendances) dans le même namespace (suffixe) ou dans un autre. L'original n'est pas modifié.",
     "Restores the application storage and objects (workloads, dependencies) into the same namespace (suffix) or another one. The original is not modified."),
    ("Restaure les données dans les volumes d'origine. L'application est arrêtée puis redémarrée.",
     "Restores the data into the original volumes. The application is stopped, then restarted."),
    ("Restaure vers de nouveaux Volume Groups et y rattache l'application. Les volumes d'origine sont conservés.",
     "Restores to new Volume Groups and attaches the application to them. The original volumes are kept."),
    ('>Cluster cible</label>', '>Target cluster</label>'),
    ('<label class="fld">Volumes à restaurer</label>', '<label class="fld">Volumes to restore</label>'),
    ("Avancé — dossier de sauvegardes personnalisé", "Advanced — custom backup folder"),
    ("Chargement des volumes…", "Loading volumes…"),
    # Sources
    ('"Sauvegarde & restauration (API REST)"', '"Backup & restore (REST API)"'),
    ('"Nutanix — Volume Groups (API v2)"', '"Nutanix — Volume Groups (v2 API)"'),
    ('"Nutanix — multi-cluster (API v3/v4)"', '"Nutanix — multi-cluster (v3/v4 API)"'),
    ('"Coffre d\'identifiants"', '"Credentials vault"'),
    ('"Mémorisation chiffrée (optionnel)"', '"Encrypted storage (optional)"'),
    ('"Coffre présent"', '"Vault present"'),
    ('"Aucun coffre"', '"No vault"'),
    ('"Connecté"', '"Connected"'),
    ('"Configuré, non connecté"', '"Configured, not connected"'),
    ('"Non configuré"', '"Not configured"'),
]

# --- Multi-cluster (kubeconfigs ajoutés depuis l'interface) + découverte NKP ---
I18N_EN += [
    # Barre du haut / menu des clusters
    ("Cluster Kubernetes actif — cliquer pour en choisir un autre", "Active Kubernetes cluster — click to choose another one"),
    ('"Cluster Kubernetes actif"+', '"Active Kubernetes cluster"+'),
    ('" — cliquer pour en choisir un autre"', '" — click to choose another one"'),
    ("⚠ jeton expiré", "⚠ token expired"),
    ('"configuration locale"', '"local configuration"'),
    ('"kubeconfig importé"', '"imported kubeconfig"'),
    ("Gérer les clusters…", "Manage clusters…"),
    ("Ajouter un cluster Kubernetes", "Add a Kubernetes cluster"),
    ("Découvrir les workspaces NKP", "Discover NKP workspaces"),
    # Sources
    ("Enregistrez ici les systèmes utilisés par l'outil — HYCU, Nutanix et vos clusters Kubernetes. Les identifiants et kubeconfigs restent en mémoire le temps de la session (ou dans le coffre chiffré si vous le choisissez).",
     "Register here the systems used by the tool — HYCU, Nutanix and your Kubernetes clusters. Credentials and kubeconfigs stay in memory for the session (or in the encrypted vault if you choose so)."),
    ("<th>URL / serveur</th>", "<th>URL / server</th>"),
    (">Clusters Kubernetes<", ">Kubernetes clusters<"),
    ("Kubernetes — configuration locale", "Kubernetes — local configuration"),
    ("Kubernetes — kubeconfig importé", "Kubernetes — imported kubeconfig"),
    ('"kubeconfig par défaut"', '"default kubeconfig"'),
    ('class="tag">ACTIF<', 'class="tag">ACTIVE<'),
    ('"Contexte : "+', '"Context: "+'),
    ('"Authentification : "+', '"Authentication: "+'),
    ("Option : enregistrer les identifiants saisis (et les kubeconfigs des clusters ajoutés) dans un coffre <b>chiffré</b>",
     "Optional: store the credentials entered (and the kubeconfigs of added clusters) in an <b>encrypted</b> vault"),
    ("Clusters Kubernetes rechargés : ", "Kubernetes clusters reloaded: "),
    ("Clusters Kubernetes chiffrés : ", "Kubernetes clusters encrypted: "),
    ("Clusters Kubernetes chargés : ", "Kubernetes clusters loaded: "),
    # Fiche d'ajout
    ("Chargez le <b>kubeconfig</b> du cluster (fichier ou copier-coller). Comme un mot de passe, il reste",
     "Load the cluster <b>kubeconfig</b> (file or copy-paste). Like a password, it stays"),
    ("<b>en mémoire</b> le temps de la session, et n'est écrit sur disque que <b>chiffré</b> si vous utilisez le coffre.",
     "<b>in memory</b> for the session, and is only written to disk <b>encrypted</b> if you use the vault."),
    ("Les sauvegardes de chaque cluster sont rangées séparément.", "Each cluster's backups are stored separately."),
    ('<label class="fld">Nom du cluster</label>', '<label class="fld">Cluster name</label>'),
    ('<label class="fld">Fichier kubeconfig</label>', '<label class="fld">Kubeconfig file</label>'),
    ("…ou collez son contenu (YAML ou JSON)", "…or paste its content (YAML or JSON)"),
    ('<label class="fld">Contexte</label><select id="clCtx">', '<label class="fld">Context</label><select id="clCtx">'),
    ('id="clAdd" type="button">Tester &amp; ajouter<', 'id="clAdd" type="button">Test &amp; add<'),
    ('"Tester & ajouter"', '"Test & add"'),
    ("Test de connexion en lecture seule (liste des namespaces, 10 s max).", "Read-only connection test (namespace list, 10 s max)."),
    ("Test de connexion…", "Testing connection…"),
    ("Chargez ou collez d'abord un kubeconfig.", "Load or paste a kubeconfig first."),
    ("Cluster ajouté. Choisissez « Définir comme cluster actif » pour l'utiliser, ou sélectionnez-le dans la barre du haut.",
     "Cluster added. Choose “Set as active cluster” to use it, or select it in the top bar."),
    # Fiche d'un cluster
    ("Définir comme cluster actif", "Set as active cluster"),
    ('"Cluster actif"', '"Active cluster"'),
    ('data-scope="one">Cluster actif<', 'data-scope="one">Active cluster<'),
    ("Tous les clusters", "All clusters"),
    ('==="*"?"Tous":', '==="*"?"All":'),
    ('id="clLocalCfg" type="button">Ouvrir les réglages<', 'id="clLocalCfg" type="button">Open settings<'),
    ('id="clRemove" type="button">Retirer<', 'id="clRemove" type="button">Remove<'),
    ('li("Contexte kubectl"', 'li("kubectl context"'),
    ('li("Serveur API"', 'li("API server"'),
    ('li("Workspace NKP"', 'li("NKP workspace"'),
    ('li("Cluster de management"', 'li("Management cluster"'),
    ('li("Sauvegardes"', 'li("Backups"'),
    ("Serveur API", "API server"),
    ("Aucun contexte kubectl local : ajoutez un cluster avec son kubeconfig, ou configurez kubectl (Réglages).",
     "No local kubectl context: add a cluster with its kubeconfig, or configure kubectl (Settings)."),
    ('"Retirer le cluster « "', '"Remove cluster « "'),
    ('" » ? Son kubeconfig est oublié ; ses sauvegardes restent sur disque."',
     '" »? Its kubeconfig is forgotten; its backups stay on disk."'),
    # Découverte NKP
    ("Découverte des workspaces NKP (optionnel)", "NKP workspace discovery (optional)"),
    ("Depuis le <b>cluster de management</b> NKP, liste les <b>workspaces</b> et leurs clusters, puis importe",
     "From the NKP <b>management cluster</b>, lists the <b>workspaces</b> and their clusters, then imports"),
    ("leurs kubeconfigs. Cluster interrogé : ", "their kubeconfigs. Queried cluster: "),
    ("(le cluster actif — choisissez le cluster de management", "(the active cluster — choose the management cluster"),
    ("dans la barre du haut).", "in the top bar)."),
    ("<b>Droits élevés requis</b> sur le cluster de management : lecture des Workspaces, des",
     "<b>Elevated rights required</b> on the management cluster: read access to Workspaces,"),
    ("KommanderClusters et des <b>Secrets</b> kubeconfig des namespaces de workspace. Les kubeconfigs importés donnent",
     "KommanderClusters and kubeconfig <b>Secrets</b> in workspace namespaces. Imported kubeconfigs often grant"),
    ("souvent un accès <b>administrateur</b> aux clusters : ils restent en mémoire (coffre chiffré en option), jamais en clair sur disque.",
     "<b>administrator</b> access to the clusters: they stay in memory (optional encrypted vault), never in clear text on disk."),
    ('id="nkpDiscover" type="button">Découvrir<', 'id="nkpDiscover" type="button">Discover<'),
    ("J'ai compris : importer les kubeconfigs des clusters cochés", "I understand: import the kubeconfigs of the checked clusters"),
    ("Importer la sélection", "Import selection"),
    ("Lecture des workspaces…", "Reading workspaces…"),
    ("Aucun cluster trouvé dans les workspaces.", "No cluster found in the workspaces."),
    ("Cluster de management (actif)", "Management cluster (active)"),
    ('"Déjà importé ("', '"Already imported ("'),
    ('"Importé sous « "', '"Imported as « "'),
    # Pages : Applications, tableau de bord, confirmations, réglages
    ("Clusters enregistrés", "Registered clusters"),
    ('"Cluster ciblé : <b>"', '"Target cluster: <b>"'),
    ("Cluster local (contexte kubectl)", "Local cluster (kubectl context)"),
    ("Les clusters <b>supplémentaires</b> (kubeconfig importé, workspaces NKP) se gèrent depuis <b>⚙ Sources</b>.",
     "<b>Additional</b> clusters (imported kubeconfig, NKP workspaces) are managed from <b>⚙ Sources</b>."),
    ("Contextes / clusters autorisés (séparés par des virgules ; vide = tous)", "Allowed contexts / clusters (comma-separated; empty = all)"),
    ("Namespaces autorisés — cluster local (vide = tous)", "Allowed namespaces — local cluster (empty = all)"),
    # Messages du serveur
    ("Authentification par plugin exec (« ", "Exec plugin authentication (« "),
    ("Authentification « auth-provider » (", "« auth-provider » authentication ("),
    ("Le jeton est lu depuis un fichier local (", "The token is read from a local file ("),
    (") : il doit exister là où tourne l'outil.", "): it must exist where the tool runs."),
    ("Le jeton a EXPIRÉ : régénérez le kubeconfig.", "The token has EXPIRED: regenerate the kubeconfig."),
    ("Le jeton a EXPIRÉ (", "The token has EXPIRED ("),
    (") : régénérez le kubeconfig.", "): regenerate the kubeconfig."),
    ("Le jeton expire dans moins de 24 h (", "The token expires in less than 24 h ("),
    (") : les sauvegardes planifiées échoueront ensuite.", "): scheduled backups will fail afterwards."),
    ("Le certificat client est un fichier local (", "The client certificate is a local file ("),
    ("Authentification par identifiant/mot de passe (basic) : désactivée sur la plupart des clusters récents.",
     "Username/password (basic) authentication: disabled on most recent clusters."),
    ("Aucune information d'authentification reconnue pour ce contexte.", "No recognized authentication information for this context."),
    ("Vérification TLS du serveur DÉSACTIVÉE (insecure-skip-tls-verify).", "Server TLS verification DISABLED (insecure-skip-tls-verify)."),
    ("L'autorité de certification est un fichier local (", "The certificate authority is a local file ("),
    ("Kubeconfig vide.", "Empty kubeconfig."),
    ("Kubeconfig trop volumineux (1 Mo max).", "Kubeconfig too large (1 MB max)."),
    ("Kubeconfig invalide : ", "Invalid kubeconfig: "),
    ("Kubeconfig illisible : ", "Unreadable kubeconfig: "),
    ("kubectl config view a échoué", "kubectl config view failed"),
    ("Aucun contexte dans ce kubeconfig.", "No context in this kubeconfig."),
    ("Cluster injoignable.", "Cluster unreachable."),
    ("Nom de cluster invalide (1 à 63 caractères, lettres/chiffres/-/./_).", "Invalid cluster name (1 to 63 characters, letters/digits/-/./_)."),
    ("Ce nom est réservé au cluster local : choisissez-en un autre.", "This name is reserved for the local cluster: choose another one."),
    ("Un cluster nommé « ", "A cluster named « "),
    (" » est déjà enregistré.", " » is already registered."),
    ("Ce kubeconfig contient plusieurs contextes : choisissez-en un.", "This kubeconfig contains several contexts: choose one."),
    (" » introuvable dans ce kubeconfig.", " » not found in this kubeconfig."),
    ("Connexion au cluster impossible : ", "Cannot connect to the cluster: "),
    ("Le cluster local (configuration) ne peut pas être retiré ici : voir Réglages.",
     "The local cluster (configuration) cannot be removed here: see Settings."),
    ("Cluster inconnu.", "Unknown cluster."),
    ("Liste des clusters NKP (KommanderCluster) indisponible : ", "NKP cluster list (KommanderCluster) unavailable: "),
    ("Confirmez d'abord l'avertissement sur les privilèges requis.", "First acknowledge the warning about required privileges."),
    ("Nom invalide.", "Invalid name."),
    (" » illisible : ", " » unreadable: "),
    ("Aucun kubeconfig trouvé dans le Secret « ", "No kubeconfig found in Secret « "),
    ("Aucun cluster importé.", "No cluster imported."),
    ("Cette sauvegarde provient du cluster « ", "This backup comes from cluster « "),
    (" », alors que le cluster actif est « ", " », while the active cluster is « "),
    ("Cluster local non configuré.", "Local cluster not configured."),
    ("aucun cluster disponible", "no cluster available"),
    ("Sauvegarde introuvable ou hors de la zone autorisée : ", "Backup not found or outside the allowed area: "),
    ("Sauvegarde illisible (", "Unreadable backup ("),
    (") : index.json manquant ou corrompu (", "): index.json missing or corrupt ("),
    ("Restauration en cours (transaction) : sauvegarde différée.", "Restore in progress (transaction): backup deferred."),
    (" en ÉCHEC : ", " FAILED: "),
    ("Inventaire des Deployments/StatefulSets impossible (", "Deployments/StatefulSets inventory unavailable ("),
    (") — séquence annulée.", ") — sequence cancelled."),
    ("état des pods invérifiable (kubectl en erreur) : ", "pod state unverifiable (kubectl failing): "),
    ("⚠ Liste des pods indisponible (contrôle des pods non gérés sauté)",
     "⚠ Pod list unavailable (unmanaged-pods check skipped)"),
    ("Inventaire des workloads impossible", "Workload inventory unavailable"),
    ('id="abSave">Enregistrer<', 'id="abSave">Save<'),
    ('"Cluster injoignable (contrôle "', '"Cluster unreachable (checked "'),
    ('"Joignable ("', '"Reachable ("'),
    ('") · authentification : "', '") · authentication: "'),
    ('li("Dernier contrôle de santé"', 'li("Last health check"'),
    ('"Joignable"', '"Reachable"'),
    ("Cluster injoignable au dernier contrôle : ", "Cluster unreachable at last check: "),
    ('<span>Réglages</span>', '<span>Settings</span>'),
    ('title="Sources & Réglages"', 'title="Sources & Settings"'),
    ("cluster injoignable", "cluster unreachable"),
    # Export S3 (stockage objet)
    ("Stockage objet S3 — export des sauvegardes (optionnel)", "S3 object storage — backup export (optional)"),
    ("Copie chaque sauvegarde de configuration (<code>.zip</code>) vers un bucket <b>compatible S3</b>",
     "Copies every configuration backup (<code>.zip</code>) to an <b>S3-compatible</b> bucket"),
    ("(Nutanix Objects, MinIO, AWS S3…) : le filet de sécurité vit alors <b>hors du cluster</b> qu'il protège.",
     "(Nutanix Objects, MinIO, AWS S3…): the safety net then lives <b>outside the cluster</b> it protects."),
    ("Clés d'accès en <b>mémoire</b> le temps de la session (coffre chiffré en option).",
     "Access keys stay <b>in memory</b> for the session (encrypted vault optional)."),
    ("<label class=\"fld\">Endpoint S3</label>", "<label class=\"fld\">S3 endpoint</label>"),
    ("Clé d'accès (Access key)", "Access key"),
    ("Clé secrète (Secret key)", "Secret key"),
    ("Région (signature)", "Region (signing)"),
    ("URL de type chemin (Objects / MinIO)", "Path-style URL (Objects / MinIO)"),
    ("<b>Export automatique</b> : envoyer chaque sauvegarde réussie (manuelle et planifiée) vers le bucket",
     "<b>Automatic export</b>: send every successful backup (manual and scheduled) to the bucket"),
    ("Test en lecture seule (liste du bucket, 1 objet). Objets créés :",
     "Read-only test (bucket listing, 1 object). Objects created:"),
    ("Test du bucket…", "Testing bucket…"),
    ("Export automatique activé.", "Automatic export enabled."),
    ("Export automatique désactivé (cochez la case pour l'activer).", "Automatic export disabled (tick the box to enable it)."),
    ("Export automatique désactivé", "Automatic export disabled"),
    ("Connecté — export automatique désactivé", "Connected — automatic export disabled"),
    ("Export des sauvegardes (optionnel)", "Backup export (optional)"),
    ('"Stockage objet S3"', '"S3 object storage"'),
    ("Export S3 (stockage objet)", "S3 export (object storage)"),
    ("Endpoint S3 ou bucket non configuré (⚙ Sources).", "S3 endpoint or bucket not configured (⚙ Sources)."),
    ("Non connecté au stockage objet : renseignez les clés d'accès (⚙ Sources).",
     "Not connected to the object storage: enter the access keys (⚙ Sources)."),
    ("Renseignez la clé d'accès (Access key) et la clé secrète (Secret key).",
     "Enter the access key and the secret key."),
    ("Test du bucket impossible : ", "Bucket test failed: "),
    (" — clés d'accès refusées (ou horloge du serveur décalée : SigV4 exige une heure juste).",
     " — access keys refused (or server clock skewed: SigV4 requires accurate time)."),
    (" — bucket introuvable : vérifiez son nom (et s3_path_style).",
     " — bucket not found: check its name (and s3_path_style)."),
    (" — mauvaise région (s3_region) ou style d'URL (s3_path_style).",
     " — wrong region (s3_region) or URL style (s3_path_style)."),
    ("Stockage objet injoignable : ", "Object storage unreachable: "),
    ("Endpoint S3 injoignable — vérifiez le PORT (MinIO : 9000 = API S3, pas la console 9001 ; Nutanix Objects : 443), le protocole http/https, et que la machine qui exécute l'outil (le Pod, pas votre poste) atteint cet hôte.",
     "S3 endpoint unreachable — check the PORT (MinIO: 9000 = S3 API, not the 9001 console; Nutanix Objects: 443), the http/https scheme, and that the machine running the tool (the Pod, not your workstation) can reach that host."),
    ("sauvegarde trop volumineuse pour l'export (", "backup too large for export ("),
    ("envoi refusé", "upload refused"),
    # Rétention GFS
    ('<option value="count">N versions</option><option value="gfs">GFS (j/sem/mois)</option>',
     '<option value="count">N versions</option><option value="gfs">GFS (d/wk/mo)</option>'),
    ('<label class="fld">Rétention</label>', '<label class="fld">Retention</label>'),
    ('<label class="fld">Jours</label>', '<label class="fld">Days</label>'),
    ('<label class="fld">Semaines</label>', '<label class="fld">Weeks</label>'),
    ('<label class="fld">Mois</label>', '<label class="fld">Months</label>'),
    ('" sem / "', '" wk / "'),
    ('" mois"', '" mo"'),
    (' · rétention : ', ' · retention: '),
    ('" par namespace."', '" per namespace."'),
    # Sélecteur d'étiquettes
    ("Sélecteur d'étiquettes des namespaces (vide = inactif ; s'applique à tous les clusters)",
     "Namespace label selector (empty = inactive; applies to all clusters)"),
    ('placeholder="hycu.io/backup=true  ou  env in (prod,preprod)"',
     'placeholder="hycu.io/backup=true  or  env in (prod,preprod)"'),
    # Rapport
    ("Rapport de conformité (HTML autonome) : applications, RPO, santé des clusters, tâches",
     "Compliance report (standalone HTML): applications, RPO, cluster health, jobs"),
    ("Export CSV des applications (Excel)", "CSV export of applications (Excel)"),
    ("<span>Rapport HTML</span>", "<span>HTML report</span>"),
    ("<title>Rapport de protection Kubernetes</title>", "<title>Kubernetes Protection Report</title>"),
    ("<h1>Rapport de protection des applications Kubernetes</h1>", "<h1>Kubernetes application protection report</h1>"),
    ("Généré le ", "Generated on "),
    ("· outil v", "· tool v"),
    ("</b>applications</span>", "</b>applications</span>"),
    ("</b>protégées</span>", "</b>protected</span>"),
    ("</b>conformes</span>", "</b>compliant</span>"),
    ("</b>tâches ok / échec / simulation</span>", "</b>jobs ok / failed / simulation</span>"),
    ("<h2>Applications (protection de la configuration)</h2>", "<h2>Applications (configuration protection)</h2>"),
    ("<th>Protégée</th>", "<th>Protected</th>"),
    ("<th>Conforme</th>", "<th>Compliant</th>"),
    ("<th>Versions</th>", "<th>Versions</th>"),
    ("<h2>Santé des clusters</h2>", "<h2>Cluster health</h2>"),
    ("<th>Joignable</th>", "<th>Reachable</th>"),
    ("<h2>Dernières tâches (30)</h2>", "<h2>Recent jobs (30)</h2>"),
    ("<th>Horodatage</th>", "<th>Timestamp</th>"),
    (">aucune application<", ">no application<"),
    (">aucun contrôle encore exécuté<", ">no check executed yet<"),
    (">aucune tâche<", ">no job<"),
    ("Rapport généré par l'outil HYCU · Kubernetes · Nutanix — politique : sauvegarde",
     "Report generated by the HYCU · Kubernetes · Nutanix tool — policy: automatic"),
    # Chiffrement S3
    ("<b>Chiffrer les exports</b> (option) : les objets envoyés sont chiffrés — le bucket peut être un stockage non maîtrisé",
     "<b>Encrypt exports</b> (optional): uploaded objects are encrypted — the bucket can be untrusted storage"),
    ("Phrase de chiffrement des exports (à conserver : elle sert au déchiffrement)",
     "Export encryption passphrase (keep it: it is needed for decryption)"),
    ("Déchiffrement hors interface : ", "Decryption outside the UI: "),
    # Restauration d'objets
    ("Restaurer des objets de configuration", "Restore configuration objects"),
    ("Ré-applique des objets choisis (Deployments, Services, ConfigMaps…) depuis l'instantané d'une sauvegarde, avec aperçu des différences. Ne touche ni aux volumes ni aux données.",
     "Re-applies selected objects (Deployments, Services, ConfigMaps…) from a backup's snapshot, with a diff preview. Volumes and data are untouched."),
    ("Sauvegarde (instantané de config)", "Backup (config snapshot)"),
    ("Objets à restaurer ", "Objects to restore "),
    (">Type</th><th>Nom</th><th>Note</th>", ">Kind</th><th>Name</th><th>Note</th>"),
    ("Aperçu des différences (live → sauvegarde)", "Diff preview (live → backup)"),
    ("Prévisualiser les différences", "Preview differences"),
    ("Appliquer (simulation)", "Apply (simulation)"),
    ("Appliquer (réel)", "Apply (real)"),
    ("objet(s) dans l'instantané)", "object(s) in the snapshot)"),
    ("(aucune sauvegarde)", "(no backup)"),
    ("Instantané vide.", "Empty snapshot."),
    ("Secret masqué — non restaurable", "Secret redacted — not restorable"),
    ('"Identique au live — apply sans effet"', '"Identical to live — apply is a no-op"'),
    ('"Diffère du live"', '"Differs from live"'),
    ('"Absent du live — sera (re)créé"', '"Absent from live — will be (re)created"'),
    ('"Lecture du live impossible"', '"Cannot read live state"'),
    ('"Secret masqué"', '"Secret redacted"'),
    ("Rien à comparer.", "Nothing to compare."),
    ("Restauration d'objets RÉELLE", "REAL object restore"),
    ("</b> objet(s) de configuration seront ÉCRASÉS par la version de la sauvegarde (kubectl apply). Les volumes et les données ne sont pas touchés.",
     "</b> configuration object(s) will be OVERWRITTEN by the backup version (kubectl apply). Volumes and data are untouched."),
    ("Application…", "Applying…"),
    (" objet(s) appliqué(s)", " object(s) applied"),
    (" ignoré(s)", " skipped"),
    ("resources.json illisible : ", "resources.json unreadable: "),
    ("Secret masqué à la sauvegarde : non restaurable.", "Secret redacted at backup time: not restorable."),
    ("Aucun objet sélectionné.", "No object selected."),
    ("Ignoré : ", "Skipped: "),
    (" (Secret masqué à la sauvegarde)", " (Secret redacted at backup time)"),
    ("Restaurez ce Secret depuis sa source d'origine.", "Restore this Secret from its original source."),
    ("Appliquer ", "Apply "),
    (" objet(s) en échec.", " object(s) failed."),
    ("<h2>Export hors cluster</h2>", "<h2>Off-cluster export</h2>"),
    (" h, rétention ", " h, retention "),
    (' · "+(x.index||{}).resources_count+" objets"', ' · "+(x.index||{}).resources_count+" objects"'),
    # Menu « ? » + page d'aide (/help)
    ('title="Aide &amp; À propos"', 'title="Help &amp; About"'),
    ("<span>Aide (guide)</span>", "<span>Help (guide)</span>"),
    ("<span>À propos</span>", "<span>About</span>"),
    ("<title>Aide — Protection Kubernetes sur Nutanix</title>", "<title>Help — Kubernetes Protection on Nutanix</title>"),
    ("<h1>Aide — Protection Kubernetes sur Nutanix</h1>", "<h1>Help — Kubernetes Protection on Nutanix</h1>"),
    ("· toutes les actions destructives sont simulées par défaut", "· every destructive action is simulated by default"),
    ("Cette page est servie par l'outil (fonctionne hors-ligne). Fermez l'onglet pour revenir à l'interface.",
     "This page is served by the tool itself (works offline). Close the tab to return to the UI."),
    ("Démarrage rapide", "Quick start"),
    ("<b>Enregistrez vos sources</b> : ⚙ (en haut à droite) → <b>Sources</b> → HYCU, Prism Central/Element, et vos <b>clusters Kubernetes</b> si besoin. Les identifiants restent en mémoire (ou dans le coffre chiffré).",
     "<b>Register your sources</b>: ⚙ (top right) → <b>Sources</b> → HYCU, Prism Central/Element, and your <b>Kubernetes clusters</b> if needed. Credentials stay in memory (or in the encrypted vault)."),
    ("<b>Sauvegardez la configuration</b> : page <b>Applications</b> → cochez vos applications → <b>Sauvegarder</b>. Activez ensuite la <b>sauvegarde automatique</b> (page Politiques).",
     "<b>Back up the configuration</b>: <b>Applications</b> page → tick your applications → <b>Back up</b>. Then enable the <b>automatic backup</b> (Policies page)."),
    ("<b>Testez une restauration</b> en <b>mode simulation</b> (bandeau du haut, activé par défaut) : Applications → une application → <b>Restaurer</b>. Rien n'est exécuté tant que la simulation est active.",
     "<b>Test a restore</b> in <b>simulation mode</b> (top banner, on by default): Applications → one application → <b>Restore</b>. Nothing runs while simulation is on."),
    ("L'outil orchestre la <b>configuration</b> (manifestes PV/PVC, objets) ; les <b>données</b> des volumes sont protégées par <b>HYCU</b> (Volume Groups Nutanix). Les deux sont complémentaires.",
     "The tool orchestrates the <b>configuration</b> (PV/PVC manifests, objects); the volume <b>data</b> is protected by <b>HYCU</b> (Nutanix Volume Groups). They complement each other."),
    ("L'interface", "The interface"),
    ("<b>Barre du haut</b> : pastilles d'état HYCU/PE/PC · <b>cluster actif</b> (cliquez pour changer de cluster ou en ajouter) · ⚙ <b>Sources / Réglages</b> · <b>?</b> Aide / À propos · <b>EN/FR</b>.",
     "<b>Top bar</b>: HYCU/PE/PC status dots · <b>active cluster</b> (click to switch or add one) · ⚙ <b>Sources / Settings</b> · <b>?</b> Help / About · <b>EN/FR</b>."),
    ("<b>Tableau de bord</b> : anneaux protection/conformité, politique, sources, cluster, activité des tâches.",
     "<b>Dashboard</b>: protection/compliance rings, policy, sources, cluster, job activity."),
    ("<b>Applications</b> : une ligne par namespace. Sélectionnez, puis agissez en haut à droite : <b>Sauvegarder · Restaurer · Définir la politique · Vérifier</b>. Bascule <b>Cluster actif / Tous les clusters</b> (regroupés par workspace NKP).",
     "<b>Applications</b>: one row per namespace. Select, then act at the top right: <b>Back up · Restore · Set Policy · Verify</b>. <b>Active cluster / All clusters</b> toggle (grouped by NKP workspace)."),
    ("<b>Politiques</b> : sauvegarde automatique de la configuration (fréquence, rétention) + politiques HYCU.",
     "<b>Policies</b>: automatic configuration backup (frequency, retention) + HYCU policies."),
    ("<b>Tâches</b> : historique (succès/échec/simulation), cluster de chaque tâche, boutons <b>Rapport HTML/CSV</b>.",
     "<b>Jobs</b>: history (success/failed/simulation), cluster of each job, <b>HTML/CSV report</b> buttons."),
    ("<b>Le bandeau Simulation</b> : tant qu'il est activé, AUCUNE commande destructive n'est exécutée — l'outil montre ce qu'il ferait. Désactivez-le seulement au moment d'agir.",
     "<b>The Simulation banner</b>: while it is on, NO destructive command runs — the tool shows what it would do. Turn it off only when ready to act."),
    ("Clusters Kubernetes (multi-cluster & NKP)", "Kubernetes clusters (multi-cluster & NKP)"),
    ("Le <b>cluster local</b> vient de la configuration (kubeconfig/contexte — ⚙ → Réglages).",
     "The <b>local cluster</b> comes from the configuration (kubeconfig/context — ⚙ → Settings)."),
    ("<b>Ajouter un cluster</b> : ⚙ → Sources → <b>Ajouter un cluster Kubernetes</b> → chargez ou collez son kubeconfig → <b>Tester &amp; ajouter</b>. L'outil analyse l'authentification (jeton expiré, plugin exec…) et vous avertit.",
     "<b>Add a cluster</b>: ⚙ → Sources → <b>Add a Kubernetes cluster</b> → load or paste its kubeconfig → <b>Test &amp; add</b>. The tool analyses the authentication (expired token, exec plugin…) and warns you."),
    ("<b>NKP</b> : rendez le cluster de management actif, puis Sources → <b>Découvrir les workspaces NKP</b> → cochez les clusters → <b>Importer</b> (droits élevés requis, avertissement explicite).",
     "<b>NKP</b>: make the management cluster active, then Sources → <b>Discover NKP workspaces</b> → tick the clusters → <b>Import</b> (elevated rights required, explicit warning)."),
    ("Les sauvegardes de chaque cluster sont rangées <b>séparément</b>, et une sauvegarde ne se restaure que sur son cluster d'origine.",
     "Each cluster's backups are stored <b>separately</b>, and a backup only restores onto its source cluster."),
    ("Les kubeconfigs sont des <b>secrets</b> : mémoire de session + coffre chiffré (jamais en clair sur disque).",
     "Kubeconfigs are <b>secrets</b>: session memory + encrypted vault (never in clear on disk)."),
    ("Sauvegarder", "Back up"),
    ("<b>Applications → Sauvegarder</b> : exporte et nettoie les manifestes <b>PV/PVC</b> (la « recette » du restore) + un <b>instantané des autres objets</b> (Deployments, Services, ConfigMaps, Secrets…) dans <code>resources.json</code> — les données des Secrets sont <b>chiffrées</b> (<code>secrets.enc</code>, phrase du coffre) ; sans coffre déverrouillé ni <code>HYCU_VAULT_PASSPHRASE</code>, elles restent en clair et la sauvegarde le signale (réglage <code>backup_secrets</code>).",
     "<b>Applications → Back up</b>: exports and cleans the <b>PV/PVC</b> manifests (the restore “recipe”) + a <b>snapshot of the other objects</b> (Deployments, Services, ConfigMaps, Secrets…) into <code>resources.json</code> — Secret data is <b>encrypted</b> (<code>secrets.enc</code>, vault passphrase); without an unlocked vault or <code>HYCU_VAULT_PASSPHRASE</code> it stays in clear and the backup says so (<code>backup_secrets</code> setting)."),
    ("<b>Sauvegarder tous (filtrés)</b> : tous les namespaces autorisés d'un coup ; un namespace sans PVC est ignoré.",
     "<b>Back up all (filtered)</b>: every allowed namespace at once; a namespace without PVCs is skipped."),
    ("Dossier par défaut : <code>hycu-backups/</code> — <b>copiez-le hors du cluster</b> (téléchargement .zip dans l'assistant de restauration, ou export S3 automatique, voir plus bas).",
     "Default folder: <code>hycu-backups/</code> — <b>copy it off the cluster</b> (.zip download in the restore wizard, or automatic S3 export, see below)."),
    ("Le filtre des namespaces (entonnoir) et le <b>sélecteur d'étiquettes</b> (Réglages) bornent ce que l'outil voit et touche.",
     "The namespace filter (funnel) and the <b>label selector</b> (Settings) bound what the tool sees and touches."),
    ("Sauvegarde automatique & rétention", "Automatic backup & retention"),
    ("Page <b>Politiques</b> : activez la sauvegarde automatique (intervalle en heures). Elle couvre <b>tous les clusters connus</b>, tant que l'outil tourne ; un passage manqué est rattrapé au démarrage.",
     "<b>Policies</b> page: enable the automatic backup (interval in hours). It covers <b>all known clusters</b> while the tool runs; a missed run is caught up at startup."),
    ("<b>Rétention</b> : « N versions » (défaut), ou <b>GFS</b> — la plus récente de chaque jour / semaine / mois (7 j / 4 sem / 12 mois par défaut).",
     "<b>Retention</b>: “N versions” (default), or <b>GFS</b> — the most recent of each day / week / month (7 d / 4 wk / 12 mo by default)."),
    ("La sauvegarde d'une restauration en cours n'est jamais supprimée par la rétention.",
     "The backup of an in-progress restore is never pruned by retention."),
    ("<b>Garde-fous du stockage</b> (Réglages) : plancher d'espace libre (sauvegarde refusée en dessous), quota global optionnel (purge des plus anciennes au-delà), historique des tâches borné (31 j par défaut). La tuile <b>Stockage</b> du tableau de bord surveille le disque.",
     "<b>Storage guardrails</b> (Settings): free-space floor (backups refused below it), optional global quota (oldest pruned above it), bounded job history (31 d by default). The dashboard's <b>Storage</b> tile watches the disk."),
    ("<b>Applications → Définir la politique</b> : l'outil associe chaque PVC à son <b>Volume Group</b> HYCU (correspondance par UUID), assigne une politique HYCU et peut lancer une sauvegarde.",
     "<b>Applications → Set Policy</b>: the tool matches each PVC to its HYCU <b>Volume Group</b> (UUID match), assigns a HYCU policy and can start a backup."),
    ("Une correspondance « par nom » doit être <b>confirmée</b> (case à cocher) ; une ambiguïté n'est jamais tranchée automatiquement.",
     "A “by name” match must be <b>confirmed</b> (checkbox); an ambiguity is never resolved automatically."),
    ("Restaurer — les 5 parcours", "Restore — the 5 flows"),
    ("<b>Restaurer toute l'application (copie)</b> : volumes + objets vers le même namespace (suffixe) ou un autre. L'original n'est pas modifié. Idéal pour vérifier une sauvegarde.",
     "<b>Restore the whole application (copy)</b>: volumes + objects into the same namespace (suffix) or another one. The original is untouched. Ideal to verify a backup."),
    ("<b>Restaurer le stockage sur place</b> : HYCU restaure les données <b>dans</b> les volumes d'origine ; l'application est arrêtée puis redémarrée. Choisissez un point de restauration par volume (le plus récent est présélectionné).",
     "<b>Restore storage in place</b>: HYCU restores the data <b>into</b> the original volumes; the application is stopped then restarted. Pick a restore point per volume (most recent pre-selected)."),
    ("<b>Restaurer le stockage vers de nouveaux volumes</b> : de nouveaux Volume Groups sont clonés, l'application y est rattachée ; les volumes d'origine sont conservés.",
     "<b>Restore storage to new volumes</b>: new Volume Groups are cloned and the application re-attached; original volumes are kept."),
    ("<b>Restaurer des objets de configuration</b> : ré-applique des objets choisis depuis l'instantané d'une sauvegarde, avec <b>aperçu des différences</b> avant tout apply. Ne touche ni aux volumes ni aux données.",
     "<b>Restore configuration objects</b>: re-applies selected objects from a backup snapshot, with a <b>diff preview</b> before any apply. Volumes and data untouched."),
    ("Déroulé conseillé : lancez d'abord en <b>simulation</b> (plan affiché, aucun effet), relisez le récapitulatif, puis désactivez la simulation et relancez. En mode réel, l'outil demande de <b>retaper le nom du cluster</b>. Après une restauration réelle, la <b>Vérification</b> s'ouvre automatiquement (PVC Bound, pods Running).",
     "Recommended flow: run in <b>simulation</b> first (plan shown, no effect), review the summary, then turn simulation off and relaunch. In real mode the tool asks you to <b>retype the cluster name</b>. After a real restore, <b>Verification</b> opens automatically (PVC Bound, pods Running)."),
    ("Si une étape échoue, la séquence <b>s'arrête</b> et l'application reste arrêtée (jamais redémarrée sur des volumes incohérents). Corrigez puis <b>relancez</b> : la reprise est idempotente et les réplicas d'origine sont mémorisés.",
     "If a step fails, the sequence <b>stops</b> and the application stays stopped (never restarted on inconsistent volumes). Fix then <b>relaunch</b>: resumption is idempotent and original replicas are remembered."),
    ("Export S3 (optionnel)", "S3 export (optional)"),
    ("Restauration en masse (même cluster)", "Bulk restore (same cluster)"),
    ("<li><b>Applications → Restaurer en masse</b> : recrée d'un coup <b>tous les namespaces supprimés</b> du cluster actif depuis leur dernière sauvegarde antérieure à un <b>instant de référence</b> (namespace, PV/PVC, workloads, dépendances, Secrets si le coffre est déverrouillé, Volume Groups restaurés par HYCU s'ils ont disparu, applications stateless). Les namespaces <b>encore présents</b> sont ignorés : une application vivante se restaure depuis sa propre ligne.</li>",
     "<li><b>Applications → Bulk restore</b>: recreates at once <b>every deleted namespace</b> of the active cluster from its latest backup prior to a <b>reference time</b> (namespace, PV/PVC, workloads, dependencies, Secrets when the vault is unlocked, Volume Groups restored by HYCU if they are gone, stateless applications). Namespaces <b>still present</b> are skipped: a live application is restored from its own row.</li>"),
    ("<li><b>Préparer le plan</b> montre, avant tout, les namespaces retenus (sauvegarde choisie, contenu, avertissements : Secrets masqués ou chiffrés avec coffre verrouillé, sauvegarde partielle, sans instantané) et ceux ignorés, avec la raison.</li>",
     "<li><b>Prepare the plan</b> first shows the selected namespaces (chosen backup, content, warnings: redacted Secrets or encrypted with a locked vault, partial backup, no snapshot) and the skipped ones, with the reason.</li>"),
    ("<li><b>Simuler</b> exécute le plan en simulation, en arrière-plan, avec un journal par namespace ; <b>Lancer (réel)</b> n'est possible qu'après une simulation complète et sans échec du <b>même</b> plan, bandeau Simulation désactivé, et confirmation du cluster.</li>",
     "<li><b>Simulate</b> runs the plan in simulation, in the background, with a journal per namespace; <b>Start (real)</b> is only possible after a complete, failure-free simulation of the <b>same</b> plan, with the Simulation banner off and the cluster confirmed.</li>"),
    ("<li>Exécution <b>séquentielle</b> (les restaurations HYCU durent des minutes chacune : comptez des heures pour des centaines de namespaces) ; <b>Arrêter</b> termine le namespace en cours ; <b>Reprendre</b> rejoue seulement les namespaces restants ou en échec — un namespace déjà recréé n'est jamais refait. Le journal (<code>_bulk_restore.json</code>) survit à un redémarrage ; la sauvegarde automatique est suspendue pendant le run.</li>",
     "<li><b>Sequential</b> execution (each HYCU restore takes minutes: expect hours for hundreds of namespaces); <b>Stop</b> finishes the current namespace; <b>Resume</b> replays only the remaining or failed namespaces — a namespace already recreated is never redone. The journal (<code>_bulk_restore.json</code>) survives a restart; the automatic backup is suspended during the run.</li>"),
    ("⚙ → Sources → <b>Stockage objet S3</b> : endpoint compatible S3 (Nutanix Objects, MinIO, AWS…), bucket, clés d'accès → <b>Tester &amp; connecter</b>.",
     "⚙ → Sources → <b>S3 object storage</b>: S3-compatible endpoint (Nutanix Objects, MinIO, AWS…), bucket, access keys → <b>Test &amp; connect</b>."),
    ("Cochez <b>Export automatique</b> : chaque sauvegarde réussie part aussi en <code>.zip</code> vers le bucket — le filet de sécurité vit hors du cluster.",
     "Tick <b>Automatic export</b>: every successful backup also goes as a <code>.zip</code> to the bucket — the safety net lives off-cluster."),
    ("Option <b>chiffrement</b> : les objets sont chiffrés avant l'envoi ; déchiffrement : <code>python3 hycu_k8s_nutanix.py --decrypt fichier.zip.enc</code>.",
     "Optional <b>encryption</b>: objects are encrypted before upload; decryption: <code>python3 hycu_k8s_nutanix.py --decrypt file.zip.enc</code>."),
    ("Rapport & supervision", "Report & monitoring"),
    ("Page <b>Tâches</b> → <b>Rapport HTML</b> (conformité : applications, RPO, santé des clusters, tâches) ou <b>CSV</b> (Excel).",
     "<b>Jobs</b> page → <b>HTML report</b> (compliance: applications, RPO, cluster health, jobs) or <b>CSV</b> (Excel)."),
    ("<code>GET /metrics</code> : métriques Prometheus (local uniquement) — outil actif, sauvegarde auto, clusters joignables, connexions.",
     "<code>GET /metrics</code>: Prometheus metrics (local only) — tool up, auto backup, reachable clusters, connections."),
    ("La <b>santé des clusters</b> est contrôlée périodiquement (pastilles dans Sources).",
     "<b>Cluster health</b> is checked periodically (dots in Sources)."),
    ("Sécurité en bref", "Security in short"),
    ("Serveur sur <b>127.0.0.1 uniquement</b>, anti-CSRF, mode simulation par défaut, confirmation du cluster avant toute action réelle, journal d'audit complet.",
     "Server on <b>127.0.0.1 only</b>, anti-CSRF, simulation mode by default, cluster confirmation before any real action, full audit log."),
    ("Identifiants et kubeconfigs : <b>mémoire de session</b> (verrouillés à chaque nouvelle session navigateur), coffre chiffré optionnel (phrase secrète maîtresse).",
     "Credentials and kubeconfigs: <b>session memory</b> (locked at each new browser session), optional encrypted vault (master passphrase)."),
    ("En mode Kubernetes, la frontière de sécurité est le <b>RBAC du namespace</b> de l'outil : qui peut faire un port-forward est opérateur.",
     "In Kubernetes mode, the security boundary is the tool's <b>namespace RBAC</b>: whoever can port-forward is an operator."),
    ("Dépannage express", "Quick troubleshooting"),
    ("<th>Symptôme</th><th>Piste</th>", "<th>Symptom</th><th>Lead</th>"),
    ("« Contexte : indisponible »</td><td>kubectl absent du PATH ou contexte non configuré (⚙ → Réglages).",
     "“Context: unavailable”</td><td>kubectl missing from PATH or context not configured (⚙ → Settings)."),
    ("« Namespace non autorisé »</td><td>Hors du filtre des namespaces (entonnoir) ou du sélecteur d'étiquettes.",
     "“Namespace not allowed”</td><td>Outside the namespace filter (funnel) or the label selector."),
    ("Les connexions redemandent le déverrouillage</td><td>Normal : nouvelle session navigateur = identifiants verrouillés. Saisissez la phrase du coffre.",
     "Connections ask to be unlocked again</td><td>Expected: new browser session = credentials locked. Enter the vault passphrase."),
    ("« Cluster « x » inconnu »</td><td>Cluster retiré ou session verrouillée : déverrouillez le coffre ou re-choisissez un cluster (barre du haut).",
     "“Cluster « x » unknown”</td><td>Cluster removed or session locked: unlock the vault or pick a cluster again (top bar)."),
    ("« Cette sauvegarde provient du cluster « x » »</td><td>Sélectionnez le cluster d'origine de la sauvegarde dans la barre du haut.",
     "“This backup comes from cluster « x »”</td><td>Select the backup's source cluster in the top bar."),
    ("Séquence « interrompue »</td><td>Lisez l'étape en échec dans le journal, corrigez, relancez (reprise idempotente).",
     "“Interrupted” sequence</td><td>Read the failing step in the log, fix, relaunch (idempotent resumption)."),
    ("Export S3 en 403</td><td>Clés refusées, ou horloge du serveur décalée (SigV4 exige une heure juste).",
     "S3 export fails with 403</td><td>Keys refused, or server clock skewed (SigV4 requires accurate time)."),
    (" · les ", " · showing the "),
    (" plus récentes affichées sur ", " most recent of "),
    (" · historique conservé ", " · history kept "),
    (" j (Réglages)", " d (Settings)"),
    ("Historique des tâches (jours ; 0 = illimité)", "Job history (days; 0 = unlimited)"),
    ('"Pas encore contrôlé"', '"Not checked yet"'),
    (">Gérer les clusters</a>", ">Manage clusters</a>"),
    ("Dossier absent : ", "Folder missing: "),
    (">disque presque plein<", ">disk almost full<"),
    ('"Disque rempli à "', '"Disk "'),
    ("% utilisé · ", "% used · "),
    (" libres sur ", " free of "),
    (" versions · ", " versions · "),
    ("<span class=\"k\">Journal d'audit</span>", "<span class=\"k\">Audit log</span>"),
    ("Plancher d'espace libre (Mo ; 0 = désactivé)", "Free-space floor (MB; 0 = disabled)"),
    ('<span class="k">Sauvegardes</span>', '<span class="k">Backups</span>'),
    ("Cette sauvegarde a été prise sur le contexte kubectl « ", "This backup was taken on kubectl context « "),
    ("Quota des sauvegardes (Go ; 0 = illimité)", "Backup quota (GB; 0 = unlimited)"),
    ("Sous le plancher, toute sauvegarde est refusée ; au-delà du quota, les plus anciennes sont purgées (la plus récente de chaque application est toujours gardée).",
     "Below the floor, every backup is refused; above the quota, the oldest are pruned (the most recent of each application is always kept)."),
    ("Garde-fou : sauvegarde refusée sous ", "Guardrail: backup refused below "),
    (" Mo libres.", " MB free."),
    ('"Quota dépassé : purge des plus anciennes au prochain passage"', '"Quota exceeded: oldest pruned at next pass"'),
    ('<span class="k">Quota</span>', '<span class="k">Quota</span>'),
    ("Espace disque insuffisant sous ", "Not enough disk space under "),
    (" Mo libres (plancher : ", " MB free (floor: "),
    # ---- Reprise d'activité (DR) + import S3 ----
    ("Restauration DR (autre cluster / contexte)", "DR restore (another cluster / context)"),
    ("Reprise d'activité : recrée une application sur CE cluster depuis une sauvegarde d'un cluster disparu (ou importée du bucket S3). Sources lues depuis la seule sauvegarde. Nécessite le réglage « Autoriser la restauration DR ».",
     "Disaster recovery: recreates an application on THIS cluster from a backup of a lost cluster (or imported from the S3 bucket). Sources read from the backup alone. Requires the “Allow DR restore” setting."),
    ("La <b>restauration DR</b> est désactivée. Activez « <b>Autoriser la restauration DR</b> » dans ⚙ → Réglages (le temps de l'exercice ou du sinistre), puis revenez ici.",
     "<b>DR restore</b> is disabled. Enable “<b>Allow DR restore</b>” in ⚙ → Settings (for the duration of the drill or disaster), then come back here."),
    ("Mode <b>reprise d'activité</b> : la garde inter-cluster est levée pour CETTE opération. Toutes les sources proviennent de la sauvegarde choisie ; le cluster cible est le <b>cluster actif</b> (",
     "<b>Disaster recovery</b> mode: the cross-cluster guard is lifted for THIS operation. Every source comes from the selected backup; the target is the <b>active cluster</b> ("),
    ("). Restaurez d'abord les Volume Groups dans HYCU vers le site cible, puis collez leurs UUID.",
     "). First restore the Volume Groups in HYCU to the target site, then paste their UUIDs."),
    ("Sauvegarde source (tous clusters / imports S3)", "Source backup (all clusters / S3 imports)"),
    ('<label class="fld">Namespace cible</label><input type="text" id="drTargetNs"', '<label class="fld">Target namespace</label><input type="text" id="drTargetNs"'),
    ("StorageClass cible (vide = inchangée)", "Target StorageClass (empty = unchanged)"),
    ("Recréer les dépendances depuis la sauvegarde (Secrets non masqués, ConfigMaps, ServiceAccounts, Services)",
     "Recreate dependencies from the backup (non-redacted Secrets, ConfigMaps, ServiceAccounts, Services)"),
    ("Volumes — collez l'UUID du VG restauré/cloné sur le site cible", "Volumes — paste the UUID of the VG restored/cloned on the target site"),
    ('"Restaurer (simulation)"', '"Restore (simulation)"'),
    ('"Restaurer (réel)"', '"Restore (real)"'),
    ("Restauration DR RÉELLE", "REAL DR restore"),
    ("Sauvegarde source : <b>", "Source backup: <b>"),
    ("Cluster CIBLE : <b>", "TARGET cluster: <b>"),
    ("</b> · namespace cible : <b>", "</b> · target namespace: <b>"),
    ("La garde inter-cluster est LEVÉE pour cette opération : l'application sera recréée sur ce cluster depuis la sauvegarde (PV/PVC, workloads, dépendances non masquées).",
     "The cross-cluster guard is LIFTED for this operation: the application will be recreated on this cluster from the backup (PV/PVC, workloads, non-redacted dependencies)."),
    ("Restauration DR…", "DR restore…"),
    (" · import S3", " · S3 import"),
    ("Aucun volume dans cette sauvegarde.", "No volume in this backup."),
    ("<b>Autoriser la restauration DR</b> (inter-cluster / inter-contexte)", "<b>Allow DR restore</b> (cross-cluster / cross-context)"),
    ("À activer le temps d'un exercice ou d'un sinistre. Chaque restauration DR reste explicite : sources lues depuis la seule sauvegarde, avertissement, re-saisie du cluster cible, audit dédié.",
     "Enable it for the duration of a drill or a disaster. Each DR restore stays explicit: sources read from the backup alone, warning, target cluster retyped, dedicated audit."),
    ("Importer depuis le bucket (reprise / DR)", "Import from the bucket (recovery / DR)"),
    ("Phrase de déchiffrement (objets .enc uniquement)", "Decryption passphrase (.enc objects only)"),
    ("Les exports rapatriés vont dans <code>hycu-backups/_imports/…</code> ; ils se restaurent via la <b>Restauration DR</b> de l'assistant (ou sur leur cluster d'origine).",
     "Repatriated exports go to <code>hycu-backups/_imports/…</code>; they are restored through the wizard's <b>DR restore</b> (or on their source cluster)."),
    ("Liste du bucket…", "Listing bucket…"),
    ('<th>Chiffré</th>', '<th>Encrypted</th>'),
    (" fichier(s)", " file(s)"),
    ('"Import S3 (rapatriement)"', '"S3 import (repatriation)"'),
    ('"Restauration d\'objets de configuration"', '"Configuration objects restore"'),
    (" » — aucune lecture du cluster d'origine.", " » — no read from the origin cluster."),
    ("StorageClass remappée vers « ", "StorageClass remapped to « "),
    (" » sur les PV/PVC recréés.", " » on the recreated PV/PVCs."),
    ("Instantané resources.json vide ou absent : seuls PV et PVC seront recréés.",
     "resources.json snapshot empty or missing: only PV and PVC will be recreated."),
    ("Restauration DR : choisissez une sauvegarde source.", "DR restore: choose a source backup."),
    # ---- Applications supprimées mais sauvegardées (récupération même cluster) ----
    ("Supprimée — restaurable", "Deleted — restorable"),
    ("Application supprimée (sauvegardes conservées)", "Deleted application (backups kept)"),
    # Applications dans les namespaces (stateful / stateless)
    ("volumes sans workload", "volumes without workload"),
    ('<h2 class="dtitle">Tâches</h2>', '<h2 class="dtitle">Jobs</h2>'),
    ("Restaurer le namespace", "Restore the namespace"),
    (">tout le namespace</a>", ">whole namespace</a>"),
    # Clone d'une application stateless
    ("Vérifier la copie", "Check the copy"),
    # Secrets sauvegardés (chiffrés / clair / masqués)
    ("Secrets sauvegardés EN CLAIR (aucune phrase de coffre disponible) : déverrouillez le coffre (⚙ → Sources) ou fournissez HYCU_VAULT_PASSPHRASE pour les chiffrer.",
     "Secrets backed up IN CLEAR (no vault passphrase available): unlock the vault (⚙ → Sources) or provide HYCU_VAULT_PASSPHRASE to encrypt them."),
    ("Secret chiffré — déverrouillez le coffre", "Secret encrypted — unlock the vault"),
    # Restauration en masse (même cluster)
    ('title="Recréer tous les namespaces supprimés du cluster actif depuis leurs sauvegardes"', 'title="Recreate every deleted namespace of the active cluster from its backups"'),
    ("<span>Restaurer en masse</span>", "<span>Bulk restore</span>"),
    ("<h2>Restauration en masse</h2>", "<h2>Bulk restore</h2>"),
    ("Recrée <b>tous les namespaces supprimés</b> du cluster actif (<b id=\"bulkCluster\"></b>) depuis leur dernière sauvegarde antérieure à l'instant de référence : namespace, PV/PVC, workloads, dépendances, Secrets (coffre déverrouillé), Volume Groups restaurés par HYCU s'ils ont disparu, applications stateless. Les namespaces <b>encore présents</b> sont ignorés : une application vivante se restaure depuis sa propre ligne. Exécution séquentielle et journalisée, reprise possible ; <b>simulation obligatoire</b> avant le réel.",
     "Recreates <b>every deleted namespace</b> of the active cluster (<b id=\"bulkCluster\"></b>) from its latest backup prior to the reference time: namespace, PV/PVC, workloads, dependencies, Secrets (vault unlocked), Volume Groups restored by HYCU if they are gone, stateless applications. Namespaces <b>still present</b> are skipped: a live application is restored from its own row. Sequential, journaled, resumable; <b>simulation is mandatory</b> before the real run."),
    ("Instant de référence</label>", "Reference time</label>"),
    ("Namespaces à exclure (virgules, optionnel)", "Namespaces to exclude (comma-separated, optional)"),
    (">Préparer le plan<", ">Prepare the plan<"),
    (">Arrêter<", ">Stop<"),
    (">Reprendre<", ">Resume<"),
    (">Simuler<", ">Simulate<"),
    (">Lancer (réel)<", ">Start (real)<"),
    ("Désactivez le bandeau Simulation pour lancer le réel.", "Turn off the Simulation banner to start the real run."),
    ("Simulez d'abord ce plan (sans échec).", "Simulate this plan first (without failure)."),
    ("Analyse des sauvegardes et du cluster…", "Analysing backups and cluster…"),
    (" namespace(s) à recréer sur <b>", " namespace(s) to recreate on <b>"),
    ("</b> · instant de référence ", "</b> · reference time "),
    (" avec avertissement</span>", " with a warning</span>"),
    (">coffre verrouillé<", ">vault locked<"),
    ("HYCU non connecté : les Volume Groups disparus ne seront pas restaurés", "HYCU not connected: vanished Volume Groups will not be restored"),
    ("<th>Sauvegarde</th><th>Contenu</th><th>Avertissements</th>", "<th>Backup</th><th>Content</th><th>Warnings</th>"),
    (">partielle<", ">partial<"),
    ("Aucun namespace supprimé avec une sauvegarde antérieure à l'instant de référence.", "No deleted namespace with a backup prior to the reference time."),
    (" namespace(s) ignoré(s)</summary>", " namespace(s) skipped</summary>"),
    ("Restauration en masse RÉELLE", "REAL bulk restore"),
    ("</b> namespace(s) seront RECRÉÉS sur <b>", "</b> namespace(s) will be RECREATED on <b>"),
    ("</b> depuis leurs sauvegardes.", "</b> from their backups."),
    ("Exécution séquentielle et journalisée ; les Volume Groups disparus seront restaurés par HYCU (opérations réelles).", "Sequential, journaled execution; vanished Volume Groups will be restored by HYCU (real operations)."),
    ("Les namespaces présents ne sont pas touchés.", "Present namespaces are left untouched."),
    ("Reprendre la restauration en masse (RÉEL)", "Resume the bulk restore (REAL)"),
    ("Les namespaces restants (en attente, arrêtés ou en échec) seront recréés ; ceux déjà recréés ne sont pas refaits.", "The remaining namespaces (pending, stopped or failed) will be recreated; those already recreated are not redone."),
    ('<span class="spin"></span> En cours', '<span class="spin"></span> Running'),
    ('"Arrêtée" : j.done ? (c.failed ? "Terminée avec échecs" : "Terminée") : "Interrompue"', '"Stopped" : j.done ? (c.failed ? "Finished with failures" : "Finished") : "Interrupted"'),
    (' échec(s)) · instant de référence ', ' failure(s)) · reference time '),
    ('" · démarrée "', '" · started "'),
    ("<th>Namespace</th><th>État</th><th>Détail</th>", "<th>Namespace</th><th>State</th><th>Detail</th>"),
    (" étape(s)</summary>", " step(s)</summary>"),
    ("Instant de référence invalide : « ", "Invalid reference time: « "),
    (" » (format AAAA-MM-JJTHH:MM).", " » (format YYYY-MM-DDTHH:MM)."),
    ("Liste des namespaces du cluster impossible (", "Cannot list the cluster's namespaces ("),
    (") : plan refusé par prudence.", "): plan refused out of caution."),
    ("exclu par l'opérateur", "excluded by the operator"),
    ("aucune sauvegarde antérieure à l'instant de référence", "no backup prior to the reference time"),
    ("présent sur le cluster — se restaure depuis sa propre ligne (Applications)", "present on the cluster — restore it from its own row (Applications)"),
    ("sauvegarde sans volume ni workload : rien à recréer", "backup without volume or workload: nothing to recreate"),
    ("sauvegarde PARTIELLE (un PV était illisible) : seule version antérieure à l'instant de référence", "PARTIAL backup (a PV was unreadable): only version prior to the reference time"),
    ("sans instantané de ressources : volumes seuls, workloads et dépendances à recréer à la main", "no resource snapshot: volumes only, workloads and dependencies to recreate by hand"),
    ("Secrets masqués dans cette sauvegarde : à recréer à la main après la restauration", "Secrets redacted in this backup: recreate them by hand after the restore"),
    ("Secrets chiffrés et coffre VERROUILLÉ : ils ne seront pas recréés — déverrouillez le coffre avant de lancer", "Secrets encrypted and vault LOCKED: they will not be recreated — unlock the vault before starting"),
    ("Une restauration en masse est déjà en cours.", "A bulk restore is already running."),
    ("Aucune restauration en masse en cours.", "No bulk restore is running."),
    ("Aucun journal à reprendre.", "No journal to resume."),
    ("Rien à reprendre : tous les namespaces du journal sont déjà recréés.", "Nothing to resume: every namespace of the journal is already recreated."),
    ("Ce journal est une simulation : lancez le réel depuis le plan, pas par reprise.", "This journal is a simulation: start the real run from the plan, not by resuming."),
    ("Rien à restaurer : aucun namespace supprimé avec une sauvegarde antérieure à l'instant de référence.", "Nothing to restore: no deleted namespace with a backup prior to the reference time."),
    ("Lancez d'abord une SIMULATION complète et sans échec de ce plan (mêmes namespaces, même instant de référence) avant le réel.", "First run a complete SIMULATION without failure of this plan (same namespaces, same reference time) before the real run."),
    ("Les <b>Secrets</b> de cette sauvegarde sont <b>masqués</b> : ils ne seront pas recréés (à recréer à la main après la restauration).",
     "The <b>Secrets</b> of this backup are <b>redacted</b>: they will not be recreated (recreate them by hand after the restore)."),
    ("Les <b>Secrets</b> de cette sauvegarde sont <b>chiffrés</b> avec la phrase du coffre : déverrouillez le coffre (⚙ → Sources) avant de lancer, sinon ils ne seront pas recréés.",
     "The <b>Secrets</b> of this backup are <b>encrypted</b> with the vault passphrase: unlock the vault (⚙ → Sources) before starting, otherwise they will not be recreated."),
    # Grands clusters
    (" (liste cluster-wide refusée ; repli par namespace non tenté au-delà de ", " (cluster-wide list refused; per-namespace fallback not attempted beyond "),
    (" namespaces — accordez un droit de liste cluster-wide)", " namespaces — grant a cluster-wide list permission)"),
    ('title="Page précédente"', 'title="Previous page"'),
    ("<li><b>Grands clusters</b> : chaque dossier de sauvegardes porte un catalogue <code>_catalog.json</code> (résumé dérivé, reconstruit s'il manque — la restauration lit toujours <code>index.json</code>), l'inventaire est mis en cache quelques dizaines de secondes (<b>Actualiser</b> force le recalcul), la page est paginée par 100 et un passage « tous les namespaces » lit les PV une fois et travaille en parallèle. Réglages : <code>apps_fallback_max</code>, <code>apps_cache_ttl_s</code>, <code>backup_parallel</code>.</li>",
     "<li><b>Large clusters</b>: each backup folder carries a <code>_catalog.json</code> catalog (derived summary, rebuilt if missing — restores always read <code>index.json</code>), the inventory is cached for a few dozen seconds (<b>Refresh</b> forces a recompute), the page is paginated by 100 and an “all namespaces” pass reads PVs once and works in parallel. Settings: <code>apps_fallback_max</code>, <code>apps_cache_ttl_s</code>, <code>backup_parallel</code>.</li>"),
    ('title="Page suivante"', 'title="Next page"'),
    ("Application stateless : aucun volume à choisir.", "Stateless application: no volume to choose."),
    ("</b> : <b>stateless</b>, aucun volume à restaurer. La copie recrée ses workloads (", "</b>: <b>stateless</b>, no volume to restore. The copy recreates its workloads ("),
    (") et leurs dépendances depuis le cluster.", ") and their dependencies from the cluster."),
    ("Lecture des workloads de « ", "Reading the workloads of « "),
    (" » impossible : ", " » failed: "),
    (" » introuvable dans le namespace « ", " » not found in namespace « "),
    (" » (aucun workload).", " » (no workload)."),
    (" » monte le(s) volume(s) ", " » mounts volume(s) "),
    (" : ce n'est pas une application stateless — sélectionnez ses volumes pour la cloner.", ": it is not a stateless application — select its volumes to clone it."),
    ("Application stateless « ", "Stateless application « "),
    (" » : aucun volume — seuls ses workloads (", " »: no volume — only its workloads ("),
    (") et leurs dépendances sont copiés.", ") and their dependencies are copied."),
    ("Aucun workload sans volume", "No workload without volume"),
    (" pour l'application « ", " for the application « "),
    (" » dans l'instantané de cette sauvegarde : rien à recréer.", " » in this backup's snapshot: nothing to recreate."),
    (" dans l'instantané de cette sauvegarde : rien à recréer.", " in this backup's snapshot: nothing to recreate."),
    ("Restaurer plutôt <b>tout le namespace « ", "Rather restore <b>the whole namespace « "),
    (" »</b> (toutes ses applications)</a>", " »</b> (all its applications)</a>"),
    ("Aucun PVC ni workload dans le namespace '", "No PVC nor workload in namespace '"),
    ("' : rien à sauvegarder.", "': nothing to back up."),
    ("Aucun volume sélectionné et aucun workload dans l'instantané de cette sauvegarde : rien à recréer.",
     "No volume selected and no workload in this backup's snapshot: nothing to recreate."),
    ("Sauvegarde sans volume (application stateless) : seuls les workloads et leurs dépendances sont recréés depuis l'instantané.",
     "Backup without volume (stateless application): only the workloads and their dependencies are recreated from the snapshot."),
    ("<b>Applications</b> : une ligne par <b>application</b> (un namespace peut en contenir plusieurs : les workloads sont regroupés par étiquette <code>app.kubernetes.io/instance</code>, <code>app.kubernetes.io/name</code> ou <code>app</code>), avec son namespace et son <b>type</b> : <b>Stateful</b> (monte des volumes) ou <b>Stateless</b> (configuration seule). Sélectionnez, puis agissez en haut à droite : <b>Sauvegarder · Restaurer · Définir la politique · Vérifier</b>. La sauvegarde reste <b>par namespace</b> (une seule recette cohérente) ; Restaurer cible l'application choisie. Bascule <b>Cluster actif / Tous les clusters</b> (regroupés par workspace NKP).",
     "<b>Applications</b>: one row per <b>application</b> (a namespace can hold several: workloads are grouped by the <code>app.kubernetes.io/instance</code>, <code>app.kubernetes.io/name</code> or <code>app</code> label), with its namespace and its <b>type</b>: <b>Stateful</b> (mounts volumes) or <b>Stateless</b> (configuration only). Select, then act at the top right: <b>Back up · Restore · Set Policy · Verify</b>. Backups stay <b>per namespace</b> (one consistent recipe); Restore targets the chosen application. <b>Active cluster / All clusters</b> toggle (grouped by NKP workspace)."),
    ("<b>Sauvegarder tous (filtrés)</b> : tous les namespaces autorisés d'un coup ; un namespace sans PVC <b>ni workload</b> est ignoré. Un namespace <b>stateless</b> (workloads sans volume) est sauvegardé : son instantané suffit à le restaurer.",
     "<b>Back up all (filtered)</b>: every allowed namespace at once; a namespace with no PVC <b>and no workload</b> is skipped. A <b>stateless</b> namespace (workloads without volume) is backed up: its snapshot is enough to restore it."),
    ("<div class=\"tip\"><b>Application stateless (sans volume) ?</b> Cliquez <b>Restaurer</b> sur sa ligne : l'assistant ne propose que deux parcours — <b>copie</b> (clone de ses workloads et dépendances, même namespace avec suffixe ou autre namespace, comme pour une application stateful) et <b>objets de configuration</b> (présélectionné) avec <b>ses</b> objets précochés (workloads, Services, ConfigMaps/Secrets référencés) — les autres applications du namespace ne sont pas touchées. Pour une application <b>stateful</b>, seuls <b>ses</b> volumes sont présélectionnés dans les parcours de stockage. <b>Tout le namespace</b> (ex. mariadb + wordpress découpés par leurs étiquettes) : cochez plusieurs applications du même namespace puis <b>Restaurer le namespace</b>, ou cliquez le lien « tout le namespace » dans l'assistant.</div>",
     "<div class=\"tip\"><b>Stateless application (no volume)?</b> Click <b>Restore</b> on its row: the wizard offers only two paths — <b>copy</b> (clone of its workloads and dependencies, same namespace with suffix or another namespace, as for a stateful application) and <b>configuration objects</b> (preselected) with <b>its</b> objects pre-ticked (workloads, Services, referenced ConfigMaps/Secrets) — the other applications of the namespace are left untouched. For a <b>stateful</b> application, only <b>its</b> volumes are preselected in the storage paths. <b>The whole namespace</b> (e.g. mariadb + wordpress split by their labels): tick several applications of the same namespace then <b>Restore the namespace</b>, or click the “whole namespace” link in the wizard.</div>"),
    ("Volume(s) absent(s) de la dernière sauvegarde : ", "Volume(s) missing from the latest backup: "),
    (" — relancez une sauvegarde", " — run a backup again"),
    (" sauvegarde(s) de configuration du namespace", " configuration backup(s) of the namespace"),
    ("(namespace entier)", "(whole namespace)"),
    ("· sans workload", "· no workload"),
    (">Vide<", ">Empty<"),
    ("</b> : <b>stateless</b> (aucun volume). Sa restauration = ré-appliquer ses objets de configuration (workloads, Services, ConfigMaps…) depuis l'instantané d'une sauvegarde — parcours <b>« objets de configuration »</b>, présélectionné.",
     "</b>: <b>stateless</b> (no volume). Restoring it = re-applying its configuration objects (workloads, Services, ConfigMaps…) from a backup snapshot — the <b>“configuration objects”</b> path, preselected."),
    ("</b> : <b>stateful</b> — ses volumes (", "</b>: <b>stateful</b> — its volumes ("),
    (") seront présélectionnés ; les autres volumes du namespace restent décochés.",
     ") will be preselected; the other volumes of the namespace stay unticked."),
    (" Seulement les objets de l'application", " Only the application's objects"),
    (" de l'application « ", " of the application « "),
    ("autre application / partagé", "other application / shared"),
    ("Sauvegarde <b>stateless</b> (aucun volume) : les workloads", "<b>Stateless</b> backup (no volume): the workloads"),
    (" et leurs dépendances seront recréés depuis l'instantané.", " and their dependencies will be recreated from the snapshot."),
    ("Namespace supprimé du cluster", "Namespace deleted from the cluster"),
    ("Restaurer l'application supprimée « ", "Restore the deleted application « "),
    ("Ce namespace n'existe plus sur le cluster <b id=\"drClusterRec\"></b> : l'application va être <b>recréée depuis sa sauvegarde</b> (namespace, PV/PVC, workloads, dépendances non masquées), en réutilisant ses volumes d'origine — ou, s'ils ont été supprimés avec le namespace, en les restaurant automatiquement depuis HYCU (« Protected deleted »). Dans le cas courant, rien à saisir : vérifiez la sauvegarde et lancez la restauration.",
     "This namespace no longer exists on cluster <b id=\"drClusterRec\"></b>: the application will be <b>recreated from its backup</b> (namespace, PV/PVC, workloads, non-redacted dependencies), reusing its original volumes — or, if they were deleted with the namespace, restoring them automatically from HYCU (“Protected deleted”). In the common case, nothing to enter: check the backup and start the restore."),
    ("Restauration d'une application SUPPRIMÉE", "Restore of a DELETED application"),
    ("L'application sera RECRÉÉE sur ce cluster depuis la sauvegarde (namespace, PV/PVC, workloads, dépendances non masquées).",
     "The application will be RECREATED on this cluster from the backup (namespace, PV/PVC, workloads, non-redacted dependencies)."),
    ("Réutiliser les volumes d'origine de l'application ", "Reuse the application's original volumes "),
    ("Rien à saisir : l'application est rebranchée sur ses volumes Nutanix d'origine (leurs identifiants sont dans la sauvegarde). Décochez seulement si vous avez restauré les données sur de <b>nouveaux</b> volumes dans HYCU.",
     "Nothing to enter: the application is reconnected to its original Nutanix volumes (their IDs are in the backup). Only untick if you restored the data onto <b>new</b> volumes in HYCU."),
    ("Nouveaux volumes — collez l'identifiant (UUID) fourni par HYCU", "New volumes — paste the ID (UUID) provided by HYCU"),
    ("Créer les volumes automatiquement via HYCU", "Create the volumes automatically via HYCU"),
    # (paires historiques conservées : certaines clés ne sont visibles qu'à l'exécution)
    ('Phrase secrète maîtresse', 'Master passphrase'),
    ('Sauvegarde &amp; restauration guidées · Nutanix', 'Guided backup &amp; restore · Nutanix'),
    ('Contexte kubectl : ', 'kubectl context: '),
    ('title="Version de la build"', 'title="Build version"'),
    ('>1 · Sauvegarder<', '>1 · Back up<'),
    ('>2 · Restaurer<', '>2 · Restore<'),
    ('>3 · Vérifier<', '>3 · Verify<'),
    ('>Connexions<', '>Connections<'),
    ('>⚙ Réglages<', '>⚙ Settings<'),
    ("Cochez le(s) PVC à restaurer. Plusieurs volumes d'une même application sont", 'Tick the PVC(s) to restore. Several volumes of the same application are'),
    ('restaurés en une seule transaction (arrêt unique, redémarrage unique).', 'restored in a single transaction (one stop, one restart).'),
    ('Manifestes PV/PVC utilisés (le « squelette »). Indépendant du point de restauration HYCU des <b>données</b>. Par défaut : la plus récente.', 'PV/PVC manifests used (the “skeleton”). Independent of the HYCU restore point for the <b>data</b>. Default: the most recent.'),
    ("Type d'opération HYCU (pour tout le lot)", 'HYCU operation type (for the whole batch)'),
    ('Indiquer le(s) Volume Group(s) restauré(s)', 'Identify the restored Volume Group(s)'),
    ('Choisissez un point de restauration HYCU par volume (bouton « Point de restauration HYCU » ci-dessus),', 'Choose one HYCU restore point per volume (“HYCU restore point” button above),'),
    ('puis lancez : <b>arrêt → restore in-place → redémarrage</b>. Aucune référence à saisir ni recréation de PV/PVC.', 'then launch: <b>stop → in-place restore → restart</b>. No reference to enter, no PV/PVC recreation.'),
    ('Flux manuel (avancé) — si vous avez déjà restauré/cloné le VG dans HYCU vous-même', 'Manual flow (advanced) — if you already restored/cloned the VG in HYCU yourself'),
    ('Prévisualiser le plan', 'Preview the plan'),
    ('(réf. VG)', '(VG ref.)'),
    ("<b>Restauration sur place (recommandé) :</b> sur chaque volume, cliquez « Point de restauration HYCU » et choisissez le point, puis « <b>Lancer la restauration sur place</b> » ci-dessous. <span class='hint'>Aucune référence à saisir.</span>", "<b>In-place restore (recommended):</b> on each volume, click “HYCU restore point” and pick the point, then “<b>Launch the in-place restore</b>” below. <span class='hint'>No reference to enter.</span>"),
    ("<b>Restauration sur place — flux manuel :</b> restaurez le VG dans HYCU, renseignez la référence du VG (UUID) par volume, puis « <b>Prévisualiser le plan</b> ». <span class='hint'>Connectez HYCU pour le flux orchestré.</span>", "<b>In-place restore — manual flow:</b> restore the VG in HYCU, fill in the VG reference (UUID) per volume, then “<b>Preview the plan</b>”. <span class='hint'>Connect HYCU for the orchestrated flow.</span>"),
    ("<b>Clone d'application — 2 étapes :</b> <b>(A)</b> sur chaque volume, « ⚙ Orchestrer depuis HYCU (clone) » → crée le VG cloné et récupère sa référence. <b>(B)</b> quand tous les volumes ont leur référence, « <b>Prévisualiser le plan</b> » puis « <b>Lancer le clone de l'application</b> » crée la copie (namespace, PV/PVC, workloads, dépendances).", '<b>Application clone — 2 steps:</b> <b>(A)</b> on each volume, “⚙ Orchestrate from HYCU (clone)” → creates the cloned VG and fetches its reference. <b>(B)</b> once every volume has its reference, “<b>Preview the plan</b>” then “<b>Launch the application clone</b>” creates the copy (namespace, PV/PVC, workloads, dependencies).'),
    ("<b>Clone d'application — flux manuel :</b> <b>(A)</b> clonez le VG de chaque volume dans HYCU et collez sa référence (UUID). <b>(B)</b> « <b>Prévisualiser le plan</b> » puis « <b>Lancer le clone de l'application</b> ». <span class='hint'>Connectez HYCU pour cloner et récupérer la référence automatiquement.</span>", "<b>Application clone — manual flow:</b> <b>(A)</b> clone each volume's VG in HYCU and paste its reference (UUID). <b>(B)</b> “<b>Preview the plan</b>” then “<b>Launch the application clone</b>”. <span class='hint'>Connect HYCU to clone and fetch the reference automatically.</span>"),
    ("<b>Clone (rattacher à l'app existante) :</b> sur chaque volume, « ⚙ Orchestrer depuis HYCU (clone) » → VG cloné + référence, puis « <b>Prévisualiser le plan</b> » → « <b>Lancer le clone</b> ».", '<b>Clone (reattach to the existing app):</b> on each volume, “⚙ Orchestrate from HYCU (clone)” → cloned VG + reference, then “<b>Preview the plan</b>” → “<b>Launch the clone</b>”.'),
    ("<b>Clone (rattacher) — flux manuel :</b> clonez le VG dans HYCU, collez la référence (UUID) par volume, puis « <b>Prévisualiser le plan</b> » → « <b>Lancer le clone</b> ». <span class='hint'>Connectez HYCU pour automatiser.</span>", "<b>Clone (reattach) — manual flow:</b> clone the VG in HYCU, paste the reference (UUID) per volume, then “<b>Preview the plan</b>” → “<b>Launch the clone</b>”. <span class='hint'>Connect HYCU to automate.</span>"),
    ('Nom du nouveau PV (modifiable)', 'New PV name (editable)'),
    ('⚙ Orchestrer depuis HYCU (clone)', '⚙ Orchestrate from HYCU (clone)'),
    ('Point de restauration HYCU', 'HYCU restore point'),
    ('Saisie manuelle / avancé — référence du Volume Group', 'Manual entry / advanced — Volume Group reference'),
    ('Référence du Volume Group restauré/cloné — UUID du VG ', 'Reference of the restored/cloned Volume Group — VG UUID '),
    ('(uniquement pour le flux manuel)', '(manual flow only)'),
    ('Aucun Volume Group HYCU associé à ce PVC. Vérifiez la connexion HYCU / la correspondance (onglet Sauvegarder).', 'No HYCU Volume Group matched to this PVC. Check the HYCU connection / the mapping (Back up tab).'),
    ('Aucun Volume Group HYCU associé à ce PVC.', 'No HYCU Volume Group matched to this PVC.'),
    ('>aucun point<', '>no points<'),
    ('VG HYCU : <b>', 'HYCU VG: <b>'),
    ('Suffixe horodaté = nom unique à chaque clone (modifiable).', 'Timestamped suffix = unique name for each clone (editable).'),
    ("'Cloner dans HYCU':'Restaurer dans HYCU'", "'Clone in HYCU':'Restore in HYCU'"),
    (' puis récupérer la réf. du VG<', ' then fetch the VG ref.<'),
    ('Choisissez un point de restauration.', 'Choose a restore point.'),
    ('Opération HYCU RÉELLE', 'REAL HYCU operation'),
    ('"Déclencher dans HYCU le <b>"', '"Trigger in HYCU the <b>"'),
    ('"clone":"restore sur place"', '"clone":"in-place restore"'),
    ('"</b> de ce Volume Group ?"', '"</b> of this Volume Group?"'),
    ('Job HYCU lancé : ', 'HYCU job started: '),
    ('Job HYCU non identifié — impossible de confirmer la fin du clone. Récupérez la réf. du VG via « Rechercher le VG dans Prism » une fois le clone terminé dans HYCU.', 'HYCU job not identified — cannot confirm the clone completion. Fetch the VG ref. via “Search for the VG in Prism” once the clone finishes in HYCU.'),
    ("Le job HYCU n\\'a pas abouti — référence du VG non récupérée.", 'The HYCU job did not succeed — VG reference not fetched.'),
    ("Opération HYCU terminée. Connectez Nutanix (Prism) pour récupérer la réf. du VG automatiquement, sinon utilisez « Rechercher le VG dans Prism » ou collez l\\'UUID du VG.", 'HYCU operation finished. Connect Nutanix (Prism) to fetch the VG ref. automatically, otherwise use “Search for the VG in Prism” or paste the VG UUID.'),
    ("Récupération de l\\'UUID du VG cloné depuis Nutanix…", 'Fetching the cloned VG UUID from Nutanix…'),
    (' » introuvable côté Nutanix — récupérez la réf. manuellement via « Rechercher le VG dans Prism ».', ' » not found on Nutanix — fetch the ref. manually via “Search for the VG in Prism”.'),
    ("?'Aucun':'Plusieurs'} VG nommé(s) exactement « ", "?'No':'Multiple'} VG named exactly « "),
    (' » côté Nutanix — récupérez la réf. manuellement via « Rechercher le VG dans Prism » pour choisir le bon.', ' » on Nutanix — fetch the ref. manually via “Search for the VG in Prism” to pick the right one.'),
    ('VG trouvé mais UUID non exposé — récupérez la réf. manuellement.', 'VG found but UUID not exposed — fetch the ref. manually.'),
    ('Référence du VG (UUID <code>', 'VG reference (UUID <code>'),
    ('</code>) remplie automatiquement depuis « ', '</code>) auto-filled from « '),
    (' ». Cliquez « Prévisualiser le plan ».', ' ». Click “Preview the plan”.'),
    ('Sélectionner ce point', 'Select this point'),
    ('✓ sélectionné', '✓ selected'),
    ('Cluster cible (contexte kubectl)', 'Target cluster (kubectl context)'),
    ('Contextes autorisés (séparés par des virgules ; vide = tous)', 'Allowed contexts (comma-separated; empty = all)'),
    ('Namespaces autorisés (vide = tous)', 'Allowed namespaces (empty = all)'),
    ('Option : enregistrer les identifiants saisis ci-dessus dans un coffre <b>chiffré</b>', 'Optional: store the credentials entered above in an <b>encrypted</b> vault'),
    (" — soit Prism Central n'est pas connecté, soit ce Volume Group n'existe plus (supprimé avec le namespace). Dans ce cas, décochez « réutiliser les volumes d'origine » et utilisez « Créer les volumes automatiquement via HYCU ». PV non recréé pour éviter un volume non attachable", ' — either Prism Central is not connected, or this Volume Group no longer exists (deleted with the namespace). In that case, untick “reuse the original volumes” and use “Create the volumes automatically via HYCU”. PV not recreated to avoid an unattachable volume'),
    ('Disque du VG cloné introuvable pour « ', 'Cloned VG disk not found for « '),
    (' » (Prism Central requis) — ', ' » (Prism Central required) — '),
    ('elles sont protégées par HYCU (voir « ', 'they are protected by HYCU (see « '),
    (' » ci-dessous).', ' » below).'),
    ('" h · conserve les "', '" h · keeps the last "'),
    ('" dernières versions par namespace."', '" versions per namespace."'),
    ('À propos de cet outil', 'About this tool'),
    ('Cluster Kubernetes ciblé (contexte kubectl) — cliquer pour le changer', 'Target Kubernetes cluster (kubectl context) — click to change it'),
    ('Sources (HYCU, Prism Central, Prism Element)', 'Sources (HYCU, Prism Central, Prism Element)'),
    ('<span class="nl">Réglages</span>', '<span class="nl">Settings</span>'),
    ('<h2 class="dtitle">Politique ', '<h2 class="dtitle">Policy '),
    ('<h2 class="dtitle">Tâches ', '<h2 class="dtitle">Jobs '),
    ('>Contexte kubectl</div>', '>kubectl context</div>'),
    ('<td>Application Kubernetes</td>', '<td>Kubernetes application</td>'),
    (' versions</td>', ' versions</td>'),
    ("Enregistrez ici les systèmes utilisés par l'outil. Les identifiants restent en mémoire le temps de la session (ou dans le coffre chiffré si vous le choisissez).", 'Register here the systems used by the tool. Credentials stay in memory for the session (or in the encrypted vault if you choose it).'),
    ('Sources (HYCU, Prism Central, Prism Element, clusters Kubernetes)', 'Sources (HYCU, Prism Central, Prism Element, Kubernetes clusters)'),
    ('"Cluster introuvable."', '"Cluster not found."'),
    ('" » accessible."', '" » reachable."'),
    ("Aucune sauvegarde pour ce namespace — lancez d'abord une sauvegarde (Applications → Sauvegarder).", 'No backup for this namespace — run a backup first (Applications → Back up).'),
    ("Comparaison avec l'état live…", 'Comparing with the live state…'),
    ('" — sauvegarde"', '" — backup"'),
    ('+++ sauvegarde', '+++ backup'),
    ('--- live', '--- live'),
    ('<b>activée</b>sauvegarde automatique</span>', '<b>enabled</b>automatic backup</span>'),
    ('<b>désactivée</b>sauvegarde automatique</span>', '<b>disabled</b>automatic backup</span>'),
    ('Stockage objet S3 : activé (chiffré).', 'S3 object storage: enabled (encrypted).'),
    ('Stockage objet S3 : activé.', 'S3 object storage: enabled.'),
    ('Stockage objet S3 : configuré, export auto désactivé.', 'S3 object storage: configured, auto export disabled.'),
    ('Stockage objet S3 : non configuré.', 'S3 object storage: not configured.'),
    ('automatique activée, intervalle ', 'backup enabled, interval '),
    ('automatique désactivée, intervalle ', 'backup disabled, interval '),
    ('>joignable<', '>reachable<'),
    ('Restaurer — les 4 parcours', 'Restore — the 4 flows'),
    ('">Stockage <', '">Storage <'),
    ('">Santé des clusters <', '">Cluster health <'),
    ('UUID du Volume Group restauré sur le site cible (8-4-4-4-12)', 'UUID of the Volume Group restored on the target site (8-4-4-4-12)'),
    ("Restauration DR terminée. Vérifiez l'application, puis re-protégez ses Volume Groups dans HYCU.", 'DR restore finished. Verify the application, then re-protect its Volume Groups in HYCU.'),
    ("Aucun export de l'outil dans ce bucket.", 'No export from this tool in that bucket.'),
    ("<b>Application supprimée du cluster ?</b> Tant que ses sauvegardes existent, elle reste listée dans <b>Applications</b> avec le badge « Supprimée — restaurable ». Cliquez <b>Restaurer</b> : le parcours de récupération recrée tout (namespace, PV/PVC, workloads, dépendances non masquées) depuis la sauvegarde choisie — restaurez d'abord ses Volume Groups dans HYCU et collez leurs UUID. Aucune dérogation DR n'est requise : la récupération reste sur le même cluster/contexte.", '<b>Application deleted from the cluster?</b> As long as its backups exist, it stays listed under <b>Applications</b> with the “Deleted — restorable” badge. Click <b>Restore</b>: the recovery flow recreates everything (namespace, PV/PVC, workloads, non-redacted dependencies) from the selected backup — first restore its Volume Groups in HYCU and paste their UUIDs. No DR override is required: the recovery stays on the same cluster/context.'),
    # ---- correctifs (lots 1-3) : nouveaux messages serveur/UI ----
    (" inconnu (retiré, ou session verrouillée) : sélectionnez un cluster dans la barre du haut. Aucune commande n'a été exécutée.", ' unknown (removed, or session locked): select a cluster in the top bar. No command was executed.'),
    (" ») : cette commande doit être installée là où tourne l'outil (absente de l'image conteneur par défaut) ; elle peut aussi ouvrir un navigateur (OIDC) que l'outil ne peut pas piloter.", ' »): this command must be installed where the tool runs (absent from the default container image); it may also open a browser (OIDC) that the tool cannot drive.'),
    (') : mécanisme déprécié, jeton OIDC à durée de vie courte — prévoyez un jeton de ServiceAccount pour un usage durable.', '): deprecated mechanism, short-lived OIDC token — use a ServiceAccount token for long-term use.'),
    ("Connexion établie, mais la liste des namespaces est refusée (RBAC) : l'outil ne verra que les namespaces explicitement autorisés.", 'Connected, but listing namespaces is forbidden (RBAC): the tool will only see explicitly allowed namespaces.'),
    ('Le cluster actif ne semble pas être un cluster de management NKP (ressource Workspace introuvable ou accès refusé) : ', 'The active cluster does not look like an NKP management cluster (Workspace resource not found or access denied): '),
    ('Kubeconfig refusé : authentification par plugin exec (commande externe) non autorisée pour un kubeconfig importé automatiquement.', 'Kubeconfig refused: exec plugin authentication (external command) is not allowed for an automatically imported kubeconfig.'),
    (" ». La restauration inter-clusters n'est pas prise en charge : sélectionnez le cluster d'origine dans la barre du haut.", ' ». Cross-cluster restore is not supported: select the source cluster in the top bar.'),
    ('Vérifiez le dossier de sauvegardes (Avancé) puis resélectionnez la sauvegarde.', 'Check the backups folder (Advanced) then reselect the backup.'),
    (") — restauration annulée : sans lui, l'application ne serait ni arrêtée proprement ni redémarrée.", ') — restore cancelled: without it, the application would be neither stopped cleanly nor restarted.'),
    ("L'échec d'un export n'échoue jamais la sauvegarde locale (visible dans les Tâches).", 'A failed export never fails the local backup (visible in Jobs).'),
    ('Chiffrement activé : choisissez une phrase de chiffrement des exports (elle servira aussi au déchiffrement — conservez-la précieusement).', 'Encryption enabled: choose an export encryption passphrase (also needed for decryption — keep it safe).'),
    ('chiffrement activé mais phrase de chiffrement absente : renseignez-la dans ⚙ Sources > Stockage objet S3', 'encryption enabled but encryption passphrase missing: enter it in ⚙ Sources > S3 object storage'),
    ("Cette sauvegarde ne contient pas d'instantané de ressources (resources.json) : elle est antérieure à la fonction, ou config_backup_full était désactivé.", 'This backup has no resource snapshot (resources.json): it predates the feature, or config_backup_full was disabled.'),
    (' », alors que le contexte actif est « ', ' », while the active context is « '),
    (" ». Rebasculez sur le contexte d'origine (Réglages) avant de restaurer.", ' ». Switch back to the original context (Settings) before restoring.'),
    (" Mo). Sauvegarde REFUSÉE pour ne pas saturer le stockage — libérez de la place, réduisez la rétention (Politiques) ou l'historique des tâches (Réglages).", ' MB). Backup REFUSED to avoid filling the storage — free some space, reduce retention (Policies) or the job history (Settings).'),
    ('MODE DR : toutes les sources (workloads, dépendances) proviennent de la sauvegarde « ', 'DR MODE: every source (workloads, dependencies) comes from backup « '),
    ("Référencé(s) par l'app mais absent(s) de la SAUVEGARDE (ou Secret masqué) — à recréer à la main dans « ", 'Referenced by the app but absent from the BACKUP (or redacted Secret) — recreate manually in « '),
    ("Restauration DR refusée : le réglage « Autoriser la restauration DR » est désactivé (⚙ → Réglages). Activez-le le temps de l'opération, puis réessayez.", 'DR restore refused: the “Allow DR restore” setting is disabled (⚙ → Settings). Enable it for the operation, then retry.'),
    ('Récupération « depuis la sauvegarde seule » : workloads et dépendances proviennent de la sauvegarde « ', 'Recovery “from the backup alone”: workloads and dependencies come from backup « '),
    ('Simulation : HYCU restaurera le Volume Group sur place (identité conservée) — aucune restauration réelle lancée.', 'Simulation: HYCU will restore the Volume Group in place (identity preserved) — no real restore launched.'),
    ("aucun point de restauration HYCU trouvé pour ce Volume Group. Vérifiez que l'application est (ou était) protégée dans HYCU.", 'no HYCU restore point found for this Volume Group. Check that the application is (or was) protected in HYCU.'),
    (' introuvable sur le cluster — restauration automatique depuis HYCU (« Protected deleted »).', ' not found on the cluster — automatic restore from HYCU (“Protected deleted”).'),
    (" : le volume d'origine n'existe plus et sa restauration automatique via HYCU a échoué : ", ': the original volume no longer exists and its automatic restore via HYCU failed: '),
    (" » (le namespace n'existe plus sur le cluster).", ' » (the namespace no longer exists on the cluster).'),
    ("Cette sauvegarde ne contient pas d'instantané de ressources : seuls les volumes (PV/PVC) sont restaurés. Recréez les workloads et dépendances depuis une sauvegarde plus récente, ou manuellement.", 'This backup has no resource snapshot: only the volumes (PV/PVC) are restored. Recreate the workloads and dependencies from a more recent backup, or manually.'),
    ('<h2 class="dtitle">Santé des clusters</h2>', '<h2 class="dtitle">Cluster health</h2>'),
    ('" j / "', '" d / "'),
    ('>recommandé<', '>recommended<'),
    ("Aucun volume à provisionner.", "No volume to provision."),
    ("Aucun volume à restaurer.", "No volume to restore."),
    (" : restauration HYCU refusée : ", ": HYCU restore refused: "),
    (" : clone HYCU refusé : ", ": HYCU clone refused: "),
    ("Impossible de vérifier l'existence du namespace « ", "Cannot verify that namespace « "),
    ("Référence invalide pour ", "Invalid reference for "),
    ("Référence identique au VG SOURCE pour ", "Reference identical to the SOURCE VG for "),
    ("Sauvegarde PARTIELLE de « ", "PARTIAL backup of « "),
    (" » : manifeste de PV illisible pour ", " »: PV manifest unreadable for "),
    ("REDÉMARRAGE INCOMPLET", "INCOMPLETE RESTART"),
    ("Volumes restaurés mais redémarrage incomplet — relancez à la main : ",
     "Volumes restored but restart incomplete — restart manually: "),
    (" non lié (aucun volumeHandle observé)", " not bound (no volumeHandle observed)"),
    ("archive rejetée : taille décompressée annoncée ", "archive rejected: announced uncompressed size "),
    ("archive rejetée : contenu décompressé supérieur à ", "archive rejected: uncompressed content larger than "),
    ("En-tête Content-Length invalide.", "Invalid Content-Length header."),
    ("Pré-vol impossible (liste des PV : ", "Pre-flight impossible (PV list: "),
    (") — rien n'a été créé.", ") — nothing was created."),
    ("Volume Group ", "Volume Group "),
    (" déjà pointé par le PV ", " already pointed to by PV "),
    ("PV de ", "PV of "),
    (" re-pointé sur le VG cloné par HYCU", " re-pointed to the VG cloned by HYCU"),
    (" » — rien n'a été créé.", " » — nothing was created."),
    ("Volume Group du volume « ", "Volume Group of volume « "),
    ("disque introuvable pour le Volume Group de ", "disk not found for the Volume Group of "),
    ("illimitée (pas de compteur)", "unlimited (no counter)"),
    ("Les nouveaux identifiants seront inscrits automatiquement dans la grille.", "The new IDs will be filled into the grid automatically."),
    ("Si un volume d'origine a disparu du cluster, HYCU le RESTAURERA automatiquement (opération HYCU réelle) avant la recréation.",
     "If an original volume has disappeared from the cluster, HYCU will RESTORE it automatically (real HYCU operation) before the recreation."),
    ("Référence provisoire (VG source) inscrite pour la simulation — remplacée par le VG cloné en réel.",
     "Provisional reference (source VG) filled in for the simulation — replaced by the cloned VG in real mode."),
    ("Rétention avant sauvegarde : ", "Retention before backup: "),
    ("Simulation du clone automatique via HYCU (aucun clone réel lancé).",
     "Simulation of the automatic clone via HYCU (no real clone launched)."),
    ("Restauration HYCU (sur place) lancée pour ", "HYCU restore (in place) started for "),
    ("Le VG est recréé à son UUID d'origine : ", "The VG is recreated at its original UUID: "),
    ("Volume Group restauré à son identité d'origine pour ", "Volume Group restored to its original identity for "),
    ("UUID conservé : ", "UUID preserved: "),
    ("Identité HYCU du VG résolue pour ", "VG HYCU identity resolved for "),
    ("Volume d'origine de ", "Original volume of "),
    (" : source HYCU ", ": HYCU source "),
    (" (identité HYCU résolue depuis ", " (HYCU identity resolved from "),
    (", point de restauration ", ", restore point "),
    (", nouveau VG ", ", new VG "),
    ("HYCU clone les Volume Groups et l'outil récupère les nouveaux identifiants — aucune saisie. En simulation, seul le plan est affiché.",
     "HYCU clones the Volume Groups and the tool retrieves the new IDs — nothing to enter. In simulation, only the plan is shown."),
    ("UUID du VG source absent de la sauvegarde : automatisation impossible, saisissez les UUID manuellement.",
     "Source VG UUID missing from the backup: automation not possible, enter the UUIDs manually."),
    ("HYCU : création des volumes…", "HYCU: creating the volumes…"),
    ("UUID du Volume Group (8-4-4-4-12)", "Volume Group UUID (8-4-4-4-12)"),
    ("UUID du VG restauré/cloné sur le site cible (8-4-4-4-12)", "UUID of the VG restored/cloned on the target site (8-4-4-4-12)"),
    ("Cette sauvegarde ne contient <b>que les volumes</b> (pas d'instantané des workloads/dépendances) : elle est antérieure à cette fonction, ou la sauvegarde de config étendue était désactivée. La restauration recréera <b>les volumes (PV/PVC)</b> ; recréez les workloads depuis une sauvegarde plus récente ou manuellement.",
     "This backup contains <b>only the volumes</b> (no snapshot of workloads/dependencies): it predates this feature, or extended config backup was disabled. The restore will recreate <b>the volumes (PV/PVC)</b>; recreate the workloads from a more recent backup or manually."),
    ("Nom de StorageClass cible invalide : « ", "Invalid target StorageClass name: « "),
    ("Restauration DR : ", "DR restore: "),
    ("Liste du bucket impossible : ", "Cannot list the bucket: "),
    ("Réponse du bucket illisible (XML) : ", "Unreadable bucket response (XML): "),
    ("l'objet n'est pas un zip valide (mauvaise phrase de déchiffrement ?)", "the object is not a valid zip (wrong decryption passphrase?)"),
    ("archive rejetée : chemin hors zone (« ", "archive rejected: path outside the target area (« "),
    ("objet chiffré : renseignez la phrase de déchiffrement", "encrypted object: provide the decryption passphrase"),
    ("déchiffrement impossible (phrase incorrecte ou objet altéré)", "decryption failed (wrong passphrase or corrupted object)"),
    ("clé invalide", "invalid key"),
    ("Aucun export importé.", "No export imported."),
    # aide (nouvelles entrées)
    ("<b>Importer depuis le bucket</b> (même carte) : rapatrie des exports vers <code>hycu-backups/_imports/…</code> — le chemin retour, indispensable en reprise d'activité.",
     "<b>Import from the bucket</b> (same card): repatriates exports to <code>hycu-backups/_imports/…</code> — the return path, essential for disaster recovery."),
    ("Reprise d'activité (DR)", "Disaster recovery (DR)"),
    ("<b>Application supprimée du cluster ?</b> Tant que ses sauvegardes existent, elle reste listée dans <b>Applications</b> avec le badge « Supprimée — restaurable ». Cliquez <b>Restaurer</b> : le parcours de récupération recrée tout (namespace, PV/PVC, workloads, dépendances non masquées) depuis la sauvegarde choisie, en <b>réutilisant les volumes d'origine</b> — rien à saisir. Si un Volume Group a été supprimé avec le namespace mais reste « Protected deleted » dans HYCU, il est <b>restauré automatiquement</b> (HYCU connecté). Décochez « réutiliser » seulement si vous avez restauré les données sur de nouveaux volumes. Aucune dérogation DR n'est requise : la récupération reste sur le même cluster/contexte.",
     "<b>Application deleted from the cluster?</b> As long as its backups exist, it stays listed under <b>Applications</b> with the “Deleted — restorable” badge. Click <b>Restore</b>: the recovery flow recreates everything (namespace, PV/PVC, workloads, non-redacted dependencies) from the selected backup, <b>reusing the original volumes</b> — nothing to enter. If a Volume Group was deleted with the namespace but remains “Protected deleted” in HYCU, it is <b>restored automatically</b> (HYCU connected). Untick “reuse” only if you restored the data onto new volumes. No DR override is required: the recovery stays on the same cluster/context."),
    ("Namespace détruit, application absente ?</td><td>Elle reste listée tant qu'une sauvegarde existe (badge « Supprimée — restaurable ») : bouton Restaurer → récupération depuis la sauvegarde.",
     "Namespace destroyed, application gone?</td><td>It stays listed as long as a backup exists (“Deleted — restorable” badge): Restore button → recovery from the backup."),
    ("<b>Préparez le retour</b> : activez l'export S3 automatique (chiffré de préférence) — le filet de sécurité doit vivre hors du cluster. Gardez en lieu sûr : <code>hycu_config.json</code>, <code>hycu_secrets.enc</code>, la phrase du coffre et celle des exports (kit DR).",
     "<b>Prepare the way back</b>: enable the automatic S3 export (preferably encrypted) — the safety net must live off-cluster. Keep safe: <code>hycu_config.json</code>, <code>hycu_secrets.enc</code>, the vault passphrase and the export passphrase (DR kit)."),
    ("<b>Le jour J</b> : relancez l'outil (poste ou cluster de secours), reconnectez HYCU/Prism, ajoutez le cluster CIBLE (⚙ → Sources) et rendez-le actif. Rapatriez les sauvegardes : carte S3 → <b>Importer depuis le bucket</b>.",
     "<b>On the day</b>: relaunch the tool (workstation or standby cluster), reconnect HYCU/Prism, add the TARGET cluster (⚙ → Sources) and make it active. Repatriate the backups: S3 card → <b>Import from the bucket</b>."),
    ("<b>Restaurez les données</b> : dans HYCU, restaurez/clonez les Volume Groups de l'application vers le site cible, et notez leurs UUID.",
     "<b>Restore the data</b>: in HYCU, restore/clone the application's Volume Groups to the target site, and note their UUIDs."),
    ("<b>Activez la dérogation</b> : ⚙ → Réglages → <b>Autoriser la restauration DR</b> (le temps de l'opération).",
     "<b>Enable the override</b>: ⚙ → Settings → <b>Allow DR restore</b> (for the duration of the operation)."),
    ("<b>Sans saisie (HYCU connecté)</b> : le bouton <b>« Créer les volumes automatiquement via HYCU »</b> clone les Volume Groups depuis leurs sauvegardes HYCU et inscrit tout seul les nouveaux identifiants — plus aucun UUID à recopier. En simulation, seul le plan est affiché.",
     "<b>No manual entry (HYCU connected)</b>: the <b>“Create the volumes automatically via HYCU”</b> button clones the Volume Groups from their HYCU backups and fills in the new IDs itself — no UUID to copy anymore. In simulation, only the plan is shown."),
    ("<b>Assistant → Restauration DR</b> : choisissez la sauvegarde source (cluster disparu ou import S3), le namespace cible, collez l'UUID de chaque VG restauré, remappez la StorageClass si le site cible en utilise une autre — simulation d'abord, puis réel (re-saisie du cluster cible).",
     "<b>Wizard → DR restore</b>: pick the source backup (lost cluster or S3 import), the target namespace, paste each restored VG's UUID, remap the StorageClass if the target site uses another one — simulation first, then real (target cluster retyped)."),
    ("<b>Après</b> : vérifiez l'application, re-protégez ses Volume Groups dans HYCU, désactivez la dérogation DR.",
     "<b>Afterwards</b>: verify the application, re-protect its Volume Groups in HYCU, disable the DR override."),
    ("Tout le reste du temps, laissez « Autoriser la restauration DR » désactivé : la garde inter-cluster/contexte protège contre les restaurations croisées accidentelles. Un Secret masqué à la sauvegarde n'est jamais restauré : re-provisionnez-le depuis sa source. Un Secret <b>chiffré</b> est recréé dès que le coffre est déverrouillé.",
     "The rest of the time, keep “Allow DR restore” disabled: the cross-cluster/context guard protects against accidental crossed restores. A Secret redacted at backup time is never restored: re-provision it from its source. An <b>encrypted</b> Secret is recreated as soon as the vault is unlocked."),
    ("Guide complet : fichiers <code>README.md</code> / <code>README.fr.md</code> du dépôt (installation, configuration détaillée, déploiement Kubernetes).",
     "Full guide: the repository's <code>README.md</code> / <code>README.fr.md</code> (installation, detailed configuration, Kubernetes deployment)."),
    ("<th>État</th>", "<th>Status</th>"),
    ("Réponse inattendue du serveur (", "Unexpected server response ("),
    (") — rechargez la page (Ctrl+Shift+R).", ") — reload the page (Ctrl+Shift+R)."),
    ("Serveur injoignable : ", "Server unreachable: "),
    (". L'outil est-il toujours lancé ?", ". Is the tool still running?"),
    (" » introuvable dans la liste — actualisez les Applications (kubectl indisponible ?).",
     " » not found in the list — refresh Applications (kubectl unavailable?)."),
]


I18N_EN += [
    ("Dans le même namespace (suffixe)", "Into the same namespace (suffix)"),
    ("La copie est créée à côté de l'application d'origine : chaque objet reçoit un suffixe (ex. <code>-clone</code>). Pratique pour vérifier une restauration sans rien déplacer.",
     "The copy is created next to the original application: every object gets a suffix (e.g. <code>-clone</code>). Handy to verify a restore without moving anything."),
    ("Vers un autre namespace", "Into another namespace"),
    ("La copie est créée dans un namespace cible (créé s'il n'existe pas), avec ses dépendances (Secrets, ConfigMaps, ServiceAccount, Services). Les noms d'origine sont conservés.",
     "The copy is created in a target namespace (created if missing), with its dependencies (Secrets, ConfigMaps, ServiceAccount, Services). Original names are kept."),
]

_I18N_SORTED = None          # (fr, en) triés du plus long au plus court
_HTML_EN = None              # cache de la page traduite


def _i18n_sorted():
    global _I18N_SORTED
    if _I18N_SORTED is None:
        _I18N_SORTED = sorted(I18N_EN, key=lambda p: len(p[0]), reverse=True)
    return _I18N_SORTED


def _tr_en(s):
    """Traduit une chaîne FR -> EN par fragments (les plus longs d'abord)."""
    for fr, en in _i18n_sorted():
        if fr in s:
            s = s.replace(fr, en)
    return s


def _html_for_lang(lang):
    global _HTML_EN
    if lang != "en":
        return HTML
    if _HTML_EN is None:
        _HTML_EN = _tr_en(HTML)
    return _HTML_EN


# Clés JSON dont la valeur est du texte destiné à l'écran (jamais des données).
_TR_TEXT_KEYS = frozenset(("error", "warning", "warn", "label", "message", "hint",
                           "detail", "stdout", "stderr", "cmd",
                           "planned_steps", "warnings", "last_summary"))


def _tr_json_en(obj, key=None):
    """Traduit récursivement les valeurs textuelles d'une réponse JSON."""
    if isinstance(obj, dict):
        return {k: _tr_json_en(v, k) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_tr_json_en(v, key) for v in obj]
    if isinstance(obj, str) and key in _TR_TEXT_KEYS:
        return _tr_en(obj)
    return obj


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
    # Déverrouillage automatique du coffre au démarrage (phrase secrète via
    # HYCU_VAULT_PASSPHRASE[_FILE]) : les connexions et clusters mémorisés
    # reviennent sans intervention — utile en Pod pour la sauvegarde auto.
    _audit_compact()                    # rétention du journal appliquée dès le démarrage
    if auto_unlock_vault("startup"):
        print("  Coffre déverrouillé automatiquement (connexions/clusters rechargés).")
    # Sauvegarde automatique planifiée : le thread tourne en permanence et ne fait
    # quelque chose que si auto_backup_enabled est vrai (activable sans redémarrer).
    threading.Thread(target=_auto_backup_loop, daemon=True).start()
    # Contrôle de santé périodique des clusters (pastille dans ⚙ Sources).
    threading.Thread(target=_cluster_health_loop, daemon=True).start()
    if CONFIG.get("open_browser"):
        try:
            threading.Timer(1.0, lambda: webbrowser.open(url)).start()
        except Exception:
            pass
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.daemon_threads = True   # arrêt propre (Ctrl+C) sans thread bloquant
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
    import sys as _sys
    if "--decrypt" in _sys.argv:
        _i = _sys.argv.index("--decrypt")
        raise SystemExit(cli_decrypt(_sys.argv[_i + 1] if _i + 1 < len(_sys.argv) else ""))
    main()
