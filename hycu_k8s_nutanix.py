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

import sys
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
    # Noms d'hôte sous lesquels l'interface peut être servie EN PLUS de la boucle locale
    # (anti-DNS-rebinding : tout autre en-tête Host/Origin est refusé). Permet au client
    # d'exposer l'outil sous un nom DNS (Ingress, reverse-proxy), ex. ["hycu.interne.fr"].
    # ⚠ L'outil n'a pas d'authentification applicative : placez une authentification
    # (oauth2-proxy, SSO, liste d'IP) et TLS devant lui dès qu'il quitte la boucle locale.
    "allowed_hosts": [],
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
    "nas_job_image": "busybox:1.36",   # image du Job qui remet à plat une copie NAS (post-restauration)
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
    # POLITIQUES NOMMÉES (en plus de la sauvegarde automatique ci-dessus, qui devient la
    # « politique par défaut ») : chacune cible des namespaces par NOM et/ou par
    # SÉLECTEUR D'ÉTIQUETTES et a sa propre fréquence, sa rétention (N versions) et,
    # optionnellement, une politique HYCU assignée aux volumes encore sans politique.
    # La PREMIÈRE politique qui correspond l'emporte ; un namespace sans politique suit
    # la politique par défaut. Ex. :
    # [{"name": "or", "label_selector": "hycu.io/policy=or", "interval_hours": 4, "keep": 30}]
    "backup_policies": [],
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
    # Bundles CA (PEM) pour vérifier les certificats des appliances quand *_verify_tls
    # est vrai : PKI interne / certificat auto-signé exporté. Vide = magasin système.
    "hycu_ca_bundle": "",
    "nutanix_ca_bundle": "",
    "prismcentral_ca_bundle": "",
    # Délai max (s) d'attente d'un job HYCU (clone / restore / sauvegarde).
    "hycu_job_timeout": 1800,
    # ---- Interface ----
    # Langue par défaut de l'interface quand le navigateur n'a pas encore choisi
    # (bouton FR/EN) : "en" ou "fr".
    # Mode simulation (dry-run) : False = l'interface travaille directement en mode
    # réel (bandeau et interrupteur masqués, garde-fous de confirmation conservés) ;
    # True = proposer l'interrupteur « Mode simulation », coché par défaut.
    "simulation_mode_available": False,
}

# Schéma de validation : clé -> (type attendu, validateur optionnel).
# Appliqué au fichier, aux variables d'environnement ET à l'API (/api/config), pour
# qu'une valeur mal typée ne puisse ni être persistée ni casser le serveur (ex. un
# wait_timeout en chaîne -> TypeError dans chaque commande kubectl).
def _is_str_list(v):
    return all(isinstance(x, str) for x in v)


_POLICY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,39}$")
_LABEL_SEL_RE = re.compile(r"^[A-Za-z0-9_./=!,() -]{0,200}$")


def _valid_backup_policies(v):
    """Politiques nommées : nom unique, au moins une cible (namespaces et/ou sélecteur),
    intervalle 0,25–8760 h, rétention 0–10000 versions (0 = illimité)."""
    seen = set()
    for p in v:
        if not isinstance(p, dict):
            return False
        name = str(p.get("name") or "").strip()
        if not _POLICY_NAME_RE.match(name) or name.lower() in seen or name.lower() in ("default", "default"):
            return False
        seen.add(name.lower())
        nss = p.get("namespaces") or []
        if not isinstance(nss, list) or not all(isinstance(x, str) and re.match(r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$", x)
                                                 for x in nss):
            return False
        sel = p.get("label_selector") or ""
        if not isinstance(sel, str) or not _LABEL_SEL_RE.match(sel):
            return False
        if not nss and not sel.strip():
            return False
        try:
            iv = float(p.get("interval_hours", 24))
            kp = int(p.get("keep", 15))
        except (TypeError, ValueError):
            return False
        if isinstance(p.get("keep"), bool) or not (0.25 <= iv <= 8760 and 0 <= kp <= 10000):
            return False
        if not isinstance(p.get("enabled", True), bool):
            return False
        for k in ("hycu_policy", "hycu_policy_name"):
            if not isinstance(p.get(k) or "", str) or len(p.get(k) or "") > 120:
                return False
    return True


CONFIG_SCHEMA = {
    "host": (str, None),
    "port": (int, lambda v: 1 <= v <= 65535),
    "kubectl_path": (str, lambda v: bool(v.strip())),
    "kube_context": (str, None),
    "kubeconfig_path": (str, None),
    "backup_root": (str, None),
    "allowed_contexts": (list, _is_str_list),
    "allowed_hosts": (list, lambda v: _is_str_list(v) and all(re.match(r"^[A-Za-z0-9.\-]+$", x) for x in v)),
    "namespace_filter": (list, _is_str_list),
    "cluster_namespace_filters": (dict, lambda v: all(isinstance(x, list) and _is_str_list(x) for x in v.values())),
    "wait_timeout": (int, lambda v: 1 <= v <= 86400),
    "subprocess_margin": (int, lambda v: 0 <= v <= 3600),
    "volume_handle_prefix": (str, None),
    "strip_claimref": (bool, None),
    "clone_strip_runtime_attrs": (bool, None),
    "clone_fix_disk_uuids": (bool, None),
    "clone_require_disk_uuids": (bool, None),
    "nas_job_image": (str, None),
    "backup_before_restore": (bool, None),
    "config_backup_full": (bool, None),
    "config_backup_kinds": (list, _is_str_list),
    "config_backup_include_secret_data": (bool, None),
    "auto_backup_enabled": (bool, None),
    "auto_backup_interval_hours": (float, lambda v: 0.25 <= v <= 8760),
    "auto_backup_dest": (str, None),
    "auto_backup_keep": (int, lambda v: 0 <= v <= 10000),          # 0 = illimité
    "auto_backup_retention": (str, lambda v: v in ("count", "gfs")),
    "auto_backup_keep_daily": (int, lambda v: 0 <= v <= 3660),
    "auto_backup_keep_weekly": (int, lambda v: 0 <= v <= 520),
    "auto_backup_keep_monthly": (int, lambda v: 0 <= v <= 1200),
    "backup_policies": (list, _valid_backup_policies),
    "cluster_health_minutes": (int, lambda v: 0 <= v <= 1440),
    "audit_retention_days": (int, lambda v: 0 <= v <= 36500),
    "storage_min_free_mb": (int, lambda v: 0 <= v <= 10_000_000),
    "storage_quota_gb": (int, lambda v: 0 <= v <= 10_000_000),
    "allow_dr_restore": (bool, None),
    "namespace_label_selector": (str, None),
    "backup_collect_restore_contract": (bool, None),
    "recover_restore_deleted_vg": (bool, None),
    "recover_deleted_vg_mode": (str, lambda v: v in ("restore", "clone")),
    "backup_secrets": (str, lambda v: v in ("auto", "encrypted", "clear", "redacted")),
    "apps_fallback_max": (int, lambda v: 0 <= v <= 100000),
    "apps_cache_ttl_s": (int, lambda v: 0 <= v <= 86400),
    "backup_parallel": (int, lambda v: 1 <= v <= 64),
    "backup_pv_prefetch_min": (int, lambda v: 0 <= v <= 100000),
    "s3_url": (str, None), "s3_bucket": (str, None), "s3_region": (str, None), "s3_prefix": (str, None),
    "s3_verify_tls": (bool, None), "s3_path_style": (bool, None), "s3_auto_upload": (bool, None),
    "s3_encrypt": (bool, None),
    "inplace_refresh_pv_disk": (bool, None),
    "retain_source_pv": (bool, None),
    "require_context_confirm": (bool, None),
    "open_browser": (bool, None),
    "logo_path": (str, None),
    "remember_credentials": (bool, None),
    "pbkdf2_iterations": (int, lambda v: 1000 <= v <= 10000000),
    "hycu_url": (str, None), "hycu_api_base": (str, None), "hycu_test_path": (str, None),
    "hycu_verify_tls": (bool, None),
    "nutanix_url": (str, None), "nutanix_api_base": (str, None), "nutanix_verify_tls": (bool, None),
    "prismcentral_url": (str, None), "prismcentral_api_base": (str, None),
    "prismcentral_verify_tls": (bool, None),
    "hycu_ca_bundle": (str, None), "nutanix_ca_bundle": (str, None), "prismcentral_ca_bundle": (str, None),
    "hycu_job_timeout": (int, lambda v: 30 <= v <= 86400),
    "simulation_mode_available": (bool, None),
}
assert set(CONFIG_SCHEMA) == set(DEFAULT_CONFIG), "CONFIG_SCHEMA and DEFAULT_CONFIG differ"

# Clés de chemins/binaires : modifiables par l'API uniquement hors conteneur. En mode
# conteneur (une variable HYCU_* posée), elles viennent du fichier ou de l'env ;
# l'API les refuse (une page web ne doit pas pouvoir changer la commande exécutée).
_CONTAINER_LOCKED_KEYS = frozenset(("kubectl_path", "kubeconfig_path", "backup_root", "logo_path",
                                    "host", "port"))
_ENV_KEYS = ("HYCU_HOST", "HYCU_PORT", "HYCU_OPEN_BROWSER", "HYCU_BACKUP_ROOT", "HYCU_KUBECTL_PATH")
# Noms de binaires acceptés pour kubectl_path (premier mot ou nom de fichier).
_KUBECTL_BIN_PREFIXES = ("kubectl", "microk8s", "k3s", "oc", "minikube", "python")


def _container_mode():
    return any(os.environ.get(e) for e in _ENV_KEYS)


def _coerce_config_value(key, value):
    """Valide/convertit une valeur selon CONFIG_SCHEMA. Lève ValueError si invalide.
    Tolère les formes « texte » courantes (fichier édité à la main) : "true"/"false",
    "120", liste en chaîne séparée par des virgules."""
    typ, check = CONFIG_SCHEMA[key]
    v = value
    if typ is bool:
        if isinstance(v, str):
            s = v.strip().lower()
            if s in ("1", "true", "yes", "on"):
                v = True
            elif s in ("0", "false", "no", "off", ""):
                v = False
        if not isinstance(v, bool):
            raise ValueError("boolean expected")
    elif typ is int:
        if isinstance(v, bool):
            raise ValueError("integer expected")
        if isinstance(v, str) and v.strip().lstrip("-").isdigit():
            v = int(v.strip())
        if not isinstance(v, int):
            raise ValueError("integer expected")
    elif typ is float:
        if isinstance(v, bool):
            raise ValueError("number expected")
        if isinstance(v, str):
            try:
                v = float(v.strip().replace(",", "."))
            except ValueError:
                raise ValueError("number expected")
        if not isinstance(v, (int, float)):
            raise ValueError("number expected")
        if isinstance(v, float) and v.is_integer():
            v = int(v)
    elif typ is str:
        if v is None:
            v = ""
        if not isinstance(v, str):
            raise ValueError("text expected")
    elif typ is list:
        if isinstance(v, str):
            v = [x.strip() for x in v.split(",") if x.strip()]
        if not isinstance(v, list):
            raise ValueError("list expected")
    elif typ is dict:
        if not isinstance(v, dict):
            raise ValueError("object expected")
    if check and not check(v):
        raise ValueError("value out of range or malformed")
    if key == "kubectl_path":
        first = v.strip().split()[0] if v.strip() else ""
        base = os.path.basename(first).lower()
        if not base.startswith(_KUBECTL_BIN_PREFIXES):
            raise ValueError("unrecognised binary (kubectl, microk8s, k3s, oc expected)")
    return v


def validate_config(updates, source="api"):
    """Valide un dict de mises à jour. Renvoie (valeurs validées, erreur ou None).
    Les clés inconnues sont ignorées (compatibilité ascendante du fichier)."""
    out = {}
    for k, v in (updates or {}).items():
        if k not in CONFIG_SCHEMA:
            continue
        try:
            cv = _coerce_config_value(k, v)
        except ValueError as e:
            return None, "Configuration: key “%s” invalid (%s)." % (k, e)
        if source == "api" and k in _CONTAINER_LOCKED_KEYS and _container_mode():
            # L'interface renvoie toujours le formulaire complet (Réglages, assistant de
            # premier lancement) : une valeur IDENTIQUE à l'actuelle est simplement ignorée ;
            # seule une tentative de CHANGEMENT est refusée.
            if cv == CONFIG.get(k):
                continue
            return None, "Key “%s” is read-only in container mode (file or environment variable)." % k
        out[k] = cv
    return out, None


# Configuration EFFECTIVE (défauts + fichier + env) ; USER_CONFIG = contenu du fichier
# seul, de sorte que les surcharges d'environnement ne soient jamais persistées.
CONFIG = dict(DEFAULT_CONFIG)
# Sérialise mutation de CONFIG + écriture du fichier : save_config est appelé depuis
# plusieurs threads (UI, clone asynchrone qui auto-ajoute un namespace au filtre).
USER_CONFIG = {}
CONFIG_LOCK = threading.RLock()


def _env_overrides():
    """Surcharges par variables d'environnement (mode conteneur / 12-factor).
    Priorité : env > hycu_config.json > défauts (ex. HYCU_HOST=0.0.0.0,
    HYCU_OPEN_BROWSER=0, HYCU_BACKUP_ROOT=/data/hycu-backups)."""
    mapping = {"HYCU_HOST": "host", "HYCU_PORT": "port", "HYCU_OPEN_BROWSER": "open_browser",
               "HYCU_BACKUP_ROOT": "backup_root", "HYCU_KUBECTL_PATH": "kubectl_path",
               "HYCU_ALLOWED_HOSTS": "allowed_hosts"}   # liste séparée par des virgules
    out = {}
    for env, key in mapping.items():
        val = os.environ.get(env)
        if val is None or val == "":
            continue
        try:
            out[key] = _coerce_config_value(key, val)
        except ValueError as e:
            print("Environment variable %s ignored (invalid value: %r, %s)." % (env, val, e))
    return out


def _apply_env_overrides():
    CONFIG.update(_env_overrides())


def _rebuild_config():
    """CONFIG = défauts + USER_CONFIG + env (sans perdre les clés ajoutées à chaud)."""
    with CONFIG_LOCK:
        merged = dict(DEFAULT_CONFIG)
        merged.update(USER_CONFIG)
        if not (merged.get("backup_root") or "").strip():
            merged["backup_root"] = DEFAULT_CONFIG["backup_root"]
        merged.update(_env_overrides())
        CONFIG.clear()
        CONFIG.update(merged)
    return CONFIG


def load_config():
    """Charge hycu_config.json par-dessus les valeurs par défaut (clés inconnues ignorées,
    valeurs invalides signalées et ignorées), puis applique les surcharges d'environnement."""
    global USER_CONFIG
    user = {}
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, encoding="utf-8") as f:
                raw = json.load(f) or {}
            for k, v in raw.items():
                if k not in CONFIG_SCHEMA:
                    continue
                try:
                    user[k] = _coerce_config_value(k, v)
                except ValueError as e:
                    print("Configuration: key “%s” ignored (%s)." % (k, e))
        except Exception as e:  # config illisible : on garde les défauts
            print("Configuration unreadable (%s): defaults used." % e)
    with CONFIG_LOCK:
        USER_CONFIG = user
        _rebuild_config()
    return CONFIG


def _write_json_atomic(path, obj, mode=0o600):
    """Écrit un JSON via un fichier temporaire puis os.replace (jamais de fichier
    tronqué en cas d'arrêt brutal). mode = permissions POSIX du fichier."""
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)
        # Windows : un antivirus peut tenir brièvement le fichier tout juste écrit
        # (PermissionError transitoire sur os.replace) -> quelques tentatives.
        for attempt in range(5):
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.05 * (attempt + 1))
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def save_config(updates, source="internal"):
    """Valide, applique et persiste des mises à jour de configuration. Seul le contenu
    « utilisateur » (fichier) est écrit : les surcharges d'environnement ne sont jamais
    persistées. Écriture atomique, sous verrou (appelants concurrents : UI, thread
    d'opération, coffre). Renvoie (ok, erreur)."""
    vals, err = validate_config(updates, source=source)
    if err:
        return False, err
    with CONFIG_LOCK:
        env = _env_overrides()
        # Une valeur égale à la surcharge d'environnement n'est pas écrite dans le fichier
        # (elle vient de l'environnement, pas de l'opérateur) ; la reconstruction garde la
        # priorité env > fichier > défauts, même après une sauvegarde depuis l'interface.
        USER_CONFIG.update({k: v for k, v in vals.items() if not (k in env and env[k] == v)})
        CONFIG.update(vals)          # effet immédiat ; CONFIG garde ses autres valeurs à chaud
        CONFIG.update(env)           # l'environnement garde la priorité sur une saisie
        try:
            _write_json_atomic(CONFIG_PATH, USER_CONFIG, mode=0o644)
            return True, None
        except Exception as e:
            return False, str(e)


# Version horodatée de la build (format AAAAMMJJ-HHMM). À incrémenter à chaque
# changement notable du programme ; affichée dans l'en-tête de l'interface.
VERSION = "20261012-0330"

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


def _host_allowed(name):
    """Vrai si `name` (nom d'hôte sans port, minuscules) est la boucle locale ou un nom
    autorisé par la configuration (allowed_hosts : nom DNS d'un Ingress / reverse-proxy)."""
    if not name:
        return False
    n = name.strip().lower().rstrip(".")
    if n in ALLOWED_HOSTS:
        return True
    return any(n == (x or "").strip().lower().rstrip(".") for x in (CONFIG.get("allowed_hosts") or []))


def _host_is_local(hostport):
    """Extrait le nom d'hôte d'un en-tête Host (gère « host:port » et « [::1]:port »)
    et vérifie qu'il est autorisé (boucle locale ou allowed_hosts)."""
    if not hostport:
        return False
    h = hostport.strip()
    if h.startswith("["):                      # [::1] ou [::1]:port
        end = h.find("]")
        h = h[1:end] if end != -1 else h[1:]
    elif h.count(":") == 1:                     # host:port (IPv4 / nom)
        h = h.rsplit(":", 1)[0]
    return _host_allowed(h)

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
                print("Audit log compaction failed: %s" % e)
                return 0
    _AUDIT_COMPACT["last"] = now
    return removed


def audit(event, **fields):
    """Écrit une ligne JSON horodatée dans backup_root/audit.log."""
    try:
        os.makedirs(CONFIG["backup_root"], exist_ok=True)
        rec = {"ts": datetime.datetime.now().astimezone().isoformat(), "event": event}
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
            print("AUDIT not written (%s): %s" % (e, json.dumps(
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
def action_lock(skip=False, wait=0.0):
    """Sérialise les actions destructives. `skip=True` (ex. dry-run) n'acquiert rien.
    `wait` > 0 : patiente jusqu'à `wait` secondes (sections critiques COURTES appelées en
    parallèle, ex. plusieurs clones HYCU lancés ensemble) au lieu de refuser aussitôt.
    Lève _Busy si le verrou n'est pas obtenu. Libère toujours en sortie."""
    if skip:
        got = True
    elif wait and wait > 0:
        got = ACTION_LOCK.acquire(timeout=float(wait))
    else:
        got = ACTION_LOCK.acquire(blocking=False)
    if not got:
        raise _Busy("Another operation is already running. Try again.")
    try:
        yield
    finally:
        if not skip:
            ACTION_LOCK.release()


# ------------------------------------------------------------------------------
# Opérations longues asynchrones (progression live) — exécutées en thread, suivies
# par /api/op_status. Le `log` partagé grossit pendant l'exécution ; le client poll.
# ------------------------------------------------------------------------------
OPERATIONS = {}                 # op_id -> {"log": [...], "done": bool, "result": dict|None, "cancel": Event}
OP_LOCK = threading.Lock()
_OP_TL = threading.local()      # op_id de l'opération exécutée par le thread courant


def _op_cancel_requested():
    """Vrai si l'opérateur a demandé l'arrêt coopératif de l'opération en cours
    (POST /api/op_cancel) : la séquence termine l'étape en cours puis s'arrête."""
    op_id = getattr(_OP_TL, "op_id", None)
    if not op_id:
        return False
    with OP_LOCK:
        op = OPERATIONS.get(op_id)
    return bool(op and op.get("cancel") and op["cancel"].is_set())


def action_op_cancel(op_id):
    with OP_LOCK:
        op = OPERATIONS.get(op_id or "")
        if not op:
            return {"ok": False, "error": "Unknown or expired operation."}
        if op["done"]:
            return {"ok": False, "error": "Operation already finished."}
        op["cancel"].set()
    audit("op_cancel_requested", op_id=op_id)
    return {"ok": True}


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
        OPERATIONS[op_id] = {"log": shared, "done": False, "result": None, "cancel": threading.Event(),
                             "kind": getattr(fn, "__name__", "").replace("action_", ""),
                             "ns": (payload or {}).get("namespace") or (payload or {}).get("ns") or "",
                             "cid": cid, "started": time.time()}

    def worker():
        _OP_TL.op_id = op_id
        try:
            with use_cluster(cid):
                res = fn(payload, log=shared)
        except Exception as e:  # filet : ne jamais laisser un thread mourir sans verdict
            res = {"ok": False, "error": "Internal error: %s" % e, "log": shared}
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
        return {"ok": False, "error": "Unknown or expired operation."}
    return {"ok": True, "done": op["done"], "log": list(op["log"]),
            "result": op["result"] if op["done"] else None}


def _operations_running():
    """Vrai si au moins une opération longue n'est pas terminée."""
    with OP_LOCK:
        return any(not v["done"] for v in OPERATIONS.values())


def action_op_list():
    """Opérations en cours (pour reprendre le suivi après un rechargement de page)."""
    with OP_LOCK:
        running = [{"op_id": k, "kind": v.get("kind") or "", "ns": v.get("ns") or "",
                    "cluster_id": v.get("cid") or "", "cancel_requested": bool(v.get("cancel") and v["cancel"].is_set())}
                   for k, v in OPERATIONS.items() if not v["done"]]
    return {"ok": True, "running": running}


# ------------------------------------------------------------------------------
# Exécution de commandes
# ------------------------------------------------------------------------------
def _kubectl_argv():
    """Argv du binaire kubectl : un chemin de fichier (même avec des espaces, ex.
    « C:\\Program Files\\Kubectl\\kubectl.exe ») reste UN argument ; sinon la valeur
    est découpée comme une ligne de commande (« microk8s kubectl »)."""
    s = (CONFIG.get("kubectl_path") or "kubectl").strip()
    if os.path.isfile(s):
        return [s]
    try:
        import shlex
        parts = shlex.split(s, posix=(os.name != "nt"))
    except ValueError:
        parts = s.split()
    return parts or ["kubectl"]


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
        timeout = int(CONFIG["wait_timeout"]) + int(CONFIG["subprocess_margin"])
    try:
        # encoding explicite : sous Windows, text=True décoderait en cp1252 (mojibake /
        # UnicodeDecodeError sur les sorties kubectl accentuées).
        p = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace",
                           timeout=timeout, input=input_text)
        return {"ok": p.returncode == 0, "dry": False, "cmd": pretty,
                "stdout": (p.stdout or "").strip(), "stderr": (p.stderr or "").strip(),
                "rc": p.returncode, "label": label or pretty}
    except FileNotFoundError:
        return {"ok": False, "dry": False, "cmd": pretty, "stdout": "", "rc": -1,
                "stderr": "Command not found: '%s' — is it installed and in the PATH?" % cmd[0],
                "label": label or pretty}
    except subprocess.TimeoutExpired:
        return {"ok": False, "dry": False, "cmd": pretty, "stdout": "", "rc": -1,
                "stderr": "Timeout exceeded (%ss)." % timeout, "label": label or pretty}
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
_NO_CLUSTER_MSG = ("Cluster “%s” unknown (removed, or session locked): "
                   "select a cluster in the top bar. No command was executed.")
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
        return False, "Unknown cluster."
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
    base = _kubectl_argv()
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
        warn("Exec plugin authentication (“%s”): this command must be "
             "installed where the tool runs (absent from the default "
             "container image); it may also open a browser (OIDC) that the tool cannot drive." % os.path.basename(str(cmd)))
    elif user.get("auth-provider"):
        typ = "auth-provider"
        warn("“auth-provider” authentication (%s): deprecated mechanism, "
             "short-lived OIDC token — use a ServiceAccount token for long-term use."
             % ((user["auth-provider"] or {}).get("name") or "oidc"))
    elif user.get("token") or user.get("tokenFile"):
        typ = "token"
        if user.get("tokenFile"):
            warn("The token is read from a local file (%s): it must exist where the tool runs."
                 % user.get("tokenFile"))
        parts = str(user.get("token") or "").split(".")
        claims = _b64url_json(parts[1]) if len(parts) == 3 else None
        if isinstance(claims, dict) and claims.get("exp"):
            try:
                exp = float(claims["exp"])
            except (TypeError, ValueError):
                exp = None
            if exp and exp <= now:
                warn("The token has EXPIRED (%s): regenerate the kubeconfig."
                     % datetime.datetime.fromtimestamp(exp).strftime("%Y-%m-%d %H:%M"), "error")
            elif exp and exp - now < 24 * 3600:
                warn("The token expires in less than 24 h (%s): scheduled backups will fail afterwards."
                     % datetime.datetime.fromtimestamp(exp).strftime("%Y-%m-%d %H:%M"))
    elif user.get("client-certificate-data") or user.get("client-certificate"):
        typ = "client-certificate"
        if user.get("client-certificate") and not user.get("client-certificate-data"):
            warn("The client certificate is a local file (%s): it must exist where the tool runs."
                 % user.get("client-certificate"))
    elif user.get("username"):
        typ = "basic"
        warn("Username/password (basic) authentication: disabled on most recent clusters.")
    else:
        warn("No recognized authentication information for this context.")
    if cluster.get("insecure-skip-tls-verify"):
        warn("Server TLS verification DISABLED (insecure-skip-tls-verify).")
    if cluster.get("certificate-authority") and not cluster.get("certificate-authority-data"):
        warn("The certificate authority is a local file (%s): it must exist where the tool runs."
             % cluster.get("certificate-authority"))
    return {"type": typ, "warnings": warnings, "level": level, "expires": exp}


def _kc_view(path):
    """Kubeconfig -> dict JSON via kubectl (résout aussi le format YAML). (data, err)."""
    r = run(_kubectl_argv() + ["--kubeconfig", path, "config", "view", "--raw", "-o", "json"],
            timeout=30)
    if not r["ok"]:
        return None, (r["stderr"] or "kubectl config view failed").replace(path, "<kubeconfig>")
    try:
        return json.loads(r["stdout"] or "{}"), None
    except ValueError as e:
        return None, "Unreadable kubeconfig: %s" % e


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
        return None, [], "", "Empty kubeconfig."
    if len(text.encode("utf-8")) > KUBECONFIG_MAX_BYTES:
        return None, [], "", "Kubeconfig too large (1 MB max)."
    path = _write_kc_file(text)
    view, err = _kc_view(path)
    if err:
        _rm_quiet(path)
        return None, [], "", "Invalid kubeconfig: %s" % err
    ctxs, cur = _kc_contexts(view)
    if not ctxs:
        _rm_quiet(path)
        return None, [], "", "No context in this kubeconfig."
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
    r = run(_kubectl_argv() + ["--kubeconfig", path, "--context", context,
            "--request-timeout=10s", "get", "ns", "-o", "name"], timeout=25)
    if r["ok"]:
        return True, None
    msg = (r["stderr"] or "").replace(path, "<kubeconfig>")
    if "forbidden" in msg.lower():
        return True, ("Connected, but listing namespaces is forbidden "
                      "(RBAC): the tool will only see explicitly allowed namespaces.")
    return False, msg or "Cluster unreachable."


def _register_cluster(name, text, context=None, workspace="", source="upload", nkp_ref="",
                      management="", test=True, allow_exec=True):
    """Enregistre un cluster supplémentaire. Renvoie _ok(cluster=…) ou _err(...).
    allow_exec=False : refuse un contexte authentifié par plugin « exec » (kubectl
    exécuterait alors une commande arbitraire décrite DANS le kubeconfig — inacceptable
    pour un kubeconfig qui ne vient pas directement de l'opérateur, ex. Secret NKP)."""
    name = (name or "").strip()
    cid = _cluster_slug(name)
    if not name or not cid or len(name) > 63:
        return _err("Invalid cluster name (1 to 63 characters, letters/digits/-/./_).")
    if cid == LOCAL_CID or name == (_local_context_name() or ""):
        return _err("This name is reserved for the local cluster: choose another one.")
    with CLUSTERS_LOCK:
        if cid in CLUSTERS or any(c["name"] == name for c in CLUSTERS.values()):
            return _err("A cluster named “%s” is already registered." % name)
    path, ctxs, cur, err = _load_kubeconfig_text(text)
    if err:
        return _err(err)
    names = [c["name"] for c in ctxs]
    context = (context or "").strip() or (cur if cur in names else "") or (names[0] if len(names) == 1 else "")
    if not context:
        _rm_quiet(path)
        return _err("This kubeconfig contains several contexts: choose one.",
                    need_context=True, contexts=ctxs)
    if context not in names:
        _rm_quiet(path)
        return _err("Context “%s” not found in this kubeconfig." % context, contexts=ctxs)
    info = next(c for c in ctxs if c["name"] == context)
    if not allow_exec and info["auth"].get("type") == "exec":
        _rm_quiet(path)
        return _err("Kubeconfig refused: exec plugin authentication (external "
                    "command) is not allowed for an automatically imported kubeconfig.")
    note = None
    if test:
        ok, note = _test_cluster(path, context)
        if not ok:
            _rm_quiet(path)
            return _err("Cannot connect to the cluster: %s" % note)
    entry = {"id": cid, "name": name, "context": context, "server": info["server"],
             "kc_path": path, "kubeconfig": text, "auth": info["auth"], "user": info["user"],
             "workspace": workspace or "", "source": source, "nkp_ref": nkp_ref or "",
             "management": management or "", "added": time.time(), "note": note}
    with CLUSTERS_LOCK:
        if cid in CLUSTERS:                     # course : ajouté entre-temps
            _rm_quiet(path)
            return _err("A cluster named “%s” is already registered." % name)
        CLUSTERS[cid] = entry
    return _ok(cluster=_cluster_public(entry))


def _cluster_public(c):
    """Vue publique d'un cluster (jamais le kubeconfig ni le chemin du fichier)."""
    auth = dict(c.get("auth") or {})
    if auth.get("expires"):                     # ré-évaluer l'expiration à chaque lecture
        exp = auth["expires"]
        if exp <= time.time() and auth.get("level") != "error":
            auth["level"] = "error"
            auth["warnings"] = list(auth.get("warnings") or []) + ["The token has EXPIRED: regenerate the kubeconfig."]
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
        return _err("The local cluster (configuration) cannot be removed here: see Settings.")
    c = _unregister_cluster(cid)
    if not c:
        return _err("Unknown cluster.")
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
            err = None if ok else (r["stderr"] or "cluster unreachable")
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
            print("Cluster health check: unexpected error: %s" % e)


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
        return _err("The active cluster does not look like an NKP management "
                    "cluster (Workspace resource not found or access denied): %s" % err)
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
        return _err("NKP cluster list (KommanderCluster) unavailable: %s" % err)
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
        return _err("First acknowledge the warning about required privileges.")
    mgmt = _cluster_label()
    results = []
    for it in payload.get("items") or []:
        ns, name = (it.get("namespace") or "").strip(), (it.get("name") or "").strip()
        secret = (it.get("secret") or "").strip() or ("%s-kubeconfig" % name)
        label = "%s/%s" % (ns, name)
        if not all(K8S_NAME_RE.match(x or "") for x in (ns, name, secret)):
            results.append({"cluster": label, "ok": False, "error": "Invalid name."})
            continue
        sec, err = kubectl_json(["get", "secret", secret, "-n", ns])
        if err:
            results.append({"cluster": label, "ok": False,
                            "error": "Secret “%s” unreadable: %s" % (secret, err)})
            continue
        text = _kubeconfig_from_secret(sec)
        if not text:
            results.append({"cluster": label, "ok": False,
                            "error": "No kubeconfig found in Secret “%s”." % secret})
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
    return {"ok": n > 0 or not results, "error": None if n or not results else "No cluster imported.",
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
        return None, "Unreadable JSON response: %s" % e


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
    data, err = kubectl_json(["get", ",".join(kinds), "-n", ns]) if len(kinds) > 1 else (None, "a single type")
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
    ref = (new_ref or "").strip()
    found = UUID_RE.findall(ref)
    if not found:
        return None
    # IQN hérité : « iqn.…:<nom-du-VG>-<uuid-du-VG>-<n>-tgt0 ». Le nom du VG est souvent
    # « pvc-<uuid-du-PVC> » : l'UUID du VG est donc le DERNIER de la chaîne.
    new_uuid = found[-1] if ref.lower().startswith("iqn.") else found[0]
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
        iqn_uuid = (UUID_RE.findall(iqn.group(0)) or [None])[-1] if iqn else None
        if iqn_uuid:
            prefix = CONFIG.get("volume_handle_prefix") or "NutanixVolumes-"
            vh = prefix + iqn_uuid
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


def _pv_nfs_info(pv):
    """Volume NAS (NFS) : {"server", "path"} si le PV monte un export NFS — plugin NFS
    natif (spec.nfs) ou driver CSI NFS (attributs server/share, nfsServer/nfsPath…).
    None pour un volume bloc (Volume Group Nutanix) ou un type inconnu."""
    spec = (pv or {}).get("spec") or {}
    nfs = spec.get("nfs")
    if isinstance(nfs, dict) and nfs.get("server") and nfs.get("path"):
        return {"server": str(nfs["server"]).strip(), "path": str(nfs["path"]).strip()}
    csi = spec.get("csi")
    if isinstance(csi, dict):
        va = csi.get("volumeAttributes") or {}
        drv = str(csi.get("driver") or "").lower()
        server = va.get("server") or va.get("nfsServer") or va.get("nfsServerName")
        path = va.get("share") or va.get("nfsPath") or va.get("exportPath") or va.get("path")
        if server and path and ("nfs" in drv or "nfs" in " ".join(str(k).lower() for k in va)
                                or va.get("share")):
            sub = (va.get("subdir") or "").strip("/")
            p = str(path).rstrip("/") + ("/" + sub if sub else "")
            return {"server": str(server).strip(), "path": p or "/"}
    return None


def _nfs_label(info):
    return "%s:%s" % (info.get("server"), info.get("path")) if info else ""


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
        return None, ("Invalid volume reference: could not extract the Volume Group UUID "
                      "from it. Paste the VG UUID (8-4-4-4-12), a volumeHandle "
                      "“NutanixVolumes-<uuid>”, or (legacy iSCSI clusters) the full IQN of the cloned VG.")

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
        replacements.append(("vg_uuid", old_uuid, new_uuid))

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
            return None, "Invalid PV name: '%s' (RFC 1123 expected)." % new_name
        new_pv.setdefault("metadata", {})["name"] = new_name
        replacements.append(("pv_name", old_name, new_name))
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
        return ("Not enough disk space under %s: %d MB free (floor: %d MB). "
                "Backup REFUSED to avoid filling the storage — free some "
                "space, reduce retention (Policies) or the job history (Settings)."
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
                if t.get("status") in ("in_progress", "restart_failed") and t.get("backup_dir"):
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
            print("Storage quota: cannot delete %s: %s" % (path, e))
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
        return None, "Unusable destination folder (%s): %s" % (root, e)
    if not os.path.isdir(root):
        return None, "The destination path is not a folder: %s" % root
    return root, None


def _safe_backup_path(p, extra_root=None):
    """Valide qu'un backup_path fourni par l'UI reste sous backup_root — ou sous un
    dossier personnalisé EXPLICITEMENT choisi par l'utilisateur (extra_root). Défense en
    profondeur contre une lecture hors zone ; la zone personnalisée n'est ouverte que si
    l'utilisateur la désigne (outil localhost mono-opérateur)."""
    if not p:
        return None
    full = os.path.realpath(p)
    root = os.path.realpath(CONFIG["backup_root"])
    if full == root or full.startswith(root + os.sep):
        return full
    extra = (extra_root or "").strip()
    if not extra:
        return None
    er = os.path.realpath(os.path.expanduser(extra))
    if not _extra_root_ok(er):
        return None
    if (full == er or full.startswith(er + os.sep)) and _holds_backup(full):
        return full
    return None


def _holds_backup(path, depth=4, budget=5000):
    """Vrai si `path` est une sauvegarde (index.json) ou contient des sauvegardes à au
    plus `depth` niveaux (racine/<ns>/<horodatage>, ou _contexts/<ctx>/<ns>/<horodatage>).
    Parcours borné (budget d'entrées) : jamais de balayage complet d'un disque."""
    if not os.path.isdir(path):
        return False
    stack, seen = [(path, 0)], 0
    while stack:
        d, lvl = stack.pop()
        if os.path.isfile(os.path.join(d, "index.json")):
            return True
        if lvl >= depth:
            continue
        try:
            entries = os.listdir(d)
        except OSError:
            continue
        for n in entries:
            seen += 1
            if seen > budget:
                return False
            sub = os.path.join(d, n)
            if os.path.isdir(sub) and not os.path.islink(sub):
                stack.append((sub, lvl + 1))
    return False


def _extra_root_ok(er):
    """Dossier de sauvegarde PERSONNALISÉ fourni par l'interface : accepté seulement s'il
    existe, n'est ni une racine de disque ni le dossier personnel, ne contient pas la
    configuration ni le coffre de l'outil, et contient réellement des sauvegardes. Sans
    cette garde, `root=/` ferait passer n'importe quel dossier pour une zone de sauvegarde."""
    if not er or not os.path.isdir(er):
        return False
    if os.path.dirname(er) == er:                                  # racine (/, C:\)
        return False
    if er == os.path.realpath(os.path.expanduser("~")):
        return False
    for f in (CONFIG_PATH, SECRETS_PATH):
        d = os.path.dirname(os.path.realpath(f))
        if d == er or d.startswith(er + os.sep):
            return False
    return _holds_backup(er)


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
            except Exception as e:
                print("Backup %s: index.json unreadable (%s) — skipped." % (os.path.join(base, ts), e))
    # Ordre chronologique réel (champ created), pas lexicographique : robuste au
    # changement d'heure et aux horodatages de fuseaux différents.
    out.sort(key=lambda b: (_backup_epoch(b) or 0.0, b["timestamp"]), reverse=True)
    return out


def list_backups(ns, root=None):
    """Liste les sauvegardes d'un namespace pour le CLUSTER ACTIF. Pour le cluster
    local, les sauvegardes de l'ancienne disposition (<root>/<ns>, antérieure à la
    hiérarchie par contexte) sont incluses SI leur index porte le contexte courant
    (ou aucun contexte). Triées plus récentes d'abord."""
    if not ns or not K8S_NAME_RE.match(ns):                  # nom RFC 1123 : jamais de « ../ »
        return []
    if root and root.strip():
        root = os.path.realpath(os.path.expanduser(root.strip()))
        if root != os.path.realpath(CONFIG["backup_root"]) and not _extra_root_ok(root):
            return []
    else:
        root = CONFIG["backup_root"]
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
CATALOG_VERSION = 2          # 2 : volumes NAS (vol_nfs)
_CATALOG_LOCK = threading.RLock()
_CATALOGS = {}            # base (chemin absolu) -> {"ns": {ns: {"key", "versions", "pending"}}, "dirty"}


def _catalog_summary(path, idx):
    """Résumé d'UNE version (index.json déjà lu) : uniquement les champs consommés par
    l'inventaire, la page Applications, la DR et le quota — jamais les manifestes."""
    vols, vol_refs, vol_hycu, vol_names, vol_nfs = [], {}, {}, {}, {}
    for v in (idx.get("volumes") or []):
        pvc = v.get("pvc")
        if not pvc:
            continue
        vols.append(pvc)
        if v.get("nfs"):
            vol_nfs[pvc] = _nfs_label(v["nfs"])
            continue                     # pas de Volume Group derrière un export NFS
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
            "vol_nfs": vol_nfs,
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
            print("Backup catalog not written (%s): %s" % (base, e))


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
    if "not found" in e or "not found" in e or "installed" in e or "no such file" in e:
        return "kubectl_missing"
    if "current-context" in e or "not set" in e:
        return "no_context"
    if "no configuration" in e or "kubeconfig" in e:
        return "no_kubeconfig"
    return "other"


def action_contexts(kubeconfig=None):
    """Liste les contextes disponibles dans le kubeconfig (ciblé ou par défaut)."""
    kc = (kubeconfig if kubeconfig is not None else (CONFIG.get("kubeconfig_path") or "")).strip()
    cmd = _kubectl_argv()
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
            ctx, err, kubectl_ok, hint = None, ("Context “%s” not found in the kubeconfig." % selected), False, "no_context"
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
        log.append(logentry("Namespace “%s” added to the allowed namespaces" % ns, ok=True,
                            stdout="Filter updated (⚙ Settings) so Verify/Restore accept this namespace."))


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
        return {"ok": False, "pvcs": [], "error": "Namespace '%s' not allowed by the configuration." % ns}
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


BACKUP_SCHEMA = 2
BACKUP_KINDS = ("manual", "auto", "pre_restore")
_ALL_POLICIES = object()      # action_backup_all : périmètre « tous les namespaces » (sauvegarde manuelle)


def action_backup(ns, dest=None, protect=None, pv_cache=None, defer_quota=False,
                  kind="manual", internal=False, keep=None, retention_mode=None):
    """Exporte + nettoie tous les PV/PVC du namespace (étapes 1-3 du document).
    `dest` (optionnel) = dossier de destination choisi par l'utilisateur (vide = défaut).
    `protect` = chemins de sauvegarde à ne jamais purger par la rétention (ex. la
    sauvegarde SOURCE d'une restauration en cours).
    `pv_cache` = {nom: manifeste PV} lu UNE fois par passage (sauvegarde de tous les
    namespaces) ; un PV absent du cache est relu individuellement. `defer_quota` : le
    quota global est appliqué par l'appelant en fin de passage (pas par namespace).
    `kind` = origine de la sauvegarde (manual | auto | pre_restore) : les « pre_restore »
    (filet de sécurité d'une restauration) ne sont jamais soumises à la rétention. `internal` = appel depuis une opération
    qui détient déjà le verrou (sauvegarde de sécurité d'une restauration, passage auto)."""
    if not _namespace_allowed(ns):
        return {"ok": False, "error": "Namespace '%s' not allowed by the configuration." % ns}
    if not internal and ACTION_LOCK.locked():
        return {"ok": False, "error": "A restore or clone is running: backup refused (the "
                                      "namespace state would be inconsistent). Try again afterwards."}
    if kind not in BACKUP_KINDS:
        kind = "manual"
    root, derr = _resolve_backup_dest(dest)
    if derr:
        return {"ok": False, "error": derr}
    if keep is None:                          # rétention de la politique du namespace
        keep, retention_mode = _retention_for(ns)
    ferr = _storage_floor_error(root)
    if ferr:
        # Donner d'abord sa chance à la rétention/au quota de libérer de la place :
        # sinon le plancher bloque la seule purge capable de le lever (verrou).
        try:
            _prune_backups(root, ns, keep, protect=protect, mode=retention_mode)
            enforce_storage_quota(root)
        except Exception as e:
            print("Retention before backup: %s" % e)
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
        return {"ok": False, "skipped": True, "error": "No PVC found in namespace '%s'." % ns}

    d = backup_dir(ns, root)
    index = {"schema": BACKUP_SCHEMA, "tool_version": VERSION, "kind": kind, "complete": False,
             "namespace": ns, "created": datetime.datetime.now().astimezone().isoformat(),
             "context": _cluster_label(),
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
                nfs_info = _pv_nfs_info(clean_v)
                if nfs_info:
                    entry["nfs"] = nfs_info
                entry["storage_class"] = (clean_v.get("spec") or {}).get("storageClassName")
                entry["capacity"] = ((clean_v.get("spec") or {}).get("capacity") or {}).get("storage")
            else:
                # Ne JAMAIS avaler l'échec : sans le manifeste du PV, ce volume n'est pas
                # restaurable ; la sauvegarde est marquée PARTIELLE et n'entraîne aucune
                # purge des versions précédentes (complètes).
                entry["pv_error"] = perr or "PV not found"
                pv_errors.append("%s (PV %s): %s" % (name, pv_name, entry["pv_error"]))
        index["volumes"].append(entry)
    if pv_errors:
        index["partial"] = True
        index["pv_errors"] = pv_errors

    # Instantané de configuration ÉTENDUE (Deployments, Services, Secrets…) — lecture
    # seule, additif, n'échoue jamais la sauvegarde PV/PVC (voir _backup_namespace_resources).
    resources_count, resources_skipped = None, []
    res_items = []
    secrets_mode = None
    if CONFIG.get("config_backup_full", True):
        try:
            resources_count, resources_skipped, res_items, secrets_mode = _backup_namespace_resources(ns, d)
            index["resources_count"] = resources_count
            index["resources_skipped"] = resources_skipped
            index["secrets"] = secrets_mode
            files.append("resources.json")
            if os.path.isfile(os.path.join(d, SECRETS_FILE)):
                files.append(SECRETS_FILE)
        except Exception as e:
            print("Extended config backup (%s) skipped: %s" % (ns, e))
    # Secrets en clair faute de phrase de coffre (mode auto) : dit explicitement, pas caché.
    secrets_warning = None
    if secrets_mode == "clear" and _secrets_mode() == "auto":
        secrets_warning = ("Secrets backed up IN CLEAR (no vault "
                           "passphrase available): unlock the vault (⚙ → "
                           "Sources) or provide HYCU_VAULT_PASSPHRASE to encrypt them.")
    # Applications du namespace (workloads regroupés, PVC montés, stateful/stateless) :
    # mémorisées dans l'index pour cibler la restauration — y compris quand le
    # namespace n'existera plus (récupération).
    try:
        index["apps"] = [{k: a[k] for k in ("name", "workloads", "pvcs", "type", "unassigned", "whole_ns") if a.get(k)}
                         for a in _apps_from_workloads(ns, res_items, [p["metadata"]["name"] for p in items])]
    except Exception as e:
        print("Applications of %s not indexed: %s" % (ns, e))
    if not items and not any(o.get("kind") in APP_WORKLOAD_KINDS for o in res_items):
        # Ni PVC ni workload : rien à protéger (namespace vide ou purement système).
        shutil.rmtree(d, ignore_errors=True)
        try:
            os.rmdir(os.path.dirname(d))          # dossier du namespace, s'il est resté vide
        except OSError:
            pass
        return {"ok": False, "skipped": True,
                "error": "No PVC nor workload in namespace '%s': nothing to back up." % ns}

    # Contrat de restauration (best-effort) : de quoi restaurer plus tard SANS saisie
    # d'UUID (nom/UUID du VG côté HYCU, disques, Prism Element, dernier point HYCU).
    # N'échoue jamais la sauvegarde ; ignoré si HYCU/Prism non connectés.
    if CONFIG.get("backup_collect_restore_contract", True):
        try:
            systems = _collect_restore_contract(ns, index["volumes"])
            if systems:
                index["systems"] = systems
        except Exception as e:
            print("Restore contract (%s) skipped: %s" % (ns, e))

    index["schema"] = BACKUP_SCHEMA
    index["kind"] = kind
    index["complete"] = not pv_errors
    # Empreintes des fichiers : une sauvegarde altérée est détectable avant restauration.
    index["files"] = []
    for fn in files:
        try:
            fp = os.path.join(d, fn)
            with open(fp, "rb") as fh:
                index["files"].append({"name": fn, "size": os.path.getsize(fp),
                                       "sha256": hashlib.sha256(fh.read()).hexdigest()})
        except OSError:
            pass
    # Écriture ATOMIQUE de l'index : un arrêt brutal ne laisse jamais un index tronqué
    # (dossier invisible, non purgeable, non compté).
    _write_json_atomic(os.path.join(d, "index.json"), index, mode=0o644)
    _catalog_forget_path(d)                   # le catalogue rescanne ce namespace

    warning = None
    if resources_skipped:
        warning = "Resources not exported (insufficient rights): %s." % ", ".join(resources_skipped)
    if pv_errors:
        audit("backup", namespace=ns, dir=d, count=len(items), resources=resources_count,
              kind=kind, partial=True, pv_errors=len(pv_errors))
        return {"ok": False, "partial": True, "dir": d, "root": root, "count": len(items), "kind": kind,
                "files": files, "volumes": index["volumes"], "resources_count": resources_count,
                "warning": warning, "resources_skipped": resources_skipped,
                "error": "PARTIAL backup of “%s”: PV manifest "
                         "unreadable for %s. Previous versions are kept (no purge)." % (ns, "; ".join(pv_errors))}
    audit("backup", namespace=ns, dir=d, count=len(items), resources=resources_count,
          secrets=secrets_mode, kind=kind)
    # Garde-fous stockage : rétention par namespace (jamais les sauvegardes de sécurité
    # pré-restauration, cf. _prune_backups) puis quota global éventuel.
    pruned = 0
    try:
        pruned = _prune_backups(root, ns, keep, protect=protect, mode=retention_mode)
        if not defer_quota:
            enforce_storage_quota(root)
    except Exception as e:
        print("Storage guard after backup: %s" % e)
    return _s3_after_backup(
        {"ok": True, "error": None, "dir": d, "root": root, "count": len(items), "pruned": pruned,
         "kind": kind, "partial": False, "warning": warning, "resources_skipped": resources_skipped,
         "files": files, "volumes": index["volumes"], "resources_count": resources_count,
         "secrets": secrets_mode, "secrets_warning": secrets_warning})


def action_backup_all(dest=None, kind="manual", internal=False, policy_scope=_ALL_POLICIES):
    """Sauvegarde la config (PV/PVC) de TOUS les namespaces autorisés par le filtre
    courant (tous les namespaces du cluster si aucun filtre). Un namespace sans PVC est
    « ignoré » (pas une erreur). Renvoie un récapitulatif par namespace + des totaux.
    `dest` (optionnel) = dossier de destination commun (vide = défaut).
    `policy_scope` : par défaut TOUS les namespaces (sauvegarde manuelle) ; None = ceux
    de la politique PAR DÉFAUT (sans politique nommée) ; une politique = ses namespaces."""
    info = action_namespaces()
    if not info.get("ok"):
        return {"ok": False, "error": info.get("error") or "Namespace list unavailable.",
                "results": []}
    namespaces = info.get("namespaces") or []
    pmap, perr = {}, None
    if policy_scope is not _ALL_POLICIES:
        pmap, perr = _policy_map(namespaces)
        want = (policy_scope or {}).get("name")
        if perr and want:
            # Membres par étiquette invérifiables : seuls les namespaces nommés explicitement
            # sont sûrs ; le passage est signalé en échec (cf. _policy_run).
            namespaces = [n for n in namespaces if n in (policy_scope.get("namespaces") or [])]
        else:
            namespaces = [n for n in namespaces if ((pmap.get(n) or {}).get("name")) == want]
        if not namespaces:
            return {"ok": True, "error": None, "results": [], "root": None, "namespaces": 0,
                    "backed_up": 0, "volumes": 0, "partial": [], "filtered": bool(_ns_filter()),
                    "selector_error": perr}
    elif not namespaces:
        return {"ok": False, "error": "No namespace to back up.", "results": []}
    root, derr = _resolve_backup_dest(dest)        # valide la destination une seule fois
    if derr:
        return {"ok": False, "error": derr, "results": []}
    if not internal and ACTION_LOCK.locked():
        return {"ok": False, "error": "A restore or clone is running: backup refused.",
                "results": []}
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
                        "error": "Restore in progress (transaction): backup deferred."}
            try:
                kp, km = (None, None)
                pol = pmap.get(ns) if policy_scope is not _ALL_POLICIES else None
                if pol:
                    kp, km = int(pol.get("keep", 15)), "count"
                b = action_backup(ns, root, pv_cache=pv_cache, defer_quota=True, kind=kind, internal=True,
                                  keep=kp, retention_mode=km)
            except Exception as e:                      # un namespace en erreur n'arrête pas le passage
                b = {"ok": False, "error": "Internal error: %s" % e}
            if b.get("ok"):
                return {"ns": ns, "ok": True, "count": b.get("count", 0), "dir": b.get("dir"),
                        "pruned": int(b.get("pruned") or 0), "warning": b.get("warning")}
            err = b.get("error") or ""
            return {"ns": ns, "ok": False, "skipped": bool(b.get("skipped")) or "No PVC" in err,
                    "partial": bool(b.get("partial")), "dir": b.get("dir"),
                    "count": 0, "error": err}

    if workers > 1 and len(namespaces) > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(namespaces))) as ex:
            results = list(ex.map(one, namespaces))     # ordre des namespaces conservé
    else:
        results = [one(ns) for ns in namespaces]
    backed_up = sum(1 for r in results if r["ok"])
    vol_total = sum(r["count"] for r in results if r["ok"])
    partial_ns = [r["ns"] for r in results if r.get("partial")]
    try:
        enforce_storage_quota(root)                     # une fois par passage, pas par namespace
    except Exception as e:
        print("Storage quota at the end of the run: %s" % e)
    audit("backup_all", namespaces=len(namespaces), backed_up=backed_up, volumes=vol_total, root=root,
          partial=partial_ns)
    return {"ok": True, "error": None, "results": results, "root": root,
            "namespaces": len(namespaces), "backed_up": backed_up, "volumes": vol_total,
            "partial": partial_ns, "filtered": bool(_ns_filter()), "selector_error": perr}


# ------------------------------------------------------------------------------
# Sauvegarde AUTOMATIQUE planifiée — tant que l'outil tourne, sauvegarde à
# intervalle régulier la config PV/PVC des namespaces autorisés par le filtre
# (= action_backup_all, en lecture seule côté cluster). Le dernier passage est
# persisté sur disque : l'intervalle est respecté même après un redémarrage.
# ------------------------------------------------------------------------------
AUTO_BACKUP = {"last_run": 0.0, "last_ok": None, "last_summary": "", "running": False, "policies": {}}


def _auto_backup_state_path():
    return os.path.join(CONFIG["backup_root"], ".auto_backup_state.json")


def _load_auto_backup_state():
    try:
        with open(_auto_backup_state_path(), encoding="utf-8") as f:
            st = json.load(f)
        for k in ("last_run", "last_ok", "last_summary"):
            if k in st:
                AUTO_BACKUP[k] = st[k]
        if isinstance(st.get("policies"), dict):
            AUTO_BACKUP["policies"] = {k: v for k, v in st["policies"].items() if isinstance(v, dict)}
    except Exception:
        pass                        # pas d'état = jamais exécutée


def _save_auto_backup_state():
    try:
        st = {k: AUTO_BACKUP[k] for k in ("last_run", "last_ok", "last_summary")}
        st["policies"] = dict(AUTO_BACKUP.get("policies") or {})
        _write_json_atomic(_auto_backup_state_path(), st, mode=0o644)
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


# ---- Politiques nommées ------------------------------------------------------
# Une politique = cible (namespaces par nom et/ou sélecteur d'étiquettes) + fréquence +
# rétention + politique HYCU optionnelle. Résolution : la PREMIÈRE politique (ordre de
# la liste) qui contient le namespace l'emporte ; sinon, politique PAR DÉFAUT (réglages
# auto_backup_* historiques). Les politiques s'appliquent à tous les clusters.
_POLICY_SEL_CACHE = {}
_POLICY_SEL_LOCK = threading.Lock()
_POLICY_SEL_TTL = 60.0


def _named_policies():
    """Politiques nommées normalisées (copies) ; liste vide si aucune."""
    out = []
    for p in (CONFIG.get("backup_policies") or []):
        if not isinstance(p, dict) or not str(p.get("name") or "").strip():
            continue
        try:
            iv = max(0.25, float(p.get("interval_hours", 24)))
            kp = max(0, int(p.get("keep", 15)))
        except (TypeError, ValueError):
            continue
        out.append({"name": str(p["name"]).strip(), "namespaces": list(p.get("namespaces") or []),
                    "label_selector": (p.get("label_selector") or "").strip(),
                    "interval_hours": iv, "keep": kp, "enabled": p.get("enabled", True) is not False,
                    "hycu_policy": (p.get("hycu_policy") or "").strip(),
                    "hycu_policy_name": (p.get("hycu_policy_name") or "").strip()})
    return out


def _policy_selector_sets(policies):
    """{nom de politique: namespaces correspondant à son sélecteur} sur le cluster ACTIF
    (un `kubectl get ns -l` par politique à sélecteur, mis en cache 60 s). Renvoie
    (ensembles, erreur) — une erreur n'est jamais assimilée à « aucun namespace »."""
    sels = tuple((p["name"], p["label_selector"]) for p in policies if p.get("label_selector"))
    if not sels:
        return {}, None
    key = (_current_cid(), sels)
    now = time.time()
    with _POLICY_SEL_LOCK:
        c = _POLICY_SEL_CACHE.get(key)
        if c and now - c["at"] <= _POLICY_SEL_TTL:
            return c["sets"], c["err"]
    sets, err = {}, None
    for name, sel in sels:
        data, e = kubectl_json(["get", "ns", "-l", sel])
        if e:
            err = "selector “%s” (policy %s): %s" % (sel, name, e)
            sets[name] = set()
            continue
        sets[name] = {(i.get("metadata") or {}).get("name") for i in (data or {}).get("items", [])}
    with _POLICY_SEL_LOCK:
        _POLICY_SEL_CACHE.clear()
        _POLICY_SEL_CACHE[key] = {"at": now, "sets": sets, "err": err}
    return sets, err


def _policy_of(ns, policies=None, sets=None):
    """Politique nommée du namespace, ou None = par défaut. Un namespace NOMMÉ
    explicitement dans une politique l'emporte sur un sélecteur d'étiquettes (choix
    délibéré de l'opérateur) ; sinon, première politique dont le sélecteur correspond."""
    pols = _named_policies() if policies is None else policies
    if not pols:
        return None
    for p in pols:
        if ns in p["namespaces"]:
            return p
    if sets is None:
        sets, _e = _policy_selector_sets(pols)
    for p in pols:
        if ns in sets.get(p["name"], ()):
            return p
    return None


def _policy_map(namespaces):
    """({namespace: politique nommée ou None}, erreur de sélecteur éventuelle)."""
    pols = _named_policies()
    if not pols:
        return {n: None for n in namespaces}, None
    sets, err = _policy_selector_sets(pols)
    return {n: _policy_of(n, pols, sets) for n in namespaces}, err


def _retention_for(ns):
    """(versions à conserver, mode) pour une sauvegarde de `ns` : celle de sa politique
    nommée, sinon les réglages par défaut. Appartenance invérifiable (sélecteur en
    erreur) -> AUCUNE purge (dans le doute, ne rien supprimer)."""
    pols = _named_policies()
    if not pols:
        return CONFIG.get("auto_backup_keep", 15), None
    sets, err = _policy_selector_sets(pols)
    p = _policy_of(ns, pols, sets)
    if p:
        return p["keep"], "count"
    if err:
        return 0, "count"
    return CONFIG.get("auto_backup_keep", 15), None


def _policy_interval_s(p):
    return max(0.25, float(p.get("interval_hours") or 24)) * 3600.0


def _policy_state(name):
    return AUTO_BACKUP.setdefault("policies", {}).setdefault(
        name, {"last_run": 0.0, "last_ok": None, "last_summary": ""})


def _policy_due(p, now):
    if not p.get("enabled", True):
        return False
    last = float(_policy_state(p["name"]).get("last_run") or 0)
    return (not last) or (now - last) >= _policy_interval_s(p)


def _hycu_assign_policy(policy_uuid, vg_uuids, share_uuids=None):
    path = "/policies/%s/assign" % urllib.parse.quote(policy_uuid)
    body = {"volumeGroupUuidList": sorted(set(vg_uuids)), "includeDependencies": False}
    if share_uuids:
        body["shareUuidList"] = sorted(set(share_uuids))
    return _rest("hycu", "POST", path, body=body)


def _policy_hycu_assign(p, namespaces):
    """Politique HYCU de la politique nommée : assignée aux Volume Groups (correspondance
    EXACTE uniquement) qui n'ont ENCORE aucune politique HYCU. Un volume déjà dans une
    autre politique HYCU n'est jamais modifié (signalé). Renvoie (ok, message)."""
    pol_uuid = p.get("hycu_policy") or ""
    if not pol_uuid or not namespaces:
        return True, ""
    if not SESSION_CREDS.get("hycu"):
        return True, "HYCU policy not applied (HYCU not connected)"
    items, herr = _hycu_list_vgs()
    if herr is not None:
        return False, "HYCU policy not applied (%s)" % herr
    todo, todo_shares, other = [], [], 0
    for ns in namespaces:
        m = action_hycu_match(ns, vg_items=items)
        if not m.get("ok"):
            continue
        for x in m.get("matches") or []:
            ident = x.get("hycu_vg_uuid") or x.get("hycu_share_uuid")
            if not (x.get("matched") and x.get("trusted") and ident):
                continue
            cur = (x.get("policy") or "").strip()
            if not cur or cur.lower() == "exclude":          # « Exclude » = non protégé dans HYCU
                (todo_shares if x.get("hycu_share_uuid") else todo).append(ident)
            elif cur != p.get("hycu_policy_name"):
                other += 1
    msgs, ok = [], True
    if todo or todo_shares:
        r = _hycu_assign_policy(pol_uuid, todo, todo_shares)
        ok = bool(r.get("ok"))
        audit("hycu_protect", ok=ok, auto=True, policy=pol_uuid, policy_name=p["name"],
              namespaces=namespaces, vgs=sorted(set(todo)), shares=sorted(set(todo_shares)))
        msgs.append(("%d volume(s) attached to HYCU policy “%s”"
                     % (len(set(todo)) + len(set(todo_shares)), p.get("hycu_policy_name") or pol_uuid)) if ok
                    else "HYCU assignment refused: %s" % r.get("error"))
    if other:
        msgs.append("%d volume(s) already in another HYCU policy (left unchanged)" % other)
    return ok, "; ".join(msgs)


def _policy_run(p, now=None):
    """Un passage d'une politique nommée sur tous les clusters : sauvegarde de ses
    namespaces (rétention de la politique) puis politique HYCU éventuelle."""
    now = time.time() if now is None else now
    if BULK["running"] or not ACTION_LOCK.acquire(blocking=False):
        return None
    AUTO_BACKUP["running"] = True
    dest = CONFIG.get("auto_backup_dest") or None
    try:
        parts = []
        cids = _cluster_ids()
        for cid in cids:
            try:
                with use_cluster(cid, req_timeout=60):
                    if cid == LOCAL_CID and len(cids) > 1 and not action_context().get("kubectl_ok"):
                        continue
                    r = action_backup_all(dest, kind="auto", internal=True, policy_scope=p)
                    ok, summary = _auto_backup_one(lambda d: r, dest)
                    if r.get("selector_error"):
                        ok, summary = False, summary + "; " + r["selector_error"]
                    done = [x["ns"] for x in (r.get("results") or []) if x.get("ok")]
                    hok, hmsg = _policy_hycu_assign(p, done)
                    if hmsg:
                        summary += "; " + hmsg
                    parts.append((_cluster_label(cid), ok and hok, summary))
            except Exception as e:
                parts.append((_cluster_label(cid), False, "error: %s" % e))
        ok = bool(parts) and all(x[1] for x in parts)
        summary = (parts[0][2] if len(parts) == 1 else
                   " | ".join("%s: %s" % (x[0], x[2]) for x in parts)) if parts else "no cluster available"
        summary = "Policy “%s”: %s" % (p["name"], summary)
        _policy_state(p["name"]).update({"last_run": now, "last_ok": ok, "last_summary": summary})
        _save_auto_backup_state()
        _apps_cache_clear()
        audit("auto_backup", ok=ok, summary=summary, policy=p["name"],
              **({"cluster": "*"} if len(parts) > 1 else {}))
        return ok
    finally:
        AUTO_BACKUP["running"] = False
        ACTION_LOCK.release()


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


def _prune_backups(root, ns, keep, protect=None, mode=None):
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
    mode = mode or (CONFIG.get("auto_backup_retention") or "count")   # politique nommée : « count » imposé
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
    # Rétention (compteur ou GFS) sur les sauvegardes automatiques ET manuelles (sinon
    # elles s'accumulent sans limite) — JAMAIS sur une sauvegarde de sécurité prise
    # avant une restauration (pre_restore : seul filet d'une opération destructive).
    # Compatibilité : une sauvegarde d'un ancien schéma (sans « kind » ni « schema »)
    # garde le comportement historique (soumise à la rétention).
    def _prunable(b):
        idx = b.get("index") or {}
        return idx.get("kind") in ("auto", "manual") or ("kind" not in idx and "schema" not in idx)
    backups = [b for b in list_backups(ns, root) if _prunable(b)]   # triée : plus récentes d'abord
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
            print("Auto backup retention: cannot delete %s: %s" % (b["path"], e))
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
        AUTO_BACKUP.update({"last_summary": "postponed: an operation is running"})
        return None
    AUTO_BACKUP["running"] = True
    try:
        if runner is not None:                  # tests : cluster courant uniquement
            parts = [(None,) + _auto_backup_one(runner, dest)]
        else:
            parts = []
            cids = _cluster_ids()
            for cid in cids:
                try:
                    with use_cluster(cid, req_timeout=60):
                        # Cluster local non configuré (outil utilisé uniquement avec des
                        # clusters ajoutés) : ignoré sans le compter comme un échec.
                        if cid == LOCAL_CID and len(cids) > 1 and not action_context().get("kubectl_ok"):
                            continue
                        parts.append((_cluster_label(cid),) + _auto_backup_one(
                            lambda d: action_backup_all(d, kind="auto", internal=True, policy_scope=None), dest))
                except Exception as e:          # un cluster en erreur n'arrête pas les autres
                    parts.append((_cluster_label(cid), False, "error: %s" % e))
        ok = bool(parts) and all(p[1] for p in parts)
        if len(parts) <= 1:
            summary = parts[0][2] if parts else "no cluster available"
        else:
            summary = " | ".join("%s: %s" % (p[0], p[2]) for p in parts)
        if runner is None and CONFIG.get("s3_auto_upload") and SESSION_CREDS.get("s3"):
            # Filet de l'outil lui-même : configuration, politiques et coffre chiffré,
            # exportés (un objet par jour) à côté des sauvegardes. Jamais bloquant.
            try:
                tok, tinfo = s3_upload_tool_kit()
                summary += "; tool kit exported" if tok else "; tool kit export failed: %s" % tinfo
            except Exception as e:
                summary += "; tool kit export failed: %s" % e
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
    summary = ("%d namespace(s) backed up, %d volume(s)" % (r.get("backed_up", 0), r.get("volumes", 0))
               if r.get("ok") else (r.get("error") or "failed"))
    if failed:
        summary += "; %d FAILED: %s" % (len(failed), ", ".join(failed[:5]))
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
            summary += "; %d old version(s) deleted" % removed
    return ok, summary


def _auto_backup_loop():
    """Thread démon : vérifie ~toutes les 30 s si une sauvegarde auto est due.
    Tick sauté si une restauration est en cours (ACTION_LOCK pris) — la sauvegarde
    repassera au tick suivant."""
    _load_auto_backup_state()
    while True:
        time.sleep(30)
        for p in _named_policies():
            try:
                if _policy_due(p, time.time()) and not ACTION_LOCK.locked():
                    _policy_run(p)
            except Exception as e:
                print("Policy %s: unexpected error: %s" % (p.get("name"), e), flush=True)
                _policy_state(p["name"]).update({"last_run": time.time(), "last_ok": False,
                                                 "last_summary": "Policy “%s”: error: %s" % (p["name"], e)})
                _save_auto_backup_state()
        try:
            if _auto_backup_due(time.time()) and not ACTION_LOCK.locked():
                _auto_backup_run()
        except Exception as e:
            # Une exception (dossier en lecture seule, disque plein…) compte comme un
            # passage en échec : last_run est posé pour NE PAS relancer toutes les 30 s.
            print("Auto backup: unexpected error: %s" % e, flush=True)
            AUTO_BACKUP.update({"last_run": time.time(), "last_ok": False,
                                "last_summary": "error: %s" % e})
            _save_auto_backup_state()
            try:
                audit("auto_backup", ok=False, summary="error: %s" % e)
            except Exception:
                pass
        try:
            enforce_storage_quota()
        except Exception as e:
            print("Storage quota: unexpected error: %s" % e)
        try:
            # Compaction quotidienne du journal d'audit (rétention audit_retention_days).
            if time.time() - _AUDIT_COMPACT["last"] >= 86400:
                n = _audit_compact()
                if n:
                    print("Audit log: %d entry(ies) older than %s days purged."
                          % (n, CONFIG.get("audit_retention_days")))
        except Exception as e:
            print("Audit log compaction: unexpected error: %s" % e)


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
            "next_due": (last + itv) if (enabled and last) else None,
            "policies": [dict(p, last_run=(_policy_state(p["name"]).get("last_run") or None),
                              last_ok=_policy_state(p["name"]).get("last_ok"),
                              last_summary=_policy_state(p["name"]).get("last_summary") or "",
                              next_due=((_policy_state(p["name"]).get("last_run") or 0) + _policy_interval_s(p))
                              if (p["enabled"] and _policy_state(p["name"]).get("last_run")) else None)
                         for p in _named_policies()]}


def action_backups_delete(payload):
    """Supprime des VERSIONS de sauvegarde de configuration d'un namespace (purge
    manuelle). Garde-fous : chemins sous les dossiers de sauvegarde de l'outil, dossier
    réellement une sauvegarde de CE namespace (index.json), jamais la sauvegarde de
    sécurité d'une restauration en cours, aucune purge pendant une opération."""
    ns = (payload.get("ns") or "").strip()
    paths = [p for p in (payload.get("paths") or []) if isinstance(p, str) and p.strip()]
    if not K8S_NAME_RE.match(ns) or not paths:
        return _err("Namespace or versions missing.")
    flt = _ns_filter()
    if flt and ns not in flt:
        return _err("Namespace '%s' not allowed." % ns)
    if ACTION_LOCK.locked() or AUTO_BACKUP.get("running"):
        return _err("An operation is running: try again when it has finished.")
    txn = _load_txn(ns) or {}
    protected = os.path.realpath(txn["backup_dir"]) if txn.get("backup_dir") else None
    removed, errors = 0, []
    for p in paths:
        full = _safe_backup_path(p)
        idx_path = os.path.join(full, "index.json") if full else ""
        try:
            idx = json.load(open(idx_path, encoding="utf-8")) if full and os.path.isfile(idx_path) else None
        except (OSError, ValueError):
            idx = None
        if not full or not idx or os.path.basename(os.path.dirname(full)) != ns \
                or (idx.get("namespace") not in (None, ns)):
            errors.append("%s: not a backup of “%s”" % (os.path.basename(p.rstrip("/\\")), ns))
            continue
        if protected and os.path.realpath(full) == protected:
            errors.append("%s: used by a running restore (kept)" % os.path.basename(full))
            continue
        try:
            shutil.rmtree(full)
            removed += 1
            _catalog_forget_path(full)
        except OSError as e:
            errors.append("%s: %s" % (os.path.basename(full), e))
    if removed:
        _apps_cache_clear()
    audit("backup_delete", namespace=ns, removed=removed, errors=len(errors))
    return {"ok": not errors, "removed": removed, "errors": errors,
            "error": ("; ".join(errors) if errors else None)}


def action_policy_members():
    """Namespaces du cluster ACTIF par politique (aperçu « qui est protégé par quoi »)."""
    info = action_namespaces()
    if not info.get("ok"):
        return _err(info.get("error") or "Namespace list unavailable.")
    pmap, err = _policy_map(info.get("namespaces") or [])
    members = {"": []}
    for p in _named_policies():
        members[p["name"]] = []
    for ns, p in sorted(pmap.items()):
        members.setdefault((p or {}).get("name", ""), []).append(ns)
    return _ok(members=members, selector_error=err)


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

    metric("hycu_build_info", 1, "Build version (version label).", labels='{version="%s"}' % VERSION)
    metric("hycu_up", 1, "1 if the tool responds.")
    metric("hycu_operation_running", 1 if ACTION_LOCK.locked() else 0,
           "1 if a destructive operation (restore/clone) is running.")
    metric("hycu_auto_backup_enabled", 1 if CONFIG.get("auto_backup_enabled") else 0,
           "1 if automatic configuration backup is enabled.")
    metric("hycu_auto_backup_interval_seconds", int(itv), "Configured interval (s).")
    metric("hycu_auto_backup_last_run_timestamp_seconds", int(last),
           "Unix timestamp of the last automatic backup (0 if never).", typ="gauge")
    metric("hycu_auto_backup_last_success", 1 if AUTO_BACKUP.get("last_ok") else 0,
           "1 if the last automatic backup succeeded.")
    with CLUSTERS_LOCK:
        n_extra = len(CLUSTERS)
    metric("hycu_clusters_registered", 1 + n_extra,
           "Known Kubernetes clusters (local + added from the interface).")
    try:
        du = shutil.disk_usage(CONFIG["backup_root"])
        metric("hycu_backup_storage_total_bytes", du.total, "Size of the backup file system.")
        metric("hycu_backup_storage_free_bytes", du.free, "Free space on the backup file system.")
    except OSError:
        pass
    if CLUSTER_HEALTH:
        out.append("# HELP hycu_cluster_reachable 1 if the last cluster "
                   "health check succeeded.\n# TYPE hycu_cluster_reachable gauge\n")
        for cid, h in sorted(CLUSTER_HEALTH.items()):
            out.append('hycu_cluster_reachable{cluster="%s"} %d\n' % (cid, 1 if h.get("ok") else 0))
    # État des connexions (par système) — un seul bloc HELP/TYPE, plusieurs lignes.
    out.append("# HELP hycu_connected 1 if the external system is "
               "connected (current session).\n# TYPE hycu_connected gauge\n")
    for sysname in ("hycu", "nutanix", "prismcentral", "s3"):
        out.append('hycu_connected{system="%s"} %d\n' % (sysname, 1 if SESSION_CREDS.get(sysname) else 0))
    return "".join(out)


# ------------------------------------------------------------------------------
# Vues « à la HYCU » (lecture seule) : Applications (namespaces + protection /
# conformité) et Tâches (historique des opérations, tiré du journal d'audit).
# ------------------------------------------------------------------------------
def _backup_freshness_s(policy=None):
    """Âge maximal d'une sauvegarde de config pour être « conforme » : l'intervalle de
    la politique (nommée si `policy`, sinon par défaut) si elle est active, sinon 24 h
    (+10 % de marge)."""
    if policy:
        base = _policy_interval_s(policy) if policy.get("enabled", True) else 24 * 3600.0
    else:
        base = _auto_backup_interval_s() if CONFIG.get("auto_backup_enabled") else 24 * 3600.0
    return base * 1.1


def _policy_view(p):
    """Politique d'une ligne Applications (nom vide = politique par défaut)."""
    if p:
        return {"name": p["name"], "enabled": p["enabled"], "interval_hours": p["interval_hours"]}
    return {"name": "", "enabled": bool(CONFIG.get("auto_backup_enabled")),
            "interval_hours": _auto_backup_interval_s() / 3600.0}


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
APP_UNASSIGNED = "volumes without workload"     # pseudo-application : PVC qu'aucun workload ne monte


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
                return err or "empty response"
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
                return {}, {}, ("%s (cluster-wide list refused; per-namespace fallback not "
                                "attempted beyond %d namespaces — grant a cluster-wide list permission)" % (err, fb_max))
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
    pmap, _perr = _policy_map(names)
    apps = []
    for ns in names:
        pol = pmap.get(ns)
        fresh_ns = _backup_freshness_s(pol) if pol else fresh
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
                "missing": missing, "compliant": bool(last and (now - last) <= fresh_ns),
                "ns_apps": len(ns_apps), "policy": _policy_view(pol)}
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
# Dernière correspondance PVC <-> Volume Group HYCU par (cluster, namespace) : calculée
# par « Analyser », réutilisée quelques minutes par la garde anti-stale des opérations
# HYCU (protéger, restaurer) au lieu de re-parcourir tous les VG HYCU à chaque clic.
_MATCH_CACHE = {}
_MATCH_CACHE_LOCK = threading.Lock()
_MATCH_CACHE_TTL = 600
_APPS_INFLIGHT = {}


def _match_cache_clear():
    with _MATCH_CACHE_LOCK:
        _MATCH_CACHE.clear()


def _apps_cache_clear():
    _match_cache_clear()          # toute écriture invalide aussi la correspondance mémorisée
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
                return dict(meta, ok=False, skipped=True, error="Local cluster not configured.", apps=[])
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
    out.write("cluster;workspace;namespace;application;type;protected;compliant;versions;last_backup;volumes;politique_h;last_s3_export\n")
    itv = round((d["apps"].get("policy") or {}).get("interval_hours") or 24, 1)
    for a in d["apps"].get("apps") or []:
        last = (datetime.datetime.fromtimestamp(a["last_backup"]).isoformat(timespec="seconds")
                if a.get("last_backup") else "")
        ns = a.get("namespace") or a["name"]
        out.write("%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s\n" % (
            a.get("cluster") or "", a.get("workspace") or "", ns, a["name"], a.get("type") or "",
            "yes" if a.get("protected") else "no", "yes" if a.get("compliant") else "NO",
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
    ago = lambda ts: (datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "never")
    ic = lambda ok: ('<span class="ok">✓</span>' if ok else '<span class="ko">✕</span>')
    exp = d.get("s3_exports") or {}
    typ = {"stateful": "Stateful", "stateless": "Stateless", "empty": "Empty"}
    rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td><b>%s</b></td><td>%s</td><td class=c>%s</td><td class=c>%s</td>"
        "<td class=c>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc_(a.get("cluster")), esc_(a.get("workspace") or "—"), esc_(a.get("namespace") or a["name"]),
            esc_(a["name"]), esc_(typ.get(a.get("type"), "—")),   # « Vide » traduit via la paire >Vide<
            ic(a.get("protected")), ic(a.get("compliant")), a.get("backups") or 0,
            esc_(ago(a.get("last_backup"))),
            esc_((exp.get(a.get("namespace") or a["name"]) or "—")[:16].replace("T", " "))) for a in apps)
    hrows = "".join("<tr><td>%s</td><td class=c>%s</td><td>%s</td></tr>"
                    % (esc_(cid), ic(h.get("ok")), esc_(h.get("error") or "reachable"))
                    for cid, h in sorted((d.get("health") or {}).items()))
    jrows = "".join("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class=c>%s</td></tr>" % (
        esc_(j.get("ts")), esc_(j.get("event")), esc_(j.get("namespace") or "—"),
        esc_(j.get("cluster") or "—"), esc_(j.get("status")))
        for j in (d["jobs"].get("jobs") or [])[:30])
    s3txt = ("enabled (encrypted)" if d["s3"].get("encrypt") else "enabled") if d["s3"].get("auto_upload")         else ("configured, auto export disabled" if d["s3"].get("configured") else "not configured")
    return ('<!doctype html><html lang="en"><head><meta '
            'charset="utf-8">\n<title>Kubernetes Protection '
            "Report</title><style>\nbody{font-family:Segoe "
            "UI,Roboto,sans-serif;color:#2A2E44;margin:30px;background:#F3F4F9}\nh1{color:#41327C;font-size:22px} "
            "h2{color:#4B5274;font-size:16px;margin-top:26px}\ntable{border-collapse:collapse;width:100%%;background:#fff;font-size:13px}\nth{background:#41327C;color:#fff;text-align:left;padding:7px "
            "10px;font-size:11px;text-transform:uppercase}\ntd{padding:6px "
            "10px;border-bottom:1px solid #E3E7EE} "
            ".c{text-align:center}\n.ok{color:#05A274;font-weight:700}.ko{color:#E9605A;font-weight:700}\n.kpi{display:inline-block;background:#fff;border-radius:6px;padding:12px "
            "22px;margin:4px 10px 4px 0;\n     box-shadow:0 1px 2px "
            "rgba(65,50,124,.12)} .kpi "
            "b{font-size:22px;color:#41327C;display:block}\nfooter{margin-top:26px;color:#6B7089;font-size:11px}</style></head><body>\n<h1>Kubernetes "
            "application protection report</h1>\n<div>Generated on %s · tool "
            'v%s</div>\n<div style="margin:14px 0">\n<span '
            "class=kpi><b>%d</b>applications</span><span "
            "class=kpi><b>%d/%d</b>protected</span>\n<span "
            "class=kpi><b>%d/%d</b>compliant</span>\n<span "
            "class=kpi><b>%s</b>automatic backup</span>\n<span class=kpi><b>%d / %d "
            "/ %d</b>jobs ok / failed / simulation</span></div>\n<h2>Applications "
            "(configuration "
            "protection)</h2>\n<table><tr><th>Cluster</th><th>Workspace</th><th>Namespace</th><th>Application</th><th>Type</th><th>Protected</th>\n<th>Compliant</th><th>Versions</th><th>Last "
            "backup</th><th>Last S3 export</th></tr>%s</table>\n<h2>Cluster "
            "health</h2>\n<table><tr><th>Cluster</th><th>Reachable</th><th>Details</th></tr>%s</table>\n<h2>Recent "
            "jobs "
            "(30)</h2>\n<table><tr><th>Timestamp</th><th>Job</th><th>Application</th><th>Cluster</th><th>Status</th></tr>%s</table>\n<h2>Off-cluster "
            "export</h2><div>S3 object storage: %s.</div>\n<footer>Report generated "
            "by the HYCU · Kubernetes · Nutanix tool — automatic backup policy: "
            "%s, interval %s h, retention %s.</footer></body></html>" % (
        esc_(d["generated"]), esc_(d["version"]), n, prot, n, comp, n,
        "enabled" if ab.get("enabled") else "disabled",
        jc.get("success", 0), jc.get("failed", 0), jc.get("simulation", 0),
        rows or "<tr><td colspan=10>no application</td></tr>",
        hrows or "<tr><td colspan=3>no check executed yet</td></tr>",
        jrows or "<tr><td colspan=5>no job</td></tr>", esc_(s3txt),
        "enabled" if ab.get("enabled") else "disabled",
        round(ab.get("interval_hours") or 24, 1),
        ("GFS %s d / %s w / %s m" % (ab.get("gfs", {}).get("daily"), ab.get("gfs", {}).get("weekly"),
                                          ab.get("gfs", {}).get("monthly"))
         if ab.get("retention") == "gfs" else "%s versions" % ab.get("keep"))))


# ------------------------------------------------------------------------------
# Page d'AIDE embarquée (« ? » en haut à droite -> Aide) : guide/tutoriel servi par
# l'outil lui-même (GET /help) — fonctionne hors-ligne / site isolé, traduit via
# l'i18n comme le reste. Contenu en sections ancrées avec sommaire.
# ------------------------------------------------------------------------------
HELP_SECTIONS = [
    ("quick-start", "Quick start", "\n<ol>\n<li><b>Register your sources</b>: ⚙ (top right) → <b>Sources</b> → HYCU, Prism Central/Element, and "
                                      "your <b>Kubernetes clusters</b> if needed. Credentials stay in memory (or in the encrypted "
                                      "vault).</li>\n<li><b>Back up the configuration</b>: <b>Applications</b> page → tick your applications → "
                                      "<b>Back up</b>. Then enable the <b>automatic backup</b> (Policies page).</li>\n<li><b>Test a restore</b> in "
                                      "<b>simulation mode</b> (top banner, on by default): Applications → one application → <b>Restore</b>. "
                                      'Nothing runs while simulation is on.</li>\n</ol>\n<div class="tip">The tool orchestrates the '
                                      "<b>configuration</b> (PV/PVC manifests, objects); the volume <b>data</b> is protected by <b>HYCU</b> (Nutanix Volume Groups). They complement each other.</div>"),
    ("interface", "The interface", "\n<ul>\n<li><b>Top bar</b>: HYCU/PE/PC status dots · <b>active cluster</b> (click to switch or add one) · ⚙ <b>Sources / Settings</b> · "
                                 "<b>?</b> Help / About · <b>EN/FR</b>.</li>\n<li><b>Dashboard</b>: protection/compliance rings, policy, sources, cluster, job "
                                 "activity.</li>\n<li><b>Applications</b>: one row per <b>application</b> (a namespace can hold several: workloads are grouped by the "
                                 "<code>app.kubernetes.io/instance</code>, <code>app.kubernetes.io/name</code> or <code>app</code> label), with its namespace and its "
                                 "<b>type</b>: <b>Stateful</b> (mounts volumes) or <b>Stateless</b> (configuration only). Select, then act at the top right: <b>Back up · "
                                 "Restore · Set Policy · Verify</b>. Backups stay <b>per namespace</b> (one consistent recipe); Restore targets the chosen application. "
                                 "<b>Active cluster / All clusters</b> toggle (grouped by NKP workspace).</li>\n<li><b>Policies</b>: automatic configuration backup "
                                 "(frequency, retention) + HYCU policies.</li>\n<li><b>Jobs</b>: history (success/failed/simulation), cluster of each job, <b>HTML/CSV "
                                 "report</b> buttons.</li>\n<li><b>The Simulation banner</b>: while it is on, NO destructive command runs — the tool shows what it would do. Turn it off only when ready to act.</li>\n</ul>"),
    ("clusters", "Kubernetes clusters (multi-cluster & NKP)", "\n<ul>\n<li>The <b>local cluster</b> comes from the configuration (kubeconfig/context — ⚙ → "
                                                              "Settings).</li>\n<li><b>Add a cluster</b>: ⚙ → Sources → <b>Add a Kubernetes cluster</b> → "
                                                              "load or paste its kubeconfig → <b>Test &amp; add</b>. The tool analyses the "
                                                              "authentication (expired token, exec plugin…) and warns you.</li>\n<li><b>NKP</b>: make the "
                                                              "management cluster active, then Sources → <b>Discover NKP workspaces</b> → tick the "
                                                              "clusters → <b>Import</b> (elevated rights required, explicit warning).</li>\n<li>Each "
                                                              "cluster's backups are stored <b>separately</b>, and a backup only restores onto its "
                                                              "source cluster.</li>\n<li>Kubeconfigs are <b>secrets</b>: session memory + encrypted vault (never in clear on disk).</li>\n</ul>"),
    ("backup", "Back up", "\n<ul>\n<li><b>Applications → Back up</b>: exports and cleans the <b>PV/PVC</b> manifests (the restore “recipe”) + a <b>snapshot of the other objects</b> (Deployments, Services, "
                                  "ConfigMaps, Secrets…) into <code>resources.json</code> — Secret data is <b>encrypted</b> (<code>secrets.enc</code>, vault passphrase); without an unlocked vault or "
                                  "<code>HYCU_VAULT_PASSPHRASE</code> it stays in clear and the backup says so (<code>backup_secrets</code> setting).</li>\n<li><b>Back up all (filtered)</b>: every allowed namespace "
                                  "at once; a namespace with no PVC <b>and no workload</b> is skipped. A <b>stateless</b> namespace (workloads without volume) is backed up: its snapshot is enough to restore "
                                  "it.</li>\n<li>Default folder: <code>hycu-backups/</code> — <b>copy it off the cluster</b> (.zip download in the restore wizard, or automatic S3 export, see below).</li>\n<li>The "
                                  "namespace filter (funnel) and the <b>label selector</b> (Settings) bound what the tool sees and touches.</li>\n<li><b>Large clusters</b>: each backup folder carries a "
                                  "<code>_catalog.json</code> catalog (derived summary, rebuilt if missing — restores always read <code>index.json</code>), the inventory is cached for a few dozen seconds "
                                  "(<b>Refresh</b> forces a recompute), the page is paginated by 100 and an “all namespaces” pass reads PVs once and works in parallel. Settings: <code>apps_fallback_max</code>, <code>apps_cache_ttl_s</code>, <code>backup_parallel</code>.</li>\n</ul>"),
    ("policies", "Automatic backup & retention", "\n<ul>\n<li><b>Policies</b> page: enable the automatic backup (interval in hours). It covers "
                                                         "<b>all known clusters</b> while the tool runs; a missed run is caught up at "
                                                         "startup.</li>\n<li><b>Retention</b>: “N versions” (default), or <b>GFS</b> — the most "
                                                         "recent of each day / week / month (7 d / 4 wk / 12 mo by default).</li>\n<li>The backup of "
                                                         "an in-progress restore is never pruned by retention.</li>\n<li><b>Storage guardrails</b> "
                                                         "(Settings): free-space floor (backups refused below it), optional global quota (oldest "
                                                         "pruned above it), bounded job history (31 d by default). The dashboard's <b>Storage</b> tile watches the disk.</li>\n</ul>"),
    ("hycu", "Protect the data in HYCU", "\n<ul>\n<li><b>Applications → Set Policy</b>: the tool "
                                               "matches each PVC to its HYCU <b>Volume Group</b> (UUID "
                                               "match), assigns a HYCU policy and can start a "
                                               "backup.</li>\n<li>A “by name” match must be "
                                               "<b>confirmed</b> (checkbox); an ambiguity is never resolved automatically.</li>\n</ul>"),
    ("restore", "Restore — the 5 flows", "\n<ol>\n<li><b>Restore the whole application (copy)</b>: volumes + objects into the same namespace (suffix) or another one. The original is untouched. Ideal to verify a backup.</li>\n<li><b>Restore storage in place</b>: HYCU restores the data "
                                                "<b>into</b> the original volumes; the application is stopped then restarted. Pick a restore point per volume (most recent pre-selected).</li>\n<li><b>Restore storage to new volumes</b>: new Volume Groups are cloned and the application "
                                                "re-attached; original volumes are kept.</li>\n<li><b>Restore configuration objects</b>: re-applies selected objects from a backup snapshot, with a <b>diff preview</b> before any apply. Volumes and data untouched.</li>\n</ol>\n<div "
                                                'class="tip"><b>Stateless application (no volume)?</b> Click <b>Restore</b> on its row: the wizard offers only two paths — <b>copy</b> (clone of its workloads and dependencies, same namespace with suffix or another namespace, as for a stateful '
                                                "application) and <b>configuration objects</b> (preselected) with <b>its</b> objects pre-ticked (workloads, Services, referenced ConfigMaps/Secrets) — the other applications of the namespace are left untouched. For a <b>stateful</b> "
                                                "application, only <b>its</b> volumes are preselected in the storage paths. <b>The whole namespace</b> (e.g. mariadb + wordpress split by their labels): tick several applications of the same namespace then <b>Restore the namespace</b>, or "
                                                'click the “whole namespace” link in the wizard.</div>\n<div class="tip">Recommended flow: run in <b>simulation</b> first (plan shown, no effect), review the summary, then turn simulation off and relaunch. In real mode the tool asks you to '
                                                '<b>retype the cluster name</b>. After a real restore, <b>Verification</b> opens automatically (PVC Bound, pods Running).</div>\n<div class="tip">If a step fails, the sequence <b>stops</b> and the application stays stopped (never restarted on '
                                                'inconsistent volumes). Fix then <b>relaunch</b>: resumption is idempotent and original replicas are remembered.</div>\n<div class="tip"><b>Application deleted from the cluster?</b> As long as its backups exist, it stays listed under '
                                                "<b>Applications</b> with the “Deleted — restorable” badge. Click <b>Restore</b>: the recovery flow recreates everything (namespace, PV/PVC, workloads, non-redacted dependencies) from the selected backup, <b>reusing the original volumes</b> — "
                                                "nothing to enter. If a Volume Group was deleted with the namespace but remains “Protected deleted” in HYCU, it is <b>restored automatically</b> (HYCU connected). Untick “reuse” only if you restored the data onto new volumes. No DR override is required: the recovery stays on the same cluster/context.</div>"),
    ("bulk", "Bulk restore (same cluster)", "\n<ul>\n<li><b>Applications → Bulk restore</b>: recreates at once <b>every deleted namespace</b> of the active cluster from its latest backup prior to a <b>reference time</b> (namespace, "
                                                      "PV/PVC, workloads, dependencies, Secrets when the vault is unlocked, Volume Groups restored by HYCU if they are gone, stateless applications). Namespaces <b>still present</b> are "
                                                      "skipped: a live application is restored from its own row.</li>\n<li><b>Prepare the plan</b> first shows the selected namespaces (chosen backup, content, warnings: redacted Secrets or "
                                                      "encrypted with a locked vault, partial backup, no snapshot) and the skipped ones, with the reason.</li>\n<li><b>Simulate</b> runs the plan in simulation, in the background, with a "
                                                      "journal per namespace; <b>Start (real)</b> is only possible after a complete, failure-free simulation of the <b>same</b> plan, with the Simulation banner off and the cluster "
                                                      "confirmed.</li>\n<li><b>Sequential</b> execution (each HYCU restore takes minutes: expect hours for hundreds of namespaces); <b>Stop</b> finishes the current namespace; <b>Resume</b> "
                                                      "replays only the remaining or failed namespaces — a namespace already recreated is never redone. The journal (<code>_bulk_restore.json</code>) survives a restart; the automatic backup is suspended during the run.</li>\n</ul>"),
    ("s3", "S3 export (optional)", "\n<ul>\n<li>⚙ → Sources → <b>S3 object storage</b>: S3-compatible endpoint (Nutanix "
                                    "Objects, MinIO, AWS…), bucket, access keys → <b>Test &amp; connect</b>.</li>\n<li>Tick "
                                    "<b>Automatic export</b>: every successful backup also goes as a <code>.zip</code> to the "
                                    "bucket — the safety net lives off-cluster.</li>\n<li>Optional <b>encryption</b>: objects "
                                    "are encrypted before upload; decryption: <code>python3 hycu_k8s_nutanix.py --decrypt "
                                    "file.zip.enc</code>.</li>\n<li><b>Import from the bucket</b> (same card): repatriates "
                                    "exports to <code>hycu-backups/_imports/…</code> — the return path, essential for disaster recovery.</li>\n</ul>"),
    ("dr", "Disaster recovery (DR)", "\n<ol>\n<li><b>Prepare the way back</b>: enable the automatic S3 export (preferably encrypted) — the safety net must live off-cluster. Keep safe: "
                                      "<code>hycu_config.json</code>, <code>hycu_secrets.enc</code>, the vault passphrase and the export passphrase (DR kit).</li>\n<li><b>On the day</b>: "
                                      "relaunch the tool (workstation or standby cluster), reconnect HYCU/Prism, add the TARGET cluster (⚙ → Sources) and make it active. Repatriate the "
                                      "backups: S3 card → <b>Import from the bucket</b>.</li>\n<li><b>Restore the data</b>: in HYCU, restore/clone the application's Volume Groups to the target "
                                      "site, and note their UUIDs.</li>\n<li><b>Enable the override</b>: ⚙ → Settings → <b>Allow DR restore</b> (for the duration of the "
                                      "operation).</li>\n<li><b>Wizard → DR restore</b>: pick the source backup (lost cluster or S3 import), the target namespace, paste each restored VG's "
                                      "UUID, remap the StorageClass if the target site uses another one — simulation first, then real (target cluster retyped).</li>\n<li><b>No manual entry "
                                      "(HYCU connected)</b>: the <b>“Create the volumes automatically via HYCU”</b> button clones the Volume Groups from their HYCU backups and fills in the "
                                      "new IDs itself — no UUID to copy anymore. In simulation, only the plan is shown.</li>\n<li><b>Afterwards</b>: verify the application, re-protect its "
                                      'Volume Groups in HYCU, disable the DR override.</li>\n</ol>\n<div class="tip">The rest of the time, keep “Allow DR restore” disabled: the '
                                      "cross-cluster/context guard protects against accidental crossed restores. A Secret redacted at backup time is never restored: re-provision it from its source. An <b>encrypted</b> Secret is recreated as soon as the vault is unlocked.</div>"),
    ("report", "Report & monitoring", "\n<ul>\n<li><b>Jobs</b> page → <b>HTML report</b> "
                                         "(compliance: applications, RPO, cluster health, jobs) "
                                         "or <b>CSV</b> (Excel).</li>\n<li><code>GET "
                                         "/metrics</code>: Prometheus metrics (local only) — "
                                         "tool up, auto backup, reachable clusters, "
                                         "connections.</li>\n<li><b>Cluster health</b> is checked periodically (dots in Sources).</li>\n</ul>"),
    ("security", "Security in short", "\n<ul>\n<li>Server on <b>127.0.0.1 only</b>, anti-CSRF, simulation mode "
                                     "by default, cluster confirmation before any real action, full audit "
                                     "log.</li>\n<li>Credentials and kubeconfigs: <b>session memory</b> "
                                     "(locked at each new browser session), optional encrypted vault (master "
                                     "passphrase).</li>\n<li>In Kubernetes mode, the security boundary is the "
                                     "tool's <b>namespace RBAC</b>: whoever can port-forward is an operator.</li>\n</ul>"),
    ("troubleshooting", "Quick troubleshooting", "\n<table><tr><th>Symptom</th><th>Lead</th></tr>\n<tr><td>“Context: unavailable”</td><td>kubectl missing "
                                           "from PATH or context not configured (⚙ → Settings).</td></tr>\n<tr><td>“Namespace not "
                                           "allowed”</td><td>Outside the namespace filter (funnel) or the label "
                                           "selector.</td></tr>\n<tr><td>Namespace destroyed, application gone?</td><td>It stays listed as long as a "
                                           "backup exists (“Deleted — restorable” badge): Restore button → recovery from the "
                                           "backup.</td></tr>\n<tr><td>Connections ask to be unlocked again</td><td>Expected: new browser session = "
                                           "credentials locked. Enter the vault passphrase.</td></tr>\n<tr><td>“Cluster “x” unknown”</td><td>Cluster "
                                           "removed or session locked: unlock the vault or pick a cluster again (top bar).</td></tr>\n<tr><td>“This "
                                           "backup comes from cluster “x””</td><td>Select the backup's source cluster in the top "
                                           "bar.</td></tr>\n<tr><td>“Interrupted” sequence</td><td>Read the failing step in the log, fix, relaunch "
                                           "(idempotent resumption).</td></tr>\n<tr><td>S3 export fails with 403</td><td>Keys refused, or server "
                                           'clock skewed (SigV4 requires accurate time).</td></tr>\n</table>\n<div class="tip">Full guide: the repository\'s <code>README.md</code> / <code>README.fr.md</code> (installation, detailed configuration, Kubernetes deployment).</div>'),
]


def help_html():
    toc = "".join('<a href="#%s">%s</a>' % (sid, title) for sid, title, _ in HELP_SECTIONS)
    body = "".join('<section id="%s"><h2>%s</h2>%s</section>' % (sid, title, html)
                   for sid, title, html in HELP_SECTIONS)
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">\n<meta '
            'name="viewport" content="width=device-width, '
            'initial-scale=1">\n<title>Help — Kubernetes Protection on '
            "Nutanix</title><style>\nbody{font-family:Segoe "
            "UI,Roboto,sans-serif;color:#2A2E44;margin:0;background:#F3F4F9}\nheader{background:#41327C;color:#fff;padding:22px "
            "34px}\nheader h1{margin:0;font-size:22px;font-weight:600}\nheader "
            ".sub{color:#B8B4FC;font-size:13px;margin-top:4px}\n.wrap{display:flex;gap:26px;max-width:1180px;margin:0 "
            "auto;padding:24px "
            "20px}\nnav{flex:none;width:250px;position:sticky;top:16px;align-self:flex-start;background:#fff;\n "
            "   border-radius:8px;padding:12px 0;box-shadow:0 1px 3px "
            "rgba(65,50,124,.12)}\nnav a{display:block;padding:7px "
            "16px;color:#3D4464;text-decoration:none;font-size:13.5px;border-left:3px "
            "solid transparent}\nnav "
            "a:hover{background:#F3EFFD;border-left-color:#7530F0;color:#41327C}\nmain{flex:1;min-width:0}\nsection{background:#fff;border-radius:8px;padding:18px "
            "24px;margin-bottom:18px;\n        box-shadow:0 1px 2px "
            "rgba(65,50,124,.08);scroll-margin-top:14px}\nh2{color:#41327C;font-size:17px;margin:0 "
            "0 10px}\nul,ol{margin:6px 0;padding-left:22px} li{margin:5px "
            "0;font-size:14px;line-height:1.55}\ncode{background:#F3EFFD;border-radius:3px;padding:1px "
            "5px;font-size:12.5px;color:#41327C}\n.tip{background:#F7F5FD;border-left:3px "
            "solid #7530F0;border-radius:0 6px 6px 0;padding:10px 14px;\n     "
            "font-size:13.5px;margin-top:10px;line-height:1.5}\ntable{border-collapse:collapse;width:100%%;font-size:13.5px}\nth{background:#41327C;color:#fff;text-align:left;padding:7px "
            "10px;font-size:11px;text-transform:uppercase}\ntd{padding:7px "
            "10px;border-bottom:1px solid "
            "#E3E7EE;vertical-align:top}\nfooter{max-width:1180px;margin:0 "
            "auto;padding:0 20px "
            "30px;color:#6B7089;font-size:12px}\n@media(max-width:820px){.wrap{flex-direction:column}nav{position:static;width:auto}}\n</style></head><body>\n<header><h1>Help "
            '— Kubernetes Protection on Nutanix</h1>\n<div class="sub">Plugin for '
            "HYCU Enterprise Cloud · version v%s · every destructive action is "
            "simulated by default</div></header>\n<div "
            'class="wrap"><nav>%s</nav><main>%s</main></div>\n<footer>This page is '
            "served by the tool itself (works offline). Close the tab to return to the UI.</footer>\n</body></html>" % (VERSION, toc, body))


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
    """Réplicas COURANTS des Deployments et StatefulSets (0 inclus) + propriétaire
    contrôleur éventuel (opérateur). Renvoie (liste, erreur) : une erreur kubectl
    (RBAC, réseau) n'est JAMAIS assimilée à « aucun workload »."""
    captured = []
    for kind in ("deployment", "statefulset"):
        data, err = kubectl_json(["get", kind, "-n", ns])
        if err:
            return [], "cannot read %ss: %s" % (kind, err)
        for i in (data or {}).get("items", []):
            owners = [o for o in ((i.get("metadata") or {}).get("ownerReferences") or [])
                      if o.get("controller")]
            captured.append({"kind": kind, "name": i["metadata"]["name"],
                             "replicas": i.get("spec", {}).get("replicas", 1) or 0,
                             "owner": ("%s/%s" % (owners[0].get("kind"), owners[0].get("name"))) if owners else ""})
    return captured, None


# --- Transaction de restauration (reprise idempotente après interruption) ---
# Statuts : in_progress (séquence en cours), restart_failed (volumes restaurés mais
# scale-up refusé : la reprise ne refait que le redémarrage). La transaction porte TOUT
# ce qu'il faut pour reprendre sans relire le cluster : manifestes, réplicas cibles,
# statut par volume. Les réplicas ne sont plus mémorisés dans un fichier global qui
# survivait aux restaurations (risque de redémarrer un workload volontairement à 0).
def _txn_path(ns):
    return os.path.join(_cluster_root(CONFIG["backup_root"]), ns, "_restore_txn.json")


def _load_txn(ns):
    """Transaction de restauration reprenable pour ce namespace, ou None (fail-safe)."""
    try:
        with open(_txn_path(ns), encoding="utf-8") as f:
            t = json.load(f)
        return t if t.get("status") in ("in_progress", "restart_failed") else None
    except Exception:
        return None


def _save_txn(ns, data):
    """Persiste la transaction (atomique). Renvoie (ok, erreur) : un échec d'écriture
    (disque plein, volume en lecture seule) doit INTERDIRE la restauration réelle."""
    try:
        _write_json_atomic(_txn_path(ns), data, mode=0o600)
        return True, None
    except Exception as e:
        return False, str(e)


def _clear_txn(ns):
    try:
        os.remove(_txn_path(ns))
    except OSError:
        pass
    try:                                   # ancien fichier de mémoire des réplicas : obsolète
        os.remove(os.path.join(_cluster_root(CONFIG["backup_root"]), ns, "_replica_state.json"))
    except OSError:
        pass


def _txn_signature(mode, prepared):
    return {"mode": mode or "clone",
            "volumes": sorted([r["pvc"], r["new_pv_name"], r.get("new_volume_handle") or ""] for r in prepared)}


def _resolve_workloads(ns, txn=None):
    """Renvoie (courants, cible, erreur). 'cible' = réplicas à RESTAURER : la valeur
    courante si > 0 ; sinon (reprise : l'app est déjà à 0) la valeur enregistrée dans
    la transaction au démarrage de la restauration interrompue. Jamais 0."""
    current, err = _scan_workloads(ns)
    if err:
        return [], [], err
    remembered = {}
    for w in (txn or {}).get("workloads") or []:
        try:
            if int(w.get("replicas") or 0) > 0:
                remembered["%s/%s" % (w["kind"], w["name"])] = int(w["replicas"])
        except (TypeError, ValueError, KeyError):
            pass
    desired = []
    for w in current:
        key = "%s/%s" % (w["kind"], w["name"])
        n = w["replicas"] if w["replicas"] > 0 else remembered.get(key, 0)
        if n > 0:
            desired.append({"kind": w["kind"], "name": w["name"], "replicas": n})
    return current, desired, None


def _stop_workloads(current, ns, dry, log):
    """Scale-down à 0 des workloads en cours. Renvoie (ok, detail_échec)."""
    for w in current:
        if w["replicas"] > 0:                       # n'arrêter que ce qui tourne
            r = kubectl(["scale", w["kind"], w["name"], "-n", ns, "--replicas=0"],
                        dry=dry, label="Stopping %s/%s" % (w["kind"], w["name"]))
            log.append(r)
            if not (r["ok"] or r["dry"]):
                return False, "stopping of %s/%s" % (w["kind"], w["name"])
    return True, ""


def _restart_workloads(desired, ns, dry, log):
    """Scale-up des workloads à leur nombre de réplicas d'origine. Renvoie (ok, [commandes
    de redémarrage restantes]) : un scale-up en échec ne doit jamais passer inaperçu
    (l'application resterait à 0 réplica avec un résultat « terminé »)."""
    failed = []
    for w in desired:
        r = kubectl(["scale", w["kind"], w["name"], "-n", ns, "--replicas=%s" % w["replicas"]],
                    dry=dry, label="Restarting %s/%s -> %s" % (w["kind"], w["name"], w["replicas"]))
        log.append(r)
        if not (r["ok"] or r.get("dry")):
            failed.append("kubectl scale %s %s -n %s --replicas=%s" % (w["kind"], w["name"], ns, w["replicas"]))
    return (not failed), failed


_TERMINAL_POD_PHASES = ("Succeeded", "Failed")


def _pods_using_pvcs(ns, pvc_names):
    """Renvoie (pods ACTIFS montant l'un des PVC visés, erreur). Une erreur kubectl n'est
    JAMAIS assimilée à « aucun pod » : conclure à tort que les pods sont partis ferait
    supprimer de force des PVC encore montés (retrait des finalizers). Les pods terminés
    (Job Succeeded/Failed) sont ignorés : ils ne tiennent plus le volume et le finalizer
    pvc-protection les ignore aussi."""
    data, err = kubectl_json(["get", "pods", "-n", ns])
    using = []
    if err:
        return using, err
    if not data:
        return using, None
    wanted = set(pvc_names)
    for pod in data.get("items", []):
        if (pod.get("status") or {}).get("phase") in _TERMINAL_POD_PHASES:
            continue
        for vol in pod.get("spec", {}).get("volumes", []) or []:
            claim = (vol.get("persistentVolumeClaim") or {}).get("claimName")
            if claim in wanted:
                using.append(pod["metadata"]["name"])
                break
    return using, None


def _volume_attachments_for_pv(pv_name):
    """Noms des VolumeAttachment qui référencent ce PV (détachement CSI en cours).
    Renvoie (liste, erreur). Une erreur = information indisponible (RBAC, API)."""
    data, err = kubectl_json(["get", "volumeattachments"])
    if err:
        return [], err
    out = []
    for va in (data or {}).get("items", []):
        if (((va.get("spec") or {}).get("source") or {}).get("persistentVolumeName")) == pv_name:
            out.append(va["metadata"]["name"])
    return out, None


def _wait_volume_attachments_gone(pv_name, timeout, log):
    """Attend que plus aucun VolumeAttachment ne référence le PV (le VG est détaché de
    la VM worker). Renvoie True si libre, False sinon. Si l'API est inaccessible
    (RBAC), on l'indique et on considère l'information indisponible (True) : on ne
    bloque pas, mais on ne forcera JAMAIS le finalizer de l'attacher (cf. _delete_and_unblock)."""
    deadline = time.time() + timeout
    last = []
    while time.time() < deadline:
        last, err = _volume_attachments_for_pv(pv_name)
        if err:
            log.append(logentry("VolumeAttachments cannot be checked (%s)" % err.strip()[:160],
                                stdout="Missing “get volumeattachments” right: the VG detach is not confirmed."))
            return True
        if not last:
            log.append(logentry("Volume %s detached (no VolumeAttachment)" % pv_name,
                                cmd="(waiting) kubectl get volumeattachments"))
            return True
        time.sleep(3)
    log.append(logentry("Volume %s still attached" % pv_name, ok=False, rc=-1,
                        cmd="(waiting) kubectl get volumeattachments",
                        stderr="Timeout; remaining VolumeAttachment(s): " + ", ".join(last)))
    return False


def _unmanaged_pods_using_pvcs(ns, pvc_names):
    """Pods ACTIFS montant les PVC ciblés dont le contrôleur racine N'EST PAS un
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
        if (pod.get("status") or {}).get("phase") in _TERMINAL_POD_PHASES:
            continue
        claims = [(v.get("persistentVolumeClaim") or {}).get("claimName")
                  for v in (pod.get("spec", {}).get("volumes") or [])]
        if not any(c in wanted for c in claims):
            continue
        kinds = {o.get("kind") for o in (pod.get("metadata", {}).get("ownerReferences") or [])}
        if not (kinds & {"ReplicaSet", "StatefulSet"}):
            out.append((pod["metadata"]["name"],
                        ", ".join(sorted(k for k in kinds if k)) or "no controller"))
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
            log.append({"ok": True, "dry": False, "label": "Pods stopped",
                        "cmd": "(waiting) pods mounting the PVCs", "stdout": "no pod mounts the targeted volumes", "stderr": "", "rc": 0})
            return True
        time.sleep(2)      # erreur kubectl = état INCONNU : on réessaie jusqu'au délai
    using, err = _pods_using_pvcs(ns, pvc_names)
    detail = ("pod state unverifiable (kubectl failing): " + (err or last_err or "?")) if (err or not using)         else ("Timeout exceeded, pods still active: " + ", ".join(using))
    log.append({"ok": False, "dry": False, "label": "Pods still present",
                "cmd": "(waiting) pods mounting the PVCs",
                "stdout": "", "stderr": detail, "rc": -1})
    return False


def _pv_finalizers(name):
    data, _ = kubectl_json(["get", "pv", name])
    return list(((data or {}).get("metadata") or {}).get("finalizers") or [])


def _delete_and_unblock(kind, name, ns, log):
    """Supprime une ressource puis attend sa disparition. Si elle reste bloquée en
    Terminating, le finalizer n'est retiré QUE si la cause est périmée :
      - PVC : aucun pod actif ne monte plus le volume (sinon on abandonne : forcer
        pvc-protection supprimerait un volume monté) ;
      - PV  : jamais pour le finalizer de l'attacher CSI (external-attacher/...) :
        on attend le détachement (VolumeAttachment) puis on re-vérifie ; pv-protection
        n'est retiré qu'une fois le PVC lié disparu.
    Un échec de `kubectl delete` (RBAC, réseau) interrompt immédiatement.
    Renvoie True si la ressource est bien absente à la fin."""
    state, _ = resource_state(kind, name, ns)
    if state == "absent":
        log.append({"ok": True, "dry": False, "label": "%s %s already absent" % (kind.upper(), name),
                    "cmd": "", "stdout": "nothing to delete", "stderr": "", "rc": 0})
        return True

    args = ["delete", kind, name, "--wait=false", "--ignore-not-found"]
    if ns:
        args += ["-n", ns]
    rd = kubectl(args, dry=False, label="Deleting %s %s" % (kind.upper(), name))
    log.append(rd)
    if not rd["ok"] and "notfound" not in (rd.get("stderr") or "").replace(" ", "").lower():
        return False

    # Attente bornée de la suppression.
    wargs = ["wait", "--for=delete", "%s/%s" % (kind, name), "--timeout=%ss" % CONFIG["wait_timeout"]]
    if ns:
        wargs += ["-n", ns]
    kubectl(wargs, dry=False, label="Waiting for deletion of %s %s" % (kind.upper(), name))

    state, detail = resource_state(kind, name, ns)
    if state == "present":
        if kind == "pvc":
            # Re-vérifier l'usage AVANT de forcer : un pod (opérateur, Job) a pu revenir.
            using, uerr = _pods_using_pvcs(ns, [name])
            if uerr:
                log.append(logentry("PVC %s: usage cannot be checked — finalizer NOT forced" % name, ok=False, rc=-1,
                                    stderr="Pod list unavailable (%s). When in doubt, the "
                                           "finalizer is not removed; fix kubectl access and try again." % uerr))
                return False
            if using:
                log.append(logentry("PVC %s still mounted — finalizer NOT forced" % name, ok=False, rc=-1,
                                    stderr="Pod(s) actif(s): " + ", ".join(using)
                                           + ". Stop them (operator / Job / bare pod) and try again."))
                return False
        else:
            fins = _pv_finalizers(name)
            attacher = [f for f in fins if "attacher" in f]
            if attacher:
                # Ne jamais retirer le finalizer de l'attacher : attendre le détachement réel.
                if not _wait_volume_attachments_gone(name, CONFIG["wait_timeout"], log):
                    log.append(logentry("PV %s: finalizer %s NOT forced (volume still attached)"
                                        % (name, ", ".join(attacher)), ok=False, rc=-1,
                                        stderr="Forcing this finalizer would leave an orphan VolumeAttachment "
                                               "and a VG attached to two VMs. Wait for the detach and try again."))
                    return False
                state, detail = resource_state(kind, name, ns)
                if state == "absent":
                    return True
                fins = _pv_finalizers(name)
                if any("attacher" in f for f in fins):
                    log.append(logentry("PV %s still held by the CSI attacher" % name, ok=False, rc=-1,
                                        stderr="Finalizers: %s" % ", ".join(fins)))
                    return False
        # Finalizer périmé (pvc-protection sans pod, pv-protection sans PVC) -> retrait.
        pargs = ["patch", kind, name, "-p", '{"metadata":{"finalizers":null}}', "--type=merge"]
        if ns:
            pargs += ["-n", ns]
        log.append(kubectl(pargs, dry=False, label="Unblocking finalizer %s %s" % (kind.upper(), name)))
        time.sleep(1)
        state, detail = resource_state(kind, name, ns)

    if state == "absent":
        return True
    log.append({"ok": False, "dry": False, "label": "%s %s not deleted" % (kind.upper(), name),
                "cmd": "", "stdout": "", "stderr": "State: %s (%s)" % (state, detail), "rc": -1})
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
    r = kubectl(wargs, dry=False, label="Waiting for PVC %s to bind (Bound)" % name)
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
        return ("Backup not found or outside the allowed area: %s. "
                "Check the backups folder (Advanced) then reselect the backup." % backup_path)
    try:
        with open(os.path.join(bp, "index.json"), encoding="utf-8") as f:
            idx = json.load(f)
    except (OSError, ValueError) as e:
        return "Unreadable backup (%s): index.json missing or corrupt (%s)." % (bp, e)
    src = idx.get("cluster_id") or LOCAL_CID
    if allow_dr:
        return None                             # dérogation DR explicite : garde levée
    if src != _current_cid():
        return ("This backup comes from cluster “%s”, while the "
                "active cluster is “%s”. Cross-cluster restore is "
                "not supported: select the source cluster in the top bar." % (idx.get("cluster") or src, _cluster_label()))
    # Même « cluster » local mais CONTEXTE kubectl différent (ex. prod vs dev avec les
    # mêmes namespaces) : refuser aussi — les PV référencent d'autres Volume Groups.
    if src == LOCAL_CID:
        bctx = (idx.get("context") or "").strip()
        cur = (_local_context_name() or "").strip()
        if bctx and cur and bctx != cur:
            return ("This backup was taken on kubectl context “%s”, "
                    "while the active context is “%s”. Switch back "
                    "to the original context (Settings) before restoring." % (bctx, cur))
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
    # repli : lecture live (une erreur kubectl est remontée, pas assimilée à « introuvable »)
    live = action_pvcs(ns)
    if live.get("error") and not live.get("pvcs"):
        raise RuntimeError(live["error"])
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
        return {"ok": False, "pvc": pvc_name, "error": "Missing PVC."}
    try:
        _nfs_pv, _ = _load_old_pv(ns, pvc_name, backup_path, backup_root)
    except RuntimeError:
        _nfs_pv = None
    if _pv_nfs_info(_nfs_pv):
        return {"ok": False, "pvc": pvc_name, "nfs": True,
                "error": "“%s” is a NAS volume (%s): its data is restored in HYCU "
                         "(NAS share), not through this Volume Group flow. Untick it."
                         % (pvc_name, _nfs_label(_pv_nfs_info(_nfs_pv)))}
    if not new_ref:
        return {"ok": False, "pvc": pvc_name,
                "error": "Provide the reference of the cloned/restored "
                         "Volume Group for “%s” (VG UUID, volumeHandle, or IQN)." % pvc_name}
    # La référence doit contenir un UUID 8-4-4-4-12 (et rien de plus si c'est un IQN :
    # on rejette un IQN mal collé, mais on accepte un UUID nu ou un volumeHandle).
    if not UUID_RE.search(new_ref):
        return {"ok": False, "pvc": pvc_name,
                "error": "Invalid reference for “%s”: no UUID detected. Paste the VG UUID "
                         "(8-4-4-4-12), a volumeHandle “NutanixVolumes-<uuid>”, or the full IQN." % pvc_name}

    try:
        old_pv, pv_name = _load_old_pv(ns, pvc_name, backup_path, backup_root)
    except RuntimeError as e:
        return {"ok": False, "pvc": pvc_name, "error": "Cannot read the cluster: %s" % e}
    if old_pv is None:
        return {"ok": False, "pvc": pvc_name,
                "error": "PV manifest not found for “%s”. Back up this "
                         "namespace first, or check that the PV still exists." % pvc_name}

    built, err = build_new_pv(old_pv, new_ref, suggested, mode)
    if err:
        return {"ok": False, "pvc": pvc_name, "error": err}

    warn = None
    if built["looks_like_vg_name"]:
        warn = ("The provided UUID matches the VG NAME (“pvc-<uuid>”, = the PVC's UUID), not the UUID "
                "of the Volume Group. You probably entered the VG name instead of its UUID — use "
                "“Search for the VG in Prism” or copy the VG UUID (the suffix of NutanixVolumes-… / ntnx-k8s-…).")
    elif mode == "clone" and built["same_uuid"]:
        warn = ("The UUID is identical to the old one: the clone may not have "
                "produced a new VG (source VG UUID entered instead of the cloned VG?).")
    elif built["no_change"]:
        warn = ("No change detected in the manifest: for an in-place restore with the "
                "same VG, simply restarting the pods is enough to mount the restored data.")

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
        return False, ("DR restore refused: the “Allow DR restore” setting is "
                       "disabled (⚙ → Settings). Enable it for the operation, then retry.")
    return True, None


def action_prepare_restore(payload):
    """Aperçu du restore SANS rien exécuter, pour un ou plusieurs PVC."""
    ns = payload.get("namespace")
    if not _namespace_allowed(ns):
        return {"ok": False, "error": "Namespace '%s' not allowed by the configuration." % ns}
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
    return {"ok": ok, "error": None if ok else "One or more volumes could not be prepared.",
            "results": results, "planned_steps": plan, "namespace": ns, "mode": mode}


def _plan_steps(ns, prepared, mode):
    """Plan textuel de la séquence transactionnelle multi-PVC."""
    steps = ["Stop the application (all Deployments/StatefulSets in the namespace -> 0 replicas)",
             "Wait for the pods mounting the targeted volumes to actually stop"]
    for r in prepared:
        steps.append("Delete the old PVC “%s” (+ finalizer unblock if needed)" % r["pvc"])
        if r.get("old_pv_name"):
            steps.append("Delete the old PV “%s” (+ finalizer unblock if needed)" % r["old_pv_name"])
        steps.append("Create the new PV “%s” (volumeHandle %s)" % (r["new_pv_name"], r["new_volume_handle"]))
        steps.append("Recreate the PVC “%s” and bind it to the new PV, wait for Bound" % r["pvc"])
    steps.append("Restart the application (original replicas restored)")
    steps.append("Verify: all PVCs Bound and pods started")
    if mode == "clone":
        steps.append("AFTER: re-protect the new Volume Group(s) in HYCU "
                     "(Prism policy / category) — not automated by this tool")
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
        return None, "Backup not found or outside the allowed area."
    rp = os.path.join(bp, "resources.json")
    if not os.path.isfile(rp):
        if missing_ok:
            return [], None                       # dégradé : volumes seulement, l'appelant avertit
        return None, ("This backup has no resource snapshot "
                      "(resources.json): it predates the "
                      "feature, or config_backup_full was disabled.")
    try:
        with open(rp, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        return None, "resources.json unreadable: %s" % e
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
        return _err("Namespace '%s' not allowed by the configuration." % ns)
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
    diff = "\n".join(difflib.unified_diff(b, a, "live", "backup", lineterm="", n=2))
    return {"status": "differs", "error": None, "diff": diff[:20000]}


def action_objects_diff(payload):
    """Aperçu : pour chaque objet coché, l'écart entre la sauvegarde et le live."""
    ns = payload.get("namespace")
    dr, derr = _dr_allowed(payload)
    if derr:
        return _err(derr)
    if not _namespace_allowed(ns):
        return _err("Namespace '%s' not allowed by the configuration." % ns)
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
            d.update(status="redacted", error="Secret redacted at backup time: not restorable.", diff="")
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
        return _err("Namespace '%s' not allowed by the configuration." % ns, log=[])
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
        return _err("No object selected.", log=[])
    try:
        with action_lock(skip=dry):
            applied, skipped, failed = 0, 0, 0
            for obj in chosen:
                k = _obj_key(obj)
                label = "%s/%s" % (k["kind"], k["name"])
                if _obj_is_redacted(obj):
                    skipped += 1
                    log.append(logentry("Skipped: %s (Secret redacted at backup time)" % label,
                                        ok=True, stdout="Restore this Secret from its original source."))
                    continue
                r = _apply_manifest(obj, "objrestore_%s_%s" % (k["kind"], k["name"]), dry,
                                    "Apply %s" % label)
                log.append(r)
                if r["ok"]:
                    applied += 1
                else:
                    failed += 1
            ok = failed == 0
            audit("restore_objects", namespace=ns, dry=dry, ok=ok,
                  count=applied, skipped=skipped, failed=failed)
            return {"ok": ok, "error": None if ok else "%d object(s) failed." % failed,
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
        return {"ok": False, "error": "kubectl context “%s” not allowed by "
                                      "the configuration (allowed_contexts)." % cinfo.get("context"), "log": []}
    if cinfo["require_confirm"] and payload.get("confirm_context") != cinfo.get("context"):
        return {"ok": False, "error": "Context confirmation required: retype "
                                      "the targeted context name (“%s”) to confirm." % cinfo.get("context"), "log": []}
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


def _kubectl_can_i(verb, resource, ns=None):
    """kubectl auth can-i <verb> <resource> : True / False / None (indéterminé)."""
    args = ["auth", "can-i", verb, resource]
    if ns:
        args += ["-n", ns]
    r = run(_kubectl_base() + args, dry=False, timeout=45)
    out = (r.get("stdout") or "").strip().lower()
    if out.startswith("yes"):
        return True
    if out.startswith("no"):
        return False
    return None


def _kubectl_client_minor():
    """Version mineure du client kubectl (int) ou None."""
    r = run(_kubectl_base() + ["version", "--client", "-o", "json"], dry=False, timeout=45)
    try:
        cv = json.loads(r.get("stdout") or "{}").get("clientVersion") or {}
        return int(re.sub(r"\D", "", str(cv.get("minor") or "")) or 0) or None
    except Exception:
        return None


def _restore_preflight(ns, prepared, mode, dry, current, log):
    """Contrôles AVANT tout arrêt de l'application. Renvoie (checks, bloquant) :
    `checks` = liste [{name, ok, detail}] renvoyée à l'interface (liste ✓/✕),
    `bloquant` = premier contrôle bloquant en échec (message) ou None. Exécuté en
    simulation aussi (lectures seules), où il n'est jamais bloquant mais signale."""
    checks = []
    blocking = None

    def add(name, ok, detail="", block=True):
        nonlocal blocking
        checks.append({"name": name, "ok": ok, "detail": detail})
        if ok is False and block and blocking is None:
            blocking = "%s%s" % (name, (" — " + detail) if detail else "")

    # 1) Droits RBAC nécessaires à la séquence.
    needed = [("delete", "persistentvolumeclaims", ns), ("create", "persistentvolumeclaims", ns),
              ("patch", "persistentvolumeclaims", ns), ("delete", "persistentvolumes", None),
              ("create", "persistentvolumes", None), ("patch", "persistentvolumes", None),
              ("list", "pods", ns), ("patch", "deployments/scale", ns), ("patch", "statefulsets/scale", ns)]
    denied, unknown = [], []
    for verb, res, nsx in needed:
        c = _kubectl_can_i(verb, res, nsx)
        if c is False:
            denied.append("%s %s" % (verb, res))
        elif c is None:
            unknown.append("%s %s" % (verb, res))
    if denied:
        add("RBAC rights", False, "denied: " + ", ".join(denied))
    elif unknown:
        add("RBAC rights", None, "undetermined: " + ", ".join(unknown), block=False)
    else:
        add("RBAC rights", True, "delete/create/patch pv+pvc, scale, list pods")
    va = _kubectl_can_i("get", "volumeattachments")
    add("Reading VolumeAttachments", va if va is not None else None,
        "" if va else "without this right, the VG detach cannot be confirmed", block=False)

    # 2) Version du client kubectl (wait --for=jsonpath exige 1.23+).
    minor = _kubectl_client_minor()
    if minor is None:
        add("Version kubectl", None, "not read", block=False)
    else:
        add("Version kubectl", minor >= 23, "1.%d (1.23 minimum)" % minor)

    # 3) Workloads possédés par un opérateur : le scale-down serait annulé par lui.
    owned = [w for w in current if w.get("owner")]
    if owned:
        add("Operator-managed workloads", False,
            "; ".join("%s/%s (owner %s)" % (w["kind"], w["name"], w["owner"]) for w in owned)
            + " — the operator would restore the replicas during "
              "deletion: pause it or restore through the operator")
    else:
        add("Operator-managed workloads", True, "none")

    # 4) Pods actifs non gérés (DaemonSet / Job / pod nu / CRD) qui montent les volumes.
    unmanaged, unm_err = _unmanaged_pods_using_pvcs(ns, [r["pvc"] for r in prepared])
    if unm_err:
        add("Unmanaged pods mounting the volumes", None, "pod list unavailable: %s" % unm_err)
    elif unmanaged:
        add("Unmanaged pods mounting the volumes", False,
            "; ".join("%s (controller: %s)" % (p, k) for p, k in unmanaged)
            + " — the scale-down will not stop them: stop them first")
    else:
        add("Unmanaged pods mounting the volumes", True, "none")

    # 5) StorageClass référencée par chaque nouveau PV.
    scs = sorted({((r.get("manifest") or {}).get("spec") or {}).get("storageClassName") or "" for r in prepared})
    scs = [s for s in scs if s]
    missing_sc = []
    for sc in scs:
        st, _ = resource_state("storageclass", sc)
        if st == "absent":
            missing_sc.append(sc)
    add("StorageClass", not missing_sc, ("absente(s): " + ", ".join(missing_sc)) if missing_sc else (", ".join(scs) or "none"))

    # 6) Nom du nouveau PV libre (apply modifierait un PV existant : spec.csi est immuable).
    taken = []
    for r in prepared:
        nn = r["new_pv_name"]
        if nn == r.get("old_pv_name"):
            continue                     # sur place : même nom, remplacé dans la séquence
        data, _ = kubectl_json(["get", "pv", nn, "--ignore-not-found"])
        cref = ((data or {}).get("spec") or {}).get("claimRef") or {}
        if data and cref and (cref.get("name") != r["pvc"] or cref.get("namespace") != ns):
            taken.append("%s (bound to %s/%s)" % (nn, cref.get("namespace"), cref.get("name")))
    add("New PV name available", not taken, ", ".join(taken) if taken else "")

    # 7) Clone : disque du VG cloné résolu via Prism Central (sinon attach iSCSI -> échec).
    if mode == "clone" and CONFIG.get("clone_fix_disk_uuids", True):
        if not SESSION_CREDS.get("prismcentral"):
            add("Cloned VG disk (hypervisorAttachedDiskUUIDs)", False if (not dry and CONFIG.get("clone_require_disk_uuids", True)) else None,
                "Prism Central not connected: hypervisorAttachedDiskUUIDs will not be set (iSCSI attach -> failure)",
                block=not dry and bool(CONFIG.get("clone_require_disk_uuids", True)))
        else:
            bad = []
            for r in prepared:
                vg_uuid = split_volume_handle(r.get("new_volume_handle") or "")[1]
                if not vg_uuid:
                    continue
                uuids = _clone_vg_disk_uuids(vg_uuid)
                if uuids:
                    csi = ((r.get("manifest") or {}).get("spec") or {}).get("csi")
                    if isinstance(csi, dict):
                        csi.setdefault("volumeAttributes", {})["hypervisorAttachedDiskUUIDs"] = uuids
                    r["disk_uuids"] = uuids
                else:
                    bad.append(r["pvc"])
            add("Cloned VG disk (hypervisorAttachedDiskUUIDs via Prism Central v4)", not bad,
                ("not found for: " + ", ".join(bad)) if bad else "set in the PVs",
                block=bool(CONFIG.get("clone_require_disk_uuids", True)))

    # 8) Écriture de la transaction possible (sinon aucune reprise ne serait possible).
    if not dry:
        # Sonde dans un fichier VOISIN : une transaction in_progress/restart_failed en cours
        # de reprise ne doit jamais être écrasée ni effacée par le préflight.
        probe = _txn_path(ns) + ".probe"
        try:
            _write_json_atomic(probe, {"status": "preflight", "started": datetime.datetime.now().isoformat()},
                               mode=0o600)
            okw, werr = True, None
        except Exception as e:
            okw, werr = False, str(e)
        add("Writing the resume transaction", okw, werr or _txn_path(ns))
        try:
            os.remove(probe)
        except OSError:
            pass

    for c in checks:
        mark = "✓" if c["ok"] else ("?" if c["ok"] is None else "✕")
        log.append(logentry("Preflight %s %s" % (mark, c["name"]), ok=(c["ok"] is not False), dry=dry,
                            rc=0 if c["ok"] is not False else -1, cmd="(preflight)",
                            stdout=c["detail"] if c["ok"] is not False else "",
                            stderr=c["detail"] if c["ok"] is False else ""))
    return checks, blocking


def _pv_reclaim_policy(pv_name):
    data, _ = kubectl_json(["get", "pv", pv_name, "--ignore-not-found"])
    return ((data or {}).get("spec") or {}).get("persistentVolumeReclaimPolicy") if data else None


def _set_pv_retain(pv_name, label, log):
    """Passe un PV en Retain s'il est présent. Renvoie False UNIQUEMENT si le patch
    a été tenté et refusé (état indéterminé = refus aussi : on ne supprime pas dans le doute)."""
    st, detail = resource_state("pv", pv_name)
    if st == "absent":
        return True
    if st == "error":
        log.append(logentry(label, ok=False, rc=-1, stderr="PV %s state undetermined: %s" % (pv_name, detail)))
        return False
    pr = kubectl(["patch", "pv", pv_name, "--type=merge",
                  "-p", '{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}'],
                 dry=False, label=label)
    log.append(pr)
    return bool(pr["ok"])


def _execute_restore_locked(payload, log=None):
    ns = payload.get("namespace")
    dry = bool(payload.get("dry", True))
    mode = payload.get("mode", "clone")
    if log is None:
        log = []

    if not _namespace_allowed(ns):
        return {"ok": False, "error": "Namespace '%s' not allowed by the configuration." % ns, "log": []}

    # Garde contexte : en mode réel, refuser si le contexte n'est pas confirmé/autorisé.
    if not dry:
        guard = _context_guard(payload)
        if guard:
            return guard

    # Reprise idempotente : transaction en cours chargée AVANT la préparation (aussi en
    # simulation, pour prévisualiser la reprise). En reprise, les manifestes viennent de
    # la transaction elle-même (le PVC/PV source a pu être supprimé du cluster).
    txn = _load_txn(ns)
    backup_path = payload.get("backup_path") or (txn or {}).get("backup_dir")

    prep = action_prepare_restore({**payload, "backup_path": backup_path, "dry": dry})
    prepared = [r for r in (prep.get("results") or []) if r.get("ok")]
    if txn and not prep.get("ok"):
        # Les manifestes capturés dans la transaction suffisent à reprendre.
        prepared = []
        for v in txn.get("volumes") or []:
            if v.get("manifest"):
                prepared.append({"ok": True, "pvc": v["pvc"], "old_pv_name": v.get("old_pv"),
                                 "new_pv_name": v["new_pv"], "new_volume_handle": v.get("new_volume_handle"),
                                 "manifest": v["manifest"], "pvc_manifest": v.get("pvc_manifest"),
                                 "pvc_captured": v.get("pvc_manifest") is not None})
    if not prepared:
        return {"ok": False, "error": prep.get("error") or "No volume prepared.", "log": [],
                "results": prep.get("results")}

    # La transaction de reprise n'est effacée après un abandon que si RIEN d'irréversible
    # n'a eu lieu : ni reprise d'une transaction existante, ni arrêt de l'application
    # (les réplicas mémorisés seraient perdus), ni suppression. Vrai dès l'un des trois.
    destructive_started = bool(txn)
    # Garde AVANT toute destruction (la prévisualisation n'émet qu'un avertissement) :
    # une référence qui est le NOM du VG (« pvc-<uuid-du-PVC> ») ou, en clone, l'UUID du
    # VG SOURCE détruirait PVC/PV pour recréer un PV sur un VG inexistant / partagé.
    if not dry and not payload.get("force_same_uuid"):
        bad_name = [r["pvc"] for r in prepared if r.get("looks_like_vg_name")]
        if bad_name:
            return {"ok": False, "log": [], "results": prep.get("results"),
                    "error": "Invalid reference for %s: this is the Volume Group "
                             "NAME (“pvc-<uuid>”), not its UUID. Nothing was changed." % ", ".join(bad_name)}
        if payload.get("mode", "clone") == "clone":
            same = [r["pvc"] for r in prepared if r.get("same_uuid")]
            if same:
                return {"ok": False, "log": [], "results": prep.get("results"),
                        "error": "Reference identical to the SOURCE VG for %s: a clone must point "
                                 "to a NEW Volume Group (multi-attach otherwise). Nothing was changed."
                                 % ", ".join(same)}
    # Reprise : la demande doit viser les MÊMES volumes que la transaction interrompue.
    if txn:
        sig = _txn_signature(mode, prepared)
        if txn.get("signature") and txn["signature"] != sig:
            want = ", ".join("%s -> %s" % (v[0], v[1]) for v in (txn["signature"].get("volumes") or []))
            return _err("An interrupted restore is pending for this namespace with "
                        "other volumes (%s, mode %s). Run it again with the same "
                        "volumes to finish it, or delete %s if it is really abandoned." % (want, txn["signature"].get("mode"), _txn_path(ns)), log=[])
        done_pvcs = {v["pvc"] for v in (txn.get("volumes") or []) if v.get("status") == "done"}
    else:
        done_pvcs = set()

    aborted = False
    abort_detail = ""

    audit("restore_start", namespace=ns, dry=dry, mode=mode, resume=bool(txn),
          volumes=[{"pvc": r["pvc"], "new_pv": r["new_pv_name"],
                    "new_volume_handle": r["new_volume_handle"]} for r in prepared])

    # 0. Réplicas (courants + cibles) puis PRÉFLIGHT, avant tout arrêt.
    current, desired, werr = _resolve_workloads(ns, txn)
    if werr:
        return _err("Workloads unreadable before stopping the application: %s" % werr, log=log)
    log.append(logentry("Target replicas", dry=dry, cmd="(read) target replicas",
                        stdout=", ".join("%s/%s=%s" % (w["kind"], w["name"], w["replicas"]) for w in desired) or "none"))
    if txn:
        log.append(logentry("Resuming an interrupted restore",
                            stdout="Started %s (mode %s, status %s). Volumes already restored: %s."
                                   % (txn.get("started"), txn.get("mode"), txn.get("status"),
                                      ", ".join(sorted(done_pvcs)) or "none")))
    checks, blocking = _restore_preflight(ns, prepared, mode, dry, current, log)
    if blocking and not dry:
        audit("restore_end", namespace=ns, dry=dry, ok=False, aborted=True, preflight=blocking)
        return {"ok": False, "error": "Blocking preflight: %s. Nothing was changed." % blocking,
                "log": log, "preflight": checks, "aborted": True}

    # 0 bis. Reprise après scale-up refusé : seuls le redémarrage et la vérification restent.
    restart_only = bool(txn and txn.get("status") == "restart_failed")

    # 1. Filet de sécurité + transaction (réel). En reprise, la sauvegarde initiale est
    #    réutilisée (ne pas re-sauvegarder un état à moitié restauré).
    original_policies = {}
    if not dry:
        backup_dir = (txn or {}).get("backup_dir")
        if not txn and CONFIG.get("backup_before_restore", True):
            b = action_backup(ns, protect=[payload.get("backup_path")], kind="pre_restore", internal=True,
                              defer_quota=True)          # jamais de purge au milieu d'une restauration
            log.append(logentry("Safety backup of the namespace before the restore",
                                ok=bool(b.get("ok")), rc=0 if b.get("ok") else -1,
                                stdout=("Manifests: %s" % b.get("dir")) if b.get("dir") else "",
                                stderr="" if b.get("ok") else (b.get("error") or "")))
            if not b.get("ok"):
                return _err("Safety backup failed (%s) — restore cancelled so as not "
                            "to destroy without a safety net. Fix the issue then retry." % b.get("error"), log=log)
            backup_dir = b.get("dir")
        txn_vols = []
        prev = {v["pvc"]: v for v in ((txn or {}).get("volumes") or [])}
        for r in prepared:
            old_pol = (prev.get(r["pvc"]) or {}).get("reclaim_policy")
            if old_pol is None and r.get("old_pv_name"):
                old_pol = _pv_reclaim_policy(r["old_pv_name"])
            original_policies[r["pvc"]] = old_pol
            txn_vols.append({"pvc": r["pvc"], "new_pv": r["new_pv_name"], "old_pv": r.get("old_pv_name"),
                             "new_volume_handle": r.get("new_volume_handle"),
                             "status": "done" if r["pvc"] in done_pvcs else "pending",
                             "reclaim_policy": old_pol,
                             "manifest": r.get("manifest"), "pvc_manifest": r.get("pvc_manifest")})
        txn = {"status": "restart_failed" if restart_only else "in_progress",
               "started": (txn.get("started") if txn else datetime.datetime.now().isoformat()),
               "mode": mode, "backup_dir": backup_dir, "signature": _txn_signature(mode, prepared),
               "workloads": [dict(w) for w in desired], "volumes": txn_vols}
        okw, werr2 = _save_txn(ns, txn)
        if not okw:
            return _err("Cannot write the resume transaction (%s) — restore "
                        "cancelled: without this marker, an interruption could not be resumed." % werr2, log=log)

    pvc_names = [r["pvc"] for r in prepared]

    # 2. Arrêt de l'application puis attente de l'arrêt effectif des pods (réel).
    if not restart_only:
        ok_stop, detail_stop = _stop_workloads(current, ns, dry, log)
        if not dry and any(int(w.get("replicas") or 0) > 0 for w in current):
            destructive_started = True       # l'application a été (au moins partiellement) arrêtée
        if not ok_stop:
            aborted = True
            abort_detail = detail_stop
        if not dry and not aborted:
            if not _wait_pods_gone(ns, pvc_names, CONFIG["wait_timeout"], log):
                aborted = True
                abort_detail = "waiting for the pods to stop"

    # 3. Pour chaque volume : Retain (PV source ET PV courant ET nouveau PV) -> delete PVC
    #    -> attente détachement -> delete PV -> apply PV (Retain) -> apply PVC -> Bound.
    for r in prepared:
        if aborted or restart_only:
            break
        if _op_cancel_requested():
            aborted = True
            abort_detail = "stop requested by the operator (volumes already restored stay restored; run again to resume)"
            log.append(logentry("Stop requested by the operator", ok=False, rc=-1,
                                stderr="Sequence stopped cleanly after the current step."))
            break
        pvc_name = r["pvc"]
        pv_old = r.get("old_pv_name")
        new_name = r["new_pv_name"]
        if pvc_name in done_pvcs:
            log.append(logentry("Volume %s already restored (resume) — skipped" % pvc_name))
            continue
        # Retain TOUJOURS forcé quand le nouveau PV re-pointe le MÊME Volume Group (restore
        # sur place) : avec reclaimPolicy=Delete, supprimer l'ancien PV détruirait le VG
        # sur lequel on s'apprête à redémarrer l'application. La config ne peut pas
        # désactiver cette protection (le passage en Retain est de toute façon systématique).
        same_vg = bool(r.get("old_volume_handle")) and r.get("new_volume_handle") == r.get("old_volume_handle")

        # Réécrire hypervisorAttachedDiskUUIDs avec le disque du VG cloné (clone) AVANT
        # l'apply : sans lui, le CSI tente l'attach iSCSI et l'attachement échoue.
        if mode == "clone":
            _fix_clone_iqn(r.get("manifest"), r.get("new_volume_handle"), dry, log)
            disk_ok = _set_clone_disk_uuids(r.get("manifest"), r.get("new_volume_handle"), dry, log,
                                            source_had="hypervisorAttachedDiskUUIDs" in (r.get("stripped") or []))
            if not disk_ok and not dry and CONFIG.get("clone_require_disk_uuids", True):
                aborted = True
                abort_detail = (("disk not found for the Volume Group of %s: Prism "
                                 "Central is not connected (connect it and try again)" if not SESSION_CREDS.get("prismcentral")
                                 else "disk not found for the Volume Group of %s: this Volume Group "
                                      "no longer exists in Nutanix — restore it in HYCU and try again")
                                % pvc_name + " — PV not recreated to avoid a volume that cannot attach")
                break
        manifest = json.loads(json.dumps(r["manifest"]))
        # Le nouveau PV est TOUJOURS appliqué en Retain : une reprise, un double clic ou
        # un nettoyage ne doit jamais faire supprimer le VG cloné/restauré par le CSI.
        manifest.setdefault("spec", {})["persistentVolumeReclaimPolicy"] = "Retain"

        if dry:
            log.append(logentry("Protection: source PV %s, current PV of the PVC and PV %s -> Retain"
                                % (pv_old or "—", new_name), dry=True, rc=None,
                                cmd='kubectl patch pv <pv> -p \'{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}\'',
                                stdout="Prevents the PV/PVC deletion from deleting the "
                                       "Nutanix Volume Group (reclaimPolicy=Delete by default)."))
            log.append(logentry("Deleting PVC %s" % pvc_name, dry=True, rc=None,
                                cmd="kubectl delete pvc %s -n %s (finalizer removed only if no pod mounts it)" % (pvc_name, ns)))
            if pv_old:
                log.append(logentry("Deleting PV %s (after confirmed detach: VolumeAttachment)" % pv_old,
                                    dry=True, rc=None, cmd="kubectl get volumeattachments; kubectl delete pv %s" % pv_old))
            log.append(_apply_manifest(manifest, "pv_%s" % new_name, True,
                                       "Creating the new PV %s (Retain)" % new_name))
        else:
            # a) Retain sur tous les PV concernés AVANT toute suppression.
            cur_pv = None
            live_pvc, _ = kubectl_json(["get", "pvc", pvc_name, "-n", ns, "--ignore-not-found"])
            if live_pvc:
                cur_pv = ((live_pvc.get("spec") or {}).get("volumeName")) or None
            targets = [p for p in dict.fromkeys([pv_old, cur_pv, new_name]) if p]
            for p in targets:
                if not _set_pv_retain(p, "Volume Group protection: PV %s -> Retain" % p, log):
                    aborted = True
                    abort_detail = ("protection (Retain) of PV %s — deletion "
                                    "cancelled to avoid risking the loss of the Volume Group" % p)
                    break
            if aborted:
                break
            destructive_started = True
            # b) Suppression du PVC puis du PV (finalizers retirés seulement si périmés).
            if not _delete_and_unblock("pvc", pvc_name, ns, log):
                aborted = True
                abort_detail = "deletion of PVC %s" % pvc_name
                break
            # Y compris quand l'ancien PV porte le MÊME nom que le nouveau (restauration sur
            # place) : un `apply` par-dessus un PV Released garderait le claimRef.uid périmé
            # et le PVC recréé ne se lierait jamais. Il est en Retain : suppression sans risque.
            for p in [x for x in dict.fromkeys([pv_old, cur_pv]) if x]:
                if not _wait_volume_attachments_gone(p, CONFIG["wait_timeout"], log):
                    aborted = True
                    abort_detail = "detach of volume %s (VolumeAttachment still present)" % p
                    break
                if not _delete_and_unblock("pv", p, None, log):
                    aborted = True
                    abort_detail = "deletion of PV %s (volume %s)" % (p, pvc_name)
                    break
            if aborted:
                break
            if pv_old == new_name or cur_pv == new_name:
                # Sur place avec le même nom : le PV a été supprimé ci-dessus et sera recréé.
                pass
            ra = _apply_manifest(manifest, "pv_%s" % new_name, False,
                                 "Creating the new PV %s (Retain)" % new_name)
            log.append(ra)
            if not ra["ok"]:
                aborted = True
                abort_detail = "creation of the new PV %s (volume %s)" % (new_name, pvc_name)
                break

        # c) Recréer le PVC à partir du manifeste CAPTURÉ à la préparation.
        pvc_manifest = r.get("pvc_manifest")
        if pvc_manifest is not None:
            pvc_manifest = json.loads(json.dumps(pvc_manifest))   # copie défensive
            pvc_manifest.setdefault("spec", {})["volumeName"] = new_name
            ra = _apply_manifest(pvc_manifest, "pvc_%s" % pvc_name, dry,
                                 "Recreating PVC %s -> %s" % (pvc_name, new_name))
            log.append(ra)
            if not (ra["ok"] or ra["dry"]):
                aborted = True
                abort_detail = "recreation of PVC %s" % pvc_name
                break
            if not dry and not _wait_pvc_bound(pvc_name, ns, log):
                aborted = True
                abort_detail = "binding (Bound) of PVC %s" % pvc_name
                break
        else:
            log.append(logentry("PVC %s not recreated" % pvc_name, dry=dry,
                                stdout="PVC manifest not found (neither backup nor live): the PVC will be "
                                       "recreated by your application deployment (check afterwards that it becomes Bound)."))
        # d) Volume terminé : statut persisté (une reprise l'ignorera).
        if not dry:
            for v in txn["volumes"]:
                if v["pvc"] == pvc_name:
                    v["status"] = "done"
            _save_txn(ns, txn)

    # 4. Redémarrer l'application — UNIQUEMENT si rien n'a échoué, en contrôlant chaque scale-up.
    restart_failed = []
    if not aborted:
        ok_restart, restart_failed = _restart_workloads(desired, ns, dry, log)
        if not ok_restart:
            aborted = True
            abort_detail = "application restart (" + "; ".join(restart_failed) + ")"
            if not dry and txn:
                txn["status"] = "restart_failed"
                _save_txn(ns, txn)
            log.append({"ok": False, "dry": dry, "label": "INCOMPLETE RESTART", "rc": -1, "stdout": "",
                        "cmd": "", "stderr": "The volumes are restored but a scale-up failed: the "
                                             "application is (partly) STOPPED. Run the restore "
                                             "again (resume: only the restart is replayed) or by hand: " + "; ".join(restart_failed)})
    if aborted:
        log.append(logentry("SEQUENCE ABORTED", ok=False, dry=dry, rc=-1,
                            stderr=("Failed at step: %s. " % (abort_detail or "unknown")) +
                            "The application stays STOPPED (replicas at 0) to avoid "
                            "restarting on inconsistent volumes. Fix the cause, then run the "
                            "restore again with the same volumes (resume: volumes already "
                            "restored are skipped, the original replicas are recorded), or restart manually: " +
                            "; ".join("kubectl scale %s %s -n %s --replicas=%s" % (w["kind"], w["name"], ns, w["replicas"]) for w in desired)))

    # 5. Vérification finale (réelle) — contrôle anti mauvais-volume : le PVC doit être
    #    lié au PV portant le volumeHandle ATTENDU. Une incohérence est un ÉCHEC.
    mism = []
    if not dry and not aborted:
        v = action_verify(ns)
        vh_by_pvc = {p["name"]: p.get("volume_handle") for p in v.get("pvcs", [])}
        for r in prepared:
            got, exp = vh_by_pvc.get(r["pvc"]), r["new_volume_handle"]
            if exp and not got:
                mism.append("%s not bound (no volumeHandle observed)" % r["pvc"])
            elif got and exp and got != exp:
                mism.append("%s bound to %s instead of %s" % (r["pvc"], got, exp))
        if mism:
            log.append(logentry("UNEXPECTED volumeHandle — the pod may be running on the wrong Volume Group",
                                ok=False, rc=-1, stderr="Inconsistency(ies): " + "; ".join(mism)))
        else:
            log.append(logentry("volumeHandle matches the expected VG for all volumes"))
        log.append(logentry("Final verification", cmd="kubectl get pvc/pv/pods",
                            stdout=json.dumps(v, indent=2)))
        # 6. Politique de récupération : remettre celle d'origine du PV source (souvent
        #    Delete) sur le nouveau PV, pour retrouver le comportement Kubernetes attendu.
        for r in prepared:
            pol = original_policies.get(r["pvc"])
            if pol and pol != "Retain":
                pr = kubectl(["patch", "pv", r["new_pv_name"], "--type=merge",
                              "-p", json.dumps({"spec": {"persistentVolumeReclaimPolicy": pol}})],
                             dry=False, label="PV %s: original reclaim policy (%s) restored" % (r["new_pv_name"], pol))
                log.append(pr)

    ok_all = (not aborted) and not mism and all(r["ok"] or r.get("dry") for r in log)
    # Transaction : effacée si la restauration s'est terminée sans interruption (réel).
    # Interrompue AVANT toute suppression (inventaire, arrêt, attente des pods) : le
    # marqueur est aussi effacé — rien n'est à reprendre, et le laisser bloquerait la
    # sauvegarde automatique du namespace. Un redémarrage refusé GARDE la transaction
    # (statut restart_failed : la reprise ne rejoue que le scale-up).
    if not dry and (not aborted or not destructive_started):
        _clear_txn(ns)
    reprotect = []
    if mode == "clone" and not dry and not aborted:
        reprotect = [{"pvc": r["pvc"], "new_pv_name": r["new_pv_name"],
                      "new_volume_handle": r["new_volume_handle"]} for r in prepared]
    audit("restore_end", namespace=ns, dry=dry, ok=ok_all, aborted=aborted,
          restart_failed=bool(restart_failed))
    err = None
    if restart_failed:
        err = ("Volumes restored but restart incomplete — run the restore again (resume) or by hand: "
               + "; ".join(restart_failed))
    return {"ok": ok_all, "error": err, "dry": dry, "aborted": aborted, "log": log,
            "preflight": checks, "reprotect": reprotect}


def action_verify(ns):
    """État des PVC et des pods du namespace."""
    out = {"ok": True, "namespace": ns, "pvcs": [], "pods": [], "error": None}
    if not _namespace_allowed(ns):
        out["ok"] = False
        out["error"] = "Namespace '%s' not allowed by the configuration." % ns
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
    ok, err = save_config(payload.get("config") or {}, source="api")
    _LOCAL_CTX["at"] = 0.0          # contexte local peut-être changé : relire
    return {"ok": ok, "error": err, "config": CONFIG}


# ------------------------------------------------------------------------------
# Connecteurs HYCU / Nutanix (REST, stdlib uniquement, identifiants en RAM)
# ------------------------------------------------------------------------------
def _ssl_ctx(verify):
    """verify : False = pas de vérification ; True = magasin système ; chaîne = chemin
    d'un bundle CA (PEM) pour une PKI interne ou un certificat auto-signé exporté."""
    if isinstance(verify, str) and verify.strip():
        ctx = ssl.create_default_context(cafile=verify.strip())
        return ctx
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
                "error": "URL scheme refused (%s): only http/https are allowed." % (scheme or "—")}
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
        return {"ok": False, "status": None, "error": "Connection failed: %s" % e.reason}
    except ssl.SSLError as e:
        return {"ok": False, "status": None, "error": "TLS error: %s" % e}
    except Exception as e:  # pragma: no cover
        return {"ok": False, "status": None, "error": str(e)}


def _system_cfg(system):
    """(url de base, base API, vérification TLS). La vérification vaut False, True
    (magasin système) ou le chemin du bundle CA configuré (*_ca_bundle)."""
    verify = bool(CONFIG.get("%s_verify_tls" % system, False))
    bundle = (CONFIG.get("%s_ca_bundle" % system) or "").strip()
    if verify and bundle:
        verify = bundle
    return (CONFIG.get("%s_url" % system, "").rstrip("/"),
            CONFIG.get("%s_api_base" % system, ""),
            verify)


def _rest(system, method, path, body=None, timeout=30):
    """Appel REST avec les identifiants de session (hycu/nutanix)."""
    base, api, verify = _system_cfg(system)
    if not base:
        return {"ok": False, "error": "URL %s not configured (⚙ Sources)." % system.upper()}
    creds = SESSION_CREDS.get(system)
    if not creds:
        return {"ok": False, "error": "Not connected to %s." % system.upper()}
    return _http_json(method, base + api + path, creds, verify, body, timeout)


def _rest_raw(system, method, raw_path, body=None, timeout=30):
    """Comme _rest mais avec un chemin ABSOLU (on ignore le api_base configuré) —
    pour atteindre une AUTRE API du même appareil (ex. Prism Central v4 Volumes,
    `/api/volumes/v4.0.b1/...`, celle qu'utilise réellement le CSI Nutanix)."""
    base, _, verify = _system_cfg(system)
    if not base:
        return {"ok": False, "error": "URL %s not configured (⚙ Sources)." % system.upper()}
    creds = SESSION_CREDS.get(system)
    if not creds:
        return {"ok": False, "error": "Not connected to %s." % system.upper()}
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
        return {"ok": False, "error": "Unknown system."}
    base, api, verify = _system_cfg(system)
    if not base:
        return {"ok": False, "error": "URL %s not configured (⚙ Sources)." % system.upper()}

    mode = payload.get("auth_mode", "basic")
    if mode == "apikey":
        key = (payload.get("api_key") or "").strip()
        if not key:
            return {"ok": False, "error": "API key required."}
        auth = {"mode": "apikey", "key": key}
    else:
        user = (payload.get("user") or "").strip()
        pwd = payload.get("password") or ""
        if not user or not pwd:
            return {"ok": False, "error": "Username and password required."}
        auth = {"mode": "basic", "user": user, "password": pwd}

    test_path = {"nutanix": "/cluster", "prismcentral": "/users/me"}.get(
        system, CONFIG.get("hycu_test_path") or "/vms")
    r = _http_json("GET", base + api + test_path, auth, verify)
    warning = None
    if not r["ok"]:
        st = r.get("status")
        if st in (401, 403):
            return {"ok": False, "error": "Authentication %s refused "
                                          "(HTTP %s). Check the credentials%s." % (system.upper(), st,
                    " or use an API key if 2FA is enabled" if system == "hycu" else "")}
        if st == 404 and system in ("hycu", "prismcentral"):
            # Serveur joignable, auth franchie, mais le chemin de test n'existe pas
            # sur cette version : on connecte quand même avec un avertissement.
            where = "Help → REST API Explorer" if system == "hycu" else "the API version v3/v4"
            warning = ("Connected, but the test endpoint “%s” was not found (HTTP 404). "
                       "REST paths depend on the version: check %s and adjust if needed."
                       % (test_path, where))
        elif system not in ("nutanix", "prismcentral"):
            return {"ok": False, "error": "Connection failed for %s: %s" % (
                system.upper(), r.get("error") or ("HTTP %s" % st))}

    # Prism Element vs Prism Central : empêcher d'inverser les deux ou de mettre
    # deux fois la même URL. On vérifie quel Prism répond réellement derrière l'URL.
    if system in ("nutanix", "prismcentral"):
        other = "prismcentral" if system == "nutanix" else "nutanix"
        other_url = (CONFIG.get(other + "_url") or "").rstrip("/")
        if other_url and other_url == base:
            return {"ok": False, "error": "This URL is identical to the one for %s. Prism "
                                          "Element and Prism Central must point to different hosts."
                    % NTX_LABEL[other]}
        identity = _nutanix_identity(base, auth, verify)
        expected = "pe" if system == "nutanix" else "pc"
        if identity == "unknown" and not r["ok"]:
            return {"ok": False, "error": "Connection failed for %s: %s" % (
                system.upper(), r.get("error") or ("HTTP %s" % r.get("status")))}
        if identity != "unknown" and identity != expected:
            note = ("Warning: this URL looks like a %s, not a %s — make sure you did "
                    "not swap the two connectors. The connection was still established."
                    % (NTX_LABEL[identity], NTX_LABEL[expected]))
            warning = (warning + " " + note) if warning else note

    if not verify:
        tls_note = ("TLS certificate NOT verified — credentials are sent to an "
                    "unauthenticated host. Use this mode only on a trusted management network.")
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


_S3_MAX_DOWNLOAD = 512 * 1024 * 1024      # import d'un export : lu en mémoire, donc borné


def _s3_request(method, key="", body=b"", query="", want_body=False):
    """Requête S3 signée SigV4. Renvoie {"ok", "status", "error", "body"} ;
    `want_body=True` renvoie le corps COMPLET en octets dans "data" (listing XML,
    téléchargement d'objet), sinon un extrait texte de 2 Ko."""
    base = (CONFIG.get("s3_url") or "").strip()
    bucket = (CONFIG.get("s3_bucket") or "").strip()
    if not base or not bucket:
        return {"ok": False, "error": "S3 endpoint or bucket not configured (⚙ Sources)."}
    creds = SESSION_CREDS.get("s3")
    if not creds:
        return {"ok": False, "error": "Not connected to the object storage: enter the access keys (⚙ Sources)."}
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
                # Objet lu en mémoire (import) : borné pour ne pas faire tomber le Pod (OOM).
                try:
                    clen = int(resp.getheader("Content-Length") or 0)
                except (TypeError, ValueError):
                    clen = 0
                if clen > _S3_MAX_DOWNLOAD:
                    return {"ok": False, "status": resp.status, "data": b"", "body": "",
                            "error": "object too large for a direct import (%d MB > %d MB)"
                                     % (clen // (1024 * 1024), _S3_MAX_DOWNLOAD // (1024 * 1024))}
                data = resp.read(_S3_MAX_DOWNLOAD + 1)
                if len(data) > _S3_MAX_DOWNLOAD:
                    return {"ok": False, "status": resp.status, "data": b"", "body": "",
                            "error": "object too large for a direct import (> %d MB)"
                                     % (_S3_MAX_DOWNLOAD // (1024 * 1024))}
                return {"ok": True, "status": resp.status, "error": None, "data": data, "body": ""}
            return {"ok": True, "status": resp.status, "error": None,
                    "body": resp.read(2048).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read(500).decode("utf-8", "replace")
        except Exception:
            pass
        hint = {403: " — access keys refused (or server clock skewed: SigV4 requires accurate time).",
                404: " — bucket not found: check its name (and s3_path_style).",
                301: " — wrong region (s3_region) or URL style (s3_path_style)."}.get(e.code, "")
        return {"ok": False, "status": e.code, "error": "HTTP %s%s %s" % (e.code, hint, detail[:200])}
    except Exception as e:
        return {"ok": False, "status": None, "error": "Object storage unreachable: %s" % e}


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
            return _err("Cannot list the bucket: %s" % r.get("error"))
        try:
            root = ET.fromstring(r["data"])
        except ET.ParseError as e:
            return _err("Unreadable bucket response (XML): %s" % e)
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


# ---- Kit de l'outil : sa propre sauvegarde (reprise après la perte de son PVC) ------
# Contenu : configuration (politiques, filtres, sources), coffre d'identifiants (déjà
# chiffré par la phrase maîtresse) et état de la sauvegarde automatique. Exporté dans
# le bucket à chaque passage automatique (un objet par jour), téléchargeable, et
# restaurable depuis le bucket sur une nouvelle instance.
TOOL_KIT_DIR = "_tool"
_TOOL_KIT_RE = re.compile(r"^hycu-tool-\d{4}-\d{2}-\d{2}\.zip(\.enc)?$")
_TOOL_KIT_FILES = ("hycu_config.json", "hycu_secrets.enc", ".auto_backup_state.json", "manifest.json")


def tool_kit_bytes():
    """Archive .zip du kit de l'outil (en mémoire)."""
    import io
    import zipfile
    buf, files = io.BytesIO(), []
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        with CONFIG_LOCK:
            z.writestr("hycu_config.json", json.dumps(USER_CONFIG, indent=2, ensure_ascii=False))
        files.append("hycu_config.json")
        for arc, path in (("hycu_secrets.enc", SECRETS_PATH), (".auto_backup_state.json", _auto_backup_state_path())):
            if os.path.isfile(path):
                z.write(path, arc)
                files.append(arc)
        z.writestr("manifest.json", json.dumps({"tool": "hycu-k8s-nutanix", "version": VERSION,
                                                 "created": datetime.datetime.now().astimezone().isoformat(),
                                                 "files": files}, indent=2))
    return buf.getvalue(), files


def s3_upload_tool_kit():
    """Envoie le kit de l'outil : <préfixe>/_tool/hycu-tool-<AAAA-MM-JJ>.zip[.enc]
    (un objet par jour, remplacé dans la journée). Renvoie (ok, clé|erreur)."""
    data, _files = tool_kit_bytes()
    ext = ".zip"
    if CONFIG.get("s3_encrypt"):
        enc_pw = ((SESSION_CREDS.get("s3") or {}).get("enc") or "")
        if not enc_pw:
            return False, "encryption enabled but encryption passphrase missing"
        data = encrypt_bytes(data, enc_pw)
        ext = ".zip.enc"
    prefix = (CONFIG.get("s3_prefix") or "hycu-backups").strip().strip("/")
    key = "/".join(x for x in (prefix, TOOL_KIT_DIR, "hycu-tool-%s%s" % (datetime.date.today().isoformat(), ext)) if x)
    r = _s3_request("PUT", key, data)
    if not r["ok"]:
        return False, r.get("error") or "upload refused"
    audit("tool_kit_upload", key=key, size=len(data), encrypted=ext.endswith(".enc"))
    return True, key


def action_tool_kit_upload():
    if not SESSION_CREDS.get("s3"):
        return _err("Connect the S3 object storage first.")
    ok, info = s3_upload_tool_kit()
    return _ok(key=info) if ok else _err("Tool kit export failed: %s" % info)


def action_tool_kit_list():
    """Kits de l'outil présents dans le bucket (plus récents d'abord)."""
    import xml.etree.ElementTree as ET
    if not SESSION_CREDS.get("s3"):
        return _err("Connect the S3 object storage first.")
    prefix = (CONFIG.get("s3_prefix") or "hycu-backups").strip().strip("/")
    pfx = "/".join(x for x in (prefix, TOOL_KIT_DIR) if x) + "/"
    r = _s3_request("GET", "", b"", "list-type=2&max-keys=1000&prefix=" + urllib.parse.quote(pfx, safe=""),
                    want_body=True)
    if not r["ok"]:
        return _err("Cannot list the bucket: %s" % r.get("error"))
    try:
        root = ET.fromstring(r["data"])
    except ET.ParseError as e:
        return _err("Unreadable bucket response (XML): %s" % e)
    nsm = {"s3": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else None

    def find(el, name):
        return el.find("s3:" + name, nsm) if nsm else el.find(name)
    out = []
    for c in (root.findall("s3:Contents", nsm) if nsm else root.findall("Contents")):
        key = find(c, "Key").text or ""
        fname = key[len(pfx):] if key.startswith(pfx) else ""
        if not _TOOL_KIT_RE.match(fname):
            continue
        out.append({"key": key, "name": fname, "size": int(find(c, "Size").text or 0),
                    "modified": (find(c, "LastModified").text or "")[:19], "encrypted": fname.endswith(".enc")})
    out.sort(key=lambda x: x["name"], reverse=True)
    return _ok(kits=out)


def action_tool_kit_restore(payload):
    """Restaure le kit de l'outil depuis le bucket : configuration (sauf les réglages
    propres à la machine : chemins, binaire kubectl, hôte/port), coffre chiffré et état
    de la sauvegarde auto. Une copie de l'existant est gardée avant remplacement."""
    import io
    import zipfile
    if not SESSION_CREDS.get("s3"):
        return _err("Connect the S3 object storage first.")
    if ACTION_LOCK.locked() or AUTO_BACKUP.get("running") or BULK["running"]:
        return _err("An operation is running: try again when it has finished.")
    key = (payload.get("key") or "").strip()
    prefix = (CONFIG.get("s3_prefix") or "hycu-backups").strip().strip("/")
    pfx = "/".join(x for x in (prefix, TOOL_KIT_DIR) if x) + "/"
    if not key.startswith(pfx) or not _TOOL_KIT_RE.match(key[len(pfx):]):
        return _err("Invalid kit.")
    r = _s3_request("GET", key, b"", "", want_body=True)
    if not r["ok"]:
        return _err("Kit download failed: %s" % r.get("error"))
    data = r["data"]
    if key.endswith(".enc"):
        pw = (payload.get("passphrase") or "") or ((SESSION_CREDS.get("s3") or {}).get("enc") or "")
        if not pw:
            return _err("Encrypted kit: enter the export encryption passphrase.")
        data = decrypt_bytes(data, pw)
        if data is None:
            return _err("Decryption failed (wrong passphrase or altered kit).")
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        content = {}
        for info in z.infolist():
            if info.filename in _TOOL_KIT_FILES and info.file_size <= 20 * 1024 * 1024:
                content[info.filename] = z.read(info.filename)
        manifest = json.loads(content.get("manifest.json") or b"{}")
        kit_cfg = json.loads(content.get("hycu_config.json") or b"{}")
    except Exception as e:
        return _err("Unreadable kit: %s" % e)
    if manifest.get("tool") != "hycu-k8s-nutanix" or not isinstance(kit_cfg, dict):
        return _err("This file is not a tool kit.")
    machine = set(_CONTAINER_LOCKED_KEYS)
    new_cfg, ignored = {}, []
    for k, v in kit_cfg.items():
        if k not in CONFIG_SCHEMA or k in machine:
            continue
        try:
            new_cfg[k] = _coerce_config_value(k, v)
        except ValueError:
            ignored.append(k)
    # Copie de sécurité de l'existant (configuration + coffre) avant remplacement.
    safe = os.path.join(CONFIG["backup_root"], "_tool_restore_backup",
                        datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
    try:
        os.makedirs(safe, exist_ok=True)
        for path in (CONFIG_PATH, SECRETS_PATH, _auto_backup_state_path()):
            if os.path.isfile(path):
                shutil.copy2(path, os.path.join(safe, os.path.basename(path)))
    except OSError as e:
        return _err("Safety copy failed (%s): nothing was changed." % e)
    with CONFIG_LOCK:
        keep_local = {k: v for k, v in USER_CONFIG.items() if k in machine}
        dropped = [k for k in USER_CONFIG if k not in new_cfg and k not in machine]
        USER_CONFIG.clear()
        USER_CONFIG.update(new_cfg)
        USER_CONFIG.update(keep_local)
        _write_json_atomic(CONFIG_PATH, USER_CONFIG, mode=0o644)
        # Effet immédiat sans toucher aux réglages propres à la machine (chemins, kubectl…) :
        # valeurs du kit, défauts pour les clés absentes du kit, l'environnement prime.
        for k in dropped:
            CONFIG[k] = DEFAULT_CONFIG[k]
        CONFIG.update(new_cfg)
        CONFIG.update(_env_overrides())
    restored = ["hycu_config.json"]
    if content.get("hycu_secrets.enc"):
        _write_text_private(SECRETS_PATH, content["hycu_secrets.enc"].decode("ascii", "replace"))
        restored.append("hycu_secrets.enc")
    if content.get(".auto_backup_state.json"):
        try:
            _write_json_atomic(_auto_backup_state_path(), json.loads(content[".auto_backup_state.json"]), mode=0o644)
            _load_auto_backup_state()
            restored.append(".auto_backup_state.json")
        except (ValueError, OSError):
            pass
    _apps_cache_clear()
    audit("tool_restore", key=key, files=restored, version=manifest.get("version"), ignored=ignored)
    return _ok(restored=restored, vault=("hycu_secrets.enc" in restored), safety_copy=safe,
               version=manifest.get("version"), ignored=ignored)


IMPORT_MAX_BYTES = 2 * 1024 ** 3     # taille DÉCOMPRESSÉE maximale d'un export importé


def _safe_extract_zip(data, dest, max_bytes=IMPORT_MAX_BYTES):
    """Extrait un zip en mémoire vers `dest`, en retirant le dossier racine unique
    et en BLOQUANT toute traversée (zip-slip) et toute archive « gonflée » (zip bomb :
    taille annoncée ET taille réellement écrite bornées). Renvoie (nb fichiers, erreur)."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return 0, "the object is not a valid zip (wrong decryption passphrase?)"
    names = [n for n in zf.namelist() if not n.endswith("/")]
    announced = sum((zf.getinfo(n).file_size or 0) for n in names)
    if announced > max_bytes:
        return 0, "archive rejected: announced uncompressed size %d Mo > %d Mo" % (
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
            return 0, "archive rejected: path outside the target area (“%s”)" % n
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with zf.open(n) as src, open(target, "wb") as f:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:          # taille réelle > annoncée (bombe)
                    return 0, "archive rejected: uncompressed content larger than %d Mo" % (max_bytes // (1024 * 1024))
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
            results.append({"key": label, "ok": False, "error": "invalid key"})
            continue
        cluster, nsname, fname = rel[-3], rel[-2], rel[-1]
        ts = fname[:-8] if fname.endswith(".zip.enc") else fname[:-4]
        if not (K8S_NAME_RE.match(nsname) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", cluster)
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", ts)):
            results.append({"key": label, "ok": False, "error": "invalid key"})
            continue
        imports_root = os.path.realpath(os.path.join(CONFIG["backup_root"], "_imports"))
        dest = os.path.join(CONFIG["backup_root"], "_imports", cluster, nsname, ts)
        if not os.path.realpath(dest).startswith(imports_root + os.sep):
            results.append({"key": label, "ok": False, "error": "invalid key"})
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
                                "error": "encrypted object: provide the decryption passphrase"})
                continue
            data = decrypt_bytes(data, pw)
            if data is None:
                results.append({"key": label, "ok": False,
                                "error": "decryption failed (wrong passphrase or corrupted object)"})
                continue
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
            "error": None if imported or not results else "No export imported."}


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
        return _err("Enter the access key and the secret key.")
    enc_pw = (payload.get("enc_passphrase") or "").strip()
    if CONFIG.get("s3_encrypt") and not enc_pw:
        return _err("Encryption enabled: choose an export encryption "
                    "passphrase (also needed for decryption — keep it safe).")
    with CRED_LOCK:
        SESSION_CREDS["s3"] = {"access": access, "secret": secret}
        if enc_pw:
            SESSION_CREDS["s3"]["enc"] = enc_pw
    r = _s3_request("GET", "", b"", "list-type=2&max-keys=1")
    if not r["ok"]:
        with CRED_LOCK:
            SESSION_CREDS["s3"] = None
        return _err("Bucket test failed: %s" % r.get("error"))
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
                        return None, "backup too large for export (%d Mo max)" % (max_bytes // 1024 // 1024)
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
            return False, ("encryption enabled but encryption passphrase "
                           "missing: enter it in ⚙ Sources > S3 object storage")
        data = encrypt_bytes(data, enc_pw)
        ext = ".zip.enc"
    prefix = (CONFIG.get("s3_prefix") or "hycu-backups").strip().strip("/")
    key = "/".join(x for x in (prefix, cid, ns, ts + ext) if x)
    r = _s3_request("PUT", key, data)
    if not r["ok"]:
        return False, r.get("error") or "upload refused"
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
        # Jamais d'éviction pendant une opération en cours (restauration, clone,
        # protection HYCU…) : les identifiants seraient effacés sous les pieds du
        # thread et l'application resterait arrêtée. La page est servie sans changer
        # de session ; le nouveau visiteur devra recharger une fois l'opération finie.
        if cur and (ACTION_LOCK.locked() or _operations_running()):
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
                  "verify_tls": bool(verify), "ca_bundle": verify if isinstance(verify, str) else "",
                  "connected": SESSION_CREDS.get(s) is not None}
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
        print("Cannot read: %s" % e)
        return 1
    pw = getpass.getpass("Encryption passphrase: ")
    data = decrypt_bytes(blob, pw)
    if data is None:
        print("Failed: wrong passphrase or altered file.")
        return 1
    out = path[:-4] if path.endswith(".enc") else path + ".dec"
    with open(out, "wb") as f:
        f.write(data)
    print("Decrypted -> %s" % out)
    return 0
def _write_text_private(path, text):
    """Écrit un fichier texte en 0600 de façon atomique (coffre)."""
    d = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        for attempt in range(5):
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.05 * (attempt + 1))
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def action_save_credentials(payload):
    """Chiffre les identifiants de session courants dans hycu_secrets.enc."""
    pw = payload.get("passphrase") or ""
    if len(pw) < 8:
        return {"ok": False, "error": "Choose a passphrase of at least 8 characters."}
    with CRED_LOCK:
        creds = {k: v for k, v in SESSION_CREDS.items() if v}
    # Clusters Kubernetes ajoutés depuis l'interface : leur kubeconfig est un secret,
    # conservé uniquement ici (chiffré), jamais dans hycu_config.json.
    with CLUSTERS_LOCK:
        clusters = [{k: c.get(k) for k in ("name", "kubeconfig", "context", "workspace",
                                           "source", "nkp_ref", "management")}
                    for c in CLUSTERS.values()]
    if not creds and not clusters:
        return {"ok": False, "error": "Connect to at least one system first."}
    names = sorted(creds.keys())
    if clusters:
        creds = dict(creds, _clusters=clusters)
    try:
        blob = encrypt_secret(json.dumps(creds).encode("utf-8"), pw)
        _write_text_private(SECRETS_PATH, blob)   # 0600 + atomique
    except Exception as e:
        return {"ok": False, "error": "Could not write the vault: %s" % e}
    global _VAULT_PW
    _VAULT_PW = pw                      # sert aussi à chiffrer les Secrets des sauvegardes
    save_config({"remember_credentials": True})
    audit("creds_saved", systems=names, clusters=[c["name"] for c in clusters])
    return {"ok": True, "saved": names, "clusters": [c["name"] for c in clusters]}


def action_load_credentials(payload):
    """Déchiffre le coffre et charge les identifiants en mémoire de session."""
    pw = payload.get("passphrase") or ""
    if not os.path.isfile(SECRETS_PATH):
        return {"ok": False, "error": "No saved connections."}
    try:
        with open(SECRETS_PATH, encoding="utf-8") as f:
            blob = f.read()
    except Exception as e:
        return {"ok": False, "error": "Could not read the vault: %s" % e}
    data = decrypt_secret(blob, pw)
    if data is None:
        return {"ok": False, "error": "Incorrect passphrase (or corrupted file)."}
    try:
        creds = json.loads(data.decode("utf-8"))
    except Exception:
        return {"ok": False, "error": "Decrypted data unreadable."}
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
            print("HYCU_VAULT_PASSPHRASE_FILE unreadable (%s): auto unlock inactive." % e)
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
    print("Automatic vault unlock failed: %s" % r.get("error"))
    return False


def action_forget_credentials():
    """Supprime le coffre chiffré du disque."""
    try:
        if os.path.isfile(SECRETS_PATH):
            os.remove(SECRETS_PATH)
    except OSError as e:
        return {"ok": False, "error": "Deletion failed: %s" % e}
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
        return {"ok": False, "error": "No Nutanix connection (Prism Element or Central).", "vgs": []}
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
                return {"ok": False, "error": r.get("error") or "Nutanix error.", "vgs": vgs}
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
                return {"ok": False, "error": r.get("error") or "Nutanix error.", "vgs": vgs}
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
        return {"ok": False, "error": "Missing Volume Group UUID."}
    sysname = _nutanix_source()
    if not sysname:
        return {"ok": False, "error": "No Nutanix connection (Prism Element or Central)."}
    r = _rest(sysname, "GET", "/volume_groups/%s" % urllib.parse.quote(str(uuid)))
    if not r["ok"]:
        return {"ok": False, "error": r.get("error")}
    j = r.get("json") or {}
    vg_uuid = j.get("uuid") or (j.get("metadata") or {}).get("uuid") or str(uuid)
    iqn = _extract_iqn(j)
    # `ref` = ce qu'on injecte dans le PV (UUID du VG). `iqn` reste informatif/legacy.
    return {"ok": bool(vg_uuid), "ref": vg_uuid, "uuid": vg_uuid, "iqn": iqn,
            "error": None if vg_uuid else "UUID not found in the Nutanix response for this VG."}


def action_nutanix_detach_vg(vg_uuid):
    """Détache un Volume Group de TOUTES ses VM/initiateurs (Prism Element v2), pour
    que le CSI Nutanix puisse l'attacher au nœud. Indispensable après un clone HYCU :
    HYCU crée le VG cloné déjà attaché à la VM worker -> le CSI échoue à l'attacher
    (AttachIscsiClient ... task failed) et les pods restent bloqués."""
    if not vg_uuid:
        return {"ok": False, "error": "Missing Volume Group UUID.", "detached": []}
    if _nutanix_source() != "nutanix":
        return {"ok": False, "detached": [],
                "error": "Automatic detach requires Prism Element (API v2). "
                         "Connect Prism Element, or detach the VG from its VM in Prism."}
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
        return {"ok": False, "error": "Missing Volume Group UUID."}
    if not SESSION_CREDS.get("prismcentral"):
        return {"ok": False, "error": "Connect Prism Central: the v4 Volumes API (and the CSI) are served there."}
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
        log.append(logentry("Align the PV's IQN with the VG's real iSCSI target %s" % vg_uuid, dry=True, rc=None,
                            stdout="Read through Prism Central v4 (a VG created by HYCU carries a “hycu-clone-vg-…” target)."))
        return True
    if not SESSION_CREDS.get("prismcentral"):
        log.append(logentry("PV IQN not checked (Prism Central not connected)", ok=False, rc=-1,
                            stderr="If the pod stays in FailedMount (“iscsiadm: No records found”), connect Prism "
                                   "Central and retry: the restored VG's iSCSI target may differ from the derived IQN."))
        return True
    tn = _vg_target_name(vg_uuid)
    if not tn:
        log.append(logentry("PV IQN not checked (iSCSI target of VG %s unreadable)" % vg_uuid, ok=False, rc=-1,
                            stderr="Prism Central did not return the VG's targetName."))
        return True
    new_iqn = _iqn_for_target(iqn, tn)
    if new_iqn and new_iqn != iqn:
        va["iqn"] = new_iqn
        log.append(logentry("PV IQN aligned with the VG's real iSCSI target",
                            stdout="%s -> %s" % (iqn, new_iqn)))
    else:
        log.append(logentry("PV IQN matches the VG's iSCSI target", stdout=iqn))
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
        log.append(logentry("hypervisorAttachedDiskUUIDs not added (the source PV does not carry it)",
                            dry=dry, rc=None,
                            stdout="This cluster's CSI attaches the Volume Group without this "
                                   "attribute, as for the original PV: the source PV's shape is reproduced."))
        return True
    if dry:
        log.append(logentry("Set hypervisorAttachedDiskUUIDs (cloned VG disk %s)" % vg_uuid,
                            dry=True, rc=None,
                            stdout="Read via Prism Central v4; without it the CSI attempts the iSCSI attach (fails)."))
        return True
    if not SESSION_CREDS.get("prismcentral"):
        log.append(logentry("hypervisorAttachedDiskUUIDs NOT set (Prism Central not connected)",
                            ok=False, rc=-1,
                            stderr="The CSI will attempt the iSCSI attach and the attachment will fail. Connect Prism Central."))
        return False
    uuids = _clone_vg_disk_uuids(vg_uuid)
    if uuids:
        csi.setdefault("volumeAttributes", {})["hypervisorAttachedDiskUUIDs"] = uuids
        log.append(logentry("hypervisorAttachedDiskUUIDs set from the cloned VG",
                            stdout="Cloned VG disk(s): %s" % uuids))
        return True
    log.append(logentry("hypervisorAttachedDiskUUIDs NOT set (disk not found)",
                        ok=False, rc=-1, stderr="No disk read for VG %s" % vg_uuid,
                        stdout="The CSI will attempt the iSCSI attach; check the cloned VG in Prism."))
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
        log.append(logentry("Cannot check the PV disk (reading PVC %s)" % pvc_name,
                            ok=False, rc=-1, stderr=perr))
        return False, ("Cannot read PVC “%s” (%s): cannot check whether "
                       "HYCU replaced the VG disk. Fix kubectl access, "
                       "then run the in-place restore again (idempotent)." % (pvc_name, perr))
    pv_name = (pvc_live.get("spec") or {}).get("volumeName") if pvc_live else None
    if not pv_name:
        return True, ""                                  # PVC/PV réellement absents : rien à rafraîchir
    pv_live, verr = kubectl_json(["get", "pv", pv_name])
    if verr:
        log.append(logentry("Cannot check the PV disk (reading PV %s)" % pv_name,
                            ok=False, rc=-1, stderr=verr))
        return False, ("Cannot read PV “%s” (%s): cannot check the VG disk. "
                       "Fix kubectl access, then run the in-place restore again." % (pv_name, verr))
    csi = ((pv_live or {}).get("spec") or {}).get("csi") or {}
    vh = csi.get("volumeHandle")
    old_disk = (csi.get("volumeAttributes") or {}).get("hypervisorAttachedDiskUUIDs")
    vg_uuid = split_volume_handle(vh or "")[1]
    if not vg_uuid:
        return True, ""
    if not SESSION_CREDS.get("prismcentral"):
        log.append(logentry("Disk of PV %s not verified (Prism Central not connected)" % pv_name,
                            ok=False, rc=-1,
                            stderr="If the pod stays in FailedMount (“failed to get "
                                   "symlink”), connect Prism Central and rerun the in-place restore."))
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
        what.append("hypervisorAttachedDiskUUIDs: %s -> %s" % (old_disk, new_disk))
    if iqn_changed:
        what.append("iqn: %s -> %s" % (old_iqn, new_iqn))
    log.append(logentry("VG changed by the in-place restore — refreshing PV %s" % pv_name,
                        stdout="; ".join(what)))
    if dry:
        log.append(logentry("Recreate PV %s with up-to-date attributes (Retain -> delete -> apply)" % pv_name,
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
        log.append(logentry("Refresh of PV %s cancelled: PV state undetermined (%s)" % (pv_name, st_pv),
                            ok=False, rc=-1,
                            stderr=(st_err or "") + " — deletion refused to avoid risking the loss of "
                                                    "the Volume Group. Check kubectl access then retry."))
        return False, "checking the state of PV %s before deletion" % pv_name
    pr = kubectl(["patch", "pv", pv_name, "--type=merge",
                  "-p", '{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}'],
                 dry=False, label="Protecting the VG: PV %s -> Retain" % pv_name)
    log.append(pr)
    if not pr["ok"]:
        return False, "protection (Retain) of PV %s" % pv_name
    if not _delete_and_unblock("pvc", pvc_name, ns, log):
        return False, "deletion of PVC %s" % pvc_name
    if not _delete_and_unblock("pv", pv_name, None, log):
        return False, "deletion of PV %s" % pv_name
    ra = _apply_manifest(new_pv, "pv_%s" % pv_name, False, "Recreating PV %s (refreshed disk)" % pv_name)
    log.append(ra)
    if not ra["ok"]:
        return False, "recreation of PV %s" % pv_name
    pvc_manifest.setdefault("spec", {})["volumeName"] = pv_name
    ra2 = _apply_manifest(pvc_manifest, "pvc_%s" % pvc_name, False, "Recreating PVC %s" % pvc_name)
    log.append(ra2)
    if not ra2["ok"]:
        return False, "recreation of PVC %s" % pvc_name
    if not _wait_pvc_bound(pvc_name, ns, log):
        return False, "binding (Bound) of PVC %s" % pvc_name
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
        return {"ok": False, "error": "Volume Group required.", "points": []}
    items_all, page, guard, total = [], 1, 0, None
    while guard < 40:
        guard += 1
        r = _rest("hycu", "GET", "/volumegroups/%s/backups?pageSize=500&pageNumber=%d"
                  % (urllib.parse.quote(str(source_uuid)), page))
        if not r["ok"]:
            return {"ok": False, "error": r.get("error"), "points": []}
        data = r.get("json") or {}
        items = _hycu_items(data)
        if not items:
            break
        items_all.extend(items)
        total = (data.get("metadata") or {}).get("totalEntityCount", total)
        if total is not None:
            if len(items_all) >= int(total):
                break
        elif len(items) < 500:
            break
        page += 1
    out = []
    for it in items_all:
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
        return {"ok": False, "error": "Restore point required."}
    mode = payload.get("mode", "clone")
    if mode != "clone":
        # L'écrasement SUR PLACE du VG live passe exclusivement par l'orchestrateur
        # (arrêt de l'app, attente du détachement, garde contexte, suivi du job).
        return {"ok": False, "error": "Only “clone” mode is accepted here; the in-place restore "
                                      "goes through the orchestrator (Restore storage in place)."}
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
                "message": "Simulation: no HYCU call sent. Review the call "
                           "above, then turn off simulation to launch for real."}
    try:
        # Section critique courte (un POST) : les clones lancés en parallèle par l'interface
        # attendent leur tour au lieu d'être refusés ; une restauration longue en cours
        # finit tout de même par faire refuser la demande (délai).
        with action_lock(wait=60):
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
        return {"ok": False, "error": "Missing job identifier."}
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
        return None, "Empty Volume Group name."
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
            return None, ("Several Volume Groups named “%s” in "
                          "Nutanix: ambiguous — manual resolution required." % name)
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
            return None, "Several Volume Groups named “%s” in HYCU: ambiguous." % name
    return None, "Volume Group “%s” not found after the clone (Prism/HYCU)." % name


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
            return None, "Several HYCU Volume Groups named “%s”: ambiguous." % vg_name
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
        return False, None, "Missing HYCU job identifier."
    deadline = time.time() + max(5, int(timeout_s))
    last, read_errors = None, 0
    while time.time() < deadline:
        j = action_hycu_job(job_id)
        if not j.get("ok"):
            # Un hoquet réseau pendant un clone de plusieurs minutes ne doit pas faire
            # échouer le provisionnement (VG orphelin jamais découvert) : on retente.
            read_errors += 1
            if read_errors > _JOB_READ_ERRORS_TOLERATED:
                return False, last, j.get("error") or "Cannot read the HYCU job."
            time.sleep(max(1, int(poll_s)))
            continue
        read_errors = 0
        st = (j.get("status") or "").strip().upper()
        last = st or last
        if st in _JOB_OK:
            return True, st, None
        if st in _JOB_KO:
            return False, st, "Job HYCU finished failed (%s)." % st
        time.sleep(max(1, int(poll_s)))
    return False, last, "Timeout while waiting for HYCU job %s (last status: %s)." % (job_id, last or "?")


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
        return {"ok": False, "error": "No volume to provision.", "items": [], "log": []}
    if not dry and not SESSION_CREDS.get("hycu"):
        return {"ok": False, "error": "Connect HYCU to create the volumes "
                                      "automatically (otherwise, enter the UUIDs manually).", "items": [], "log": []}
    if not dry and not (SESSION_CREDS.get("prismcentral") or SESSION_CREDS.get("nutanix")):
        return {"ok": False, "error": "Connect Prism (Element or Central): "
                                      "the cloned VG UUID is discovered there.", "items": [], "log": []}
    ts = time.strftime("%Y%m%d-%H%M%S")
    timeout_s = int(payload.get("job_timeout_s") or 600)
    items, log = [], []
    for i, v in enumerate(vols):
        pvc = v.get("pvc")
        src = (v.get("source_vg_uuid") or "").strip()
        if not pvc or not src or not UUID_RE.search(src):
            return {"ok": False, "error": "Volume “%s”: source VG UUID "
                                          "missing/invalid (run the HYCU analysis again)." % (pvc or "?"), "items": [], "log": log}
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
                    return {"ok": False, "error": "Volume “%s”: %s" % (pvc, rerr), "items": [], "log": log}
                if resolved and resolved.lower() != hy_src.lower():
                    hy_src = resolved
                    log.append(logentry("VG HYCU identity resolved for %s" % pvc,
                                        stdout="%s -> %s" % (src, hy_src)))
                    good = [p for p in (action_hycu_restore_points(hy_src).get("points") or [])
                            if p.get("restorable", True)]
            if not good:
                return {"ok": False, "error": "Volume “%s”: no HYCU restore point "
                                              "found for this Volume Group. Check that "
                                              "the application is (or was) protected in HYCU." % pvc, "items": [], "log": log}
            rp = good[0].get("id")
        else:
            resolved, _ = _resolve_hycu_vg(src, v.get("vg_name"))
            if resolved:
                hy_src = resolved
        if dry:
            resolved_note = (" (HYCU identity resolved from %s)" % src) if hy_src != src else ""
            detail = "%s: HYCU source %s%s, restore point %s, new VG %s" % (
                pvc, hy_src, resolved_note, rp, new_name)
            log.append(logentry("Simulation of the automatic clone via HYCU (no real clone launched).",
                                dry=True, rc=None, stdout=detail))
            items.append({"pvc": pvc, "new_ref": None, "planned_name": new_name,
                          "hycu_source": hy_src, "restore_point_id": rp})
            continue
        # Réel : déclencher le clone HYCU (nom imposé), attendre, découvrir l'UUID.
        rr = action_hycu_restore({"restore_point_id": rp, "mode": "clone", "new_name": new_name,
                                  "source_uuid": hy_src, "dry": False})
        if not rr.get("ok"):
            return {"ok": False, "error": "Volume “%s”: HYCU clone refused: %s"
                    % (pvc, rr.get("error")), "items": items, "log": log}
        job_id = rr.get("job_id")
        log.append(logentry("HYCU clone started for %s (source VG %s, point %s, job %s)"
                            % (pvc, src, rp, job_id), stdout="New VG requested: %s" % new_name))
        ok, st, jerr = _await_hycu_job(job_id, timeout_s=timeout_s)
        if not ok:
            return {"ok": False, "error": "Volume “%s”: %s" % (pvc, jerr), "items": items, "log": log}
        new_uuid, derr = _discover_vg_uuid_by_name(new_name)
        if not new_uuid:
            return {"ok": False, "error": "Volume “%s”: HYCU clone finished but %s"
                    % (pvc, (derr or "UUID not found")), "items": items, "log": log}
        log.append(logentry("Cloned VG UUID discovered automatically for %s" % pvc,
                            stdout="%s -> %s (VG “%s”)" % (src, new_uuid, new_name)))
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
            log.append(logentry("VG HYCU identity resolved for %s" % pvc,
                                stdout="%s -> %s" % (src, hy_src)))
            good = [p for p in (action_hycu_restore_points(hy_src).get("points") or []) if p.get("restorable", True)]
    else:
        resolved, _ = _resolve_hycu_vg(src, vg_name)
        if resolved:
            hy_src = resolved
    if not good:
        return None, None, ("no HYCU restore point found for this Volume Group. "
                            "Check that the application is (or was) protected in HYCU.")
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
        return {"ok": False, "error": "No volume to restore.", "log": []}
    if not dry and not SESSION_CREDS.get("hycu"):
        return {"ok": False, "error": "Connect HYCU to restore the volumes "
                                      "automatically (otherwise, enter the UUIDs manually).", "log": []}
    timeout_s = int(payload.get("job_timeout_s") or 600)
    log = []
    for v in vols:
        pvc = v.get("pvc")
        src = (v.get("source_vg_uuid") or "").strip()
        if not pvc or not src or not UUID_RE.search(src):
            return {"ok": False, "error": "Volume “%s”: source VG UUID "
                                          "missing/invalid (run the HYCU analysis again)." % (pvc or "?"), "log": log}
        hy_src, rp, err = _resolve_source_and_point(pvc, src, v.get("vg_name"), log)
        if err:
            return {"ok": False, "error": "Volume “%s”: %s" % (pvc, err), "log": log}
        if dry:
            log.append(logentry("Simulation: HYCU will restore the Volume Group in "
                                "place (identity preserved) — no real restore launched.", dry=True, rc=None,
                                stdout="%s: HYCU source %s, restore point %s, UUID kept %s"
                                       % (pvc, hy_src, rp, src)))
            continue
        rr = action_hycu_restore({"restore_point_id": rp, "mode": "inplace", "source_uuid": hy_src, "dry": False})
        if not rr.get("ok"):
            return {"ok": False, "error": "Volume “%s”: HYCU restore refused: %s"
                    % (pvc, rr.get("error")), "log": log}
        job_id = rr.get("job_id")
        log.append(logentry("HYCU restore (in place) started for %s (VG %s, point %s, job %s)"
                            % (pvc, hy_src, rp, job_id), stdout="The VG is recreated at its original UUID: %s" % src))
        ok, st, jerr = _await_hycu_job(job_id, timeout_s=timeout_s)
        if not ok:
            return {"ok": False, "error": "Volume “%s”: %s" % (pvc, jerr), "log": log}
        log.append(logentry("Volume Group restored to its original identity for %s" % pvc,
                            stdout="UUID preserved: %s" % src))
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
        nutanix_uuid, nfs = None, None
        if pv_name:
            pv_data, _ = kubectl_json(["get", "pv", pv_name])
            if pv_data:
                nfs = _pv_nfs_info(pv_data)
                info = analyse_pv(pv_data)
                if info["old_volume_handle"] and not nfs:
                    nutanix_uuid = split_volume_handle(info["old_volume_handle"])[1]
        out.append({"pvc": name, "pv": pv_name, "nutanix_uuid": nutanix_uuid, "nfs": nfs})
    return out, None


def _hycu_list_shares():
    """Tous les partages connus de HYCU (Nutanix Files et NAS génériques), paginés.
    Renvoie (items, erreur)."""
    out, seen = [], set()
    page, page_size = 1, 500
    for _guard in range(80):
        r = _rest("hycu", "GET", "/shares?pageSize=%d&pageNumber=%d" % (page_size, page))
        if not r["ok"]:
            return None, r.get("error")
        data = r.get("json") or {}
        items = [it for it in _hycu_items(data) if isinstance(it, dict)]
        fresh = 0
        for it in items:
            uid = it.get("uuid") or it.get("externalId") or (it.get("fileServerName"), it.get("shareName"))
            if uid in seen:
                continue
            seen.add(uid)
            out.append(it)
            fresh += 1
        total = (data.get("metadata") or {}).get("totalEntityCount")
        if not items or fresh == 0 or (total is not None and len(out) >= int(total)) \
                or (total is None and len(items) < page_size):
            break
        page += 1
    return out, None


def _share_root(share):
    """Chemin d'export d'un partage HYCU, normalisé : « serveur:/a/b » -> « /a/b »."""
    p = str(share.get("sharePath") or "").strip()
    if ":/" in p:
        p = p.split(":", 1)[1]
    p = "/" + p.strip("/") if p.strip("/") else ""
    return p or ("/" + str(share.get("shareName") or "").strip("/"))


def _match_share(nfs, shares):
    """Partage HYCU d'un export NFS. Correspondance EXACTE = même chemin d'export (ou
    sous-dossier) ET même serveur de fichiers ; chemin seul = suggestion à confirmer
    (serveur nommé autrement, IP…). Plusieurs candidats égaux = ambigu.
    Renvoie (partage ou None, 'exact'|'name'|'ambiguous'|'none', sous-chemin)."""
    path = "/" + (nfs.get("path") or "").strip("/")
    host = (nfs.get("server") or "").strip().lower().rstrip(".")
    short = host.split(".")[0]
    cands = []
    for sh in shares or []:
        root = _share_root(sh).lower()
        if not root or not (path.lower() == root or path.lower().startswith(root + "/")):
            continue
        names = {str(sh.get(k) or "").strip().lower().rstrip(".")
                 for k in ("fileServerName", "externalHypervisorName", "svm_name") if sh.get(k)}
        srv = bool(names) and any(n == host or n == short or n.split(".")[0] == short for n in names)
        cands.append((len(root), srv, sh, path[len(root):] or "/"))
    if not cands:
        return None, "none", ""
    best = max(c[0] for c in cands)
    top = [c for c in cands if c[0] == best]
    exact = [c for c in top if c[1]]
    if len(exact) == 1:
        return exact[0][2], "exact", exact[0][3]
    if len(exact) > 1 or len(top) > 1:
        return None, "ambiguous", ""
    return top[0][2], "name", top[0][3]


def _share_backups(share_uuid):
    """Sauvegardes HYCU d'un partage, la plus récente d'abord (échecs écartés).
    Renvoie (liste, erreur)."""
    r = _rest("hycu", "GET", "/shares/%s/backups?pageSize=200&pageNumber=1"
              % urllib.parse.quote(str(share_uuid)))
    if not r["ok"]:
        return None, r.get("error")
    out = []
    for b in _hycu_items(r.get("json") or {}):
        if not isinstance(b, dict) or not b.get("uuid"):
            continue
        st = " ".join(str(b.get(k) or "") for k in ("status", "primaryTargetStatus")).upper()
        if "FAIL" in st or "ERROR" in st or "ABORT" in st or "RUNNING" in st or "PROGRESS" in st:
            continue
        if not b.get("endTime") and "endTime" in b:      # sauvegarde encore en cours
            continue
        out.append(b)
    out.sort(key=_hycu_ts, reverse=True)
    return out, None


def _share_backup_has(backup_uuid, sub):
    """Vrai si la sauvegarde de partage contient le dossier « sub » (listage de son parent)."""
    parent = "/".join(sub.strip("/").split("/")[:-1])
    entries, _err = _share_browse(backup_uuid, parent)
    names = {str(e.get("fullItemName") or e.get("displayName") or "").strip("/").split("/")[-1]
             for e in (entries or [])}
    return sub.strip("/").split("/")[-1] in names


def _share_backup_now(share_uuid, log, label="share"):
    """Lance une sauvegarde HYCU du partage et attend sa fin. Renvoie (ok, erreur)."""
    r = _rest("hycu", "POST", "/schedules/backupShare", body={"uuidList": [share_uuid], "forceFull": False})
    if not r["ok"]:
        return False, r.get("error") or "backup request refused"
    log.append(logentry("HYCU backup of %s started (the latest backup predates the folder to copy)" % label,
                        stdout=json.dumps(r.get("json"), ensure_ascii=False)[:300]))
    return _wait_hycu_job(_hycu_job_id(r.get("json") or {}), log, label="HYCU backup of %s" % label), None


def _hycu_ts(b):
    """Horodatage (s) d'une sauvegarde HYCU : fin, début ou création (ms ou s)."""
    for k in ("endTime", "startTime", "created"):
        try:
            v = float(b.get(k) or 0)
        except (TypeError, ValueError):
            continue
        if v:
            return v / 1000.0 if v > 1e11 else v
    return 0.0


def _hycu_ts_label(b):
    """Date lisible d'une sauvegarde HYCU."""
    v = _hycu_ts(b)
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(v)) if v else str(b.get("uuid") or "?")


def _share_browse(backup_uuid, path):
    """Contenu d'un dossier d'une sauvegarde de partage (lecture seule). Même protocole que
    l'interface HYCU : session FLR créée côté client (flrSessId), chemin RELATIF au partage
    (« » pour la racine, « a/b » sinon), 503 passager pendant le montage de la sauvegarde
    (nouvelles tentatives) ; la session est refermée à la fin. Renvoie (éléments, erreur) ;
    chaque élément garde fullItemName (format attendu par restoreShareItems)."""
    sess = "hycu-k8s-%d" % int(time.time() * 1000)
    rel = (path or "").strip("/")
    items, err, page, tries, diag = [], None, 1, 0, None
    while page <= 20:
        params = {"path": rel, "flrSessId": sess, "restoreSource": "AUTO", "pageNumber": page,
                  "pageSize": 1000, "orderBy": "displayName"}
        r = _rest("hycu", "GET", "/shares/backup/%s/browseShare?%s"
                  % (urllib.parse.quote(str(backup_uuid)), urllib.parse.urlencode(params)), timeout=120)
        data = r.get("json") if r["ok"] else None
        got = [e for e in _hycu_items(data or {})
               if isinstance(e, dict) and (e.get("fullItemName") or e.get("displayName"))]
        if diag is None:
            diag = (json.dumps(data, ensure_ascii=False) if data else (r.get("raw") or r.get("error") or ""))[:400]
        # Montage de la sauvegarde en cours : 503, ou première page vide -> on réessaie.
        if (not r["ok"] and r.get("status") in (502, 503, 504)) or (r["ok"] and not got and not items):
            if tries < 8:
                tries += 1
                time.sleep(3)
                continue
        if not r["ok"]:
            err = ("%s %s" % (r.get("error") or "browse failed", (r.get("raw") or "")[:300])).strip()
            break
        items.extend(got)
        meta = data.get("metadata") if isinstance(data, dict) else None
        total = meta.get("totalEntityCount") if isinstance(meta, dict) else None
        if len(got) < 1000 or (total is not None and len(items) >= int(total)):
            break
        page += 1
    _rest("hycu", "POST", "/shares/backup/%s/browseShareClose?%s"
          % (urllib.parse.quote(str(backup_uuid)), urllib.parse.urlencode({"flrSessId": sess})))
    if not items and not err:
        err = "HYCU answered: %s" % (diag or "nothing")
    return (None, err) if err else (items, None)


def _nfs_copy_excluded(share_root_path, server):
    """Dossiers de 1er niveau d'un partage occupés par des COPIES déjà créées par l'outil
    (PV clonés vivants visant ce partage) : jamais recopiés dans une nouvelle copie."""
    out = set()
    pvs, _e = kubectl_json(["get", "pv", "-l", "%s=%s" % (CLONE_LABEL, CLONE_LABEL_VAL)])
    root = share_root_path.rstrip("/")
    for pv in (pvs or {}).get("items", []) or []:
        nfs = _pv_nfs_info(pv)
        if not nfs or nfs["server"].lower() != (server or "").lower():
            continue
        p = "/" + nfs["path"].strip("/")
        if p.startswith(root + "/"):
            first = p[len(root) + 1:].split("/")[0]
            if first:
                out.add(first)
    return out


def _nfs_copy_plan(nfs, pvc_name):
    """Prépare la COPIE d'un volume NAS : partage HYCU (correspondance exacte exigée),
    sauvegarde la plus récente et éléments à restaurer (contenu du dossier monté par le
    PV). Le dossier cible et le chemin du nouveau PV sont fixés par _nfs_copy_target.
    Renvoie (plan, erreur)."""
    if not SESSION_CREDS.get("hycu"):
        return None, ("“%s” is a NAS volume: its copy goes through an HYCU "
                      "restore of the share into a new folder. Connect HYCU and try again." % pvc_name)
    shares, err = _hycu_list_shares()
    if shares is None:
        return None, "HYCU shares unreadable: %s" % err
    sh, kind, sub = _match_share(nfs, shares)
    if kind != "exact" or not sh:
        why = {"name": "path-only match",
               "ambiguous": "several possible shares"}.get(kind, "no share")
        return None, ("“%s” (%s): no HYCU share exactly "
                      "matches this export (%s) — add this NAS in HYCU." % (pvc_name, _nfs_label(nfs), why))
    backups, err = _share_backups(sh["uuid"])
    if backups is None:
        return None, "Backups of share “%s” unreadable: %s" % (sh.get("shareName"), err)
    if not backups:
        return None, ("HYCU share “%s” has no backup yet: run "
                      "one (Set Policy), then run the copy again." % sh.get("shareName"))
    bk = backups[0]
    sub = ("/" + sub.strip("/")) if (sub or "").strip("/") else "/"
    root_path = "/" + nfs["path"].strip("/")
    if sub != "/":
        root_path = root_path[:-len(sub)] or "/"
    entries, err = _share_browse(bk["uuid"], sub)
    # Sous-dossier monté par le PV : la sauvegarde la plus récente doit le CONTENIR, sinon
    # HYCU restaurerait autre chose (dossier créé après la dernière sauvegarde du partage :
    # cas d'une copie faite juste après la création de l'application ou d'une autre copie).
    needs_backup = sub != "/" and not _share_backup_has(bk["uuid"], sub)
    return {"share_uuid": sh["uuid"], "share_name": sh.get("shareName") or "", "backup_uuid": bk["uuid"],
            "backup_time": _hycu_ts_label(bk), "sub": sub, "root_path": root_path,
            "server": nfs["server"], "entries": entries or [], "browse_error": err,
            "needs_backup": needs_backup}, None


def _nfs_copy_target(plan, folder, src_ns=None):
    """Dossier cible (relatif au partage) -> (corps de la restauration HYCU, chemin d'export
    du nouveau PV, éléments retenus, éléments écartés, sous-dossier à remettre à plat).
    Invariant : les données de la copie vivent dans <racine>/<dossier>, avec EXACTEMENT
    l'arborescence que l'application voyait sous son point de montage ; le PV de la copie
    vise toujours <racine>/<dossier>. Comme HYCU recrée le chemin d'origine sous le dossier
    cible (« /app1 » restauré dans « copie » donne « copie/app1 »), un PV monté sur un
    sous-dossier « app1 » exige une remise à plat après coup (Job _nas_flatten : « copie/app1/* »
    -> « copie/ ») — sinon chaque copie de copie ajouterait un niveau.
    Partage monté à la racine : un partage sert souvent plusieurs namespaces (un dossier par
    namespace) — seul le dossier au nom du namespace SOURCE est copié s'il existe ; ce dossier
    fait partie des chemins de l'application, il est donc conservé tel quel."""
    pv_path = plan["root_path"].rstrip("/") + "/" + folder
    if plan["sub"] != "/":
        sub = plan["sub"].strip("/")
        body = {"shareUuid": plan["share_uuid"], "targetShareUuid": plan["share_uuid"],
                "restoreItemType": "FILESYSTEM", "selectedItems": ["/" + sub], "restoreSource": "AUTO",
                "restoreOverwriteMode": "OVERWRITE", "restoreACLs": False, "sharedLocation": False,
                "restoreTargetPath": folder}
        return body, pv_path, ["/" + sub], [], sub
    if src_ns:
        mine = [str(e.get("fullItemName") or e.get("displayName") or "") for e in plan["entries"]
                if str(e.get("fullItemName") or e.get("displayName") or "").strip("/").split("/")[-1] == src_ns]
        if mine:
            others = sorted({str(e.get("fullItemName") or e.get("displayName") or "").strip("/").split("/")[-1]
                             for e in plan["entries"]} - {src_ns})
            plan["ns_folder"] = src_ns
            body = {"shareUuid": plan["share_uuid"], "targetShareUuid": plan["share_uuid"],
                    "restoreItemType": "FILESYSTEM", "selectedItems": mine[:1], "restoreSource": "AUTO",
                    "restoreOverwriteMode": "OVERWRITE", "restoreACLs": False, "sharedLocation": False,
                    "restoreTargetPath": folder}
            return body, pv_path, mine[:1], others, None
    excluded = _nfs_copy_excluded(plan["root_path"], plan["server"]) | {folder.split("/")[0]}
    sel, skipped = [], []
    if not plan["entries"]:
        # Parcours vide ou indisponible : on restaure la racine du partage en entier.
        sel = ["/"]
    for e in plan["entries"]:
        full = str(e.get("fullItemName") or e.get("displayName") or "")
        top = full.strip("/").split("/")[-1]
        if top in excluded:
            skipped.append(top)
            continue
        sel.append(full)
    body = {"shareUuid": plan["share_uuid"], "targetShareUuid": plan["share_uuid"],
            "restoreItemType": "FILESYSTEM", "selectedItems": sel, "restoreSource": "AUTO",
            "restoreOverwriteMode": "OVERWRITE", "restoreACLs": False, "sharedLocation": False,
            "restoreTargetPath": folder}
    return body, pv_path, sel, skipped, None


_NAS_FLATTEN_SCRIPT = r"""cd /w || exit 5
S="$1"
[ -d "$S" ] || { echo "folder $S not found under the target folder"; ls -la; exit 4; }
moved=0
for e in "$S"/* "$S"/.[!.]* "$S"/..?*; do
  [ -e "$e" ] || continue
  if ! mv -n "$e" . 2>/tmp/err; then
    cat /tmp/err
    if [ "$moved" = 0 ] && grep -qi "denied" /tmp/err; then exit 3; fi
    exit 5
  fi
  moved=$((moved+1))
done
rmdir -p "$S" 2>/dev/null
echo "moved $moved entry(ies) of $S to the folder root"
ls -la
"""


def _nas_flatten(ns, server, folder_path, sub, log, timeout=180):
    """Post-traitement d'une copie NAS : Job Kubernetes (namespace cible) qui monte
    <serveur>:<folder_path> et remonte « <sub>/* » d'un niveau, pour que la copie garde
    l'arborescence de l'original. Renvoie ("ok" | "denied" | "error", détail).
    « denied » = rien n'a été déplacé (root squash : le Job tourne en anonyme et ne peut pas
    écrire dans le dossier créé par HYCU) -> l'appelant garde le chemin imbriqué."""
    name = re.sub(r"[^a-z0-9-]+", "-", ("hycu-nas-flatten-%s-%d" % (sub.split("/")[-1], int(time.time()))).lower())[:63].strip("-")
    job = {"apiVersion": "batch/v1", "kind": "Job",
           "metadata": {"name": name, "namespace": ns, "labels": {CLONE_LABEL: CLONE_LABEL_VAL}},
           "spec": {"backoffLimit": 0, "ttlSecondsAfterFinished": 600, "template": {"spec": {
               "restartPolicy": "Never", "securityContext": {"runAsUser": 0},
               "containers": [{"name": "flatten", "image": CONFIG.get("nas_job_image") or "busybox:1.36",
                               "command": ["/bin/sh", "-c", _NAS_FLATTEN_SCRIPT, "flatten", sub],
                               "volumeMounts": [{"name": "w", "mountPath": "/w"}]}],
               "volumes": [{"name": "w", "nfs": {"server": server, "path": folder_path}}]}}}}
    r = _apply_manifest(job, "nas_flatten_%s" % name, False, "NAS copy: flatten “%s/%s” (Job %s)" % (folder_path, sub, name))
    log.append(r)
    if not r["ok"]:
        return "error", r.get("stderr") or "Job not created"
    status, deadline = None, time.time() + timeout
    while time.time() < deadline:
        data, _e = kubectl_json(["get", "job", name, "-n", ns])
        st = (data or {}).get("status") or {}
        if st.get("succeeded"):
            status = "ok"
            break
        if st.get("failed") or any((c.get("type") == "Failed" and c.get("status") == "True")
                                   for c in st.get("conditions") or []):
            status = "failed"
            break
        time.sleep(3)
    lg = kubectl(["logs", "job/%s" % name, "-n", ns], dry=False, label="Flatten Job output")
    out = (lg.get("stdout") or "").strip()
    rc = None
    pods, _e = kubectl_json(["get", "pods", "-n", ns, "-l", "job-name=%s" % name])
    for pod in (pods or {}).get("items", []) or []:
        for cs in ((pod.get("status") or {}).get("containerStatuses") or []):
            term = (cs.get("state") or {}).get("terminated") or {}
            if term.get("exitCode") is not None:
                rc = int(term["exitCode"])
    kubectl(["delete", "job", name, "-n", ns, "--wait=false", "--ignore-not-found"], dry=False, label="Delete Job %s" % name)
    if status == "ok":
        log.append(logentry("NAS copy flattened: “%s/%s” moved to “%s”" % (folder_path, sub, folder_path), stdout=out))
        return "ok", out
    if status is None:
        return "error", "Job %s did not finish within %ss%s" % (name, timeout, (": " + out) if out else "")
    if rc == 3:
        log.append(logentry("NAS copy: flatten refused by the NAS (permission denied) — nested path kept",
                            ok=False, rc=3, stderr=out))
        return "denied", out
    return "error", "Job %s failed (exit %s): %s" % (name, rc, out or "no output")


def action_hycu_match(ns, vg_items=None):
    """Associe chaque PVC du namespace à son Volume Group HYCU.
    Pivot FIABLE = égalité EXACTE de l'UUID : l'externalId d'un VG Nutanix est
    l'UUID du Volume Group, identique à celui du volumeHandle du PV. Le match par
    NOM (nom du VG = nom du PV côté CSI) n'est qu'une SUGGESTION à confirmer, jamais
    auto-protégée. Toute ambiguïté (plusieurs VG pour un même UUID/nom) n'est jamais
    tranchée au hasard : le PVC est marqué 'ambiguous'."""
    if not _namespace_allowed(ns):
        return {"ok": False, "error": "Namespace '%s' not allowed." % ns, "matches": []}
    vols, err = _namespace_nutanix_vgs(ns)
    if err:
        return {"ok": False, "error": err, "matches": []}
    # `vg_items` : liste des VG HYCU déjà lue (une seule lecture pour plusieurs namespaces).
    items, herr = (vg_items, None) if vg_items is not None else _hycu_list_vgs()
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
    shares, sherr = None, None
    if any(v.get("nfs") for v in vols):
        shares, sherr = _hycu_list_shares()
    matches = []
    for v in vols:
        if v.get("nfs"):
            # Volume NAS : correspondance avec un PARTAGE HYCU (Nutanix Files ou NAS générique).
            sh, kind = (None, "none")
            sub = ""
            if shares is not None:
                sh, kind, sub = _match_share(v["nfs"], shares)
            matches.append({
                "pvc": v["pvc"], "pv": v.get("pv"), "nutanix_uuid": None,
                "volume_kind": "nfs", "nfs": _nfs_label(v["nfs"]),
                "hycu_vg_uuid": None, "hycu_vg_name": None, "hycu_external_id": None,
                "hycu_share_uuid": sh.get("uuid") if sh else None,
                "hycu_share_name": (sh.get("shareName") if sh else None),
                "hycu_file_server": (sh.get("fileServerName") or sh.get("externalHypervisorName")) if sh else None,
                "share_subpath": sub,
                "match_kind": kind, "trusted": kind == "exact", "matched": sh is not None,
                "protected": sh.get("status") if sh else None,
                "compliancy": sh.get("compliancyStatus") if sh else None,
                "policy": sh.get("protectionGroupName") if sh else None,
                "has_backups": bool(sh and (sh.get("status") == "PROTECTED" or sh.get("compliancyStatus") == "GREEN")),
                "error": sherr if (shares is None and sherr) else None,
            })
            continue
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
    out = {"ok": True, "namespace": ns, "matches": matches}
    with _MATCH_CACHE_LOCK:
        _MATCH_CACHE[(_current_cid(), ns)] = {"at": time.time(), "match": out}
    return out


def _reject_stale_vgs(ns, uuids, confirmed_by_name=None):
    """Re-vérifie côté serveur que tous les `uuids` (VG HYCU) appartiennent à la
    correspondance COURANTE du namespace (anti-stale / anti mauvais-volume). Renvoie
    un message d'erreur si l'un est hors-correspondance, sinon None."""
    if not ns:
        return None
    # La correspondance vient en général d'être calculée par l'interface (« Analyser ») :
    # réutilisée si récente — un nouveau parcours complet des VG HYCU prendrait de
    # longues secondes à chaque clic — sinon recalculée. Toute écriture (restauration,
    # clone, sauvegarde) vide ce cache.
    match = None
    with _MATCH_CACHE_LOCK:
        cached = _MATCH_CACHE.get((_current_cid(), ns))
    if cached and time.time() - cached["at"] <= _MATCH_CACHE_TTL:
        match = cached["match"]
    if match is None:
        match = action_hycu_match(ns)
    if not match.get("ok"):
        return "Could not re-verify the mapping: %s" % match.get("error")
    # Seule une correspondance de CONFIANCE (UUID exact) autorise une opération HYCU :
    # un match « par nom » n'est qu'une suggestion (cf. action_hycu_match) et ne doit
    # jamais suffire à restaurer/protéger un volume.
    def ident(m):                          # Volume Group OU partage NAS
        return m.get("hycu_vg_uuid") or m.get("hycu_share_uuid")
    allowed = {ident(m) for m in match.get("matches", [])
               if m.get("matched") and ident(m) and m.get("trusted")}
    by_name = {ident(m) for m in match.get("matches", [])
               if m.get("matched") and ident(m) and not m.get("trusted")}
    if confirmed_by_name:
        allowed |= (by_name & set(confirmed_by_name))
    bad = [u for u in uuids if u and u not in allowed]
    if bad:
        unconfirmed = [u for u in bad if u in by_name]
        if unconfirmed:
            return ("Volume Group(s) matched only BY NAME (externalId differs from the "
                    "volumeHandle): %s. Explicitly confirm each “by name” volume before a destructive operation."
                    % ", ".join(unconfirmed))
        return ("Volume Group(s) outside the current mapping "
                "of namespace “%s”: %s. Run the analysis again." % (ns, ", ".join(bad)))
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
    Deux formes de charge :
      - un namespace : { namespace, vg_uuids, confirm_name_uuids, ... } ;
      - PLUSIEURS applications en une fois : { items: [{namespace, vg_uuids,
        confirm_name_uuids}, ...], ... } — un seul appel HYCU d'assignation et un
        seul lancement de sauvegarde pour tous les Volume Groups.
    Garde-fou par namespace : tout VG hors de la correspondance courante est REFUSÉ
    (anti-état périmé / anti-mauvaise cible) ; rien n'est envoyé à HYCU si un seul
    namespace échoue à cette vérification."""
    dry = bool(payload.get("dry", True))
    policy_uuid = (payload.get("policy_uuid") or "").strip()
    force_full = bool(payload.get("force_full"))
    items = payload.get("items")
    if not isinstance(items, list) or not items:
        items = [{"namespace": payload.get("namespace"), "vg_uuids": payload.get("vg_uuids") or [],
                  "share_uuids": payload.get("share_uuids") or [],
                  "confirm_name_uuids": payload.get("confirm_name_uuids") or []}]
    vg_uuids = sorted({u for it in items for u in (it.get("vg_uuids") or []) if u})
    share_uuids = sorted({u for it in items for u in (it.get("share_uuids") or []) if u})
    namespaces = [it.get("namespace") for it in items if it.get("namespace")]
    ns = namespaces[0] if len(namespaces) == 1 else None      # audit / compatibilité
    if not vg_uuids and not share_uuids:
        return {"ok": False, "error": "No HYCU Volume Group or share to "
                                      "protect (no match found — see the analysis)."}

    for it in items:
        it_ns = it.get("namespace")
        it_vgs = sorted({u for u in (it.get("vg_uuids") or []) + (it.get("share_uuids") or []) if u})
        if it_ns and it_vgs:
            stale = _reject_stale_vgs(it_ns, it_vgs, confirmed_by_name=it.get("confirm_name_uuids") or [])
            if stale:
                return _err(stale)

    acquired = False
    if not dry:
        if not ACTION_LOCK.acquire(blocking=False):
            return _err("Another operation is already running. Try again.")
        acquired = True
    try:
        base, api, _ = _system_cfg("hycu")
        steps = []
        if policy_uuid:
            path = "/policies/%s/assign" % urllib.parse.quote(policy_uuid)
            body = {"volumeGroupUuidList": vg_uuids, "includeDependencies": False}
            if share_uuids:
                body["shareUuidList"] = share_uuids
            if dry:
                steps.append({"label": "Assign the policy", "ok": True, "dry": True,
                              "planned": {"method": "POST", "url": base + api + path, "body": body}})
            else:
                r = _rest("hycu", "POST", path, body=body)
                steps.append({"label": "Assign the policy", "ok": r["ok"],
                              "error": r.get("error"), "raw": (r.get("raw") or "")[:300]})
                if not r["ok"]:
                    audit("hycu_protect", ok=False, step="assign", namespace=ns,
                          namespaces=namespaces, policy=policy_uuid, vgs=vg_uuids)
                    return {"ok": False, "error": "Policy assignment failed: %s" % r.get("error"),
                            "steps": steps, "dry": False}

        runs = []
        if vg_uuids:
            runs.append(("Start the backup now", "/schedules/backupVolumeGroup", vg_uuids))
        if share_uuids:
            runs.append(("Start the NAS shares backup", "/schedules/backupShare", share_uuids))
        if dry:
            for label, path, uuids in runs:
                steps.append({"label": label, "ok": True, "dry": True,
                              "planned": {"method": "POST", "url": base + api + path,
                                          "body": {"uuidList": uuids, "forceFull": force_full}}})
            return {"ok": True, "dry": True, "steps": steps}
        ok_all, job_id = True, None
        for label, path, uuids in runs:
            r = _rest("hycu", "POST", path, body={"uuidList": uuids, "forceFull": force_full})
            jid = _hycu_job_id(r.get("json") or {})
            job_id = job_id or jid
            ok_all = ok_all and bool(r["ok"])
            steps.append({"label": label, "ok": r["ok"], "error": r.get("error"), "job_id": jid,
                          "raw": (r.get("raw") or "")[:300]})
        audit("hycu_protect", ok=ok_all, policy=policy_uuid or None, force_full=force_full,
              namespace=ns, namespaces=namespaces, vgs=vg_uuids, shares=share_uuids, job=job_id)
        return {"ok": ok_all, "dry": False, "steps": steps, "job_id": job_id,
                "namespaces": namespaces, "count": len(vg_uuids) + len(share_uuids)}
    finally:
        if acquired:
            ACTION_LOCK.release()




def _wait_hycu_job(job_id, log, timeout=None, label="Job HYCU"):
    """Attend la fin d'un job HYCU (poll /jobs/{uuid}). Renvoie True si succès.
    - les erreurs de poll sont comptées : abandon après 5 échecs consécutifs, et
      immédiatement si la session HYCU a disparu (« Non connecté ») ;
    - WARNING = terminé avec avertissements (succès, signalé) ; tout statut inconnu
      est journalisé à la fin pour diagnostic ;
    - délai = CONFIG["hycu_job_timeout"] (1800 s par défaut)."""
    if timeout is None:
        timeout = int(CONFIG.get("hycu_job_timeout") or 1800)
    if not job_id:
        log.append({"ok": False, "dry": False, "label": label, "rc": -1, "stdout": "",
                    "stderr": "HYCU job not identified — completion cannot be confirmed."})
        return False
    deadline = time.time() + timeout
    errors, last_status, last_error = 0, "", ""
    while time.time() < deadline:
        r = _rest("hycu", "GET", "/jobs/%s" % urllib.parse.quote(str(job_id)))
        if r["ok"]:
            errors = 0
            job = _hycu_first(r.get("json") or {})
            status = str((job or {}).get("status") or "").upper()
            last_status = status or last_status
            if status in _JOB_OK:
                log.append({"ok": True, "dry": False, "label": "%s finished" % label, "rc": 0,
                            "stdout": status + (" (with warnings in HYCU)" if "WARN" in status else ""),
                            "stderr": ""})
                return True
            if status in _JOB_KO:
                log.append({"ok": False, "dry": False, "label": "%s failed" % label, "rc": -1,
                            "stdout": "", "stderr": status})
                return False
        else:
            errors += 1
            last_error = r.get("error") or ""
            if last_error.startswith("Not connected") or errors >= 5:
                log.append({"ok": False, "dry": False, "label": label, "rc": -1, "stdout": "",
                            "stderr": "HYCU job tracking interrupted (%s) — last status seen: %s. The "
                                      "job may still be running in HYCU: check it before running again."
                                      % (last_error, last_status or "none")})
                return False
        time.sleep(3)
    log.append({"ok": False, "dry": False, "label": label, "rc": -1, "stdout": "",
                "stderr": "Timeout exceeded (%ss) — last status seen: %s. The job keeps running in HYCU."
                          % (timeout, last_status or "none")})
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
        return {"ok": False, "error": "Namespace '%s' not allowed." % ns, "log": []}
    if not SESSION_CREDS.get("hycu"):
        return {"ok": False, "error": "Connect to HYCU to orchestrate the in-place restore.", "log": []}
    items = [it for it in (payload.get("items") or [])
             if it.get("source_vg_uuid") and it.get("restore_point_id")]
    if not items:
        return {"ok": False, "error": "No volume with a selected restore point.", "log": []}

    # Garde anti-stale : les VG source doivent appartenir à la correspondance courante.
    stale = _reject_stale_vgs(ns, [it["source_vg_uuid"] for it in items],
                              confirmed_by_name=[it["source_vg_uuid"] for it in items if it.get("confirm_name_match")])
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
            return {"ok": False, "error": "Another operation is already running. Try again.", "log": []}
        acquired = True
    try:
        aborted = False
        pvc_names = [it["pvc"] for it in items]
        base, api, _ = _system_cfg("hycu")

        current, desired, werr = _resolve_workloads(ns)
        if werr:
            return _err("Workloads unreadable: %s" % werr, log=log)
        # Pré-vol : HYCU joignable (et Prism Central si le rafraîchissement du disque est
        # actif) AVANT d'arrêter l'application. Un workload géré par un opérateur bloque.
        if not dry:
            pf = _rest("hycu", "GET", "/jobs?pageSize=1&pageNumber=1")
            if not pf.get("ok"):
                return _err("Preflight: HYCU unreachable (%s) — application not stopped." % pf.get("error"), log=log)
            log.append(logentry("Preflight ✓ HYCU reachable", cmd="GET /jobs"))
            if CONFIG.get("inplace_refresh_pv_disk", True) and not SESSION_CREDS.get("prismcentral"):
                log.append(logentry("Preflight ? Prism Central not connected: the PV disk "
                                    "cannot be refreshed after the restore (FailedMount possible)", ok=True))
            owned = [w for w in current if w.get("owner")]
            if owned:
                return _err("Preflight: operator-managed workload(s) (%s) — the "
                            "scale-down would be undone during the restore. Pause the operator." %
                            "; ".join("%s/%s <- %s" % (w["kind"], w["name"], w["owner"]) for w in owned), log=log)
        log.append({"ok": True, "dry": dry, "label": "Replicas recorded", "rc": 0, "stderr": "", "cmd": "(read)",
                    "stdout": ", ".join("%s/%s=%s" % (w["kind"], w["name"], w["replicas"]) for w in desired) or "none"})
        if not _stop_workloads(current, ns, dry, log)[0]:
            aborted = True

        if not dry and not aborted:
            if not _wait_pods_gone(ns, pvc_names, CONFIG["wait_timeout"], log):
                aborted = True
            # Le VG doit être DÉTACHÉ de la VM worker avant que HYCU ne le restaure
            # (ControllerUnpublish est asynchrone et postérieur à la disparition du pod).
            if not aborted:
                for it in items:
                    pvc_live, _ = kubectl_json(["get", "pvc", it["pvc"], "-n", ns, "--ignore-not-found"])
                    pvn = ((pvc_live or {}).get("spec") or {}).get("volumeName")
                    if pvn and not _wait_volume_attachments_gone(pvn, CONFIG["wait_timeout"], log):
                        aborted = True
                        break

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
                    log.append(logentry("PV refresh interrupted: %s" % detail_ref, ok=False, rc=-1))
                    break

        restart_failed = []
        if not aborted:
            ok_restart, restart_failed = _restart_workloads(desired, ns, dry, log)
            if not ok_restart:
                aborted = True
        if aborted:
            log.append({"ok": False, "dry": dry, "label": "SEQUENCE ABORTED", "rc": -1, "stdout": "", "cmd": "",
                        "stderr": "A step failed. The application stays STOPPED to avoid restarting "
                                  "on inconsistent data. Fix the issue then retry, or restart manually: " +
                        "; ".join(restart_failed or ["kubectl scale %s %s -n %s --replicas=%s" % (w["kind"], w["name"], ns, w["replicas"]) for w in desired])})

        if not dry:
            v = action_verify(ns)
            log.append({"ok": True, "dry": False, "label": "Final verification", "rc": 0, "stderr": "",
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
            w.setdefault("kind", "Deployment" if kind == "deployment" else "StatefulSet")
            # volumes du pod template ET volumeClaimTemplates d'un StatefulSet
            if any(c in wanted for c in _workload_pvcs(w, list(wanted))):
                out.append(w)
    return out


CLONE_LABEL = "hycu.io/clone"              # label dédié : n'écrase pas app.kubernetes.io/managed-by (Helm, Argo)
CLONE_LABEL_VAL = "true"
# Suffixe de clone : RFC 1123 (minuscules, chiffres, tirets), 30 caractères max.
CLONE_SUFFIX_RE = re.compile(r"^-?[a-z0-9]([-a-z0-9]{0,28}[a-z0-9])?$")


def _suffix_selectors(sel_or_labels, suffix, keys):
    for k in keys:
        if k in sel_or_labels:
            sel_or_labels[k] = str(sel_or_labels[k]) + suffix


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
        keys = list(sel.keys())
        for k in keys:
            sel[k] = str(sel[k]) + suffix
            if k in tmpl_labels:
                tmpl_labels[k] = str(tmpl_labels[k]) + suffix
        sel["hycu-clone"] = iso
        tmpl_labels["hycu-clone"] = iso
        # Les sélecteurs d'affinité / anti-affinité / topologySpread du template doivent
        # suivre le même suffixe, sinon le clone s'exclut des nœuds des pods d'origine.
        pspec = spec.setdefault("template", {}).setdefault("spec", {})
        aff = pspec.get("affinity") or {}
        for kind_aff in ("podAffinity", "podAntiAffinity"):
            block = aff.get(kind_aff) or {}
            for term in (block.get("requiredDuringSchedulingIgnoredDuringExecution") or []):
                _suffix_selectors(((term.get("labelSelector") or {}).get("matchLabels") or {}), suffix, keys)
            for wt in (block.get("preferredDuringSchedulingIgnoredDuringExecution") or []):
                _suffix_selectors((((wt.get("podAffinityTerm") or {}).get("labelSelector") or {}).get("matchLabels") or {}), suffix, keys)
        for tsc in (pspec.get("topologySpreadConstraints") or []):
            _suffix_selectors(((tsc.get("labelSelector") or {}).get("matchLabels") or {}), suffix, keys)
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
        headless = (spec.get("clusterIP") == "None")
        for k in ("clusterIP", "clusterIPs", "externalIPs", "loadBalancerIP", "healthCheckNodePort"):
            spec.pop(k, None)
        if headless:                       # Service headless (StatefulSet) : DNS par pod à conserver
            spec["clusterIP"] = "None"
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
        # volumes du pod template ET volumeClaimTemplates d'un StatefulSet (PVC
        # « <template>-<sts>-<n> » sauvegardés comme les autres : le STS recréé les adopte).
        if any(c in wanted for c in _workload_pvcs(o, list(wanted))):
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
                            "vol_nfs": dict(v.get("vol_nfs") or {}),
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
        print("Bulk restore journal not written: %s" % e)


def _parse_as_of(s):
    """Instant de référence (ISO local, ex. 2026-09-26T08:30) -> (epoch, erreur) ; vide = maintenant."""
    s = (s or "").strip()
    if not s:
        return time.time(), None
    try:
        return datetime.datetime.fromisoformat(s.replace("Z", "")).timestamp(), None
    except ValueError:
        return None, "Invalid reference time: “%s” (format YYYY-MM-DDTHH:MM)." % s


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
        return _err("Cannot list the cluster's namespaces (%s): plan refused out of caution." % lerr)
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
            skipped.append({"ns": ns, "reason": "excluded by the operator"})
            continue
        vs = [(b, v) for b, v in allv[ns] if (v.get("epoch") or 0) <= as_of]
        if not vs:
            skipped.append({"ns": ns, "reason": "no backup prior to the reference time"})
            continue
        full = [(b, v) for b, v in vs if not v.get("partial")]
        base, v = max(full or vs, key=lambda bv: bv[1].get("epoch") or 0)
        if ns in present:
            skipped.append({"ns": ns, "reason": "present on the cluster — restore it from its own row (Applications)"})
            continue
        stateless = bool(not v.get("volumes") and any(a.get("type") == "stateless" for a in (v.get("apps") or [])))
        if not v.get("volumes") and not stateless:
            skipped.append({"ns": ns, "reason": "backup without volume or workload: nothing to recreate"})
            continue
        warns = []
        if v.get("partial"):
            warns.append("PARTIAL backup (a PV was unreadable): only version prior to the reference time")
        if not v.get("has_resources"):
            warns.append("no resource snapshot: volumes only, workloads and dependencies to recreate by hand")
        elif v.get("secrets") == "redacted" or (v.get("secrets") is None):
            warns.append("Secrets redacted in this backup: recreate them by hand after the restore")
        elif v.get("secrets") == "encrypted" and not pw_ok:
            warns.append("Secrets encrypted and vault LOCKED: they will not be recreated — unlock the vault before starting")
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
        return _err("No bulk restore is running.")
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
                    r = {"ok": False, "error": "Internal error: %s" % e, "log": log}
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
            return _err("A bulk restore is already running.")
        if not payload.get("dry", True) and (ACTION_LOCK.locked() or AUTO_BACKUP["running"]):
            return _err("Another operation (restore, clone or automatic backup) is "
                        "running: start the bulk restore again once it has finished.")
        if not dry:
            guard = _context_guard(payload)
            if guard:
                return guard
        prev = _bulk_load()
        if resume:
            if not prev:
                return _err("No journal to resume.")
            todo = [it for it in prev["items"] if it.get("status") != "done"]
            if not todo:
                return _err("Nothing to resume: every namespace of the journal is already recreated.")
            if not dry and prev.get("dry", True):
                return _err("This journal is a simulation: start the real run from the plan, not by resuming.")
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
                return _err("Nothing to restore: no deleted namespace "
                            "with a backup prior to the reference time.")
            wanted = {it["ns"] for it in plan["items"]}
            if not dry:
                sim_ok = (prev and prev.get("dry") and prev.get("done") and not prev.get("stopped")
                          and _bulk_counts(prev)["failed"] == 0 and prev.get("as_of") == plan["as_of_iso"]
                          and {it["ns"] for it in prev["items"]} == wanted)
                if not sim_ok:
                    return _err("First run a complete SIMULATION without failure of this "
                                "plan (same namespaces, same reference time) before the real run.")
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
                    "Namespace “%s” still exists on the cluster: "
                    "recovery is reserved for a DELETED application. "
                    "For a copy, use “Restore the whole application (copy)”." % ns}
        if st_ns != "absent":
            return {"ok": False, "log": [], "error":
                    "Cannot verify namespace “%s” "
                    "(%s): recovery refused as a precaution." % (ns, st_err or "kubectl")}
    if from_backup and not backup_path:
        return {"ok": False, "error": ("DR restore" if dr else "Application restore")
                + ": choose a source backup.", "log": []}
    if not from_backup and not _namespace_allowed(ns):
        return {"ok": False, "error": "Namespace '%s' not allowed." % ns, "log": []}
    if from_backup and not dr and _ns_filter() and ns not in _ns_filter():
        return {"ok": False, "error": "Namespace '%s' not allowed." % ns, "log": []}
    # NB : le namespace CIBLE d'un clone est une destination de COPIE (créée par l'outil),
    # pas une source : on ne le restreint donc PAS au namespace_filter (qui borne les
    # sources). On valide seulement son nom (RFC 1123) ; il est créé s'il n'existe pas.
    if same_ns and not suffix:
        return {"ok": False, "error": "A suffix is required to clone within the same namespace.", "log": []}
    if suffix and not CLONE_SUFFIX_RE.match(suffix):
        return {"ok": False, "error": "Invalid suffix “%s”: lowercase letters, "
                                      "digits and hyphens only (e.g. -clone, -test2)." % suffix, "log": []}
    if not K8S_NAME_RE.match(target_ns):
        return {"ok": False, "error": "Invalid target namespace name: '%s'." % target_ns, "log": []}
    # Sans volume : clone d'une application STATELESS (`app` : workloads live du
    # namespace, aucun PVC), ou récupération/DR d'une sauvegarde STATELESS (namespace
    # sans PVC, workloads dans l'instantané) — vérifié plus bas, une fois l'instantané lu.
    app = (payload.get("app") or "").strip()
    if not items and not from_backup and not app:
        return {"ok": False, "error": "No volume selected.", "log": []}
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
            return {"ok": False, "error": "%s: %s" % ("DR restore" if dr else "Application restore", berr),
                    "log": []}
        if not items:
            stateless = any((o.get("kind") or "") in APP_WORKLOAD_KINDS for o in (bitems or []))
            if not stateless:
                return {"ok": False, "log": [], "error":
                        "No volume selected and no workload in "
                        "this backup's snapshot: nothing to recreate."}
    elif not items:
        # Clone STATELESS depuis le cluster : les workloads de l'application, qui ne
        # doivent monter aucun PVC (sinon : sélectionner ses volumes, clone stateful).
        wl_map, pvc_map, werr = _list_namespace_workloads([ns], full=True)   # manifestes COMPLETS : ils sont copiés
        if werr and not wl_map.get(ns):
            return {"ok": False, "error": "Reading the workloads of “%s” failed: %s" % (ns, werr), "log": []}
        for w in wl_map.get(ns) or []:
            owners = {o.get("kind") for o in ((w.get("metadata") or {}).get("ownerReferences") or [])}
            if (w.get("kind") or "") in APP_WORKLOAD_KINDS and _app_key_of(w) == app \
                    and not (owners & (set(APP_WORKLOAD_KINDS) | {"Job", "ReplicaSet"})):
                live_stateless.append(json.loads(json.dumps(w)))
        if not live_stateless:
            return {"ok": False, "log": [], "error":
                    "Application “%s” not found in namespace “%s” (no workload)." % (app, ns)}
        mounted = sorted({c for w in live_stateless for c in _workload_pvcs(w, pvc_map.get(ns) or [])})
        if mounted:
            return {"ok": False, "log": [], "error":
                    "Application “%s” mounts volume(s) %s: it is not a "
                    "stateless application — select its volumes to clone it." % (app, ", ".join(mounted))}
        stateless = True
    # Remap optionnel de la StorageClass (site DR : classes souvent différentes).
    dr_sc = (payload.get("dr_storageclass") or "").strip()
    if dr_sc and not K8S_NAME_RE.match(dr_sc):
        return {"ok": False, "error": "Invalid target StorageClass name: “%s”." % dr_sc, "log": []}
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
            return {"ok": False, "error": "PV manifest not found for “%s”%s." % (
                pvc_name, " in the backup (no cluster read in “from the backup only” mode)"
                if from_backup else ""), "log": []}
        nfs = _pv_nfs_info(old_pv)
        if nfs:
            # Volume NAS : les données sont sur le NAS, pas dans un Volume Group. En
            # récupération ou en DR, le PV est recréé à l'IDENTIQUE vers le même export.
            # Une COPIE d'une application vivante partagerait au contraire les données de
            # production (même export, en écriture) : refusée.
            copy_plan = None
            if not (recover or dr):
                # COPIE : jamais le même export (données de production partagées en écriture).
                # HYCU restaure la dernière sauvegarde du partage dans un NOUVEAU dossier au nom
                # du namespace cible, et le nouveau PV vise ce dossier.
                copy_plan, cperr = _nfs_copy_plan(nfs, pvc_name)
                if cperr:
                    return {"ok": False, "log": [], "error": cperr}
            src_pvc = _load_backup_pvc(backup_path, pvc_name, backup_root)
            if src_pvc is None and not from_backup:      # copie sans sauvegarde de config : PVC vivant
                live, _ = kubectl_json(["get", "pvc", pvc_name, "-n", ns])
                src_pvc = clean_pvc(json.loads(json.dumps(live))) if live else None
            if src_pvc is None:
                return {"ok": False, "error": "PVC manifest not found for “%s”." % pvc_name, "log": []}
            orig_pv_name = (old_pv.get("metadata") or {}).get("name") or ""
            dflt_sfx = (suffix or "-r") if (recover or dr or same_ns) else "-" + target_ns
            clone_pv_name = (it.get("new_name") or "").strip() or ((orig_pv_name or pvc_name) + dflt_sfx)[:253]
            if clone_pv_name == orig_pv_name:
                clone_pv_name = orig_pv_name + "-r"
            pv = clean_pv(json.loads(json.dumps(old_pv)))
            pv.setdefault("metadata", {})["name"] = clone_pv_name
            pv["metadata"].setdefault("labels", {})[CLONE_LABEL] = CLONE_LABEL_VAL
            if copy_plan and not isinstance((pv.get("spec") or {}).get("nfs"), dict):
                # Source provisionnée par un driver CSI NFS : la copie est un PV NFS natif
                # (statique) vers le dossier que HYCU crée — aucune dépendance au driver.
                spec = pv.setdefault("spec", {})
                spec.pop("csi", None)
                spec.pop("volumeAttributesClassName", None)
                spec.pop("nodeAffinity", None)
                spec["nfs"] = {"server": nfs["server"], "path": nfs["path"]}
                warnings.append("“%s”: the source is provisioned by a CSI NFS driver; the copy uses a static "
                                "native NFS PV on the same server." % pvc_name)
            new_pvc_name, pvc_manifest = _clone_pvc_manifest(src_pvc, target_ns, same_ns, suffix, clone_pv_name)
            cr = (pv.get("spec") or {}).get("claimRef")
            if isinstance(cr, dict):
                cr["name"] = new_pvc_name
                cr["namespace"] = target_ns
            pvc_rename[pvc_name] = new_pvc_name
            if not copy_plan:
                warnings.append("“%s”: NAS volume recreated on the same "
                                "export (%s) — the data stays on the NAS." % (pvc_name, _nfs_label(nfs)))
            prepared.append({"pvc": pvc_name, "pv": pv, "pvc_manifest": pvc_manifest,
                             "new_pv_name": clone_pv_name, "new_pvc_name": new_pvc_name,
                             "orig_pv_name": orig_pv_name, "src_disk_attr": False, "nfs": True,
                             "nfs_copy": copy_plan})
            continue
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
                    log.append(logentry("Original volume of %s not found on the cluster — "
                                        "automatic restore from HYCU (“Protected deleted”)."
                                        % pvc_name, dry=dry, rc=None))
                    prov_fn = action_hycu_provision_clone if mode == "clone" else action_hycu_provision_restore
                    if dry:
                        # Simulation : lectures HYCU seulement (plan, points de restauration).
                        prov = prov_fn({"volumes": [vol], "dry": True})
                        for l in prov.get("log", []):
                            log.append(l)
                        if not prov.get("ok"):
                            return {"ok": False, "error": "“%s”: the original volume no longer exists "
                                                          "and its automatic restore via HYCU failed: %s"
                                    % (pvc_name, prov.get("error")), "log": log}
                        if mode == "clone":
                            warnings.append("“%s”: HYCU will create a NEW Volume Group "
                                            "(new UUID discovered during the real run) "
                                            "— the preview still shows the original UUID." % pvc_name)
                    else:
                        # Réel : DIFFÉRÉ après le verrou d'action et le pré-vol de collision —
                        # aucun clone/restore HYCU ne doit partir si le run va être refusé.
                        deferred_provision.append({"pvc": pvc_name, "vol": vol, "mode": mode,
                                                   "orig": orig, "old_vh": vh})
                    # mode "restore" : new_ref reste = orig (UUID d'origine conservé) ; mode
                    # "clone" : le PV préparé est re-pointé après découverte (réel).
        if not new_ref or not UUID_RE.search(new_ref):
            return {"ok": False, "error": "Missing/invalid cloned VG reference "
                                          "for “%s” (VG UUID, volumeHandle, or IQN)." % pvc_name, "log": []}
        built, err = build_new_pv(old_pv, new_ref, (it.get("new_name") or "").strip(), "clone")
        if err:
            return {"ok": False, "error": "%s: %s" % (pvc_name, err), "log": []}
        # Garde anti-confusion (comme la prévisualisation du restore) : refuser si la réf
        # est l'UUID du VG SOURCE (le clone pointerait vers le MÊME disque que l'app
        # d'origine -> multi-attach/corruption) ou le NOM du VG au lieu de son UUID.
        # EXCEPTION en récupération : l'app d'origine n'existe plus, réutiliser son VG
        # d'origine est justement le but (rebranchement à l'identique, pas un clone).
        if built.get("same_uuid") and not recover:
            return {"ok": False, "error": "“%s”: the reference is identical to the SOURCE volume — the clone "
                                          "would point to the same Nutanix disk as the original application "
                                          "(risk of multi-attach/corruption). Paste the UUID of the CLONED VG." % pvc_name, "log": []}
        if built.get("looks_like_vg_name"):
            return {"ok": False, "error": "“%s”: the reference matches the Volume Group NAME "
                                          "(“pvc-<PVC-uuid>”) and not its UUID. Paste the cloned VG UUID." % pvc_name, "log": []}
        src_pvc = _load_backup_pvc(backup_path, pvc_name, backup_root)
        if src_pvc is None and not from_backup:          # depuis-la-sauvegarde : jamais de live
            live, _ = kubectl_json(["get", "pvc", pvc_name, "-n", ns])
            src_pvc = clean_pvc(json.loads(json.dumps(live))) if live else None
        if src_pvc is None:
            return {"ok": False, "error": "PVC manifest not found for “%s”." % pvc_name, "log": []}
        # Nom de PV cloné TOUJOURS distinct de l'original (les PV sont cluster-scoped ;
        # l'app d'origine garde le sien). Sinon on viserait à muter le PV de production.
        orig_pv_name = (old_pv.get("metadata") or {}).get("name") or ""
        clone_pv_name = built["new_name"]
        if not clone_pv_name or clone_pv_name == orig_pv_name:
            clone_pv_name = (orig_pv_name or "pvc-clone") + (suffix or "-clone")
        if clone_pv_name == orig_pv_name:
            return {"ok": False, "error": "The cloned PV name must differ from the original “%s”." % orig_pv_name, "log": []}
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
        warnings.append("Stateless application “%s”: no volume — only its "
                        "workloads (%s) and their dependencies are copied." % (app, ", ".join("%s/%s" % (w["kind"], w["metadata"]["name"])
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
                    "No workload without volume%s in this backup's snapshot: nothing to recreate."
                    % ((" for the application “%s”" % app) if app else "")}
        warnings.append("Backup without volume (stateless application): only the "
                        "workloads and their dependencies are recreated from the snapshot.")
    else:
        workloads = (_workloads_from_items(bitems, [it["pvc"] for it in items]) if from_backup
                     else _find_workloads_using_pvcs(ns, [it["pvc"] for it in items]))
        # Une application = TOUS ses workloads : ceux qui ne montent aucun volume (frontend,
        # workers…) sont copiés/recréés aussi — ceux de l'application ciblée (`app`), ou de
        # tout le namespace quand aucune application n'est ciblée. Jusqu'ici seuls les
        # workloads montant les volumes sélectionnés suivaient : la copie de « pacman »
        # n'avait que sa base, pas son frontend.
        if from_backup:
            pool = list(bitems or [])
        else:
            wl_map, _pm, _werr = _list_namespace_workloads([ns], full=True)
            pool = wl_map.get(ns) or []
        have = {((w.get("kind") or ""), (w.get("metadata") or {}).get("name")) for w in workloads}
        extra = []
        for w in pool:
            kind = w.get("kind") or ""
            owners = {x.get("kind") for x in ((w.get("metadata") or {}).get("ownerReferences") or [])}
            if (kind not in APP_WORKLOAD_KINDS or (kind, (w.get("metadata") or {}).get("name")) in have
                    or owners & (set(APP_WORKLOAD_KINDS) | {"Job", "ReplicaSet"})
                    or _workload_pvcs(w, []) or (app and _app_key_of(w) != app)):
                continue
            extra.append(json.loads(json.dumps(w)))
        if extra:
            workloads = list(workloads) + extra
            warnings.append("Workloads without volumes %s also copied: %s." % (
                ("of application “%s”" % app) if app else "of the namespace",
                ", ".join("%s/%s" % (w["kind"], w["metadata"]["name"]) for w in extra)))
    if from_backup and not dr:
        warnings.append("Recovery “from the backup alone”: "
                        "workloads and dependencies come from "
                        "backup “%s” (the namespace no longer exists on the cluster)." % os.path.basename(backup_path or ""))
        if dr_sc:
            warnings.append("StorageClass remapped to “%s” on the recreated PV/PVCs." % dr_sc)
        if bitems is None or not bitems:
            warnings.append("This backup has no resource snapshot: only the "
                            "volumes (PV/PVC) are restored. Recreate the "
                            "workloads and dependencies from a more recent backup, or manually.")
    if dr:
        warnings.append("DR MODE: every source (workloads, dependencies) "
                        "comes from backup “%s” — no read from the origin cluster." % os.path.basename(backup_path or ""))
        if dr_sc:
            warnings.append("StorageClass remapped to “%s” on the recreated PV/PVCs." % dr_sc)
        if bitems is None or not bitems:
            warnings.append("resources.json snapshot empty or missing: only PV and PVC will be recreated.")
    for w in workloads:
        wname = w["metadata"]["name"]
        # Le workload ne doit monter QUE des PVC sélectionnés : sinon son clone
        # référencerait le volume d'ORIGINE (multi-attach RWO / partage RWX prod,
        # ou claimName inexistant en autre namespace).
        vols = ((w.get("spec") or {}).get("template", {}).get("spec", {}).get("volumes")) or []
        claims = [(v.get("persistentVolumeClaim") or {}).get("claimName") for v in vols if v.get("persistentVolumeClaim")]
        missing = sorted({c for c in claims if c and c not in pvc_rename})
        if missing:
            return {"ok": False, "error": "The workload “%s” also mounts the PVC(s) %s not "
                                          "selected: select ALL the volumes of this application to clone it." % (wname, ", ".join(missing)),
                    "log": []}
        # Clone même-namespace : un sélecteur matchExpressions ne peut pas être isolé
        # par simple suffixe -> refuser (utiliser un autre namespace).
        if same_ns and ((w.get("spec") or {}).get("selector") or {}).get("matchExpressions"):
            return {"ok": False, "error": "The workload “%s” uses a matchExpressions selector: cloning within the "
                                          "same namespace is not supported (pod collision risk). Choose “Other namespace”." % wname,
                    "log": []}
        if w.get("kind") == "StatefulSet" and (w.get("spec") or {}).get("volumeClaimTemplates"):
            warnings.append("StatefulSet “%s” uses volumeClaimTemplates: its clone will "
                            "provision NEW volumes (not the cloned VG). Adapt it manually." % wname)
    cloned_workloads = [_clone_workload_manifest(w, target_ns, same_ns, suffix, pvc_rename) for w in workloads]
    # Tous les noms produits doivent rester valides (RFC 1123) : refus AVANT toute création.
    bad_names = [n for n in ([p["new_pv_name"] for p in prepared] + [p["new_pvc_name"] for p in prepared]
                             + [w["metadata"]["name"] for w in cloned_workloads])
                 if not K8S_NAME_RE.match(n or "") or len(n) > 253]
    if bad_names:
        return {"ok": False, "error": "Invalid name(s) after applying the suffix: %s." % ", ".join(bad_names),
                "log": []}
    if same_ns:
        long_labels = []
        for w in cloned_workloads:
            for v in (((w.get("spec") or {}).get("selector") or {}).get("matchLabels") or {}).values():
                if len(str(v)) > 63:
                    long_labels.append(str(v))
        if long_labels:
            return {"ok": False, "error": "Label value(s) too long (> 63) after "
                                          "the suffix: %s. Choose a shorter suffix." % ", ".join(long_labels), "log": []}

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
            warnings.append("Dependencies automatically cloned to “%s”: %s." % (target_ns, ", ".join(dep_summary)))
        if dep_missing:
            warnings.append(("Referenced by the app but absent from the BACKUP "
                             "(or redacted Secret) — recreate manually in “%s”: %s." % (target_ns, ", ".join(dep_missing))) if from_backup else
                            ("Referenced by the app but NOT FOUND in “%s” — create manually: %s."
                             % (ns, ", ".join(dep_missing))))
        warnings.append("Not cloned automatically: Ingress, NetworkPolicies and the RBAC bindings "
                        "(RoleBindings) of the ServiceAccounts — recreate them if the app depends on them.")
    elif not same_ns and workloads and not clone_refs:
        allrefs = set()
        for w in workloads:
            r = _referenced_objects(w)
            allrefs |= {"Secret " + s for s in r["secrets"]} | {"ConfigMap " + c for c in r["configmaps"]}
            if r["serviceaccount"]:
                allrefs.add("ServiceAccount " + r["serviceaccount"])
        if allrefs:
            warnings.append("Dependency cloning DISABLED: recreate manually in “%s”: %s."
                            % (target_ns, ", ".join(sorted(allrefs))))
    if same_ns and workloads:
        warnings.append("Same-namespace: the app's Services / Ingress / NetworkPolicies are NOT cloned and "
                        "may route to the original pods (non-selector labels kept). Clone/edit them separately.")
    if not workloads:
        warnings.append("No Deployment/StatefulSet mounts these PVCs: only the cloned PV "
                        "and PVC will be created (deploy your application on top of them).")

    # Copies NAS : un dossier par namespace cible (« <ns> », ou « <ns>/<pvc> » si plusieurs
    # volumes de la copie visent le même partage).
    nas_copies = [p for p in prepared if p.get("nfs_copy")]
    for p in nas_copies:
        cp = p["nfs_copy"]
        base = (target_ns + suffix) if same_ns else target_ns
        siblings = [q for q in nas_copies if q["nfs_copy"]["share_uuid"] == cp["share_uuid"]]
        folder = base if len(siblings) == 1 else "%s/%s" % (base, p["pvc"])
        body, pv_path, sel, skipped, flatten = _nfs_copy_target(cp, folder, ns)
        if not sel:
            return {"ok": False, "log": log, "error": "“%s”: the backup of share “%s” (%s) "
                                                      "contains no file to copy for this volume." % (p["pvc"], cp["share_name"], cp["backup_time"])}
        p["pv"]["spec"]["nfs"]["path"] = pv_path
        p["nfs_restore"] = body
        p["nfs_flatten"] = flatten
        p["nfs_folder"] = folder
        warnings.append("“%s”: NAS copy — HYCU restores the backup of %s of "
                        "share “%s” into the folder “%s”; the new PV points to %s:%s." % (p["pvc"], cp["backup_time"],
                                                                      cp["share_name"], folder, cp["server"], pv_path))
        if cp["sub"] == "/":
            warnings.append("“%s”: the original application mounts the share root, it will see the "
                            "folder “%s”. To isolate copies, mount one subfolder per application instead."
                            % (p["pvc"], folder.split("/")[0]))
        if cp.get("ns_folder"):
            warnings.append("“%s”: only the folder “%s” of the share is copied (one folder per namespace)%s."
                            % (p["pvc"], cp["ns_folder"], ("; left out: %s" % ", ".join(skipped)) if skipped else ""))
        elif skipped:
            warnings.append("Folders of existing copies not copied again: %s." % ", ".join(sorted(set(skipped))))
        elif cp["sub"] == "/" and len(cp["entries"]) > 1:
            warnings.append("“%s”: no folder named “%s” at the share root — the whole share is copied (%s)."
                            % (p["pvc"], ns, ", ".join(str(e.get("fullItemName") or e.get("displayName") or "")
                                                        .strip("/") for e in cp["entries"][:6])))
        if not cp["entries"] and cp["sub"] == "/":
            warnings.append("“%s”: the share backup could not be listed%s; the whole share root is restored "
                            "(earlier copy folders included)." % (p["pvc"], (" (%s)" % cp["browse_error"])
                                                                  if cp.get("browse_error") else ""))
        if cp.get("needs_backup"):
            warnings.append("“%s”: the latest backup of share “%s” (%s) does not contain “%s” yet — the copy first "
                            "backs up the share in HYCU (a few minutes), then restores from that fresh backup."
                            % (p["pvc"], cp["share_name"], cp["backup_time"], cp["sub"].strip("/")))
        if flatten:
            warnings.append("“%s”: HYCU recreates “%s” under “%s”; a short Job then moves its content up so the "
                            "copy keeps the original tree (it needs root on the share — nodes exempt from root "
                            "squash; otherwise the PV points to “%s/%s”)." % (p["pvc"], flatten, folder, folder, flatten))
            log.append(logentry("Flatten Job (namespace “%s”, image %s): %s/%s -> %s/"
                                % (target_ns, CONFIG.get("nas_job_image") or "busybox:1.36", folder, flatten, folder),
                                dry=dry, rc=None))
        log.append(logentry("HYCU restore of share “%s” to “%s” (%d item(s))"
                            % (cp["share_name"], folder, len(sel)), dry=dry, rc=None,
                            stdout=json.dumps(body, ensure_ascii=False)))

    preview = {"target_namespace": target_ns, "same_namespace": same_ns,
               "pvs": [p["new_pv_name"] for p in prepared],
               "pvcs": [p["new_pvc_name"] for p in prepared],
               "workloads": ["%s/%s" % (w["kind"], w["metadata"]["name"]) for w in cloned_workloads],
               "dependencies": dep_summary}

    acquired = False
    if not dry:
        if not ACTION_LOCK.acquire(blocking=False):
            return {"ok": False, "error": "Another operation is already running. Try again.", "log": []}
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
                    coll.append("PV %s%s" % (p["new_pv_name"], " (unreachable)" if st == "error" else ""))
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
                return {"ok": False, "error": "Pre-flight impossible (PV list: %s) — nothing was created." % pverr,
                        "log": []}
            handles = {}
            for pv in (pvs_live or {}).get("items", []) or []:
                h = ((pv.get("spec") or {}).get("csi") or {}).get("volumeHandle")
                if h:
                    handles.setdefault(h, []).append((pv.get("metadata") or {}).get("name"))
            for p in prepared:
                if p["pvc"] in deferred_clone or p.get("nfs"):   # NAS : plusieurs PV peuvent viser un export
                    continue
                h = ((p["pv"].get("spec") or {}).get("csi") or {}).get("volumeHandle")
                others = [n for n in handles.get(h, []) if n != p["new_pv_name"]]
                if h and others:
                    coll.append("Volume Group %s already pointed to by "
                                "PV %s (volume %s) — delete this PV first" % (h, ", ".join(str(x) for x in others), p["pvc"]))
            if coll:
                return {"ok": False, "error": "Object(s) already present — refusing to overwrite "
                                              "anything: %s. Change the suffix or the target namespace." % ", ".join(coll), "log": []}
        # Provisionnement HYCU DIFFÉRÉ (réel) : après verrou et pré-vol, jamais avant.
        for dp in deferred_provision:
            prov_fn = action_hycu_provision_clone if dp["mode"] == "clone" else action_hycu_provision_restore
            prov = prov_fn({"volumes": [dp["vol"]], "dry": False})
            for l in prov.get("log", []):
                log.append(l)
            if not prov.get("ok"):
                return {"ok": False, "log": log, "warnings": warnings, "preview": preview,
                        "error": "“%s”: the original volume no longer exists "
                                 "and its automatic restore via HYCU failed: %s" % (dp["pvc"], prov.get("error"))}
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
                    log.append(logentry("PV of %s re-pointed to the VG cloned by HYCU" % dp["pvc"],
                                        stdout="%s -> %s" % (dp["orig"], disc)))
        # Pré-résoudre le disque de CHAQUE VG cloné (renseigne hypervisorAttachedDiskUUIDs)
        # AVANT toute création : si introuvable en réel, on abandonne sans rien créer.
        for p in prepared:
            if p.get("nfs"):                                  # volume NAS : ni disque ni cible iSCSI
                continue
            handle = ((p["pv"].get("spec") or {}).get("csi") or {}).get("volumeHandle")
            _fix_clone_iqn(p["pv"], handle, dry, log)        # cible iSCSI réelle (VG HYCU : « hycu-clone-vg-… »)
            if not _set_clone_disk_uuids(p["pv"], handle, dry, log, source_had=p.get("src_disk_attr", True)) \
                    and not dry and CONFIG.get("clone_require_disk_uuids", True):
                return {"ok": False, "log": log, "warnings": warnings, "preview": preview,
                        "error": (("Prism Central is not connected: cannot set "
                                   "the disk of volume “%s” — nothing was created." if not SESSION_CREDS.get("prismcentral")
                                   else "Volume Group of volume “%s” not found in Nutanix "
                                        "(deleted?) — connect HYCU to restore it "
                                        "automatically, or untick “reuse the original volumes” "
                                        "and use “Create the volumes automatically via HYCU”. Nothing was created.") % p["new_pvc_name"])}
        if not same_ns:
            log.append(_apply_manifest({"apiVersion": "v1", "kind": "Namespace",
                                        "metadata": {"name": target_ns}},
                                       "ns_%s" % target_ns, dry, "Target namespace “%s”" % target_ns))
            # Namespace créé par l'outil -> l'ajouter à la liste blanche, sinon les
            # onglets Vérifier/Restaurer refuseront ce namespace juste après le clone.
            if not dry and log[-1].get("ok"):
                _allow_namespace(target_ns, log)
        # Copies NAS (réel) : restauration HYCU dans le nouveau dossier, attendue avant le PV.
        if not dry:
            for p in prepared:
                if not p.get("nfs_restore"):
                    continue
                cp = p["nfs_copy"]
                if cp.get("needs_backup"):
                    okb, berr = _share_backup_now(cp["share_uuid"], log, label="share “%s”" % cp["share_name"])
                    fresh, lerr = _share_backups(cp["share_uuid"]) if okb else (None, berr)
                    fresh = [b for b in (fresh or []) if _share_backup_has(b["uuid"], cp["sub"])]
                    if not okb or not fresh:
                        return {"ok": False, "log": log, "warnings": warnings, "preview": preview,
                                "error": "“%s”: no HYCU backup of share “%s” contains “%s” (%s) — nothing was "
                                         "created. Check the share backup in HYCU, then run the copy again."
                                         % (p["pvc"], cp["share_name"], cp["sub"].strip("/"), berr or lerr or "backup started but folder still missing")}
                    cp["backup_uuid"], cp["backup_time"] = fresh[0]["uuid"], _hycu_ts_label(fresh[0])
                    log.append(logentry("Fresh share backup selected: %s" % cp["backup_time"]))
                rr = _rest("hycu", "POST", "/shares/backup/%s/restoreShareItems"
                           % urllib.parse.quote(str(cp["backup_uuid"])), p["nfs_restore"])
                if not rr["ok"]:
                    return {"ok": False, "log": log, "warnings": warnings, "preview": preview,
                            "error": "“%s”: HYCU share restore refused: %s — nothing was created."
                                     % (p["pvc"], rr.get("error"))}
                if not _wait_hycu_job(_hycu_job_id(rr.get("json") or {}), log,
                                      label="NAS copy of %s (HYCU)" % p["pvc"]):
                    return {"ok": False, "log": log, "warnings": warnings, "preview": preview,
                            "error": "“%s”: the HYCU share restore did not "
                                     "complete — no PV/PVC/workload created." % p["pvc"]}
                if p.get("nfs_flatten"):
                    cp_path = p["pv"]["spec"]["nfs"]["path"]
                    st, detail = _nas_flatten(target_ns, cp["server"], cp_path, p["nfs_flatten"], log)
                    if st == "denied":
                        p["pv"]["spec"]["nfs"]["path"] = cp_path.rstrip("/") + "/" + p["nfs_flatten"]
                        warnings.append("“%s”: the NAS refused the move (root squash): the PV points to %s:%s "
                                        "instead — the data is complete, only nested one level. Exempt the cluster "
                                        "nodes from root squash on this share to get flat copies."
                                        % (p["pvc"], cp["server"], p["pv"]["spec"]["nfs"]["path"]))
                    elif st != "ok":
                        return {"ok": False, "log": log, "warnings": warnings, "preview": preview,
                                "error": "“%s”: the data was restored by HYCU into “%s” but the flatten Job failed "
                                         "(%s) — no PV/PVC/workload created; fix the cause and run the copy again "
                                         "(HYCU overwrites the folder)." % (p["pvc"], p["nfs_folder"], detail)}
        # Dépendances (Secrets/ConfigMaps/SA/Services) AVANT les workloads. On NE
        # remplace PAS une dépendance déjà présente dans la cible (ne rien écraser).
        for o in dep_manifests:
            k = (o.get("kind") or "").lower()
            nm = o["metadata"]["name"]
            if not dry:
                st, _ = resource_state(k, nm, target_ns)
                if st == "present":
                    log.append({"ok": True, "dry": False, "rc": 0, "cmd": "", "stderr": "",
                                "label": "%s %s already present — kept" % (o.get("kind"), nm),
                                "stdout": "Not overwritten (the existing version of “%s” is kept)." % target_ns})
                    continue
            log.append(_apply_manifest(o, "clonedep_%s_%s" % (k, nm), dry,
                                       "Cloned dependency %s %s/%s" % (o.get("kind"), target_ns, nm)))
        created = []                     # (kind, name, ns) dans l'ordre de création -> rollback inverse
        failed_step = None
        for p in prepared:  # hypervisorAttachedDiskUUIDs déjà renseigné dans la pré-passe ci-dessus
            # Le PV cloné est TOUJOURS créé en Retain : une suppression ultérieure du PVC/PV
            # (nettoyage, échec partiel) ne doit jamais détruire le VG cloné via le CSI.
            p["pv"].setdefault("spec", {})["persistentVolumeReclaimPolicy"] = "Retain"
            # claimRef toujours posé (même avec strip_claimref) : jamais de PV « Available »
            # qu'un PVC Pending étranger pourrait capturer entre les deux applies.
            p["pv"]["spec"]["claimRef"] = {"kind": "PersistentVolumeClaim", "apiVersion": "v1",
                                           "name": p["new_pvc_name"], "namespace": target_ns}
            ra = _apply_manifest(p["pv"], "clonepv_%s" % p["new_pv_name"], dry, "Cloned PV %s (Retain)" % p["new_pv_name"])
            log.append(ra)
            if not (ra["ok"] or ra["dry"]):
                failed_step = "PV %s" % p["new_pv_name"]
                break
            created.append(("pv", p["new_pv_name"], None))
            ra = _apply_manifest(p["pvc_manifest"], "clonepvc_%s" % p["new_pvc_name"], dry,
                                 "Cloned PVC %s (ns %s)" % (p["new_pvc_name"], target_ns))
            log.append(ra)
            if not (ra["ok"] or ra["dry"]):
                failed_step = "PVC %s" % p["new_pvc_name"]
                break
            created.append(("pvc", p["new_pvc_name"], target_ns))
        if failed_step is None:
            for w in cloned_workloads:
                ra = _apply_manifest(w, "clonewl_%s" % w["metadata"]["name"], dry,
                                     "Cloned application %s/%s (ns %s)" % (w["kind"], w["metadata"]["name"], target_ns))
                log.append(ra)
                if not (ra["ok"] or ra["dry"]):
                    failed_step = "%s %s" % (w["kind"], w["metadata"]["name"])
                    break
                created.append((w["kind"].lower(), w["metadata"]["name"], target_ns))
        if failed_step and not dry:
            # Nettoyage INVERSE des objets créés par cette tentative (les PV sont en
            # Retain : leur suppression ne touche pas le VG cloné). Les dépendances
            # clonées (Secrets/ConfigMaps/SA/Services) sont laissées en place (idempotentes).
            log.append(logentry("Failure on %s — cleaning up the objects created by this clone" % failed_step,
                                ok=False, rc=-1, stderr="No cloned application is left half-created."))
            for kind_c, name_c, ns_c in reversed(created):
                args = ["delete", kind_c, name_c, "--ignore-not-found", "--wait=false"]
                if ns_c:
                    args += ["-n", ns_c]
                log.append(kubectl(args, dry=False, label="Cleanup %s %s" % (kind_c.upper(), name_c)))
        elif not dry and prepared:
            # Attendre que les PVC clonés soient liés : un FailedAttach / mauvais disque
            # doit apparaître ici et non après le clic suivant de l'opérateur.
            for p in prepared:
                if not _wait_pvc_bound(p["new_pvc_name"], target_ns, log):
                    warnings.append("Cloned PVC “%s” is not Bound: check the "
                                    "cloned VG and the hypervisorAttachedDiskUUIDs." % p["new_pvc_name"])
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
            return self._send(404, "Backup not found.", "text/plain")
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
                            return self._send(413, "Backup too large for a direct download.", "text/plain")
                        z.write(fp, os.path.join(top, os.path.relpath(fp, full)))
        except OSError as e:
            print("Backup zip error %s: %s" % (full, e))
            return self._send(500, "Error while creating the archive.", "text/plain")
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
                if not _host_allowed(name):
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
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path in ("/healthz", "/readyz"):
            # Sonde de santé (Docker HEALTHCHECK, sondes K8s) : répond AVANT la garde Host
            # (une sonde kubelet n'envoie pas forcément l'en-tête attendu) et sans AUCUNE
            # logique de session — charger « / » sans cookie tournerait la session.
            return self._send(200, "ok", "text/plain")
        if not self._origin_ok():
            return self._send(403, "Forbidden", "text/plain")
        qs = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        if path == "/":
            # La rotation de session n'a de sens que pour un navigateur (Accept: text/html) ;
            # un outil ou une sonde qui touche « / » ne doit pas évincer l'opérateur.
            accept = self.headers.get("Accept") or ""
            browser = ("text/html" in accept) or ("*/*" in accept and "Mozilla" in (self.headers.get("User-Agent") or ""))
            set_cookie = check_ui_session(self.headers.get("Cookie")) if browser else None
            return self._send(200, HTML.replace("__CSRF_TOKEN__", CSRF_TOKEN)
                              .replace("__VERSION__", VERSION).replace("__LOGO__", _logo_markup()),
                              "text/html", {"Set-Cookie": set_cookie} if set_cookie else None)
        if path == "/help":
            page = help_html()
            return self._send(200, page, "text/html")
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
            if path == "/api/policy_members":
                return self._json(action_policy_members())
            if path == "/api/tool_kit/list":
                return self._json(action_tool_kit_list())
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
                return self._send(200, report_html(d),
                                  "text/html",
                                  {"Content-Disposition": 'attachment; filename="rapport_hycu_%s.html"' % today})
            if path == "/api/op_status":
                if not qs.get("id"):
                    return self._json(action_op_list())
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
            print("GET error %s: %s" % (path, e))
            return self._json({"error": "Internal error."}, 500)
        return self._json({"error": "not found"}, 404)

    def _do_POST(self):
        if not self._origin_ok(require_origin=True):
            return self._send(403, "Forbidden", "text/plain")
        if not hmac.compare_digest(str(self.headers.get("X-CSRF-Token") or ""), CSRF_TOKEN):
            return self._json({"error": "CSRF token invalid or missing."}, 403)
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            return self._json({"error": "Invalid Content-Length header."}, 400)
        if length > 5 * 1024 * 1024:
            return self._json({"error": "Payload too large."}, 413)
        try:
            raw = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
            payload = json.loads(raw or "{}")
        except (ValueError, json.JSONDecodeError):
            return self._json({"error": "Invalid JSON"}, 400)
        path = urllib.parse.urlparse(self.path).path
        try:
            if path == "/api/op_cancel":
                return self._json(action_op_cancel(payload.get("id", "")))
            if path == "/api/backup":
                return self._json(action_backup(payload.get("ns", ""), payload.get("dest"), kind="manual"))
            if path == "/api/backup_all":
                return self._json(action_backup_all(payload.get("dest"), kind="manual"))
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
            if path == "/api/backups/delete":
                return self._json(action_backups_delete(payload))
            if path == "/api/tool_kit/upload":
                return self._json(action_tool_kit_upload())
            if path == "/api/tool_kit/restore":
                return self._json(action_tool_kit_restore(payload))
            if path == "/api/tool_kit/download":
                data, _f = tool_kit_bytes()
                audit("tool_kit_download", size=len(data))
                return self._send(200, data, "application/zip",
                                  {"Content-Disposition": 'attachment; filename="hycu-tool-%s.zip"'
                                   % datetime.date.today().isoformat()})
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
            print("POST error %s: %s" % (path, e))
            return self._json({"ok": False, "error": "Internal error."}, 500)
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
# >>> UI-BEGIN — région GÉNÉRÉE par build.py depuis ui/ (ne pas éditer à la main)
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf-token" content="__CSRF_TOKEN__">
<title>HYCU · Kubernetes on Nutanix</title>
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
    --muted:#6B7089; --grey:#8A8FA3; --rule:#8A9BB0; --line:#E3E7EE;
  /* variantes « texte » conformes aux contrastes (≥ 4.5:1 sur blanc) */
  --green-t:#047857; --red-t:#C53030; --orange-t:#4B5274;
    --green:#05A274; --green-l:#9BDAC7; --red:#E9605A; --orange:#8A94B8; --blue:#6688FF;
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
  input[type=checkbox]{accent-color:var(--purple);width:18px;height:18px;vertical-align:-3px}
  textarea{resize:vertical;min-height:46px;font-size:12.5px}
  .row{display:flex;gap:12px;flex-wrap:wrap}
  .row > div{flex:1;min-width:180px}
  .btn{background:var(--purple);color:#fff;border:1px solid var(--purple);border-radius:4px;padding:8px 20px;
       font-size:14px;cursor:pointer;font-weight:500;font-family:inherit;min-height:38px;
       display:inline-flex;align-items:center;justify-content:center;gap:6px}
  .btn:hover{background:var(--purple-d);border-color:var(--purple-d)}
  .btn:disabled{background:#E9E6F3;border-color:#E9E6F3;color:#6B7089;cursor:not-allowed}
  .btn.ghost:disabled{background:#F3F4F9;border-color:#C9CDD9;color:#6B7089}
  .btn.ghost{background:#fff;color:var(--top);border:1px solid var(--top)}
  .btn.ghost:hover{background:var(--purple-t)}
  .btn.danger{background:var(--red);border-color:var(--red)}
  .btn.danger:hover{background:#D64B45;border-color:#D64B45}
  .lnk{background:none;border:none;padding:8px 10px;min-height:36px;color:var(--strong);text-decoration:underline;
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
  .tcard{background:#fff;border-radius:6px;box-shadow:0 1px 2px rgba(65,50,124,.06);overflow:hidden;overflow-x:auto}
  .tcard table.ht{min-width:900px}
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
  #appsTable td{padding-top:6px;padding-bottom:6px}       /* liste dense : plus de lignes à l'écran */
  #mPurge table.ht, #tkOut table.ht{min-width:0}          /* tableaux étroits (fenêtre / carte) */
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
                 width:40px;height:40px;display:inline-flex;align-items:center;justify-content:center;border-radius:6px;
                 font-family:inherit;font-weight:700}
  .hm-body,.wiz-body{padding:16px 18px;overflow:auto}
  .hm-foot,.wiz-foot{display:flex;align-items:center;justify-content:flex-end;gap:14px;padding:12px 18px;
       border-top:1px solid var(--rule)}
  .wiz-foot{justify-content:space-between}
  .hm-foot .btn,.wiz-foot .btn:not(.ghost){min-width:92px}
  .modal-actions .btn.ghost{background:none;border:none;color:var(--strong);
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
  .b-pending{background:#EEF0F5;color:var(--muted)} .b-na{background:#EEF0F5;color:var(--muted)}
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
  .ok{color:var(--green)} .ko{color:var(--red)} .sim{color:var(--muted)}
  .hint{font-size:12.5px;color:var(--muted);margin-top:8px}
  .note{background:#F7F5FD;border-left:3px solid var(--purple);padding:10px 14px;border-radius:0 4px 4px 0;
        font-size:13px;margin-top:12px;color:var(--text)}
  .warnbox{background:#F3F4F9;border-left:3px solid var(--grey);padding:10px 14px;border-radius:0 4px 4px 0;
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
  #rsNextBar{display:none !important}
  .nextbar{display:none;align-items:center;justify-content:space-between;gap:12px;margin-top:14px;padding:10px 12px;
           background:#fff;border:1px solid var(--line);border-radius:6px}
  .nextbar.show{display:flex}
  #rsStepsWrap:has(ol:empty){display:none}
  .step-no{display:none}
  /* ---------- Assistant de restauration : étapes visibles ---------- */
  .stepper{display:flex;gap:0;margin:0 0 16px;border:1px solid var(--line);border-radius:6px;overflow:hidden;background:#fff}
  /* (la classe .st est aussi celle des pastilles d'état, qui masque le texte en !important) */
  .stepper .st{flex:1;padding:10px 12px;font-size:13px !important;color:var(--muted) !important;background:#fff;
               background-image:none !important;border-right:1px solid var(--line);border-radius:0 !important;
               display:flex;align-items:center;gap:8px;width:auto !important;height:auto !important;cursor:default}
  .stepper .st:last-child{border-right:none}
  .stepper .st.on{color:#fff !important;background:var(--purple);font-weight:700}
  .stepper .st.done{color:var(--green-t) !important;background:#F0FAF6}
  .progress{margin-top:14px;border:1px solid var(--line);border-radius:6px;padding:10px 12px;background:#fff}
  .progress-head{display:flex;justify-content:space-between;align-items:center;gap:12px;font-size:13px;color:var(--strong);margin-bottom:8px}
  .progress-track{height:8px;background:#EEF0F5;border-radius:4px;overflow:hidden}
  .progress-bar{height:100%;width:0;background:var(--purple);transition:width .4s}
  body.realmode .progress-bar{background:var(--red)}
  ol.plan li.danger{color:var(--red-t)}
  ol.plan li.danger::marker{color:var(--red-t);font-weight:700}
  .preflight{margin:10px 0}
  .preflight summary{cursor:pointer;font-size:13px}
  /* ---------- Mode réel : indicateur permanent dans la barre du haut ---------- */
  #netBanner{margin-bottom:12px}
  .dq{display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;border:1.5px solid var(--muted);
      border-radius:50%;font-size:11px;font-weight:700;color:var(--grey);cursor:help;vertical-align:middle}
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
<!-- ===================== MODALE DE CONFIRMATION (actions destructives) ===================== -->
<div id="dangerModal" class="modal-bg" style="display:none">
  <div class="modal">
    <h3 id="dmTitle">Confirm the real action</h3>
    <div id="dmBody"></div>
    <div id="dmConfirmWrap" class="dm-need" style="display:none">
      <label class="fld">To confirm, retype <b id="dmWord"></b></label>
      <input type="text" id="dmInput" autocomplete="off">
    </div>
    <div class="modal-actions">
      <button class="btn ghost" id="dmCancel">Cancel</button>
      <button class="btn danger" id="dmOk">Confirm</button>
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
      <h2 id="wizTitle">Initial setup</h2>
      <div class="wiz-bar"><span id="wizBar"></span></div>
    </div>
    <div class="wiz-body" id="wizBody"></div>
    <div class="wiz-foot">
      <button class="btn ghost" id="wizBack">Back</button>
      <span class="hint" id="wizStep" style="margin:0"></span>
      <button class="btn" id="wizNext">Next</button>
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
      <h2>Unlock saved connections</h2>
    </div>
    <div class="wiz-body">
      <p class="q">An encrypted credentials vault was found. Enter the master passphrase
        to reconnect HYCU / Nutanix automatically.</p>
      <label class="fld">Passphrase</label>
      <input type="password" id="unlockPass" autocomplete="off">
      <div id="unlockErr"></div>
    </div>
    <div class="wiz-foot">
      <button class="btn ghost" id="unlockSkip">Later</button>
      <button class="btn" id="unlockGo">Unlock</button>
    </div>
  </div>
</div>

<!-- ===================== À PROPOS ===================== -->
<div id="aboutModal" class="wiz" style="display:none">
  <div class="wiz-card" style="max-width:560px">
    <div class="wiz-head dark">
      <div class="wiz-brand">__LOGO__</div>
      <h2 style="margin-top:10px">Kubernetes Protection on Nutanix</h2>
      <div style="color:#B8B4FC;font-weight:700;font-size:13px;margin-top:2px">Plugin for HYCU Enterprise Cloud</div>
      <div style="font-style:italic;margin-top:6px;font-size:12px;color:#fff">This is a free plugin, provided as-is, without any warranty or engagement from HYCU.</div>
    </div>
    <div class="wiz-body" style="font-size:13px">
      <div style="display:grid;grid-template-columns:auto 1fr;gap:6px 14px;align-items:baseline">
        <b>Version:</b><code>__VERSION__</code>
        <b>Audit log:</b><code id="aboutAudit" style="word-break:break-all">…</code>
        <b>Configuration:</b><code id="aboutCfg" style="word-break:break-all">…</code>
        <b>Backups:</b><code id="aboutBk" style="word-break:break-all">…</code>
      </div>
    </div>
    <div class="wiz-foot">
      <span></span>
      <button class="btn" id="aboutClose">Close</button>
    </div>
  </div>
</div>

<!-- ===================== FILTRE DES NAMESPACES ===================== -->
<div id="nsFilter" class="wiz" style="display:none">
  <div class="wiz-card">
    <div class="wiz-head">
      <div class="wiz-brand">HYCU</div>
      <h2>Filter namespaces</h2>
    </div>
    <div class="wiz-body">
      <label class="wiz-opt" id="nsAllOpt" style="cursor:pointer">
        <input type="checkbox" id="nsAll" style="width:auto;margin-right:8px">
        <b>All namespaces (no filter)</b>
        <div class="d">Shows every namespace, including ones created later.</div>
      </label>
      <div id="nsPick">
        <input type="text" id="nsSearch" placeholder="search for a namespace…">
        <div style="display:flex;gap:8px;margin:8px 0">
          <button class="btn ghost" id="nsCheckAll" type="button">Check all (visible)</button>
          <button class="btn ghost" id="nsUncheckAll" type="button">Uncheck all (visible)</button>
        </div>
        <div id="nsList" style="max-height:260px;overflow:auto"></div>
      </div>
      <div id="nsFilterErr"></div>
    </div>
    <div class="wiz-foot">
      <button class="btn ghost" id="nsCancel">Cancel</button>
      <span class="hint" id="nsCount" style="margin:0"></span>
      <button class="btn" id="nsSave">Save filter</button>
    </div>
  </div>
</div>

<header class="topbar">
  <a class="tb-brand" id="tbHome" href="#" title="Dashboard">__LOGO__<span class="tb-word">HYCU<sup>®</sup></span><span class="tb-prod">Kubernetes · Nutanix</span></a>
  <div class="tb-right">
    <span id="hdrConn" class="hdrconn" title="Source status — click to open Sources"></span>
    <button class="tb-link" id="ctxLink" type="button" title="Active Kubernetes cluster — click to choose another one"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="4" width="16" height="6.5" rx="1.3"/><rect x="4" y="13.5" width="16" height="6.5" rx="1.3"/><path d="M7.6 7.25h.01M7.6 16.75h.01"/></svg><u id="ctx">…</u><span id="ctxWarn"></span><svg class="caret" width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M2.5 4.5l3.5 3.5 3.5-3.5" stroke="currentColor" stroke-width="1.5" fill="none" stroke-linecap="round"/></svg></button>
    <button class="tb-ico" id="srcBtn" type="button" title="Sources & Settings"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg></button>
    <button class="tb-ico" id="aboutBtn" type="button" title="Help &amp; About"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9.4"/><path d="M9.6 9.4a2.5 2.5 0 0 1 4.9.8c0 1.7-2.5 2.1-2.5 3.8"/><circle cx="12" cy="17.1" r=".7" fill="currentColor" stroke="none"/></svg></button>
  </div>
</header>
<div id="clMenu" class="clmenu" role="menu"></div>
<div id="helpMenu" class="clmenu" role="menu" style="min-width:210px">
  <a class="cli" href="/help" target="_blank" rel="noopener" role="menuitem" style="text-decoration:none"><span class="chk"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 4.5h6a2.5 2.5 0 0 1 2.5 2.5v12.5a2 2 0 0 0-2-2H5z"/><path d="M19 4.5h-5.5A2.5 2.5 0 0 0 11 7v12.5a2 2 0 0 1 2-2h6z" transform="scale(-1,1) translate(-24,0)" display="none"/><path d="M19 4.5h-6v13h6z" display="none"/></svg></span><span>Help (guide)</span></a>
  <div class="cli" data-act="about" role="menuitem"><span class="chk"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 11v6"/><circle cx="12" cy="7.6" r=".8" fill="currentColor" stroke="none"/></svg></span><span>About</span></div>
</div>
<div id="gearMenu" class="clmenu" role="menu" style="min-width:210px">
  <div class="cli" data-act="sources" role="menuitem"><span class="chk"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/></svg></span><span>Sources</span></div>
  <div class="cli" data-act="settings" role="menuitem"><span class="chk"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 20v-5M5 11V4M12 20v-8M12 8V4M19 20v-3M19 13V4"/><path d="M3 15h4M10 8h4M17 17h4"/></svg></span><span>Settings</span></div>
</div>

<div class="shell">
<nav class="sidebar" role="tablist" aria-label="Tool sections">
  <button class="on" role="tab" aria-selected="true" data-tab="dashboard"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4.2 17.5a8.6 8.6 0 1 1 15.6 0"/><path d="M12 13.4l4.2-4.2"/><circle cx="12" cy="13.6" r="1.4"/></svg><span class="nl">Dashboard</span></button>
  <div class="sb-sep"></div>
  <button role="tab" aria-selected="false" data-tab="apps"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3.5" y="3.5" width="7" height="7" rx="1.2"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.2"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.2"/><circle cx="17" cy="17" r="3.6"/></svg><span class="nl">Applications</span></button>
  <div class="sb-sep"></div>
  <button role="tab" aria-selected="false" data-tab="policies"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l7.5 3v5.4c0 4.6-3.2 8.3-7.5 9.6-4.3-1.3-7.5-5-7.5-9.6V6z"/><path d="M8.6 12.1l2.4 2.4 4.4-4.8"/></svg><span class="nl">Policies</span></button>
  <div class="sb-sep"></div>
  <button role="tab" aria-selected="false" data-tab="jobs"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4.5" y="3.5" width="15" height="17" rx="1.6"/><path d="M8 8.5h8M8 12h8M8 15.5h5"/></svg><span class="nl">Jobs</span></button>
  <div class="sb-foot"><button class="sb-col" id="sbCol" type="button" title="Collapse / expand the menu"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 5l-7 7 7 7"/></svg></button><span class="ver">v__VERSION__</span></div>
</nav>
<main class="wrap">
  <div id="netBanner" class="err" style="display:none" role="alert">Server unreachable — check the tool is running (or the port-forward), then reload.</div>
  <div id="opBanner" style="display:none"></div>
  <div id="kubeBanner"></div>
  <div class="dry" id="dryBar">
    <label class="switch"><input type="checkbox" id="dry" checked role="switch" aria-checked="true" aria-labelledby="dryLabel"><span class="slider"></span></label>
    <div><b id="dryLabel">Simulation mode on</b> — no destructive command is executed.
      Turn it off only when you are ready to act for real.</div>
  </div>


  <!-- ===================== TABLEAU DE BORD ===================== -->
  <section id="tab-dashboard">
    <div class="pagehead"><h1 class="ptitle">Dashboard</h1></div>
    <div class="dgrid">
      <div><h2 class="dtitle">Applications</h2><div class="dcard" id="dbApps"></div></div>
      <div><h2 class="dtitle">Policy</h2><div class="dcard" id="dbPolicy"></div></div>
      <div><h2 class="dtitle">Sources</h2><div class="dcard" id="dbSources"></div></div>
      <div><h2 class="dtitle">Cluster</h2><div class="dcard" id="dbCluster"></div></div>
      <div><h2 class="dtitle">Storage</h2><div class="dcard" id="dbStorage"></div></div>
      <div><h2 class="dtitle">Jobs</h2><div class="dcard" id="dbJobs"></div></div>
      <div><h2 class="dtitle">Recent jobs</h2><div class="dcard" id="dbLast"></div></div>
      <div><h2 class="dtitle">Cluster health</h2><div class="dcard" id="dbHealth"></div></div>
    </div>
  </section>
  <!-- ===================== APPLICATIONS ===================== -->
  <section id="tab-apps" style="display:none">
    <div class="pagehead"><h1 class="ptitle">Applications <button class="refresh" id="appsRefresh" type="button" title="Refresh"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19.4 12.6a7.5 7.5 0 1 1-2.3-5.9"/><path d="M19.6 4.4v4h-4"/></svg></button></h1>
      <div class="pacts">
        <button class="pact" id="actBackup" type="button" disabled><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19.6 12.5a7.6 7.6 0 1 1-2.1-5.8"/><path d="M19.8 4.3v3.9h-3.9"/><path d="M12 8.3v4l2.6 1.9"/></svg><span>Back up</span></button>
        <button class="pact" id="actRestore" type="button" disabled><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4.4 12.5a7.6 7.6 0 1 0 2.1-5.8"/><path d="M4.2 4.3v3.9h3.9"/><path d="M12 8.3v4l2.6 1.9"/></svg><span>Restore</span></button>
        <button class="pact" id="actPolicy" type="button" disabled><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l7.5 3v5.4c0 4.6-3.2 8.3-7.5 9.6-4.3-1.3-7.5-5-7.5-9.6V6z"/><path d="M12 8.8v6.4M8.8 12h6.4"/></svg><span>Set Policy</span></button>
        <button class="pact" id="actVerify" type="button" disabled><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="8.6"/><path d="M8.3 12.2l2.5 2.5 5-5.3"/></svg><span>Verify</span></button>
        <button class="pact" id="actPurge" type="button" disabled title="Delete configuration backup versions"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4.5 7h15M9.5 7V4.8h5V7M6.8 7l.8 12.2h8.8l.8-12.2M10.2 10.6v5.6M13.8 10.6v5.6"/></svg><span>Purge</span></button>
        <button class="pact" id="actBulk" type="button" title="Recreate every deleted namespace of the active cluster from its backups"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3.5" y="4" width="17" height="5" rx="1.2"/><rect x="3.5" y="11" width="17" height="5" rx="1.2"/><path d="M6 18.5h12M4.4 21a7 7 0 0 0 1.9-5.3"/><path d="M4.2 13.2v3.6h3.6"/></svg><span>Bulk restore</span></button>
      </div></div>
    <div class="tcard">
      <div class="tbar"><div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap"><input type="text" id="appsSearch" placeholder="Search" autocomplete="off">
        <label class="fld" style="margin:0;display:flex;align-items:center;gap:6px;font-size:13px;white-space:nowrap"><input type="checkbox" id="appsHideDel" style="width:auto;margin:0"> Hide deleted</label>
        <div class="seg" id="appsScope" style="display:none"><button class="on" type="button" data-scope="one">Active cluster</button><button type="button" data-scope="all">All clusters</button></div></div>
        <div style="display:flex;align-items:center;gap:14px"><span class="tinfo" id="appsInfo"></span><span class="tinfo" id="appsPager" style="display:none"></span>
          <button class="pact nsEdit" type="button" title="Filter the namespace list"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 5h16l-6.2 7.4V19l-3.6-1.8v-4.8z"/></svg></button></div></div>
      <table class="ht" id="appsTable"><thead><tr><th class="cb"><input type="checkbox" id="appsAll" title="Select all"></th>
        <th>Name</th><th>Namespace</th><th class="mc">Workspace</th><th class="mc">Cluster</th><th>Type</th><th>Policy</th><th class="ctr">Compliance</th><th class="ctr">Protection</th>
        <th>Last backup</th><th class="ctr">Versions</th></tr></thead>
        <tbody id="appsBody"><tr><td colspan="11" class="tempty"><span class="spin"></span></td></tr></tbody></table>
    </div>
  </section>
  <!-- ===================== POLITIQUES ===================== -->
  <section id="tab-policies" style="display:none">
    <div class="pagehead"><h1 class="ptitle">Policies</h1>
      <div class="pacts"><button class="pact" id="polNew" type="button"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg><span>New policy</span></button></div></div>
    <div class="tcard" style="margin-bottom:16px">
      <table class="ht"><thead><tr><th>Name</th><th>Namespaces</th><th>Frequency</th><th>Retention</th><th>HYCU policy</th><th>Last run</th><th class="ctr">Status</th></tr></thead>
        <tbody id="polBody"></tbody></table>
    </div>
    <div class="card" id="polEdit" style="display:none">
      <h3 id="polEditTitle">New policy</h3>
      <div class="row">
        <div style="flex:none;width:200px"><label class="fld">Nom</label><input type="text" id="peName" maxlength="40" placeholder="or"></div>
        <div><label class="fld">Namespaces (comma-separated)</label><input type="text" id="peNs" placeholder="shop, billing"></div>
        <div><label class="fld">and/or label selector</label><input type="text" id="peSel" placeholder="hycu.io/policy=or"></div>
      </div>
      <div class="row">
        <div style="flex:none;width:150px"><label class="fld">Interval (hours)</label><input type="number" id="peInterval" min="0.25" step="0.25" value="24"></div>
        <div style="flex:none;width:170px"><label class="fld">Versions to keep</label><input type="number" id="peKeep" min="0" step="1" value="15"></div>
        <div><label class="fld">HYCU policy (optional)</label><select id="peHycu"></select></div>
        <div style="flex:none;align-self:flex-end"><label class="fld"><input type="checkbox" id="peEnabled" style="width:auto" checked> Enabled</label></div>
      </div>
      <div class="hint" style="margin-top:6px">A namespace named explicitly wins over a label selector; otherwise, the first matching policy in the list. A namespace without a policy follows the default policy. The HYCU policy is assigned to volumes that do not have one yet.</div>
      <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <button class="btn" id="peSave" type="button">Save</button>
        <button class="btn ghost" id="peCancel" type="button">Cancel</button>
        <button class="lnk" id="peDelete" type="button" style="margin-left:auto;color:var(--red-t)">Delete the policy</button>
      </div>
      <div id="peMsg"></div>
    </div>
    <div class="card">
      <h3><span class="step-no">⏱</span>Default policy — automatic configuration backup</h3>
      <p class="sub">Regularly backs up the <b>PV/PVC manifests</b> (the restore “recipe”) of all
        namespaces allowed by the filter — while the tool is running. <b>Not the data</b> of the volumes:
        they are protected by HYCU (<b>Applications → Set Policy</b>).</p>
      <div class="row">
        <div style="flex:none"><label class="fld">Automatic backup</label>
          <div style="display:flex;align-items:center;gap:10px;min-height:38px">
            <label class="switch onoff"><input type="checkbox" id="abEnabled"><span class="slider"></span></label>
            <b id="abEnabledLbl" style="font-size:13px;color:var(--muted)">Disabled</b>
          </div></div>
        <div style="flex:none;width:140px"><label class="fld">Interval (hours)</label>
          <input type="number" id="abInterval" min="1" step="1" value="24"></div>
        <div style="flex:none;width:150px"><label class="fld">Retention</label>
          <select id="abRet"><option value="count">N versions</option><option value="gfs">GFS (d/wk/mo)</option></select></div>
        <div style="flex:none;width:150px" id="abKeepWrap"><label class="fld">Versions to keep</label>
          <input type="number" id="abKeep" min="1" step="1" value="15"></div>
        <div style="flex:none;display:none;gap:8px" id="abGfsWrap">
          <div style="width:86px"><label class="fld">Days</label><input type="number" id="abGfsD" min="0" value="7"></div>
          <div style="width:86px"><label class="fld">Weeks</label><input type="number" id="abGfsW" min="0" value="4"></div>
          <div style="width:86px"><label class="fld">Months</label><input type="number" id="abGfsM" min="0" value="12"></div>
        </div>
        <div><label class="fld">Destination folder (optional)</label>
          <input type="text" id="abDest" placeholder="Empty = hycu-backups/"></div>
        <div style="flex:none;align-self:flex-end"><button class="btn" id="abSave">Save</button></div>
      </div>
      <div class="hint" id="abStatus" style="margin-top:8px"></div>
    </div>

    <div class="card" id="polHycuCard">
      <h3>HYCU policies (volume data)</h3>
      <p class="sub">Policies defined in HYCU, assignable to an application's Volume Groups via
        <b>Applications → Set Policy</b>.</p>
      <div id="polHycu"></div>
    </div>
  </section>
  <!-- ===================== TÂCHES ===================== -->
  <section id="tab-jobs" style="display:none">
    <div class="pagehead"><h1 class="ptitle">Jobs <button class="refresh" id="jobsRefresh" type="button" title="Refresh"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19.4 12.6a7.5 7.5 0 1 1-2.3-5.9"/><path d="M19.6 4.4v4h-4"/></svg></button></h1>
      <div class="pacts">
        <a class="pact" href="/api/report?format=html" download title="Compliance report (standalone HTML): applications, RPO, cluster health, jobs"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 3.5h9l4 4V20.5H6z"/><path d="M14.5 3.5v4.5H19"/><path d="M9 13h7M9 16.5h5"/></svg><span>HTML report</span></a>
        <a class="pact" href="/api/report?format=csv" download title="CSV export of applications (Excel)"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 3.5h9l4 4V20.5H6z"/><path d="M14.5 3.5v4.5H19"/><path d="M9 12.5l2.2 5M11.2 12.5L9 17.5M14 12.5v5h2.6"/></svg><span>CSV</span></a>
      </div></div>
    <div class="tcard" style="margin-bottom:16px;padding:14px 16px"><div class="jcounts" id="jobsCounts" style="margin-top:0"></div></div>
    <div class="tcard">
      <div class="tbar"><input type="text" id="jobsSearch" placeholder="Search" autocomplete="off"><span class="tinfo" id="jobsInfo"></span></div>
      <table class="ht"><thead><tr><th>Job</th><th>Application</th><th>Cluster</th><th>Details</th><th>Started</th><th class="ctr">Status</th></tr></thead>
        <tbody id="jobsBody"><tr><td colspan="6" class="tempty"><span class="spin"></span></td></tr></tbody></table>
    </div>
  </section>

  <!-- ===================== VÉRIFICATION ===================== -->
  <section id="tab-verify" style="display:none">
    <div class="pagehead"><h1 class="ptitle"><a class="crumb" data-go="apps">Applications</a><span class="sep">›</span>Verification</h1></div>
    <div class="card">
      <h3><span class="step-no">3</span>Verify a namespace's state</h3>
      <p class="sub">Confirms that the PVCs are Bound and the pods are running.</p>
      <label class="fld">Namespace</label>
      <div class="row">
        <div><select id="vfNs"></select></div>
        <div style="flex:none"><button class="btn ghost nsEdit" title="Filter the namespace list">✎ Filter</button></div>
        <div style="flex:none"><button class="btn" id="vfRun">Verify</button></div>
        <div style="flex:none"><button class="btn ghost" id="vfAuto" title="Re-runs the check every ~3 s and stops as soon as all PVCs are Bound and pods are Running (10 min max); click again to stop">Auto-track (until stable)</button></div>
      </div>
      <div id="vfOut"></div>
    </div>
  </section>

  <!-- ===================== RÉGLAGES ===================== -->
  <section id="tab-settings" style="display:none">
    <div class="pagehead"><h1 class="ptitle">Settings</h1></div>
    <div class="card">
      <h3><span class="step-no">⎈</span>Local cluster (kubectl context)</h3>
      <p class="sub">Choose the cluster explicitly instead of following the current context.
        The tool adds <code>--context</code> (and <code>--kubeconfig</code>) to every kubectl command.
        <b>Additional</b> clusters (imported kubeconfig, NKP workspaces) are managed from <b>⚙ Sources</b>.</p>
      <label class="fld">kubeconfig file (empty = default ~/.kube/config)</label>
      <input type="text" id="cfgKubeconfig" placeholder="%USERPROFILE%\.kube\config">
      <div class="row" style="margin-top:6px">
        <div><label class="fld">Context</label><select id="cfgContext"></select></div>
        <div style="flex:none;align-self:flex-end"><button class="btn ghost" id="ctxList">List contexts</button></div>
      </div>
      <div style="margin-top:12px"><button class="btn" id="ctxApply">Use this context</button>
        <span class="hint" id="ctxMsg" style="margin:0"></span></div>
    </div>

    <div class="card">
      <h3><span class="step-no">⚙</span>Settings (per-customer adaptation)</h3>
      <p class="sub">These settings are saved in <code>hycu_config.json</code> next to the program.
        Leave blank anything you don't want to constrain.</p>
      <div class="row">
        <div><label class="fld">kubectl binary</label><input type="text" id="cfgKubectl" placeholder="kubectl"></div>
        <div><label class="fld">volumeHandle prefix (empty = auto)</label><input type="text" id="cfgVhPrefix" placeholder="auto-detected"></div>
      </div>
      <div class="row">
        <div><label class="fld">Allowed contexts / clusters (comma-separated; empty = all)</label><input type="text" id="cfgCtx" placeholder="prod-cluster, dr-cluster"></div>
        <div><label class="fld">Allowed namespaces — local cluster (empty = all)</label><input type="text" id="cfgNs" placeholder="wordpress, bo-dev"></div>
      </div>
      <div class="row">
        <div><label class="fld">Namespace label selector (empty = inactive; applies to all clusters)</label><input type="text" id="cfgLabelSel" placeholder="hycu.io/backup=true  or  env in (prod,preprod)"></div>
        <div style="flex:none;width:230px"><label class="fld">Job history (days; 0 = unlimited)</label><input type="number" id="cfgAuditDays" min="0" step="1" placeholder="31"></div>
      </div>
      <div class="row">
        <div style="flex:none;width:250px"><label class="fld">Free-space floor (MB; 0 = disabled)</label><input type="number" id="cfgMinFree" min="0" step="100" placeholder="500"></div>
        <div style="flex:none;width:280px"><label class="fld">Backup quota (GB; 0 = unlimited)</label><input type="number" id="cfgQuota" min="0" step="1" placeholder="0"></div>
        <div style="align-self:flex-end" class="hint">Below the floor, every backup is refused; above the quota, the oldest are pruned (the most recent of each application is always kept).</div>
      </div>
      <div class="row">
        <div><label class="fld"><input type="checkbox" id="cfgDr" style="width:auto"> <b>Allow DR restore</b> (cross-cluster / cross-context)</label>
        <div class="hint">Enable it for the duration of a drill or a disaster. Each DR restore stays explicit: sources read from the backup alone, warning, target cluster retyped, dedicated audit.</div></div>
        <div><label class="fld">Host names allowed to reach the interface (empty = loopback only)</label><input type="text" id="cfgHosts" placeholder="hycu.internal.example.com">
          <div class="hint" style="margin-top:4px">DNS name of an Ingress or reverse proxy. The tool has no authentication: put authentication (SSO, oauth2-proxy, IP allowlist) and TLS in front of it as soon as it leaves the loopback.</div></div>
      </div>
      <div class="row">
        <div style="flex:none;width:260px"><label class="fld">Wait timeout (s)</label><input type="text" id="cfgWait" placeholder="120"></div>
      </div>
      <label class="fld" style="margin-top:14px"><input type="checkbox" id="cfgConfirm" style="width:auto"> Require context confirmation before any real action</label>
      <label class="fld"><input type="checkbox" id="cfgStrip" style="width:auto"> Strip claimRef entirely from the PV (let the PVC rebind)</label>
      <label class="fld"><input type="checkbox" id="cfgSim" style="width:auto"> Offer the simulation mode (switch in the banner; otherwise the tool works in live mode)</label>
      <div style="margin-top:14px"><button class="btn" id="cfgSave">Save settings</button> <span class="hint" id="cfgMsg"></span></div>
    </div>
  </section>
</main>
</div>

<div id="mBackup" class="hmodal-bg" style="display:none">
  <div class="hmodal" style="max-width:640px">
    <div class="hm-head"><h2 id="mBackupTitle">Configuration backup</h2><div class="hm-ico"><button type="button" data-close="mBackup" title="Close">✕</button></div></div>
    <div class="hm-body">
    <div class="card">
      <h3><span class="step-no">1</span>Back up a namespace's volumes</h3>
      <p class="sub">Automatically exports and cleans all PVs and PVCs in the namespace.
        Equivalent to the kubectl loops + manual manifest cleanup.</p>
      <div id="bkNsRow"><label class="fld">Namespace</label>
      <div class="row">
        <div><select id="bkNs"></select></div>
        <div style="flex:none"><button class="btn ghost nsEdit" title="Filter the namespace list">✎ Filter</button></div>
        <div style="flex:none"><button class="btn" id="bkRun">Back up this namespace</button></div>
        <div style="flex:none"><button class="btn ghost" id="bkRunAll" title="Back up all namespaces allowed by the filter (all if no filter)">Back up all (filtered)</button></div>
      </div></div>
      <div id="bkSelInfo" style="display:none"><label class="fld">Selected namespaces</label><div class="fbox" id="bkSelList"></div></div>
      <label class="fld" style="margin-top:10px">Destination folder (optional)</label>
      <input type="text" id="bkDest" placeholder="Empty = hycu-backups/ (next to the program). E.g. D:\backups\hycu  or  /mnt/backups">
      <div class="hint" style="margin-top:4px">Path on the machine running the tool. The &lt;namespace&gt;/&lt;timestamp&gt; subfolder is created automatically.</div>
      <div id="bkOut"></div>
    </div>

    </div>
    <div class="hm-foot" id="mBackupFoot"><button class="lnk" type="button" data-close="mBackup">Close</button><button class="btn" id="bkRunSel" type="button" style="display:none">Back up the selection</button></div>
  </div>
</div>
<div id="mPurge" class="hmodal-bg" style="display:none">
  <div class="hmodal" style="max-width:640px">
    <div class="hm-head"><h2 id="mPurgeTitle">Saved versions</h2><div class="hm-ico"><button type="button" data-close="mPurge" title="Close">✕</button></div></div>
    <div class="hm-body"><div id="purgeList"></div><div id="purgeMsg"></div></div>
    <div class="hm-foot"><button class="lnk" type="button" id="purgeOld" style="margin-right:auto">All but the most recent</button>
      <button class="lnk" type="button" data-close="mPurge">Close</button>
      <button class="btn danger" id="purgeGo" type="button" disabled>Delete the selection</button></div>
  </div>
</div>
<div id="mBulk" class="hmodal-bg" style="display:none">
  <div class="hmodal" style="max-width:860px">
    <div class="hm-head"><h2>Bulk restore</h2><div class="hm-ico"><button type="button" data-close="mBulk" title="Close">✕</button></div></div>
    <div class="hm-body">
      <div class="note">Recreates <b>every deleted namespace</b> of the active cluster (<b id="bulkCluster"></b>) from its latest backup prior to the reference time: namespace, PV/PVC, workloads, dependencies, Secrets (vault unlocked), Volume Groups restored by HYCU if they are gone, stateless applications. Namespaces <b>still present</b> are skipped: a live application is restored from its own row. Sequential, journaled, resumable; <b>simulation is mandatory</b> before the real run.</div>
      <div class="row" style="margin-top:10px">
        <div style="flex:none;width:230px"><label class="fld">Reference time</label><input type="datetime-local" id="bulkAsOf"></div>
        <div><label class="fld">Namespaces to exclude (comma-separated, optional)</label><input type="text" id="bulkExclude" placeholder="kube-system, monitoring" autocomplete="off"></div>
        <div style="flex:none;align-self:flex-end"><button class="btn ghost" id="bulkPlanBtn" type="button">Prepare the plan</button></div>
      </div>
      <div id="bulkPlanOut" style="margin-top:10px"></div>
      <div id="bulkRunOut" style="margin-top:10px"></div>
    </div>
    <div class="hm-foot"><button class="lnk" type="button" data-close="mBulk">Close</button>
      <button class="btn ghost" id="bulkStop" type="button" style="display:none">Stop</button>
      <button class="btn ghost" id="bulkResume" type="button" style="display:none">Resume</button>
      <button class="btn" id="bulkSim" type="button" disabled>Simulate</button>
      <button class="btn danger" id="bulkReal" type="button" disabled>Start (real)</button></div>
  </div>
</div>
<div id="mPolicy" class="hmodal-bg" style="display:none">
  <div class="hmodal" style="max-width:700px">
    <div class="hm-head"><h2 id="mPolicyTitle">Set Policy</h2><div class="hm-ico"><button type="button" data-close="mPolicy" title="Close">✕</button></div></div>
    <div class="hm-body">
    <div class="card" id="bkProtectCard">
      <h3><span class="step-no">2</span>Protect the data in HYCU</h3>
      <div id="bkCfgPolWrap" style="margin-bottom:14px;padding-bottom:12px;border-bottom:1px solid var(--line)">
        <label class="fld">Configuration backup policy</label>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
          <select id="bkCfgPol" style="max-width:360px"></select>
          <button class="btn ghost" id="bkCfgPolSave" type="button">Apply</button>
          <span class="hint" id="bkCfgPolMsg" style="margin:0"></span>
        </div>
      </div>
      <p class="sub">The <b>data</b> lives in Nutanix Volume Groups or on NAS shares: only HYCU
        actually backs it up. Here the namespace's PVCs are matched to their HYCU Volume Groups or shares,
        a HYCU policy is assigned, and a backup is started.</p>
      <div id="bkProtectOff" class="warnbox">Register the HYCU source (⚙ at the top right) to enable this section.</div>
      <div id="bkProtectOn" style="display:none">
        <button class="btn ghost" id="bkMatch">Analyze the PVC ↔ HYCU mapping (Volume Groups, NAS shares)</button>
        <div id="bkMatchOut"></div>
        <div id="bkProtectForm" style="display:none">
          <label class="fld">HYCU policy to assign (optional)</label>
          <select id="bkPolicy"></select>
          <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
            <button class="btn" id="bkProtect">Assign + back up now</button>
            <span class="hint" id="bkProtectHint" style="margin:0"></span>
          </div>
          <div id="bkProtectLog"></div>
        </div>
      </div>
    </div>
    </div>
    <div class="hm-foot" id="mPolicyFoot"><button class="lnk" type="button" data-close="mPolicy">Close</button></div>
  </div>
</div>
<div id="mRestore" class="hmodal-bg" style="display:none">
  <div class="hmodal" style="max-width:760px">
    <div class="hm-head"><h2 id="mRestoreTitle">Application restore</h2><div class="hm-ico"><button type="button" data-close="mRestore" title="Close">✕</button></div></div>
    <div class="hm-body">
  <!-- ===================== RESTAURATION ===================== -->
  <section id="tab-restore">
    <div class="stepper" id="rsStepper" aria-label="Restore steps">
      <span class="st on" data-st="1">1 · Type</span>
      <span class="st" data-st="2">2 · Options</span>
      <span class="st" data-st="3">3 · Verify &amp; run</span>
      <span class="st" data-st="4">4 · Follow-up</span>
    </div>
    <div id="rsPgType">
      <div class="note" id="rsAppNote" style="display:none;margin-bottom:10px"></div>
      <div class="opt" data-kind="cloneapp"><svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="4" y="27" width="16" height="16" rx="2"/><circle cx="35.5" cy="35" r="8.5"/><path d="M27.5 12.5a8.3 8.3 0 1 1 3 6.3"/><path d="M27 6.8v5.4h5.4"/></svg><div><b>Restore the whole application (copy)</b><span>Restores the application storage and objects (workloads, dependencies) into the same namespace (suffix) or another one. The original is not modified.</span></div></div>
      <div class="opt" data-kind="inplace"><svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><ellipse cx="19" cy="10.5" rx="12" ry="4.5"/><path d="M7 10.5v25c0 2.5 5.4 4.5 12 4.5"/><path d="M31 10.5v10"/><path d="M7 23c0 2.5 5.4 4.5 12 4.5"/><path d="M27.3 36.3a8.2 8.2 0 1 0 2.4-5.8"/><path d="M27 26.6v4.9h4.9"/></svg><div><b>Restore storage in place</b><span>Restores the data into the original volumes. The application is stopped, then restarted.</span></div></div>
      <div class="opt" data-kind="reattach"><svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><ellipse cx="16" cy="10.5" rx="11" ry="4.3"/><path d="M5 10.5v25c0 2.4 4.9 4.3 11 4.3s11-1.9 11-4.3v-25"/><path d="M5 23c0 2.4 4.9 4.3 11 4.3s11-1.9 11-4.3"/><path d="M32 23.5h11M38.5 18.5l5 5-5 5"/></svg><div><b>Restore storage to new volumes</b><span>Restores to new Volume Groups and attaches the application to them. The original volumes are kept.</span></div></div>
      <div class="opt" data-kind="dr"><svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M24 5l17 8v10c0 10.5-7.2 18.6-17 21-9.8-2.4-17-10.5-17-21V13z"/><path d="M24 15v10M24 30.5h.01"/></svg><div><b>DR restore (another cluster / context)</b><span>Disaster recovery: recreates an application on THIS cluster from a backup of a lost cluster (or imported from the S3 bucket). Sources read from the backup alone. Requires the “Allow DR restore” setting.</span></div></div>
      <div class="opt" data-kind="objects"><svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="6" width="26" height="34" rx="3"/><path d="M11 14h14M11 20h14M11 26h9"/><path d="M28.5 36.5a8.2 8.2 0 1 0 2.4-5.8"/><path d="M28.2 26.8v4.9h4.9"/></svg><div><b>Restore configuration objects</b><span>Re-applies selected objects (Deployments, Services, ConfigMaps…) from a backup's snapshot, with a diff preview. Volumes and data are untouched.</span></div></div>
    </div>
    <div id="rsPgDr" style="display:none">
      <div id="drGate" style="display:none"><div class="warnbox"><b>DR restore</b> is disabled. Enable “<b>Allow DR restore</b>” in ⚙ → Settings (for the duration of the drill or disaster), then come back here.</div>
        <div style="margin-top:10px"><button class="btn ghost" id="drOpenCfg" type="button">Open the settings</button></div></div>
      <div id="drForm" style="display:none">
        <div class="warnbox" id="drWarnDr"><b>Disaster recovery</b> mode: the cross-cluster guard is lifted for THIS operation. Every source comes from the selected backup; the target is the <b>active cluster</b> (<b id="drCluster"></b>). First restore the Volume Groups in HYCU to the target site, then paste their UUIDs.</div>
        <div class="note" id="drWarnRec" style="display:none">This namespace no longer exists on cluster <b id="drClusterRec"></b>: the application will be <b>recreated from its backup</b> (namespace, PV/PVC, workloads, non-redacted dependencies), reusing its original volumes — or, if they were deleted with the namespace, restoring them automatically from HYCU (“Protected deleted”). In the common case, nothing to enter: check the backup and start the restore.</div>
        <div class="row" style="margin-top:10px">
          <div><label class="fld">Source backup (all clusters / S3 imports)</label><select id="drBackupSel"></select></div>
          <div style="flex:none;width:220px"><label class="fld">Target namespace</label><input type="text" id="drTargetNs" autocomplete="off"></div>
        </div>
        <div class="row" id="drScRow">
          <div style="flex:none;width:260px"><label class="fld">Target StorageClass (empty = unchanged)</label><input type="text" id="drSc" placeholder="nutanix-volume" autocomplete="off"></div>
          <div style="align-self:flex-end"><label class="fld"><input type="checkbox" id="drRefs" checked style="width:auto"> Recreate dependencies from the backup (non-redacted Secrets, ConfigMaps, ServiceAccounts, Services)</label></div>
        </div>
        <div class="note" id="drSecretsNote" style="display:none;margin:8px 0"></div>
        <div class="note" id="drNoRes" style="display:none;margin:8px 0">This backup contains <b>only the volumes</b> (no snapshot of workloads/dependencies): it predates this feature, or extended config backup was disabled. The restore will recreate <b>the volumes (PV/PVC)</b>; recreate the workloads from a more recent backup or manually.</div>
        <div id="drReuseWrap" style="display:none;margin:6px 0 4px">
          <label class="fld" style="display:flex;gap:9px;align-items:flex-start;cursor:pointer;font-weight:600">
            <input type="checkbox" id="drReuse" checked style="width:auto;margin-top:2px">
            <span>Reuse the application's original volumes <span class="badge sim">recommended</span>
            <span class="hint" style="display:block;font-weight:400;margin-top:3px">Nothing to enter: the application is reconnected to its original Nutanix volumes (their IDs are in the backup). Only untick if you restored the data onto <b>new</b> volumes in HYCU.</span></span>
          </label>
        </div>
        <label class="fld" id="drVolsLabel">Volumes — paste the UUID of the VG restored/cloned on the target site</label>
        <div id="drVols"></div>
        <div id="drAutoWrap" style="display:none;margin:8px 0 2px">
          <button class="btn ghost" id="drAuto" type="button">Create the volumes automatically via HYCU</button>
          <span class="hint" style="margin-left:8px">HYCU clones the Volume Groups and the tool retrieves the new IDs — nothing to enter. In simulation, only the plan is shown.</span>
        </div>
        <div id="drLog" style="margin-top:10px"></div>
        <div id="drErr"></div>
      </div>
    </div>
    <div id="rsPgObjects" style="display:none">
      <div class="row" style="margin-bottom:4px">
        <div><label class="fld" style="margin-top:0">Application</label><div class="fbox" id="objApp"></div></div>
        <div><label class="fld" style="margin-top:0">Backup (config snapshot)</label><select id="objBackupSel"></select></div>
      </div>
      <div id="objPick">
        <label class="fld" style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">Objects to restore <span class="hint" id="objInfo"></span>
          <span id="objOnlyAppWrap" style="display:none;font-weight:400;margin-left:auto"><input type="checkbox" id="objOnlyApp" checked style="width:auto"> Only the application's objects</span></label>
        <div class="tcard" style="box-shadow:none;border:1px solid var(--rule)">
          <table class="ht"><thead><tr><th class="cb"><input type="checkbox" id="objAll"></th><th>Kind</th><th>Name</th><th>Note</th></tr></thead>
          <tbody id="objBody"></tbody></table></div>
      </div>
      <div id="objDiffWrap" style="display:none">
        <label class="fld">Diff preview (live → backup)</label>
        <div id="objDiff"></div>
      </div>
      <div id="objLog" style="margin-top:10px"></div>
      <div id="objErr"></div>
    </div>
    <div id="rsPgTarget" style="display:none">
      <div class="opt" data-nsmode="same"><svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="6" y="6" width="24" height="24" rx="3"/><rect x="18" y="18" width="24" height="24" rx="3"/><path d="M25 30h10M30 25v10"/></svg><div><b>Into the same namespace (suffix)</b><span>The copy is created next to the original application: every object gets a suffix (e.g. <code>-clone</code>). Handy to verify a restore without moving anything.</span></div></div>
      <div class="opt" data-nsmode="other"><svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="12" width="17" height="24" rx="3"/><rect x="30" y="12" width="14" height="24" rx="3" stroke-dasharray="4 3"/><path d="M21 24h11M27.5 19.5l4.5 4.5-4.5 4.5"/></svg><div><b>Into another namespace</b><span>The copy is created in a target namespace (created if missing), with its dependencies (Secrets, ConfigMaps, ServiceAccount, Services). Original names are kept.</span></div></div>
    </div>
    <div id="rsPgForm" style="display:none">
      <div class="row" style="margin-bottom:4px">
        <div><label class="fld" style="margin-top:0">Application</label><div class="fbox" id="rsWizApp"></div></div>
        <div><label class="fld" style="margin-top:0">Target cluster</label><div class="fbox" id="rsWizCluster"></div></div>
      </div>
    <div class="card">
      <h3><span class="step-no">1</span>Choose the namespace and volumes</h3>
      <p class="sub">Tick the volume(s) to restore — several volumes = a single transaction.</p>
      <div id="rsNsRow" style="display:none"><label class="fld">Namespace</label>
      <div class="row">
        <div><select id="rsNs"></select></div>
        <div style="flex:none;align-self:flex-end"><button class="btn ghost nsEdit" title="Filter the namespace list">✎ Filter</button></div>
      </div></div>
      <label class="fld" id="rsCustomDirLbl" style="margin-top:8px"><input type="checkbox" id="rsCustomDir" style="width:auto"> Read backups from a custom folder</label>
      <div id="rsCustomDirWrap" style="display:none;margin-top:4px">
        <input type="text" id="rsBackupRoot" placeholder="E.g. D:\backups\hycu  or  /mnt/backups  (folder containing &lt;namespace&gt;/&lt;timestamp&gt;/)">
        <div class="hint" style="margin-top:4px">Backups will be read (and used for the restore) from here instead of <code>hycu-backups/</code>.</div>
      </div>
      <div id="rsBackupSelWrap" style="display:none;margin-top:8px">
        <label class="fld">Configuration backup to restore</label>
        <select id="rsBackupSel"></select>
        <div class="hint" style="margin-top:4px">PV/PVC manifests (the “skeleton”) — independent from the HYCU restore point of the <b>data</b>.<a id="rsBackupDl" href="#" download style="display:none;margin-left:6px;text-decoration:none">⬇ Download (.zip)</a></div>
      </div>
      <div id="rsModeRow" style="display:none"><label class="fld">Operation type</label>
      <div class="seg" id="rsMode">
        <button class="on" data-mode="clone">Clone (new VG)</button>
        <button data-mode="inplace">Restore in place</button>
      </div></div>
      <div id="rsCloneSubWrap">
        <label class="fld" style="display:none">What to do with the clone?</label>
        <div class="seg" id="rsCloneSub" style="display:none">
          <button class="on" data-sub="reattach">Reattach to the existing app</button>
          <button data-sub="cloneapp">Clone the application</button>
        </div>
        <div id="rsCloneAppWrap" style="display:none">
          <label class="fld">Application clone target</label>
          <div class="seg" id="rsCloneNsMode">
            <button class="on" data-nsmode="same">Same namespace (suffix)</button>
            <button data-nsmode="other">Other namespace</button>
          </div>
          <div class="row" style="margin-top:6px">
            <div id="rsCloneSuffixWrap"><label class="fld">Suffix applied to the copies</label><input type="text" id="rsCloneSuffix" value="-clone"></div>
            <div id="rsCloneTargetWrap" style="display:none"><label class="fld">Target namespace</label><input type="text" id="rsCloneTargetNs" placeholder="bo-dev-restore"></div>
          </div>
          <label class="fld" id="rsCloneRefsWrap" style="margin-top:8px;display:none"><input type="checkbox" id="rsCloneRefs" checked style="width:auto">
            Also clone the dependencies (Secrets, ConfigMaps, ServiceAccount, Services targeting the app)
            <span class="hint">— required for the pods to start in the other namespace</span></label>
        </div>
      </div>
      <label class="fld">Volumes to restore</label>
      <ul class="pvc-list" id="rsPvcs" style="margin-top:12px"></ul>
    </div>

    <div class="card" id="rsConfig" style="display:none">
      <h3><span class="step-no">2</span>Restore the data (Volume Groups)</h3>
      <div id="rsFlowGuide" class="rsGuide"></div>
      <div id="rsVolCfgs"></div>
      <div id="rsHyActions"></div>
      <div id="rsInplaceRunWrap" style="display:none;margin-top:14px;border-top:1px solid var(--line);padding-top:12px">
        <p class="sub" style="margin:4px 0 8px"><b>Stop the application → HYCU in-place restore → restart.</b> No reference to enter.</p>
        <button class="btn" id="rsInplaceRun" disabled>Launch the in-place restore</button>
        <span class="hint" id="rsInplaceHint" style="margin:0"></span>
        <div aria-live="polite" id="rsInplaceLog"></div>
      </div>
      <div id="rsContinueWrap" style="margin-top:14px">
        <button class="btn" id="rsPreview">Continue: review and launch →</button>
      </div>
      <div id="rsErr"></div>
    </div>

    <details class="rsAdv" id="rsAdvWrap"><summary class="rsAdvSum">Advanced — custom backup folder</summary><div id="rsAdvBody"></div></details>
    </div>
    <div id="rsPgPlan" style="display:none">
    <div class="card" id="rsPlan" style="display:none">
      <h3><span class="step-no">3</span>Review then launch</h3>
      <p class="sub">Review the derived replacements and the sequence, then launch.</p>
      <div id="rsRepl"></div>
      <div id="rsStepsWrap"><b style="font-size:13px">Planned sequence</b><ol class="plan" id="rsSteps"></ol></div>
      <div id="rsCtxConfirm" style="display:none;margin-top:14px">
        <label class="fld">Target context confirmation before any action</label>
        <input type="text" id="rsCtxInput" placeholder="retype the kubectl context name">
      </div>
      <div style="margin-top:16px;display:flex;gap:10px;flex-wrap:wrap;align-items:center">
        <button class="btn" id="rsGo">Launch the restore</button>
        <span class="hint" id="rsGoHint"></span>
      </div>
      <div id="rsProgress" class="progress" style="display:none">
        <div class="progress-head"><span id="rsProgressTxt"></span><button class="btn ghost" type="button" id="rsCancel" style="display:none">Stop after the current step</button></div>
        <div class="progress-track"><div class="progress-bar" id="rsProgressBar"></div></div>
      </div>
      <div id="rsLog" aria-live="polite"></div>
    </div>
    </div>
    <div class="nextbar" id="rsNextBar"><span id="rsNextTxt"></span><button class="btn" id="rsNextBtn"></button></div>
  </section>

    </div>
    <div class="hm-foot" id="mRestoreFoot"><span id="rsWizMode" class="badge" style="margin-right:auto"></span><button class="lnk" type="button" data-close="mRestore">Close</button><button class="btn ghost" type="button" id="rsWizBack">Back</button><button class="btn" type="button" id="rsWizGo">Next</button></div>
  </div>
</div>
<div id="mSources" class="hmodal-bg" style="display:none">
  <div class="hmodal" style="max-width:860px">
    <div class="hm-head"><h2 id="mSourcesTitle">Sources</h2><div class="hm-ico"><button type="button" data-close="mSources" title="Close">✕</button></div></div>
    <div class="hm-body">
      <p class="hint" style="margin:0 0 12px">Register here the systems used by the tool — HYCU, Nutanix and your Kubernetes clusters. Credentials and kubeconfigs stay in memory for the session (or in the encrypted vault if you choose so).</p>
      <div class="srctools">
        <button class="pact" id="clAddBtn" type="button"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="4" width="16" height="6.5" rx="1.3"/><rect x="4" y="13.5" width="10" height="6.5" rx="1.3"/><path d="M18.5 14.5v5M16 17h5"/></svg><span>Add a Kubernetes cluster</span></button>
        <button class="pact" id="nkpBtn" type="button"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3.5" y="3.5" width="7" height="7" rx="1.2"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.2"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.2"/><circle cx="16.6" cy="16.6" r="3"/><path d="M18.8 18.8l2 2"/></svg><span>Discover NKP workspaces</span></button>
      </div>
      <div class="tcard" style="box-shadow:none;border:1px solid var(--rule);margin-bottom:14px">
        <table class="ht"><thead><tr><th>Name</th><th>Type</th><th>URL / server</th><th class="ctr">Status</th></tr></thead><tbody id="srcBody"></tbody></table>
      </div>
  <!-- ===================== CONNEXIONS ===================== -->
  <section id="tab-connect">
    <div class="card" data-card="hycu">
      <h3><span class="step-no">H</span>HYCU — connection</h3>
      <p class="sub">To list restore points and orchestrate the clone/restore of a Volume Group
        from the restore wizard (<b>Applications → Restore</b>). Credentials stay <b>in memory</b> for the session — never written to disk.</p>
      <label class="fld">HYCU URL (port 8443)</label>
      <input type="text" id="hyUrl" placeholder="https://hycu.example.com:8443">
      <label class="fld">Authentication</label>
      <div class="seg" id="hyAuthMode">
        <button class="on" data-mode="basic">Basic (user)</button>
        <button data-mode="apikey">API key</button>
      </div>
      <div id="hyBasicFields" class="row">
        <div><label class="fld">Username</label><input type="text" id="hyUser" autocomplete="off"></div>
        <div><label class="fld">Password</label><input type="password" id="hyPass" autocomplete="off"></div>
      </div>
      <div id="hyApiField" style="display:none">
        <label class="fld">API key <span class="hint">(HYCU: Help → API Keys)</span></label>
        <input type="password" id="hyApiKey" autocomplete="off">
      </div>
      <label class="fld" style="margin-top:10px"><input type="checkbox" id="hyTls" style="width:auto"> Verify the TLS certificate (unchecked = self-signed accepted)</label>
      <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <button class="btn" id="hyConnect">Test &amp; connect</button>
        <button class="btn ghost" id="hyDisconnect">Disconnect</button>
        <span class="hint" id="hyStatus" style="margin:0"><span class="conn-dot"></span>not connected</span>
      </div>
      <div id="hyErr"></div>
    </div>

    <div class="card" data-card="nutanix">
      <h3><span class="step-no">N</span>Nutanix Prism Element — connection</h3>
      <p class="sub">Automatically fetches the cloned Volume Group's reference (UUID) (read-only, API v2)
        in the restore wizard. Credentials kept in session memory only.</p>
      <label class="fld">Prism Element URL</label>
      <input type="text" id="ntUrl" placeholder="https://prism-element.example.com:9440">
      <div class="row">
        <div><label class="fld">Username</label><input type="text" id="ntUser" autocomplete="off"></div>
        <div><label class="fld">Password</label><input type="password" id="ntPass" autocomplete="off"></div>
      </div>
      <label class="fld" style="margin-top:10px"><input type="checkbox" id="ntTls" style="width:auto"> Verify the TLS certificate</label>
      <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <button class="btn" id="ntConnect">Test &amp; connect</button>
        <button class="btn ghost" id="ntDisconnect">Disconnect</button>
        <span class="hint" id="ntStatus" style="margin:0"><span class="conn-dot"></span>not connected</span>
      </div>
      <div id="ntErr"></div>
    </div>

    <div class="card" data-card="prismcentral">
      <h3><span class="step-no">PC</span>Nutanix Prism Central — connection</h3>
      <p class="sub">Multi-cluster alternative (API v3). Also used to fetch the reference (UUID) of the Volume Group
        cloned if you do not use Prism Element. Credentials kept in session memory only.</p>
      <label class="fld">Prism Central URL</label>
      <input type="text" id="pcUrl" placeholder="https://prism-central.example.com:9440">
      <div class="row">
        <div><label class="fld">Username</label><input type="text" id="pcUser" autocomplete="off"></div>
        <div><label class="fld">Password</label><input type="password" id="pcPass" autocomplete="off"></div>
      </div>
      <label class="fld" style="margin-top:10px"><input type="checkbox" id="pcTls" style="width:auto"> Verify the TLS certificate</label>
      <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <button class="btn" id="pcConnect">Test &amp; connect</button>
        <button class="btn ghost" id="pcDisconnect">Disconnect</button>
        <span class="hint" id="pcStatus" style="margin:0"><span class="conn-dot"></span>not connected</span>
      </div>
      <div id="pcErr"></div>
    </div>

    <div class="card" data-card="s3">
      <h3><span class="step-no">S3</span>S3 object storage — backup export (optional)</h3>
      <p class="sub">Copies every configuration backup (<code>.zip</code>) to an <b>S3-compatible</b> bucket
        (Nutanix Objects, MinIO, AWS S3…): the safety net then lives <b>outside the cluster</b> it protects.
        Access keys stay <b>in memory</b> for the session (encrypted vault optional).</p>
      <div class="row">
        <div><label class="fld">S3 endpoint</label><input type="text" id="s3Url" placeholder="https://objects.example.com"></div>
        <div><label class="fld">Bucket</label><input type="text" id="s3Bucket" placeholder="hycu-backups" autocomplete="off"></div>
      </div>
      <div class="row">
        <div><label class="fld">Access key</label><input type="text" id="s3Access" autocomplete="off"></div>
        <div><label class="fld">Secret key</label><input type="password" id="s3Secret" autocomplete="off"></div>
      </div>
      <div class="row">
        <div><label class="fld">Region (signing)</label><input type="text" id="s3Region" placeholder="us-east-1"></div>
        <div style="align-self:flex-end">
          <label class="fld"><input type="checkbox" id="s3PathStyle" checked style="width:auto"> Path-style URL (Objects / MinIO)</label>
          <label class="fld"><input type="checkbox" id="s3Tls" style="width:auto"> Verify the TLS certificate</label>
        </div>
      </div>
      <label class="fld" style="margin-top:10px"><input type="checkbox" id="s3Auto" style="width:auto">
        <b>Automatic export</b>: send every successful backup (manual and scheduled) to the bucket</label>
      <label class="fld"><input type="checkbox" id="s3Enc" style="width:auto">
        <b>Encrypt exports</b> (optional): uploaded objects are encrypted — the bucket can be untrusted storage</label>
      <div id="s3EncWrap" style="display:none"><label class="fld">Export encryption passphrase (keep it: it is needed for decryption)</label>
        <input type="password" id="s3EncPass" autocomplete="off">
        <div class="hint" style="margin-top:4px">Decryption outside the UI: <code>python3 hycu_k8s_nutanix.py --decrypt file.zip.enc</code></div></div>
      <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <button class="btn" id="s3Connect">Test &amp; connect</button>
        <button class="btn ghost" id="s3Disconnect">Disconnect</button>
        <span class="hint" id="s3Status" style="margin:0"><span class="conn-dot"></span>not connected</span>
      </div>
      <div class="hint" style="margin-top:8px">Read-only test (bucket listing, 1 object). Objects created:
        <code>&lt;prefix&gt;/&lt;cluster&gt;/&lt;namespace&gt;/&lt;timestamp&gt;.zip</code>. A failed export
          never fails the local backup (visible in Jobs).</div>
      <div id="s3Err"></div>
      <div style="margin-top:14px;border-top:1px solid var(--line);padding-top:12px">
        <button class="pact" id="s3ListBtn" type="button"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v12M7.5 10.5L12 15l4.5-4.5"/><path d="M4 17v2.5h16V17"/></svg><span>Import from the bucket (recovery / DR)</span></button>
        <div id="s3ImportWrap" style="display:none;margin-top:10px">
          <div id="s3ListOut"></div>
          <div class="row" style="margin-top:8px">
            <div><label class="fld">Decryption passphrase (.enc objects only)</label><input type="password" id="s3ImpPass" autocomplete="off"></div>
            <div style="flex:none;align-self:flex-end"><button class="btn" id="s3ImportBtn" type="button" disabled>Import selection</button></div>
          </div>
          <div class="hint" style="margin-top:4px">Repatriated exports go to <code>hycu-backups/_imports/…</code>; they are restored through the wizard's <b>DR restore</b> (or on their source cluster).</div>
          <div id="s3ImpRes"></div>
        </div>
      </div>
      <div style="margin-top:14px;border-top:1px solid var(--line);padding-top:12px" id="tkCard">
        <b style="font-size:13px">Tool backup</b>
        <div class="hint" style="margin:2px 0 8px">Configuration, policies and encrypted vault. Exported daily with the automatic export; restorable on a new instance.</div>
        <div style="display:flex;gap:10px;flex-wrap:wrap">
          <button class="btn ghost" id="tkUpload" type="button">Export now</button>
          <button class="btn ghost" id="tkDownload" type="button">Download</button>
          <button class="btn ghost" id="tkList" type="button">Restore the tool from the bucket…</button>
        </div>
        <div id="tkOut"></div>
      </div>
    </div>

    <div class="card" data-card="vault">
      <h3><span class="step-no">🔒</span>Remember connections (encrypted)</h3>
      <p class="sub">Optional: store the credentials entered (and the kubeconfigs of added clusters) in an <b>encrypted</b> vault
        (<code>hycu_secrets.enc</code>), protected by a <b>master passphrase</b> — never stored.
        By default nothing is written (RAM only), the safest choice.</p>
      <label class="fld">Passphrase (≥ 8 characters)</label>
      <input type="password" id="vaultPass" autocomplete="off">
      <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <button class="btn" id="vaultSave">Save (encrypt)</button>
        <button class="btn ghost" id="vaultLoad">Load (decrypt)</button>
        <button class="btn danger" id="vaultForget">Forget</button>
        <span class="hint" id="vaultStatus" style="margin:0"><span class="conn-dot"></span>no vault</span>
      </div>
      <div class="hint" style="margin-top:8px">The vault uses passphrase-based encryption
        (PBKDF2-HMAC-SHA256 + integrity seal).</div>
      <div id="vaultErr"></div>
    </div>

    <div class="card" data-card="cluster-add">
      <h3><span class="step-no">K</span>Add a Kubernetes cluster</h3>
      <p class="sub">Load the cluster <b>kubeconfig</b> (file or copy-paste). Like a password, it stays
        <b>in memory</b> for the session, and is only written to disk <b>encrypted</b> if you use the vault.
        Each cluster's backups are stored separately.</p>
      <div class="row">
        <div><label class="fld">Cluster name</label><input type="text" id="clName" placeholder="prod-paris" autocomplete="off"></div>
        <div><label class="fld">Kubeconfig file</label><input type="file" id="clFile"></div>
      </div>
      <label class="fld">…or paste its content (YAML or JSON)</label>
      <textarea id="clKc" class="kc" spellcheck="false" autocomplete="off" placeholder="apiVersion: v1&#10;kind: Config&#10;clusters: …"></textarea>
      <div id="clCtxWrap" style="display:none"><label class="fld">Context</label><select id="clCtx"></select><div id="clCtxInfo"></div></div>
      <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <button class="btn" id="clAdd" type="button">Test &amp; add</button>
        <span class="hint" style="margin:0">Read-only connection test (namespace list, 10 s max).</span>
      </div>
      <div id="clErr"></div>
    </div>

    <div class="card" data-card="cluster">
      <h3><span class="step-no">K</span><span id="clDTitle">Cluster</span></h3>
      <div id="clDBody"></div>
      <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <button class="btn" id="clUse" type="button">Set as active cluster</button>
        <button class="btn ghost" id="clLocalCfg" type="button">Open settings</button>
        <button class="btn danger" id="clRemove" type="button">Remove</button>
      </div>
      <div id="clDErr"></div>
    </div>

    <div class="card" data-card="nkp">
      <h3><span class="step-no">W</span>NKP workspace discovery (optional)</h3>
      <p class="sub">From the NKP <b>management cluster</b>, lists the <b>workspaces</b> and their clusters, then imports
        their kubeconfigs. Queried cluster: <b id="nkpMgmt">—</b> (the active cluster — choose the management cluster
        in the top bar).</p>
      <div class="warnbox">⚠ <b>Elevated rights required</b> on the management cluster: read access to Workspaces,
        KommanderClusters and kubeconfig <b>Secrets</b> in workspace namespaces. Imported kubeconfigs often grant
        <b>administrator</b> access to the clusters: they stay in memory (optional encrypted vault), never in clear text on disk.</div>
      <div style="margin-top:12px"><button class="btn" id="nkpDiscover" type="button">Discover</button></div>
      <div id="nkpOut"></div>
      <div id="nkpImportWrap" style="display:none;margin-top:10px">
        <label class="fld"><input type="checkbox" id="nkpAck" style="width:auto"> I understand: import the kubeconfigs of the checked clusters</label>
        <button class="btn" id="nkpImport" type="button" disabled>Import selection</button>
      </div>
      <div id="nkpRes"></div>
    </div>
  </section>

    </div>
    <div class="hm-foot" id="mSourcesFoot"><button class="lnk" type="button" data-close="mSources">Close</button></div>
  </div>
</div>

<script>
const $ = s => document.querySelector(s);
const CSRF = document.querySelector('meta[name=csrf-token]').content;
const dry = () => $("#dry").checked;
let state = {selected:{}, mode:"clone", cloneSub:"reattach", cloneNsMode:"same", backup_path:null, backup_root:null, preview:null, ns:null, app:null};
let ctxInfo = {};
function isCloneApp(){ return state.mode==="clone" && state.cloneSub==="cloneapp"; }
function refOk(i){ return !!(i.nfs && isCloneApp()) || !!(i.new_ref||"").trim(); }

function badge(phase){
  const p=(phase||"").toLowerCase();
  const c = p==="bound"?"b-bound":p==="lost"?"b-lost":p==="pending"?"b-pending":"b-na";
  return `<span class="badge ${c}">${esc(phase||"—")}</span>`;
}
function esc(s){return (s==null?"":String(s)).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
// Cluster Kubernetes ACTIF: chaque requête le désigne (en-tête X-HYCU-Cluster) ;
// le serveur route kubectl vers ce cluster. “local” = cluster de la configuration.
let ACTIVE_CID="local", CLUSTERS=[{id:"local", name:"local", local:true}];
// Couche API unique: ne lève JAMAIS vers les handlers (une coupure réseau ou une
// réponse non-JSON renvoie {ok:false, error, status}), délai borné, bandeau hors-ligne.
let NET_DOWN=false;
function setNet(down){
  if(down===NET_DOWN) return; NET_DOWN=down;
  const b=$("#netBanner"); if(b) b.style.display = down ? "block": "none";
}
async function api(u, opts){
  const ctrl=new AbortController(); const t=setTimeout(()=>ctrl.abort(), (opts&&opts.timeout)||45000);
  try{
    const r=await fetch(u, Object.assign({signal:ctrl.signal}, opts||{}, {headers:Object.assign(
      {"X-HYCU-Cluster":(opts&&opts.cid)||ACTIVE_CID}, (opts&&opts.headers)||{})}));
    setNet(false);
    const txt=await r.text();
    let j=null; try{ j=txt?JSON.parse(txt):{}; }catch(e){ j=null; }
    if(j===null) return {ok:false, status:r.status, http_status:r.status, error:(r.status>=400?("HTTP "+r.status+" — "):"")+(txt||"unreadable response").slice(0,200)};
    if(j && typeof j==="object" && j.ok===undefined && j.error && r.status>=400) j.ok=false;
    // Le code HTTP est exposé à part: `status` appartient à la réponse du serveur
    // (statut d'un job HYCU, d'une comparaison d'objets…) et ne doit jamais être écrasé.
    if(j && typeof j==="object" && j.http_status===undefined) j.http_status=r.status;
    return j;
  }catch(e){
    const aborted = e && e.name==="AbortError";
    if(!aborted) setNet(true);
    return {ok:false, status:0, http_status:0, error: aborted ? "Timeout: the server is not responding.": "Server unreachable (network or tool stopped)."};
  }finally{ clearTimeout(t); }
}
async function get(u, cid){ return api(u, {cid}); }
async function post(u,b,cid){ return api(u, {method:"POST", cid, headers:{"Content-Type":"application/json","X-CSRF-Token":CSRF}, body:JSON.stringify(b)}); }
window.addEventListener("unhandledrejection", e=>{ console.warn("Unhandled promise:", e.reason); });

// Erreurs actionnables: reconnaît les causes courantes (HYCU/Nutanix/kubectl/HTTP)
// et préfixe un conseil concret, en gardant le détail brut en dessous.
function errHint(raw){
  const e=(raw||"").toLowerCase();
  if(/401|unauthorized|password|invalid cred/.test(e)) return "Credentials rejected — check the username/password, or the HYCU API key (Help → API Keys, required with 2FA).";
  if(/\b403\b|forbidden|rbac/.test(e)) return "Access denied — insufficient rights (RBAC / API role).";
  if(/\b404\b|api-docs|endpoint.*not found/.test(e)) return "Endpoint not found — check the base URL and the API version (⚙ Settings).";
  if(/certificat|certificate|ssl|tls|self.?signed/.test(e)) return "TLS certificate — tick/untick “Verify the TLS certificate” in Connections to match your PKI.";
  if(/object storage/.test(e)) return "S3 endpoint unreachable — check the PORT (MinIO: 9000 = S3 API, not the 9001 console; Nutanix Objects: 443), the http/https scheme, and that the machine running the tool (the Pod, not your workstation) can reach that host.";
  if(/^(host|server) unreachable|timed out|connection (failed|refused)|getaddrinfo|name or service|errno \d+|10061|10060/.test(e)) return "Host unreachable — check the URL:port (HYCU 8443, Prism 9440), the network and the firewall.";
  if(/not connected|connect to at least|connect to hycu/.test(e)) return "Register the source first (⚙ at the top right).";
  if(/namespace.*not allowed/.test(e)) return "Namespace not in the allowed list — see ⚙ Settings → allowed namespaces.";
  if(/context.*not allowed|allowed_contexts/.test(e)) return "kubectl context not in the allowed list — see ⚙ Settings.";
  if(/context confirmation/.test(e)) return "Retype the exact target context name to confirm.";
  if(/jeton anti-csrf|csrf token/.test(e)) return "Reload the page (Ctrl+Shift+R): the security token has expired.";
  return "";
}
function errBox(raw){
  const h=errHint(raw);
  return `<div class="err">${h?`<b>${esc(h)}</b><div class="hint" style="margin-top:4px">${esc(raw||"")}</div>`:esc(raw||"error")}</div>`;
}

// Préférences mémorisées PAR NAVIGATEUR (localStorage): namespace, type d'opération,
// dossiers. Confort uniquement — jamais d'identifiant ni de secret ici.
const PREFS_KEY="hycu_prefs";
function prefs(){ try{ const p=JSON.parse(localStorage.getItem(PREFS_KEY)||"{}"); return (p && typeof p==="object" && !Array.isArray(p)) ? p: {}; }catch(e){ return {}; } }
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
// Namespace GLOBAL synchronisé entre les 3 onglets (fluidité: un seul choix).
function applyGlobalNs(){ if(!state.ns) return; ["#bkNs","#rsNs","#vfNs"].forEach(id=>{ const e=$(id); if(e && e.value!==state.ns) e.value=state.ns; }); }
// Stepper du parcours Restaurer: surligne l'étape courante (1 Volumes, 2 Configurer, 3 Lancer).
function setRsStep(n){ document.querySelectorAll("#rsStepper .st").forEach(e=>{ const k=+e.dataset.st;
  e.classList.toggle("on",k===n); e.classList.toggle("done",k<n); }); }
// Pastilles cliquables du stepper: faire défiler vers la carte de l'étape (si affichée).
document.querySelectorAll("#rsStepper .st").forEach(s=>s.onclick=()=>{
  const n=+s.dataset.st;
  const el = n===1? document.querySelector("#tab-restore .card"): (n===2? $("#rsConfig"): $("#rsPlan"));
  if(el && el.style.display!=="none") el.scrollIntoView({behavior:"smooth",block:"start"});
});
const navBtns=[...document.querySelectorAll("nav button[data-tab]")];
// Pages (barre latérale) — navigation “à la HYCU”. Les opérations (sauvegarde,
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
  if(tab!=="verify" && vfTrack) vfStop();           // le suivi auto ne survit pas à un changement de page
  const navTab = tab==="verify" ? "apps": tab;     // Vérification = sous-page d'Applications
  navBtns.forEach(x=>{ const on=x.dataset.tab===navTab; x.classList.toggle("on",on); x.setAttribute("aria-selected",on?"true":"false"); });
  PAGES.forEach(t=>$("#tab-"+t).style.display="none");
  $("#tab-"+tab).style.display="block";
  applyGlobalNs();                                   // la page ouverte reflète le namespace courant
  curPage=tab; onPageShown(tab);
  window.scrollTo({top:0});
}
navBtns.forEach(b=>b.onclick=()=>switchTab(b.dataset.tab));
$("#hdrConn").onclick=()=>openSources();

// ----- Fenêtre “À propos” (bouton ? de l'en-tête) -----
// “?”: menu Aide (guide dans un nouvel onglet) / À propos (modale existante).
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

// ----- Barre “action suivante” du parcours Restaurer (anti-scroll) -----
// La page Restaurer est longue: cette barre flottante rend l'étape suivante
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
    return rsNext("Stateless application: no volume to choose.","Check the copy",()=>$("#rsPreview").click());
  const hyOn = conn.hycu && conn.hycu.connected;
  // Étape 3: plan affiché et lancement possible -> guider vers le bouton Lancer.
  if($("#rsPlan").style.display!=="none" && !$("#rsGo").disabled){
    return rsNext("Plan ready — final step:", $("#rsGo").textContent, ()=>scrollPulse($("#rsGo")));
  }
  // Orchestrated in-place restore: compte des points sélectionnés.
  if(state.mode==="inplace" && hyOn){
    const ready=chks.map(c=>c.dataset.pvc).filter(p=>rsInplaceSel[p]).length;
    if(ready===chks.length)
      return rsNext("All restore points are selected.","Go to launch",()=>scrollPulse($("#rsInplaceRun")));
    return rsNext(ready+" / "+chks.length+" restore point(s) selected.","Show the volumes",()=>scrollPulse($("#rsVolCfgs")));
  }
  // Clone / flux manuel: compte des références VG remplies.
  const items=collectItems();
  const filled=items.filter(refOk).length;
  if(filled===items.length)
    return rsNext("All VG references are filled.","Continue: review and launch",()=>$("#rsPreview").click());
  const batch=$("#hyBatchGo");   // panneau HYCU groupé disponible -> c'est l'action naturelle
  if(batch && !batch.disabled)
    return rsNext(filled+" / "+items.length+" VG reference(s) filled.","Restore the VGs from HYCU",()=>scrollPulse(batch));
  return rsNext(filled+" / "+items.length+" VG reference(s) filled.","Show the volumes",()=>scrollPulse($("#rsVolCfgs")));
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

// Bandeau simulation (source de vérité unique: #dry)
// E1: le mode simulation n'est proposé que si la configuration l'active
// (simulation_mode_available). Sinon l'interface travaille en mode réel, bandeau et
// interrupteur masqués; les garde-fous (confirmation du cluster, préflight) restent.
let SIM_AVAILABLE=false;
function applySimAvailability(avail){
  const was=SIM_AVAILABLE; SIM_AVAILABLE=!!avail;
  $("#dryBar").style.display = SIM_AVAILABLE ? "": "none";
  if(!SIM_AVAILABLE) $("#dry").checked=false;
  else if(!was) $("#dry").checked=true;          // simulation cochée par défaut quand elle est proposée
  refreshDry();
}
function refreshDry(){
  const live=!dry();
  $("#dryBar").classList.toggle("live",live);
  document.body.classList.toggle("realmode",live);   // barre rouge fixe + indicateur en-tête
  $("#dryLabel").textContent = live? "Simulation off — commands will be executed": "Simulation mode on";
  $("#dry").setAttribute("aria-checked", dry() ? "true": "false");
}
$("#dry").onchange=refreshDry;

// Modale de confirmation pour les actions destructives. Renvoie une Promise :
//  - false si annulé;  - true (ou le texte retapé) si confirmé.
// opts = { title, lines:[html…], requireText:(string|null) }
function confirmDanger(opts){
  const bgx=$("#dangerModal");
  if(bgx.style.display!=="none") return Promise.resolve(false);     // déjà ouverte: ignorer le double appel
  return new Promise(resolve=>{
    const bg=$("#dangerModal"), ok=$("#dmOk"), cancel=$("#dmCancel"), inp=$("#dmInput");
    $("#dmTitle").textContent=opts.title||"Confirm the real action";
    $("#dmBody").innerHTML=(opts.lines||[]).map(l=>`<div class="dm-line">${l}</div>`).join("");
    const need=opts.requireText||"";
    $("#dmConfirmWrap").style.display=need?"block":"none";
    $("#dmWord").textContent=need; inp.value="";
    function sync(){ ok.disabled = need ? (inp.value.trim()!==need): false; }
    sync(); inp.oninput=sync;
    bg.style.display="flex"; if(need) setTimeout(()=>inp.focus(),30);
    function close(val){ bg.style.display="none"; inp.oninput=null; ok.onclick=null; cancel.onclick=null; resolve(val); }
    ok.onclick=()=>close(need?inp.value.trim():true);
    cancel.onclick=()=>close(false);
  });
}

function sleep(ms){ return new Promise(r=>setTimeout(r,ms)); }

// Rendu HTML d'un log d'étapes (UNIFIE les 4 rendus dupliqués: restore, in-place,
// clone-app, protect). Une entrée = {ok,dry,label,cmd,stdout,stderr,planned,job_id}.
function renderLog(log){
  return (log||[]).map(l=>{
    const ic = l.dry? '<span class="ic sim">○</span>': (l.ok?'<span class="ic ok">✓</span>':'<span class="ic ko">✕</span>');
    const planned = l.planned? ` <code style="font-size:11px;color:#888">${esc(JSON.stringify(l.planned.body||l.planned))}</code>`:'';
    const cmd = l.cmd? ` <code style="font-size:11px;color:#888">${esc(l.cmd)}</code>`:'';
    const detail = (l.stderr&&!l.ok)? ` — <span class="ko">${esc(l.stderr)}</span>` :
       (l.stdout? ` <span class="hint">${esc(l.stdout.length>200?l.stdout.slice(0,200)+'…':l.stdout)}</span>`:'');
    return `<div class="logline">${ic}<span><b>${esc(l.label||'')}</b>${l.job_id?(' · job '+esc(l.job_id)):''}${cmd}${planned}${detail}</span></div>`;
  }).join("");
}

// Lance une opération longue côté serveur et suit sa progression (polling), en
// rafraîchissant l'affichage à chaque tick. Renvoie le résultat final.
let CURRENT_OP=null;                 // {id, url, cid, ns} de l'opération suivie (persisté: reprise après F5)
const OP_KEY="hycu_op";
function rememberOp(o){ CURRENT_OP=o; try{ if(o) sessionStorage.setItem(OP_KEY, JSON.stringify(o)); else sessionStorage.removeItem(OP_KEY); }catch(e){} }
async function followOp(opId, onProgress){
  let errors=0;
  for(let i=0;i<6000;i++){            // garde-fou: ~90 min à 0,9 s
    const st = await get("/api/op_status?id="+encodeURIComponent(opId));
    if(!st.ok){
      if(st.http_status===0 || st.http_status>=500){   // coupure réseau / serveur: on réessaie (borné)
        if(++errors<=20){ await sleep(2000); continue; }
      }
      rememberOp(null);
      return {ok:false, error:st.error||"Operation tracking interrupted (the operation may still be running server-side)."};
    }
    errors=0;
    if(onProgress) onProgress(st.log||[], st.done);
    if(st.done){ rememberOp(null); return st.result || {ok:false, error:"Operation finished with no result."}; }
    await sleep(900);
  }
  rememberOp(null);
  return {ok:false, error:"Tracking timed out (the operation may still be running server-side)."};
}
async function runOp(url, body, onProgress){
  const start = await post(url, body);
  if(!start || !start.op_id){ return start || {ok:false, error:"Could not start the operation."}; }
  rememberOp({id:start.op_id, url, cid:ACTIVE_CID, ns:body&&body.namespace});
  return followOp(start.op_id, onProgress);
}
// Demande d'arrêt coopératif: le serveur termine l'étape (volume) en cours puis s'arrête proprement.
async function cancelCurrentOp(){
  if(!CURRENT_OP) return;
  const r=await post("/api/op_cancel",{id:CURRENT_OP.id});
  const el=$("#rsProgressTxt"); if(el) el.textContent = r.ok ? "Stop requested — finishing the current step…": (r.error||"Cannot stop");
}
// Reprise du suivi après rechargement: une opération encore en cours côté serveur est proposée.
async function resumeOps(){
  let saved=null; try{ saved=JSON.parse(sessionStorage.getItem(OP_KEY)||"null"); }catch(e){}
  const l=await get("/api/op_status");
  const running=(l&&l.running)||[];
  if(!running.length){ rememberOp(null); return; }
  const op = (saved && running.find(o=>o.op_id===saved.id)) || running[0];
  const banner=$("#opBanner"); if(!banner) return;
  banner.style.display="block";
  banner.innerHTML=`<div class="warnbox" style="display:flex;gap:12px;align-items:center;flex-wrap:wrap"><span class="spin"></span>
    <b>An operation is running</b> (${esc(op.kind||"operation")}${op.ns?(" · "+esc(op.ns)):""}).
    <button class="btn ghost" id="opFollow">Follow</button></div><div id="opBannerLog"></div>`;
  $("#opFollow").onclick=async()=>{
    $("#opFollow").disabled=true;
    const r=await followOp(op.op_id, log=>{ $("#opBannerLog").innerHTML=renderLog(log); });
    $("#opBannerLog").innerHTML=(r.ok?'<div class="note">Operation finished.</div>':errBox(r.error||"Operation finished with errors."))+renderLog(r.log);
    banner.querySelector(".spin").style.display="none";
  };
}

// Init: contexte + namespaces + config
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
  await loadConfig();
  loadAutoBackup();
  await loadConnStatus();                     // ATTENDRE que `conn` soit prêt (sinon la popup
  maybePromptUnlock();                        // de déverrouillage ne s'affichait jamais)
  onPageShown(curPage);                       // (re)charge les données de la page affichée
  resumeOps();                                // opération encore en cours côté serveur ?
}
// Accessibilité: associe chaque <label class="fld"> sans `for` au champ qui le suit
// (HTML statique et blocs rendus dynamiquement: observateur du DOM, débounce).
let _lblN=0, _lblT=null;
function linkLabels(){
  document.querySelectorAll("label.fld").forEach(l=>{
    if(l.getAttribute("for") || l.querySelector("input,select,textarea")) return;
    const el=l.nextElementSibling && (l.nextElementSibling.matches("input,select,textarea") ? l.nextElementSibling: l.nextElementSibling.querySelector("input,select,textarea"));
    if(!el) return;
    if(!el.id) el.id="fld-"+(++_lblN);
    l.setAttribute("for", el.id);
  });
}
linkLabels();
new MutationObserver(()=>{ clearTimeout(_lblT); _lblT=setTimeout(linkLabels, 150); }).observe(document.body, {childList:true, subtree:true});
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
$("#unlockSkip").onclick=()=>{ $("#unlockPass").value=""; $("#unlock").style.display="none"; };
$("#unlockPass").onkeydown=(e)=>{ if(e.key==="Enter") $("#unlockGo").click(); };
$("#unlockGo").onclick=async()=>{
  $("#unlockErr").innerHTML="";
  const b=$("#unlockGo"); b.disabled=true; b.innerHTML='<span class="spin"></span>…';
  const r=await post("/api/creds/load",{passphrase:$("#unlockPass").value});
  $("#unlockPass").value=""; b.disabled=false; b.textContent="Unlock";
  if(!r.ok){ $("#unlockErr").innerHTML=errBox(r.error);
    setTimeout(()=>$("#unlockPass").focus(),30); return; }
  const names={hycu:"HYCU", nutanix:"Prism Element", prismcentral:"Prism Central", s3:"S3 object storage"};
  const lst=(r.loaded||[]).map(s=>names[s]||s).join(", ");
  const cls=(r.clusters||[]).join(", ");
  $("#unlockErr").innerHTML=`<div class="note">Connections reloaded: ${esc(lst||"none")}.`+
    (cls?`<br>Kubernetes clusters reloaded: ${esc(cls)}.`:"")+`</div>`;
  await loadConnStatus();
  await afterVaultLoad();
  setTimeout(()=>{ $("#unlock").style.display="none"; $("#unlockErr").innerHTML=""; }, 900);
};

// ----- Assistant de configuration (affiché si hycu_config.json est absent) -----
const wcfg = {kubectl_path:"kubectl", allowed_contexts:[], namespace_filter:[],
  require_context_confirm:true, wait_timeout:120, volume_handle_prefix:""};
let wizStep=0, wizSteps=[];

function wizFinalConfig(){
  return {kubectl_path:wcfg.kubectl_path, allowed_contexts:wcfg.allowed_contexts,
    namespace_filter:wcfg.namespace_filter, require_context_confirm:wcfg.require_context_confirm,
    wait_timeout:wcfg.wait_timeout,
    volume_handle_prefix:wcfg.volume_handle_prefix};
}
function buildWizSteps(){
  const ctx = ctxInfo.context || "";
  wizSteps = [
    {render:()=>`<h3>First-time setup</h3>
      <p class="q">No <code>hycu_config.json</code> file was found. A few questions
      to generate it — you can change everything later in the Settings page.</p>
      <div class="note" style="margin-top:14px">Detected kubectl context: <b>${esc(ctx||"unavailable")}</b></div>
      <div class="hint" style="margin-top:14px">Reinstalling an existing instance? <a href="#" id="wRestoreKit">Restore the tool from an S3 bucket</a></div>`,
     enter:()=>{ const rk=$("#wRestoreKit"); if(rk) rk.onclick=(e)=>{ e.preventDefault(); $("#wizard").style.display="none"; openSources("s3"); }; },
     commit:()=>{}},

    {render:()=>`<h3>Which kubectl binary should be used?</h3>
      <p class="q">Pick the distribution, or enter a custom command / path.</p>
      <div id="wKChips">${["kubectl","microk8s kubectl","k3s kubectl"].map(v=>
        `<span class="chip ${wcfg.kubectl_path===v?'sel':''}" data-v="${v}">${v}</span>`).join("")}</div>
      <label class="fld">kubectl command</label>
      <input type="text" id="wK" value="${esc(wcfg.kubectl_path)}">`,
     enter:()=>{document.querySelectorAll("#wKChips .chip").forEach(c=>c.onclick=()=>{
        $("#wK").value=c.dataset.v;
        document.querySelectorAll("#wKChips .chip").forEach(x=>x.classList.remove("sel")); c.classList.add("sel");});},
     commit:()=>{ wcfg.kubectl_path=($("#wK").value.trim()||"kubectl"); }},

    {render:()=>{const r=wcfg.allowed_contexts.length>0;
      return `<h3>Lock down the cluster(s)?</h3>
      <p class="q">Restricting the tool to specific kubectl contexts avoids acting on the wrong cluster by mistake.</p>
      <div class="wiz-opt ${!r?'sel':''}" data-mode="all"><b>All contexts</b><div class="d">No restriction.</div></div>
      <div class="wiz-opt ${r?'sel':''}" data-mode="restrict"><b>Restrict</b><div class="d">Allow only the listed contexts.</div></div>
      <div id="wCtxWrap" style="${r?'':'display:none'}"><label class="fld">Allowed contexts (commas)</label>
        <input type="text" id="wCtx" value="${esc(wcfg.allowed_contexts.join(', ')||ctx)}"></div>`;},
     enter:()=>{document.querySelectorAll('.wiz-opt[data-mode]').forEach(o=>o.onclick=()=>{
        document.querySelectorAll('.wiz-opt[data-mode]').forEach(x=>x.classList.remove('sel')); o.classList.add('sel');
        $("#wCtxWrap").style.display=o.dataset.mode==='restrict'?'block':'none';});},
     commit:()=>{ wcfg.allowed_contexts = document.querySelector('.wiz-opt[data-mode=restrict].sel')? csv($("#wCtx").value):[]; }},

    {render:()=>{const r=wcfg.namespace_filter.length>0;
      return `<h3>Limit to the relevant namespaces?</h3>
      <p class="q">You can expose only the application namespaces protected by HYCU.</p>
      <div class="wiz-opt ${!r?'sel':''}" data-mode="all"><b>All namespaces</b><div class="d">List every namespace in the cluster.</div></div>
      <div class="wiz-opt ${r?'sel':''}" data-mode="restrict"><b>Restrict</b><div class="d">Show only the listed namespaces.</div></div>
      <div id="wNsWrap" style="${r?'':'display:none'}"><label class="fld">Allowed namespaces (commas)</label>
        <input type="text" id="wNs" value="${esc(wcfg.namespace_filter.join(', '))}" placeholder="wordpress, bo-dev"></div>`;},
     enter:()=>{document.querySelectorAll('.wiz-opt[data-mode]').forEach(o=>o.onclick=()=>{
        document.querySelectorAll('.wiz-opt[data-mode]').forEach(x=>x.classList.remove('sel')); o.classList.add('sel');
        $("#wNsWrap").style.display=o.dataset.mode==='restrict'?'block':'none';});},
     commit:()=>{ wcfg.namespace_filter = document.querySelector('.wiz-opt[data-mode=restrict].sel')? csv($("#wNs").value):[]; }},

    {render:()=>`<h3>Safety check before real actions</h3>
      <p class="q">Recommended: require retyping the context name before any real restore.</p>
      <label class="wiz-opt ${wcfg.require_context_confirm?'sel':''}" id="wConfirmOpt">
        <input type="checkbox" id="wConfirm" ${wcfg.require_context_confirm?'checked':''} style="width:auto;margin-right:8px">
        <b>Require context confirmation</b><div class="d">The operator retypes the target context before acting.</div></label>`,
     enter:()=>{ $("#wConfirm").onchange=()=>$("#wConfirmOpt").classList.toggle('sel',$("#wConfirm").checked); },
     commit:()=>{ wcfg.require_context_confirm=$("#wConfirm").checked; }},

    {render:()=>`<h3>Advanced settings (optional)</h3>
      <p class="q">The defaults suit most environments.</p>
      <label class="fld">Wait timeout (s)</label><input type="text" id="wWait" value="${wcfg.wait_timeout}">
      <label class="fld">volumeHandle prefix (empty = auto-detected)</label>
      <input type="text" id="wVh" value="${esc(wcfg.volume_handle_prefix)}" placeholder="auto-detected from the existing PV">`,
     commit:()=>{ wcfg.wait_timeout=parseInt($("#wWait").value)||120;
        wcfg.volume_handle_prefix=$("#wVh").value.trim(); }},

    {final:true, render:()=>`<h3>Create the configuration</h3>
      <p class="q">Review then create <code>hycu_config.json</code> (editable later in ⚙ Settings).</p>
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
  $("#wizStep").textContent=`Step ${wizStep+1} / ${wizSteps.length}`;
  $("#wizBack").style.visibility=wizStep===0?"hidden":"visible";
  $("#wizNext").textContent=s.final?"Create the configuration":"Next";
}
$("#wizBack").onclick=()=>{ if(wizStep>0){ wizSteps[wizStep].commit&&wizSteps[wizStep].commit(); wizStep--; renderWiz(); } };
$("#wizNext").onclick=async()=>{
  const s=wizSteps[wizStep]; if(s.commit) s.commit();
  if(s.final){
    const b=$("#wizNext"); b.disabled=true; b.innerHTML='<span class="spin"></span>Creating…';
    const r=await post("/api/config",{config:wizFinalConfig()});
    b.disabled=false; b.textContent="Create the configuration";
    if(!r.ok){ $("#wizBody").innerHTML+=`<div class="err">Failed: ${esc(r.error||'')}</div>`; return; }
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
  return `<a class="btn ghost" href="${u}" download style="padding:2px 8px;font-size:12px;text-decoration:none;margin-left:6px">⬇ ${esc(label||'Download (.zip)')}</a>`;
}
// ----- Sauvegarde automatique de la configuration (onglet 1) -----
function abSyncLbl(){
  const on=$("#abEnabled").checked, l=$("#abEnabledLbl");
  l.textContent = on? "Enabled": "Disabled";
  l.style.color = on? "var(--good)": "var(--muted)";
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
    ? "GFS "+((s.gfs||{}).daily??7)+" d / "+((s.gfs||{}).weekly??4)+" wk / "+((s.gfs||{}).monthly??12)+" mo"
   : (s.keep===0 ? "unlimited (no counter)": (s.keep||15)+" versions");
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
  let txt = s.enabled? ("Every "+Math.round(s.interval_hours||24)+" h · retention: "+abRetLabel(s)+" per namespace."): "";
  if(s.running) txt+=" Backup in progress…";
  if(s.last_run) txt+=" Last: "+new Date(s.last_run*1000).toLocaleString()+" "+(s.last_ok?"✓":"✕")+" "+(s.last_summary||"");
  if(s.enabled) txt+= s.next_due? (" · Next: "+new Date(s.next_due*1000).toLocaleString()): " · First run in less than a minute.";
  $("#abStatus").textContent=txt;
}
$("#abSave").onclick=async()=>{
  const cfg={auto_backup_enabled:$("#abEnabled").checked,
    auto_backup_interval_hours:Math.max(0.25,parseFloat(String($("#abInterval").value).replace(",","."))||24),
    auto_backup_keep:Math.max(0,parseInt($("#abKeep").value)||0),
    auto_backup_retention:$("#abRet").value,
    auto_backup_keep_daily:Math.max(0,parseInt($("#abGfsD").value)||0),
    auto_backup_keep_weekly:Math.max(0,parseInt($("#abGfsW").value)||0),
    auto_backup_keep_monthly:Math.max(0,parseInt($("#abGfsM").value)||0),
    auto_backup_dest:$("#abDest").value.trim()};
  const r=await post("/api/config",{config:cfg});
  $("#abStatus").textContent = r.ok? "Saved.": ("Error: "+(r.error||""));
  setTimeout(loadAutoBackup, 700);
};
$("#bkRun").onclick=async()=>{
  const ns=$("#bkNs").value, b=$("#bkRun"), dest=$("#bkDest").value.trim();
  b.disabled=true; b.innerHTML='<span class="spin"></span>Backing up…';
  const r=await post("/api/backup",{ns, dest});
  b.disabled=false; b.textContent="Back up this namespace";
  if(!r.ok){$("#bkOut").innerHTML=errBox(r.error);return;}
  const rows=r.volumes.map(v=>{
    const vh=v.analysis&&v.analysis.old_volume_handle;
    const vgUuid=vh?(String(vh).match(/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/)||[null])[0]:null;
    const tag=vgUuid?`<span class="hint">(VG ${esc(vgUuid)})</span>`:(v.analysis&&v.analysis.old_iqn?'<span class="hint">(IQN detected)</span>':'');
    return `<li class="logline"><span class="ic ok">✓</span>
     <span><b>${esc(v.pvc)}</b> → PV ${esc(v.pv||"—")} ${tag}</span></li>`;
  }).join("");
  const resLine = (r.resources_count!=null)
    ? ` <span class="hint">+ ${r.resources_count} config resource(s) (Deployments, Services, Secrets…)${r.secrets==="encrypted"?" · Secrets encrypted":r.secrets==="redacted"?" · Secrets redacted":""}</span>`: "";
  const secWarn = r.secrets_warning ? `<div class="warnbox">⚠ ${esc(r.secrets_warning)}</div>`: "";
  $("#bkOut").innerHTML=`<div class="note">${r.count} volume(s) backed up to
     <code>${esc(r.dir)}</code>${resLine}${dlBackupLink(r.dir, r.root)}</div>${secWarn}<ul class="pvc-list" style="margin-top:10px">${rows}</ul>
     <div class="warnbox">⚠ Get this backup <b>off the cluster</b> via ⬇ Download (.zip) — or copy the folder to other storage: it is your safety net in a disaster.</div>`;
};
$("#bkRunAll").onclick=async()=>{
  const b=$("#bkRunAll"), dest=$("#bkDest").value.trim();
  b.disabled=true; b.innerHTML='<span class="spin"></span>Backing up…';
  const r=await post("/api/backup_all",{dest});
  b.disabled=false; b.textContent="Back up all (filtered)";
  if(!r.ok){$("#bkOut").innerHTML=errBox(r.error);return;}
  const rows=(r.results||[]).map(x=>{
    if(x.ok) return `<li class="logline"><span class="ic ok">✓</span><span><b>${esc(x.ns)}</b> — ${x.count} volume(s) → <code>${esc(x.dir)}</code>${dlBackupLink(x.dir, r.root, 'Download')}</span></li>`;
    if(x.skipped) return `<li class="logline"><span class="ic sim">○</span><span><b>${esc(x.ns)}</b> — no PVC (skipped)</span></li>`;
    return `<li class="logline"><span class="ic ko">✕</span><span><b>${esc(x.ns)}</b> — ${esc(x.error||'failed')}</span></li>`;
  }).join("");
  const scope = r.filtered? "namespaces in the filter": "all cluster namespaces";
  $("#bkOut").innerHTML=`<div class="note">${r.backed_up}/${r.namespaces} namespace(s) backed up · ${r.volumes} volume(s) in total <span class="hint">(${scope})</span>.${dlBackupLink(r.root, r.root, 'Download all (.zip)')}</div>
     <ul class="pvc-list" style="margin-top:10px">${rows}</ul>
     <div class="warnbox">⚠ Get these backups <b>off the cluster</b> via ⬇ Download — or copy the folders to other storage: it is your safety net in a disaster.</div>`;
};

// --------- Protection HYCU (assigner politique + sauvegarder) ---------
let bkMatches=[], bkMatchNs=null, bkNsList=[];   // bkNsList: namespaces ciblés (plusieurs applications en une fois)
function clearBkProtect(){ bkMatches=[]; bkMatchNs=null; $("#bkMatchOut").innerHTML=""; $("#bkProtectForm").style.display="none"; $("#bkProtectLog").innerHTML=""; }

// Re-protection HYCU après un clone: bascule sur l'onglet Back up, cible le bon
// namespace et lance l'analyse de correspondance (puis l'utilisateur choisit la politique).
function goReprotect(ns){
  openPolicyModal(ns || $("#bkNs").value);      // HYCU: “Set Policy” (analyse lancée d'office)
}
$("#bkNs").onchange=()=>{ state.ns=$("#bkNs").value; savePref("ns",state.ns); applyGlobalNs(); clearBkProtect(); };  // ns global + invalide l'analyse
$("#vfNs").onchange=()=>{ state.ns=$("#vfNs").value; savePref("ns",state.ns); applyGlobalNs(); };
$("#bkDest").addEventListener("change",()=>savePref("bkDest",$("#bkDest").value.trim()));
$("#bkMatch").onclick=async()=>{
  // Une application (namespace courant) ou PLUSIEURS (sélection de la page Applications) :
  // une analyse par namespace, un seul formulaire, un seul envoi à HYCU.
  const list = bkNsList.length ? bkNsList.slice(): [$("#bkNs").value];
  clearBkProtect();
  $("#bkMatchOut").innerHTML='<div class="hint">Analyzing…</div>';
  const results=[];
  for(const ns of list){
    const r=await get("/api/hycu/match?ns="+encodeURIComponent(ns));
    if(!r.ok){ $("#bkMatchOut").innerHTML=errBox((list.length>1?("Namespace “"+ns+"”: "):"")+r.error); return; }
    (r.matches||[]).forEach(m=>{ m.ns=r.namespace||ns; });
    results.push({ns:r.namespace||ns, matches:r.matches||[]});
  }
  bkMatches=results.flatMap(x=>x.matches); bkMatchNs=list.length===1 ? results[0].ns: null;
  const rowOf=m=>{
    let chk="", label="";
    if(m.volume_kind==="nfs"){
      // Volume NAS: partage HYCU (Nutanix Files ou NAS générique) au lieu d'un Volume Group.
      const shareLbl=`→ NAS share <b>${esc(m.hycu_share_name||"")}</b> <span class="hint">(${esc(m.hycu_file_server||m.nfs||"")})</span>`;
      if(m.match_kind==="exact"){
        chk=`<input type="checkbox" class="bkMchk" data-type="share" data-ns="${esc(m.ns)}" data-uuid="${esc(m.hycu_share_uuid)}" data-name="${esc(m.hycu_share_name||'')}" checked style="width:auto;margin-right:8px">`;
        label=shareLbl;
      } else if(m.match_kind==="name"){
        chk=`<input type="checkbox" class="bkMchk" data-type="share" data-kind="name" data-ns="${esc(m.ns)}" data-uuid="${esc(m.hycu_share_uuid)}" data-name="${esc(m.hycu_share_name||'')}" style="width:auto;margin-right:8px">`;
        label=shareLbl+' <span class="sim">same path, server to confirm</span>';
      } else if(m.match_kind==="ambiguous"){
        chk=`<span class="ic ko" style="width:18px;display:inline-block;text-align:center;margin-right:8px">⚠</span>`;
        label=`<span class="ko">ambiguous: several HYCU shares match ${esc(m.nfs||"")} — check in HYCU</span>`;
      } else {
        chk=`<span class="ic ko" style="width:18px;display:inline-block;text-align:center;margin-right:8px">✕</span>`;
        label=`<span class="ko">${m.error ? esc("HYCU shares unreadable: "+m.error): "no HYCU share for "+esc(m.nfs||"")+" — add this NAS in HYCU"}</span>`;
      }
    }
    else if(m.match_kind==="exact"){
      chk=`<input type="checkbox" class="bkMchk" data-ns="${esc(m.ns)}" data-uuid="${esc(m.hycu_vg_uuid)}" data-name="${esc(m.hycu_vg_name||'')}" data-ext="${esc(m.hycu_external_id||'')}" checked style="width:auto;margin-right:8px">`;
      label=`→ VG <b>${esc(m.hycu_vg_name||m.hycu_vg_uuid)}</b> <span class="hint">(externalId ${esc(m.hycu_external_id||'')})</span>`;
    } else if(m.match_kind==="name"){
      // data-kind: cocher cette ligne vaut CONFIRMATION du match par nom (transmise au serveur)
      chk=`<input type="checkbox" class="bkMchk" data-kind="name" data-ns="${esc(m.ns)}" data-uuid="${esc(m.hycu_vg_uuid)}" data-name="${esc(m.hycu_vg_name||'')}" data-ext="${esc(m.hycu_external_id||'')}" style="width:auto;margin-right:8px">`;
      label=`→ VG <b>${esc(m.hycu_vg_name||m.hycu_vg_uuid)}</b> <span class="sim">by name — to be confirmed</span>`;
    } else if(m.match_kind==="ambiguous"){
      chk=`<span class="ic ko" style="width:18px;display:inline-block;text-align:center;margin-right:8px">⚠</span>`;
      label=`<span class="ko">ambiguous: several Volume Groups match — check in HYCU</span>`;
    } else {
      chk=`<span class="ic ko" style="width:18px;display:inline-block;text-align:center;margin-right:8px">✕</span>`;
      label=`<span class="ko">no HYCU Volume Group found</span>`;
    }
    let prot="";
    if(m.matched){
      const cs=(m.compliancy||"").toUpperCase();
      const cb = cs==="GREEN"? '<span class="badge b-bound">compliant</span>'
              : cs==="RED"? '<span class="badge b-lost">non-compliant</span>'
              : '<span class="badge b-pending">to back up</span>';
      const unp = (m.protected && m.protected!=="PROTECTED")? ' <span class="badge b-pending">not protected</span>':'';
      prot=`<div class="meta">${cb}${unp} · policy: <b>${esc(m.policy||'none')}</b> · backups: ${m.has_backups?'yes':'no'}</div>`;
    }
    return `<li class="logline">${chk}<span style="flex:1"><b>${esc(m.pvc)}</b> ${label}${prot}</span></li>`;
  };
  const rows = list.length===1
    ? (bkMatches.map(rowOf).join("") || '<div class="hint">No PVC in this namespace.</div>')
   : results.map(x=>`<li class="logline" style="background:#F6F7FB;font-weight:700">${esc(x.ns)} <span class="hint" style="font-weight:400;margin-left:8px">${x.matches.length} PVC</span></li>`
        + (x.matches.map(rowOf).join("") || '<li class="logline"><span class="hint">No PVC in this namespace.</span></li>')).join("");
  const nx=bkMatches.filter(m=>m.match_kind==="exact").length, nn=bkMatches.filter(m=>m.match_kind==="name").length,
        na=bkMatches.filter(m=>m.match_kind==="ambiguous").length, n0=bkMatches.filter(m=>m.match_kind==="none").length;
  $("#bkMatchOut").innerHTML=`<ul class="pvc-list" style="margin-top:10px">${rows}</ul>
     <div class="hint">${nx} exact(s) · ${nn} by name (to confirm) · ${na} ambiguous · ${n0} not found</div>`;
  if(nx+nn>0){ $("#bkProtectForm").style.display="block"; loadBkPolicies(); updateBkHint(); }
};
// Liste des politiques HYCU de la modale “Set Policy”. NB: nom distinct de
// loadPolicies() (page Politiques) — deux déclarations homonymes se masqueraient.
async function loadBkPolicies(){
  const r=await get("/api/hycu/policies");
  $("#bkPolicy").innerHTML=`<option value="">(do not change the policy)</option>`+
    (r.ok? (r.policies||[]).map(p=>`<option value="${esc(p.uuid)}">${esc(p.name||p.uuid)}</option>`).join(""): "");
}
function updateBkHint(){ $("#bkProtectHint").textContent = dry()? "Simulation mode (banner at top): shows the HYCU calls.": ""; }
$("#dry").addEventListener("change",()=>{ if($("#bkProtectForm").style.display!=="none") updateBkHint(); });
$("#bkProtect").onclick=async()=>{
  const sel=[...document.querySelectorAll(".bkMchk:checked")];
  const vg_uuids=sel.map(c=>c.dataset.uuid);
  if(!vg_uuids.length){ $("#bkProtectLog").innerHTML='<div class="err">Tick at least one volume (“by name” matches must be confirmed).</div>'; return; }
  const live=!dry(), pol=$("#bkPolicy").value;
  const names=sel.map(c=>"• "+(c.dataset.name||c.dataset.uuid)+(c.dataset.ext?(" ("+c.dataset.ext+")"):""));
  if(live && !(await confirmDanger({title:"Confirm the HYCU protection", lines:[
     (pol?"Assign the policy then <b>back up</b>":"<b>Back up</b>")+" these Volume Groups:",
     "<b>"+names.map(esc).join("</b>, <b>")+"</b>"]}))) return;
  const b=$("#bkProtect"); b.disabled=true; b.innerHTML='<span class="spin"></span>…';
  const byName=sel.filter(c=>c.dataset.kind==="name").map(c=>c.dataset.uuid);   // cochés = confirmés par l'opérateur
  // Regroupement par namespace: la garde anti-stale du serveur est faite namespace par
  // namespace, puis UN SEUL appel HYCU (assignation) + UN SEUL lancement de sauvegarde.
  const byNs={};
  sel.forEach(c=>{ const k=c.dataset.ns||bkMatchNs||"";
    const it=(byNs[k]=byNs[k]||{namespace:k, vg_uuids:[], share_uuids:[], confirm_name_uuids:[]});
    (c.dataset.type==="share" ? it.share_uuids: it.vg_uuids).push(c.dataset.uuid);
    if(c.dataset.kind==="name") it.confirm_name_uuids.push(c.dataset.uuid); });
  const r=await post("/api/hycu/protect",{items:Object.values(byNs), namespace:bkMatchNs,
    vg_uuids:sel.filter(c=>c.dataset.type!=="share").map(c=>c.dataset.uuid),
    share_uuids:sel.filter(c=>c.dataset.type==="share").map(c=>c.dataset.uuid),
    policy_uuid:pol, dry:dry(), confirm_name_uuids:byName});
  b.disabled=false; b.textContent="Assign + back up now";
  if(!r.ok && !(r.steps&&r.steps.length)){ $("#bkProtectLog").innerHTML=errBox(r.error); return; }
  const lines=(r.steps||[]).map(s=> s.dry
    ? `<div class="logline"><span class="ic sim">○</span><span><b>${esc(s.label)}</b><pre class="box" style="margin-top:4px">${esc(JSON.stringify(s.planned,null,2))}</pre></span></div>`
   : `<div class="logline"><span class="ic ${s.ok?'ok':'ko'}">${s.ok?'✓':'✕'}</span><span><b>${esc(s.label)}</b>${s.job_id?(' · job '+esc(s.job_id)):''}${(s.error&&!s.ok)?(' — <span class="ko">'+esc(s.error)+'</span>'):''}</span></div>`
  ).join("");
  const head = r.dry? '<div class="warnbox">Simulation — calls that would be sent to HYCU:</div>'
    : (r.ok? '<div class="note">Request sent to HYCU: policy assigned, backup started. You can carry on — the job progress is shown below and in HYCU.</div>': '<div class="err">Failed — see details.</div>');
  $("#bkProtectLog").innerHTML=head+lines;
  if(!r.dry && r.ok && r.job_id){ $("#bkProtectLog").innerHTML+='<div id="bkJobProgress"></div>'; pollJobBar(r.job_id,"#bkJobProgress"); }
};

// --------- Restauration ---------
$("#rsNs").onchange=()=>{ state.ns=$("#rsNs").value; savePref("ns",state.ns); applyGlobalNs(); loadPvcs(); };
$("#rsCustomDir").onchange=()=>{ savePref("customDir",$("#rsCustomDir").checked); $("#rsCustomDirWrap").style.display=$("#rsCustomDir").checked?"block":"none"; if($("#rsNs").value) loadPvcs(); };
$("#rsBackupRoot").addEventListener("change",()=>{ savePref("backupRoot",$("#rsBackupRoot").value.trim()); if($("#rsCustomDir").checked && $("#rsNs").value) loadPvcs(); });
$("#rsBackupSel").onchange=applyBackupSelection;   // changer de sauvegarde de config sans re-fetch
let rsBackups = [];   // sauvegardes de config du namespace courant (la plus récente en premier)
let loadPvcsSeq=0;     // jeton anti-course: un fetch dépassé (autre namespace/cluster) est ignoré
async function loadPvcs(){
  const sel=$("#rsNs"); if(!sel.value) return;
  const ns=sel.value; state.ns=ns; state.pvcNs=ns; rsHyMatch=null; rsInplaceSel={}; invalidatePlan();
  if(state.app && state.app.ns!==ns){ state.app=null; $("#rsWizApp").innerHTML=rsAppLabel(); }   // autre namespace choisi: plus d'application ciblée
  const seq=++loadPvcsSeq;
  const customRoot = $("#rsCustomDir").checked ? $("#rsBackupRoot").value.trim(): "";
  state.backup_root = customRoot || null;
  const bk=await get("/api/backups?ns="+encodeURIComponent(ns)+(customRoot?("&root="+encodeURIComponent(customRoot)):""));
  if(seq!==loadPvcsSeq || state.ns!==ns) return;   // périmé: une autre application a été ouverte entre-temps
  if(bk.error && !bk.backups){ $("#rsPvcs").innerHTML=errBox(bk.error); return; }
  rsBackups = bk.backups || [];
  const wrap=$("#rsBackupSelWrap"), selEl=$("#rsBackupSel");
  if(rsBackups.length){
    selEl.innerHTML = rsBackups.map((b,i)=>{
      const idx=b.index||{}; const n=(idx.volumes||[]).length;
      const created=((idx.created||b.timestamp||"")+"").replace("T"," ").slice(0,19);
      const ctx=idx.context?(" · ctx "+idx.context):"";
      return `<option value="${i}">${esc(created)} — ${n} volume(s)${esc(ctx)}${i===0?" (most recent)":""}</option>`;
    }).join("");
    selEl.value="0"; wrap.style.display="block";
  }else{ selEl.innerHTML=""; wrap.style.display="none"; }
  await applyBackupSelection();
}
async function applyBackupSelection(){
  const ns=state.ns; state.selected={};
  const customRoot=state.backup_root, i=$("#rsBackupSel").value;
  let pvcs=[], src=customRoot?"custom folder":"cluster";
  if(rsBackups.length && i!=="" && rsBackups[i*1]){
    const b=rsBackups[i*1];
    state.backup_path=b.path;
    pvcs=((b.index||{}).volumes||[]).map(v=>({name:v.pvc,pv:v.pv,phase:"backed up",nfs:v.nfs?(v.nfs.server+":"+v.nfs.path):""}));
    src=customRoot?"backup (custom folder)":(i==="0"?"latest backup":"selected backup");
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
     <li><input type="checkbox" style="width:auto" class="rsChk" data-pvc="${esc(p.name)}" data-pv="${esc(p.pv||'')}"${p.nfs?' data-nfs="1"':''}>
       <div style="flex:1"><div class="nm">${esc(p.name)}${p.nfs?' <span class="badge b-na">NAS</span>':''}</div>
       <div class="meta">${p.nfs ? esc("NFS "+p.nfs)+" · data restored in HYCU (NAS share)": "PV "+esc(p.pv||'—')} · source: ${src}</div></div>${badge(p.phase)}</li>`).join("")
    : `<div class="hint">No volume. First back up this application's configuration (Applications → Back up).</div>`;
  document.querySelectorAll(".rsChk").forEach(c=>c.onchange=rebuildVolCfgs);
  $("#rsConfig").style.display="none"; $("#rsPlan").style.display="none"; setRsStep(1);
  // Assistant de restauration: comme dans HYCU, TOUS les volumes de l'application
  // sont présélectionnés (l'opérateur peut en décocher). Application ciblée (page
  // Applications): seuls SES volumes le sont — les autres applications du namespace
  // ne sont pas touchées par défaut.
  if(rsAutoCheck && pvcs.length){
    const only = state.app && state.app.pvcs && state.app.pvcs.length ? new Set(state.app.pvcs): null;
    document.querySelectorAll(".rsChk").forEach(c=>c.checked = (!c.dataset.nfs || isCloneApp()) && (!only || only.has(c.dataset.pvc)));
    if(only && ![...document.querySelectorAll(".rsChk")].some(c=>c.checked)) document.querySelectorAll(".rsChk").forEach(c=>c.checked=true);
    rebuildVolCfgs();
  }
  updateNextBar();
}
// Horodatage epoch en secondes (≈ `date -u +%s`): sert de suffixe UNIQUE à chaque clone,
// pour ne JAMAIS réutiliser un nom déjà créé (sinon: “le PVC/VG …-0000 existe déjà” au
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
  // Une carte ÉPURÉE par volume: à l'écran, seulement “volume → VG HYCU” et le
  // point de restauration (rempli en asynchrone par buildHyPanel). Tout le reste —
  // noms générés (VG cloné, nouveau PV) et saisie manuelle de la référence — vit
  // dans UN SEUL volet “Avancé” replié: ce sont des valeurs par défaut correctes.
  $("#rsVolCfgs").innerHTML = chks.map(c=>{
    const pvc=c.dataset.pvc, pv=c.dataset.pv;
    const vgNameRow = (hyOn && state.mode==="clone")
      ? `<label class="fld">Cloned VG name</label>
         <input type="text" class="hyVgName" data-pvc="${esc(pvc)}" value="${esc(pvc+'-'+cloneStamp())}">`: "";
    const nameRow = state.mode==="clone"
      ? `<label class="fld">New PV name</label>
         <input type="text" class="rsName" data-pvc="${esc(pvc)}" value="${esc(suggestName(pv))}">`: "";
    const ntRow = ntOn
      ? `<button class="btn ghost ntRefBtn" data-pvc="${esc(pvc)}" style="margin-top:6px">Search for the VG in Prism</button>
         <div class="ntpick" data-pvc="${esc(pvc)}"></div>`: "";
    const advOpen = hyOn ? "": "open";   // sans HYCU, la saisie manuelle est la seule voie -> volet ouvert
    const advSum = hyOn ? "Advanced (optional) — generated names, manual entry"
                       : "VG reference (required) & generated names";
    return `<div class="vol-cfg" data-pvc="${esc(pvc)}">
      <div class="nm">${esc(pvc)} <span class="hint">(PV ${esc(pv||'—')})</span> <span class="hint vgLabel" data-pvc="${esc(pvc)}" style="margin:0"></span> <span class="refStat hint" data-pvc="${esc(pvc)}" style="margin:0"></span></div>
      <div class="hySlot" data-pvc="${esc(pvc)}"></div>
      <details class="rsAdv" ${advOpen}>
        <summary class="rsAdvSum">${advSum}</summary>
        ${vgNameRow}${nameRow}
        <textarea class="rsRef" data-pvc="${esc(pvc)}" placeholder="5b4d284b-7109-4e82-4c71-7d0e36ecb5ab  (VG UUID, or NutanixVolumes-&lt;uuid&gt;, or legacy IQN)"></textarea>${ntRow}
      </details></div>`;
  }).join("");
  document.querySelectorAll(".ntRefBtn").forEach(b=>b.onclick=()=>ntFindRef(b.dataset.pvc));
  // Bouton global d'orchestration sur place (mode inplace + HYCU)
  $("#rsInplaceRunWrap").style.display = inplaceOrch? "block":"none";
  if(inplaceOrch) updateInplaceRunBtn();
  // “Continuer” (construit le plan): voie principale, sauf en sur-place orchestré
  // où le lancement se fait par le bouton dédié ci-dessus.
  $("#rsContinueWrap").style.display = inplaceOrch? "none":"block";

  // Guide en UNE ligne, adapté au cas (type d'opération + HYCU connecté ou non).
  let guide;
  if(state.mode==="inplace"){
    guide = hyOn
      ? "Choose a <b>restore point</b> per volume (the most recent is pre-selected), then <b>Launch the in-place restore</b>."
     : "Restore the VG in HYCU, paste its UUID per volume (<b>Advanced</b> section), then <b>Continue: review and launch</b>. <span class='hint'>Connect HYCU to automate.</span>";
  } else {
    guide = hyOn
      ? "Choose a <b>restore point</b> per volume (the most recent is pre-selected), then click <b>Restore the VGs from HYCU</b> — references and plan follow automatically."
     : "Clone each VG in HYCU, paste its UUID per volume (<b>Advanced</b> section), then <b>Continue: review and launch</b>. <span class='hint'>Connect HYCU to automate.</span>";
  }
  $("#rsFlowGuide").innerHTML = guide;
  // Barre “action suivante” + état des références en direct.
  document.querySelectorAll(".rsRef").forEach(t=>t.addEventListener("input",()=>{ invalidatePlan(); refreshRefStats(); syncContinueVisibility(); updateNextBar(); }));
  document.querySelectorAll(".rsName").forEach(t=>t.addEventListener("input",invalidatePlan));
  refreshRefStats();
  rsFullOrch=false;     // recalculé par buildHyPanel selon la couverture HYCU
  buildHyPanel();       // remplit les points de restauration (asynchrone) — rien si HYCU non connecté
  updateNextBar();
}
// “Continue: review and launch” n'est utile que pour le flux manuel: quand
// TOUS les volumes passent par le bouton HYCU groupé (plan automatique), on le
// masque pour ne laisser qu'UNE action à l'écran. Il réapparaît si l'utilisateur
// remplit les références à la main (volet Avancé).
let rsFullOrch=false;
function syncContinueVisibility(){
  const hyOn = conn.hycu && conn.hycu.connected;
  if(state.mode==="inplace" && hyOn){ $("#rsContinueWrap").style.display="none"; return; }
  const items=collectItems();
  const allFilled=items.length && items.every(refOk);
  $("#rsContinueWrap").style.display = (rsFullOrch && !allFilled)? "none":"block";
}
// État “référence remplie / à remplir” affiché à côté de chaque volume.
// En sur-place orchestré la référence n'est pas requise -> pas d'état.
function refreshRefStats(){
  const inplaceOrch = state.mode==="inplace" && conn.hycu && conn.hycu.connected;
  document.querySelectorAll(".refStat").forEach(el=>{
    const ta=document.querySelector(`.rsRef[data-pvc="${CSS.escape(el.dataset.pvc)}"]`);
    const nasCopy = isCloneApp() && !!(document.querySelector(`.rsChk[data-pvc="${CSS.escape(el.dataset.pvc)}"]`)||{dataset:{}}).dataset.nfs;
    el.innerHTML = (inplaceOrch || nasCopy)? "" :
      ((ta && ta.value.trim())? '<span class="ok">✓ reference filled</span>': '<span class="sim">— reference to fill</span>');
  });
}
let rsHyMatch=null;   // cache de la correspondance PVC↔VG HYCU pour le namespace courant
let hyPanelSeq=0;     // jeton anti-rendu périmé (la sélection peut changer pendant les fetch)
// --------- Panneau HYCU groupé: TOUS les volumes cochés en un seul geste ---------
// Remplit le point de restauration DANS la carte de chaque volume (.hySlot), puis
// rend l'action globale (#rsHyActions). Clone: UN SEUL bouton “Restaurer les VG
// depuis HYCU” qui clone tout et remplit les références. Sur place: le point le
// plus récent est pré-sélectionné -> le lancement est prêt d'emblée.
async function buildHyPanel(){
  const actions=$("#rsHyActions");
  const hyOn = conn.hycu && conn.hycu.connected;
  const chks=[...document.querySelectorAll(".rsChk:checked")].map(c=>c.dataset.pvc);
  actions.innerHTML="";
  if(!hyOn || !chks.length) return;
  const seq=++hyPanelSeq;
  document.querySelectorAll("#rsVolCfgs .hySlot").forEach(s=>
    s.innerHTML='<div class="hint" style="margin-top:4px"><span class="spin"></span> Searching for the HYCU Volume Group…</div>');
  const ns=$("#rsNs").value;
  if(!rsHyMatch || rsHyMatch.ns!==ns){
    const r=await get("/api/hycu/match?ns="+encodeURIComponent(ns));
    if(seq!==hyPanelSeq) return;
    if(!r.ok){ document.querySelectorAll("#rsVolCfgs .hySlot").forEach(s=>s.innerHTML=errBox(r.error)); return; }
    rsHyMatch={ns, matches:r.matches||[]};
  }
  const rows=await Promise.all(chks.map(async pvc=>{
    const m=(rsHyMatch.matches||[]).find(x=>x.pvc===pvc);
    if(m && m.volume_kind==="nfs") return {pvc, matched:false, nfs:m.nfs||"NFS"};
    if(!m || !m.matched) return {pvc, matched:false};
    const rp=await get("/api/hycu/restorepoints?source="+encodeURIComponent(m.hycu_vg_uuid));
    return {pvc, matched:true, vg:m.hycu_vg_uuid, vgName:m.hycu_vg_name||"", kind:m.match_kind,
            points:(rp.ok?(rp.points||[]):[]), rpErr:(rp.ok?null:(rp.error||"restore points unavailable"))};
  }));
  if(seq!==hyPanelSeq) return;
  const isClone = state.mode==="clone";
  rows.forEach(r=>{
    const slot=document.querySelector(`#rsVolCfgs .hySlot[data-pvc="${CSS.escape(r.pvc)}"]`);
    if(!slot) return;
    const card=slot.closest(".vol-cfg");
    if(r.nfs){
      slot.innerHTML = isCloneApp()
        ? '<div class="hint" style="margin-top:6px">'+esc("NAS volume ("+r.nfs+"): HYCU restores the latest share backup into a folder named after the target namespace, and the new PV points to that folder.")+'</div>'
       : '<div class="warnbox" style="margin-top:6px">'+esc("NAS volume ("+r.nfs+"): its data is restored in HYCU (NAS share). Untick it for this flow.")+'</div>';
      return;
    }
    if(!r.matched){
      slot.innerHTML='<div class="warnbox" style="margin-top:6px">No HYCU Volume Group matched — paste the reference under “Advanced”.</div>';
      const d=card&&card.querySelector("details.rsAdv"); if(d) d.open=true;
      return;
    }
    const lbl=card&&card.querySelector(".vgLabel");
    if(lbl) lbl.innerHTML='→ HYCU VG <b>'+esc(r.vgName||r.vg)+'</b>'+(r.kind!=='exact'?' <span class="sim">(match '+esc(r.kind)+' — to verify)</span>':'');
    if(r.rpErr){ slot.innerHTML=`<div class="warnbox" style="margin-top:6px">${esc(r.rpErr)}</div>`; return; }
    if(!(r.points||[]).length){ slot.innerHTML='<div class="warnbox" style="margin-top:6px">No restore point for this VG.</div>'; return; }
    const opts=r.points.map((p,i)=>`<option value="${esc(p.id)}"${i===0?' selected':''}>${esc(p.time||p.id)}${p.status?(' · '+esc(p.status)):''}${i===0?' (most recent)':''}</option>`).join("");
    slot.innerHTML=`<label class="fld">Restore point</label>
      <select class="hyRp" data-pvc="${esc(r.pvc)}" data-vg="${esc(r.vg)}" data-name="${esc(r.vgName)}">${opts}</select>
      <div class="hyStat" data-pvc="${esc(r.pvc)}"></div>`;
    // Cloned VG name (volet Avancé): basé sur le VG source dès qu'on le connaît,
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
           <button class="btn" id="hyBatchGo">Restore the VGs from HYCU (${ready.length} volume(s))</button>
           <span class="hint" style="margin:0">Clones the VGs at the chosen point and fills the references — no data overwritten.</span>
         </div>`;
      $("#hyBatchGo").onclick=hyBatchRun;
    }
    const nas = isCloneApp() ? rows.filter(r=>r.nfs).length: 0;
    rsFullOrch = ready.length+nas===chks.length && ready.length>0;
    syncContinueVisibility();
  } else {
    // Sur place: pré-sélectionner le point le plus récent de chaque volume.
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
// VG UUID cloné, retrouvé côté Nutanix par nom EXACT (ne jamais deviner :
// un mauvais VG = un mauvais volume attaché).
async function lookupVgUuid(vgName){
  if(!((conn.nutanix&&conn.nutanix.connected)||(conn.prismcentral&&conn.prismcentral.connected)))
    return {ok:false, err:"Connect Nutanix (Prism) to fetch the reference automatically, or use the Advanced section."};
  const r=await get("/api/nutanix/vgs?q="+encodeURIComponent(vgName||""));
  if(!r.ok || !(r.vgs||[]).length) return {ok:false, err:"VG “"+vgName+"” not found on the Nutanix side — use the Advanced section."};
  const exact=r.vgs.filter(v=>(v.name||"")===vgName);
  if(exact.length!==1) return {ok:false, err:(exact.length===0?"No":"Multiple")+" VG named exactly “"+vgName+"” — use the Advanced section to pick the right one."};
  if(!exact[0].uuid) return {ok:false, err:"VG found but UUID not exposed — use the Advanced section."};
  return {ok:true, uuid:exact[0].uuid, name:exact[0].name};
}
// Clone TOUS les volumes prêts dans HYCU (séquentiel: suivi lisible ligne par ligne),
// remplit les références, puis construit le plan automatiquement.
async function hyBatchRun(opts){
  opts = (opts && !(opts instanceof Event)) ? opts: {};
  const rows=[...document.querySelectorAll("#rsVolCfgs .vol-cfg")].map(div=>{
    const sel=div.querySelector(".hyRp"); if(!sel || !sel.value) return null;
    const nameEl=div.querySelector(".hyVgName");
    const newName=(nameEl&&nameEl.value.trim()) || ((sel.dataset.name||div.dataset.pvc)+"-"+cloneStamp());
    return {pvc:div.dataset.pvc, vg:sel.dataset.vg, rp:sel.value,
            newName, stat:div.querySelector(".hyStat")};
  }).filter(Boolean);
  if(!rows.length) return false;
  const live=!dry();
  if(live && !opts.skipConfirm && !(await confirmDanger({title:"Confirm the HYCU clones", lines:[
     "Trigger in HYCU the <b>clone</b> of <b>"+rows.length+"</b> Volume Group(s) at the chosen point?",
     "The source VGs are <b>not</b> modified — <b>new</b> VGs are created."]}))) return false;
  const b=$("#hyBatchGo"); b.disabled=true; b.innerHTML='<span class="spin"></span>HYCU clones in progress…';
  hideNextBar();
  // Clones HYCU en PARALLÈLE (au plus 4 à la fois): chaque volume garde sa ligne de
  // suivi; HYCU exécute ses jobs indépendamment et l'endpoint serveur est sans verrou.
  async function cloneRow(row){
    row.stat.innerHTML='<div class="hint" style="margin-top:6px"><span class="spin"></span> HYCU clone…</div>';
    const body={namespace:rsHyMatch.ns, source_uuid:row.vg, restore_point_id:row.rp,
                mode:"clone", new_name:row.newName, dry:dry()};
    const r=await post("/api/hycu/restore",body);
    if(!r.ok){ row.stat.innerHTML=errBox(r.error); return false; }
    if(r.dry){
      row.stat.innerHTML=`<div class="warnbox" style="margin-top:6px">Simulation — HYCU call that would be sent:</div><pre class="box">${esc(JSON.stringify(r.planned,null,2))}</pre>`;
      // En simulation aucun VG n'est créé: on inscrit une référence PROVISOIRE (le VG
      // source) pour pouvoir dérouler l'aperçu du plan; en réel elle sera remplacée
      // par l'VG UUID cloné découvert.
      const m=((rsHyMatch&&rsHyMatch.matches)||[]).find(x=>x.pvc===row.pvc);
      if(m && m.nutanix_uuid){ setRef(row.pvc, m.nutanix_uuid);
        row.stat.innerHTML+='<div class="hint">Provisional reference (source VG) filled in for the simulation — replaced by the cloned VG in real mode.</div>'; }
      return true; }
    if(!r.job_id){ row.stat.innerHTML='<div class="warnbox" style="margin-top:6px">HYCU job not identified — fetch the reference via the Advanced section once the clone completes.</div>'; return false; }
    const ok=await pollJobBar(r.job_id, row.stat);
    if(!ok){ return false; }
    const lu=await lookupVgUuid(row.newName);
    if(!lu.ok){ row.stat.innerHTML+=`<div class="warnbox">${esc(lu.err)}</div>`; return false; }
    setRef(row.pvc, lu.uuid);
    row.stat.innerHTML=`<div class="note" style="margin-top:6px">✓ VG cloned — reference <code>${esc(lu.uuid)}</code> filled.</div>`;
    return true;
  }
  let failed=0, next=0;
  const worker=async()=>{ while(next<rows.length){ const row=rows[next++]; try{ if(!(await cloneRow(row))) failed++; }catch(e){ row.stat.innerHTML=errBox(String(e&&e.message||e)); failed++; } } };
  await Promise.all(Array.from({length:Math.min(4, rows.length)}, worker));
  b.disabled=false; b.textContent="Restore the VGs from HYCU ("+rows.length+" volume(s))";
  if(dry()) return false;                    // simulation: rien à préparer
  const items=collectItems();
  const allFilled=!!(items.length && items.every(refOk));
  const ok=!failed && allFilled;
  if(opts.noChain) return ok;
  if(ok){
    // Enchaîner directement: construire le plan et amener l'opérateur au lancement.
    $("#rsPreview").click();
  } else {
    updateNextBar();
  }
  return ok;
}
// --------- Orchestration RESTAURATION SUR PLACE (arrêt -> restore in-place -> redémarrage) ---------
let rsInplaceSel={};   // {pvc: {source_vg_uuid, restore_point_id, vg_name}}
function updateInplaceRunBtn(){
  const chosen=[...document.querySelectorAll(".rsChk:checked")].map(c=>c.dataset.pvc);
  const ready=chosen.filter(p=>rsInplaceSel[p]);
  if(!$("#rsInplaceRun")) return;
  $("#rsInplaceRun").disabled = ready.length===0;
  $("#rsInplaceHint").textContent = ready.length
    ? (ready.length+" / "+chosen.length+" volume(s) ready"+(dry()?" · simulation":""))
   : "Select a restore point for each volume.";
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
    const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||""): null;
    const res = await confirmDanger({title:"Confirm the in-place restore", requireText:needCtx, lines:[
       "Namespace: <b>"+esc((rsHyMatch?rsHyMatch.ns:$("#rsNs").value)||"?")+"</b>",
       "Target cluster: <b>"+esc(ctxInfo.context||"?")+"</b>",
       "The application will be <b>STOPPED</b>, the volumes restored <b>in-place</b> in HYCU (data overwritten by the chosen point), then the application <b>RESTARTED</b>."]});
    if(!res) return;
    if(typeof res==="string") confirmedCtx=res;
  }
  hideNextBar();   // pas de “prochaine action” pendant l'exécution
  const b=$("#rsInplaceRun"); b.disabled=true; b.innerHTML='<span class="spin"></span>Orchestrating…';
  $("#rsInplaceLog").innerHTML='<div class="hint"><span class="spin"></span> Starting…</div>';
  const ipBody={namespace:(rsHyMatch?rsHyMatch.ns:$("#rsNs").value), items, dry:dry()};
  if(live && ctxInfo.require_confirm) ipBody.confirm_context=confirmedCtx;
  const sess=rsSession, mine=()=>sess===rsSession;
  const r=await runOp("/api/orchestrate/inplace", ipBody,
    log=>{ if(mine()) $("#rsInplaceLog").innerHTML='<div class="hint"><span class="spin"></span> Orchestration in progress…</div>'+renderLog(log); });
  if(!mine()) return;
  b.disabled=false; b.textContent="Launch the in-place restore";
  if(r.error && !(r.log&&r.log.length)){ $("#rsInplaceLog").innerHTML=errBox(r.error); return; }
  const lines=renderLog(r.log);
  const head=r.dry?'<div class="warnbox">Simulation — sequence and HYCU calls that would be executed.</div>'
    :(r.aborted?'<div class="err"><b>Sequence aborted</b> — the application was left stopped. See details.</div>'
      :(r.ok?'<div class="note">In-place restore complete.</div>':'<div class="err">Some steps failed — see details.</div>'));
  $("#rsInplaceLog").innerHTML=head+lines;
  if(!r.dry && r.ok && !r.aborted) rsFinish(ipBody.namespace, false, sess);
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
          app: (state.app && !state.app.unassigned) ? state.app.name: undefined,   // application ciblée: tous ses workloads
          target_namespace: same? "": $("#rsCloneTargetNs").value.trim(),
          suffix: same? ($("#rsCloneSuffix").value.trim()||"-clone"): "",
          clone_refs: same? false: !!($("#rsCloneRefs")&&$("#rsCloneRefs").checked)};
}
function cloneWarnings(ws){
  // Le résumé liste déjà les dépendances clonées: seules les limites restent, en une ligne.
  return (ws||[]).filter(w=>!/^Dependencies automatically cloned/.test(w)).map(w=>`<div class="hint" style="margin-top:6px">${esc(w)}</div>`).join("");
}
function renderCloneAppPlan(r){
  if(!r.ok && !r.preview){ $("#rsErr").innerHTML=errBox(r.error); return; }
  const p=r.preview||{};
  let html=`<div class="repl"><div class="nm">Copy → namespace <b>${esc(p.target_namespace)}</b>${p.same_namespace?' (suffix)':''}</div>
     ${(p.pvcs||[]).length?`<div><span class="k">Volumes</span>: ${esc(p.pvcs.join(', '))}</div>`:''}
     <div><span class="k">Applications</span>: ${esc((p.workloads||[]).join(', ')||'none')}</div>
     ${(p.dependencies&&p.dependencies.length)?`<div><span class="k">Dependencies</span>: ${esc(p.dependencies.join(', '))}</div>`:''}</div>`;
  html+=cloneWarnings(r.warnings);
  if(r.manifests_preview){ html+=`<details style="margin-top:6px"><summary class="hint">View the manifests</summary><pre class="box">${esc(r.manifests_preview)}</pre></details>`; }
  $("#rsRepl").innerHTML=html;
  $("#rsSteps").innerHTML="";
  $("#rsPlan").style.display="block"; setRsStep(3);
  updateGoButton(r.ok);
  if($("#mRestore").style.display!=="none") rsShowPage("plan");
  else $("#rsPlan").scrollIntoView({behavior:"smooth",block:"start"});
}

function collectItems(){
  const items=[];
  document.querySelectorAll(".rsChk:checked").forEach(c=>{
    const pvc=c.dataset.pvc;
    const ref=(document.querySelector(`.rsRef[data-pvc="${CSS.escape(pvc)}"]`)||{}).value||"";
    const nameEl=document.querySelector(`.rsName[data-pvc="${CSS.escape(pvc)}"]`);
    items.push({pvc, new_ref:ref, new_name:nameEl?nameEl.value:"", nfs:!!c.dataset.nfs});
  });
  return items;
}

$("#rsPreview").onclick=async()=>{
  $("#rsErr").innerHTML="";
  const items=collectItems();
  if(!items.length && !rsStatelessClone()){$("#rsErr").innerHTML='<div class="err">Tick at least one PVC.</div>';return;}
  if(isCloneApp()){
    if(state.cloneNsMode==="other" && !$("#rsCloneTargetNs").value.trim()){ $("#rsErr").innerHTML='<div class="err">Provide the target namespace.</div>'; return; }
    const cb=cloneAppBody(); cb.dry=true;
    const r=await runOp("/api/clone_app",cb);
    state.preview={_cloneapp:true};
    renderCloneAppPlan(r);
    return;
  }
  const body={namespace:$("#rsNs").value,mode:state.mode,items,backup_path:state.backup_path,backup_root:state.backup_root,dry:dry()};
  const r=await post("/api/prepare_restore",body);
  if(!r.ok && !(r.results||[]).length){ $("#rsErr").innerHTML=errBox(r.error||"Preparation failed."); updateGoButton(false); return; }
  state.preview=body;
  let html="";
  (r.results||[]).forEach(res=>{
    if(!res.ok){html+=`<div class="err"><b>${esc(res.pvc)}</b>: ${esc(res.error)}</div>`;return;}
    const REPL_LABEL={vg_uuid:"VG UUID", pv_name:"PV name", volumeHandle:"volumeHandle"};   // clés stables -> libellés
    const repl=(res.replacements||[]).map(([k,o,n])=>`<div><span class="k">${esc(REPL_LABEL[k]||k)}</span> :
       <span class="old">${esc(o)}</span> → <span class="new">${esc(n)}</span></div>`).join("")||
       '<div class="hint">No string change.</div>';
    const warn = res.warn? `<div class="warnbox">⚠ ${esc(res.warn)}</div>`: "";
    html+=`<div class="repl"><div class="nm">${esc(res.pvc)} → PV ${esc(res.new_pv_name)}</div>${repl}
       <div><span class="k">derived volumeHandle</span>: <span class="new">${esc(res.new_volume_handle)}</span></div>${warn}
       <details style="margin-top:6px"><summary class="hint">View the full manifest of the new PV</summary>
       <pre class="box">${esc(res.manifest_preview)}</pre></details></div>`;
  });
  $("#rsRepl").innerHTML=html;
  $("#rsSteps").innerHTML=(r.planned_steps||[]).map(s=>`<li class="${/^(Delete|Stop)/.test(s)?'danger':''}">${esc(s)}</li>`).join("");
  $("#rsPlan").style.display="block"; setRsStep(3);
  if(!r.ok){$("#rsErr").innerHTML='<div class="err">Fix the volumes in error before launching.</div>';}
  updateGoButton(r.ok);
  if($("#mRestore").style.display!=="none") rsShowPage("plan");       // page 3 de l'assistant
  else $("#rsPlan").scrollIntoView({behavior:"smooth",block:"start"});
};
// Toute modification des références/noms rend le plan périmé: il faut re-prévisualiser.
function invalidatePlan(){
  if(rsDone) return;                       // parcours finished: rien à relancer
  if(!state.preview) return;
  state.preview=null; $("#rsPlan").style.display="none"; $("#rsLog").innerHTML="";
  if(typeof rsWizPage!=="undefined" && rsWizPage==="plan") rsShowPage("form");
  setRsStep(2);
}

let rsRunning=false;
$("#rsCancel").onclick=()=>{ $("#rsCancel").disabled=true; cancelCurrentOp(); };
// Liste ✓/✕ du préflight renvoyée par le serveur (contrôles AVANT tout stopping of l'application).
function renderPreflight(checks){
  if(!checks || !checks.length) return "";
  return `<details class="preflight" ${checks.some(c=>c.ok===false)?"open":""}><summary><b>Preflight</b> — ${checks.filter(c=>c.ok!==false).length}/${checks.length} checks passed</summary>
    <ul class="pvc-list">${checks.map(c=>`<li class="logline">${stIc(c.ok===false?"ko":(c.ok===null?"na":"ok"), c.ok===false?"Failed":"OK")}<span><b>${esc(c.name)}</b>${c.detail?(' — <span class="hint">'+esc(c.detail)+'</span>'):''}</span></li>`).join("")}</ul></details>`;
}
function updateGoButton(ready){
  refreshDry();
  const live=!dry();
  const needConfirm = live && ctxInfo.require_confirm;
  $("#rsCtxConfirm").style.display = "none";          // la confirmation se fait dans la boîte de dialogue
  $("#rsGoHint").textContent = live? "": "Simulation mode: nothing will be changed.";
  $("#rsGo").className = live? "btn danger": "btn";
  const kind = state.mode!=="clone" ? "inplace": (isCloneApp() ? "cloneapp": "clone");
  $("#rsGo").textContent = live
    ? {inplace:"Restore in place", clone:"Restore to the new volumes", cloneapp:"Launch the application clone"}[kind]
   : {inplace:"Simulate the in-place restore", clone:"Simulate the restore", cloneapp:"Simulate the application clone"}[kind];
  $("#rsGo").disabled = !ready;
  updateNextBar();
}
$("#dry").addEventListener("change",()=>{ if($("#rsPlan").style.display!=="none") updateGoButton(!$("#rsGo").disabled); });


// ----- Clone d'application: confirmation unique, exécution, état “finished” -----
let rsDone=false, rsDoneTarget="", cloneBusy=false;
// Chaque ouverture de la fenêtre de restauration est une “session”: une opération
// lancée dans une session précédente (fenêtre fermée en cours de route) n'écrit plus
// dans les journaux et ne termine plus l'assistant de la nouvelle ouverture.
let rsSession=0;
function rsNewSession(){
  rsSession++; rsDone=false; cloneBusy=false; state.preview=null;
  $("#rsProgress").style.display="none"; $("#rsCloneTargetNs").value="";
  document.querySelectorAll("#drForm input, #drForm select").forEach(e=>e.disabled=false);
}
// Fin RÉUSSIE d'une opération réelle, quel que soit le parcours: seul “Vérifier” reste.
// `stay`: quelque chose est à lire (avertissements, re-protection) -> pas de bascule auto.
function rsFinish(ns, stay, sess, slow){
  if(sess!==undefined && sess!==rsSession) return;        // opération d'une ouverture précédente
  rsDone=true; rsDoneTarget=ns||state.ns||"";
  setRsStep(4);
  // Plus rien de relançable une fois finished (bouton HYCU de la page DR, champs).
  $("#drAutoWrap").style.display="none";
  document.querySelectorAll("#drForm input, #drForm select").forEach(e=>e.disabled=true);
  rsWizSync();
  if(!stay) setTimeout(()=>{ if(rsDone && sess===rsSession && $("#mRestore").style.display!=="none") gotoVerify(rsDoneTarget, true); }, slow ? 4000: 1500);
}
function confirmCloneApp(withHycu){
  const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||""): null;
  const tgt = state.cloneNsMode==="same" ? "in the <b>same namespace</b> (with a suffix)"
           : "in namespace <b>"+esc($("#rsCloneTargetNs").value.trim()||"?")+"</b>";
  const lines=[];
  if(withHycu) lines.push("Clone the Volume Groups in HYCU at the chosen points (the original volumes are not modified).");
  lines.push("Create a copy of the application "+tgt+" — the original application is neither modified nor stopped.");
  lines.push("Cluster: <b>"+esc(ctxInfo.context||"?")+"</b>");
  return confirmDanger({title:"Confirm the application clone", requireText:needCtx, lines});
}
async function runCloneApp(confirmedCtxCA){
  const live=!dry(), sess=rsSession, mine=()=>sess===rsSession;
  rsDone=false;
  const bb=$("#rsGo"); bb.disabled=true; bb.innerHTML='<span class="spin"></span>…';
  $("#rsLog").innerHTML='<div class="hint"><span class="spin"></span> Starting…</div>';
  const caBody={...cloneAppBody(), dry:dry()};
  if(live && ctxInfo.require_confirm) caBody.confirm_context=confirmedCtxCA;
  const r=await runOp("/api/clone_app", caBody,
    log=>{ if(mine()) $("#rsLog").innerHTML='<div class="hint"><span class="spin"></span> Cloning in progress…</div>'+renderLog(log); });
  if(!mine()) return;
  bb.disabled=false; updateGoButton(true);
  if(r.error && !(r.log&&r.log.length)){ $("#rsLog").innerHTML=errBox(r.error); return; }
  const lns=renderLog(r.log);
  const hd=r.dry?'<div class="note">Simulation — resources that would be created (the original app stays intact).</div>'
    :(r.ok?'<div class="note">Application copy finished. The original application is intact.</div>':'<div class="err">Some steps failed — see details.</div>');
  $("#rsLog").innerHTML=hd+lns+cloneWarnings(r.warnings);
  if(!r.dry && r.ok){
    // Terminé: plus de bouton de lancement, seule la vérification reste (pied de la fenêtre).
    rsFinish(state.cloneNsMode==="other" ? $("#rsCloneTargetNs").value.trim(): $("#rsNs").value,
             false, sess, !!cloneWarnings(r.warnings));
  }
}
// Étape 2 -> lancement direct: une seule confirmation, clones HYCU si nécessaire, puis la copie.
async function cloneAppDirect(){
  $("#rsErr").innerHTML="";
  const items=collectItems();
  if(!items.length && !rsStatelessClone()){ $("#rsErr").innerHTML='<div class="err">Tick at least one PVC.</div>'; return; }
  if(state.cloneNsMode==="other" && !$("#rsCloneTargetNs").value.trim()){ $("#rsErr").innerHTML='<div class="err">Provide the target namespace.</div>'; return; }
  if(dry()){ $("#rsPreview").click(); return; }          // simulation: aperçu, rien n'est créé
  const batch=$("#hyBatchGo");
  const pending = !rsStatelessClone() && !!batch && !(items.length && items.every(refOk));
  const res=await confirmCloneApp(pending);
  if(!res) return;
  const confirmedCtx = (typeof res==="string") ? res: "";
  cloneBusy=true; rsWizSync();
  try{
    if(pending){
      const ok=await hyBatchRun({skipConfirm:true, noChain:true});
      if(!ok) return;                                      // erreurs affichées volume par volume
    }
    $("#rsRepl").innerHTML=""; $("#rsSteps").innerHTML=""; $("#rsLog").innerHTML="";
    state.preview={_cloneapp:true};          // “Relancer” depuis cette page = la copie, jamais la restauration destructive
    $("#rsPlan").style.display="block"; rsShowPage("plan");
    await runCloneApp(confirmedCtx);
  } finally { cloneBusy=false; rsWizSync(); }
}
$("#rsGo").onclick=async()=>{
  hideNextBar();   // pas de “prochaine action” pendant l'exécution
  const live=!dry();
  if(state.preview && state.preview._cloneapp){
    let confirmedCtxCA="";
    if(live){
      const res = await confirmCloneApp(false);
      if(!res) return;
      if(typeof res==="string") confirmedCtxCA=res;
    }
    await runCloneApp(confirmedCtxCA);
    return;
  }
  let confirmedCtx="";
  if(live){
    const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||""): null;
    const res = await confirmDanger({title:"Confirm the restore", requireText:needCtx, lines:[
      "Namespace: <b>"+esc($("#rsNs").value||"?")+"</b>",
      "Target cluster: <b>"+esc(ctxInfo.context||"?")+"</b>",
      "The application will be <b>stopped</b>, the old PVCs/PVs <b>deleted</b> then recreated on the restored Volume Group(s)."]});
    if(!res) return;
    if(typeof res==="string") confirmedCtx=res;
  }
  const b=$("#rsGo"); b.disabled=true; b.innerHTML='<span class="spin"></span>Executing…';
  const sess=rsSession, mine=()=>sess===rsSession;
  const body={...state.preview,dry:dry()};
  if(live && ctxInfo.require_confirm) body.confirm_context=confirmedCtx || $("#rsCtxInput").value.trim();
  setRsStep(4); rsRunning=true;
  const total=($("#rsSteps").children.length||1)+8;              // étapes prévues + préflight/réplicas/vérif
  $("#rsProgress").style.display="block"; $("#rsProgressBar").style.width="2%";
  $("#rsProgressTxt").textContent="Starting…"; $("#rsCancel").style.display = live ? "": "none"; $("#rsCancel").disabled=false;
  $("#rsLog").innerHTML='<div class="hint"><span class="spin"></span> Starting…</div>';
  const r=await runOp("/api/execute_restore", body, log=>{
    const done=log.length, last=log[log.length-1];
    $("#rsProgressBar").style.width=Math.min(96, Math.round(100*done/total))+"%";
    $("#rsProgressTxt").textContent="Step "+done+" · "+((last&&last.label)||"…");
    if(mine()) $("#rsLog").innerHTML='<div class="hint"><span class="spin"></span> Execution in progress…</div>'+renderLog(log); });
  rsRunning=false; if(!mine()) return;
  $("#rsCancel").style.display="none";
  $("#rsProgressBar").style.width="100%"; $("#rsProgressTxt").textContent = r.aborted ? "Interrupted": (r.ok ? "Completed": "Completed with errors");
  b.disabled=false; updateGoButton(true);
  if(r.error && !(r.log&&r.log.length)){$("#rsLog").innerHTML=errBox(r.error)+renderPreflight(r.preflight);return;}
  const lines=renderLog(r.log);
  let head;
  if(r.dry) head='<div class="note">Simulation finished — here is what would be executed.</div>';
  else if(r.aborted) head='<div class="err"><b>Sequence aborted</b> — the application was left stopped to avoid an inconsistent restart. See details.</div>';
  else if(r.ok) head='<div class="note">Restore to the new volumes finished.</div>';
  else head='<div class="err">Some steps failed — see below.</div>';
  let reprot="";
  if(r.reprotect && r.reprotect.length){
    const items=r.reprotect.map(x=>`<li><b>${esc(x.new_pv_name)}</b> <span class="hint">${esc(x.new_volume_handle||'')}</span></li>`).join("");
    reprot=`<div class="warnbox">⚠ <b>HYCU re-protection required.</b> The cloned Volume Group(s) below
       are <b>not yet protected</b> by HYCU (the app's policy pointed at the old VG).
       <ul class="pvc-list" style="margin-top:8px">${items}</ul>
       <button class="btn" id="rsReprotectBtn" style="margin-top:6px">Re-protect now in HYCU</button></div>`;
  }
  $("#rsLog").innerHTML = head + renderPreflight(r.preflight) + lines + reprot;
  const rb=$("#rsReprotectBtn"); if(rb) rb.onclick=()=>goReprotect($("#rsNs").value);
  // Re-protection HYCU à traiter: pas de bascule automatique (le bouton reste dans le journal).
  if(!r.dry && r.ok && !r.aborted) rsFinish($("#rsNs").value, !!reprot, sess);
};

// --------- Vérification ---------
async function runVerify(){
  const ns=$("#vfNs").value;
  const r=await get("/api/verify?ns="+encodeURIComponent(ns));
  if(r.error){
    let html=errBox(r.error);
    // Erreur actionnable: namespace hors liste blanche (ex. namespace créé par un
    // clone AVANT que l'ajout automatique n'existe) -> proposer l'ajout en un clic.
    if(r.ns_not_allowed) html+=`<div style="margin-top:8px"><button class="btn" id="vfAllowNs">Allow “${esc(ns)}” and retry</button></div>`;
    $("#vfOut").innerHTML=html;
    const ab=$("#vfAllowNs");
    if(ab) ab.onclick=async()=>{
      const f=await get("/api/ns_filter");
      const rr=await post("/api/ns_filter",{filter:(f.filter||[]).concat([ns])});
      if(!rr.ok){ $("#vfOut").innerHTML=errBox(rr.error||"Could not update the filter."); return; }
      const n=await get("/api/namespaces");            // recharger les listes déroulantes
      const opts=(n.namespaces||[]).map(x=>`<option>${esc(x)}</option>`).join("");
      ["#bkNs","#rsNs","#vfNs"].forEach(id=>$(id).innerHTML=opts||"<option>—</option>");
      $("#vfNs").value=ns; state.ns=ns; applyGlobalNs();
      runVerify();
    };
    return false;
  }
  const pvcs=r.pvcs.map(p=>`<li class="logline"><span>${badge(p.phase)} <b>${esc(p.name)}</b>
     <span class="hint">→ ${esc(p.pv||'—')}</span></span></li>`).join("")||'<div class="hint">No PVC.</div>';
  let allReady=r.pods.length>0;
  const pods=r.pods.map(p=>{
    const ok=p.phase==="Running"; if(!ok) allReady=false;
    const issue = p.issue ? `<div class="hint" style="color:var(--red);margin-top:3px">⚠ ${esc(p.issue.reason)}${p.issue.count>1?' (×'+p.issue.count+')':''}: ${esc(p.issue.message)}</div>`: "";
    return `<li class="logline"><span class="ic ${ok?'ok':'sim'}">${ok?'✓':'○'}</span>
     <span><b>${esc(p.name)}</b> <span class="hint">${esc(p.phase)}${p.waiting?' · '+esc(p.waiting):''} · ready ${esc(p.ready)}</span>${issue}</span></li>`;}).join("")
     ||'<div class="hint">No pods.</div>';
  $("#vfOut").innerHTML=`<div style="margin-top:12px"><b style="font-size:13px">PVC</b>
     <ul class="pvc-list">${pvcs}</ul><b style="font-size:13px">Pods</b><ul class="pvc-list">${pods}</ul></div>`;
  const allBound=r.pvcs.every(p=>(p.phase||"").toLowerCase()==="bound");
  return allBound && allReady;
}
$("#vfRun").onclick=runVerify;
// Suivi auto CONTINU: rafraîchit toutes les ~3 s jusqu'à l'état stable (tous les PVC
// Bound + pods Running), avec plafond de sécurité ~10 min. Re-cliquer arrête le suivi.
let vfTrack=false, vfSeq=0;
function vfSetBtn(){ $("#vfAuto").textContent = vfTrack? "■ Stop tracking": "Auto-track (until stable)"; }
function vfStop(){ vfSeq++; vfTrack=false; vfSetBtn(); }
async function vfAutoTrack(){
  if(vfTrack){ vfStop(); return; }               // stop demandé: la boucle en cours s'arrête
  const my=++vfSeq; vfTrack=true; vfSetBtn();
  for(let i=0;i<200 && vfTrack && vfSeq===my;i++){   // ~10 min à 3 s; une seule boucle à la fois
    const done=await runVerify();
    if(vfSeq!==my) return;
    if(done){ $("#vfOut").insertAdjacentHTML("afterbegin",'<div class="note">Stable state: all PVCs are Bound and pods are Running.</div>'); break; }
    await sleep(3000);
  }
  if(vfSeq===my){ vfTrack=false; vfSetBtn(); }
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
  $("#cfgHosts").value=(c.allowed_hosts||[]).join(", ");
  $("#cfgWait").value=c.wait_timeout;
  $("#cfgConfirm").checked=!!c.require_context_confirm; $("#cfgStrip").checked=!!c.strip_claimref;
  $("#cfgSim").checked=!!c.simulation_mode_available;
  applySimAvailability(c.simulation_mode_available);
  $("#cfgKubeconfig").value=c.kubeconfig_path||"";
  $("#cfgContext").innerHTML=`<option value="${esc(c.kube_context||'')}">${esc(c.kube_context||'(current kubeconfig context)')}</option>`;
}
$("#ctxList").onclick=async()=>{
  const kc=$("#cfgKubeconfig").value.trim();
  $("#ctxMsg").textContent="…";
  const r=await get("/api/contexts"+(kc?("?kubeconfig="+encodeURIComponent(kc)):""));
  if(!r.ok){ $("#ctxMsg").innerHTML=`<span class="ko">${esc(r.error||'kubectl unavailable')}</span>`; return; }
  const cur=r.selected||"";
  $("#cfgContext").innerHTML=`<option value="">(current kubeconfig context)</option>`+
    (r.contexts||[]).map(c=>`<option value="${esc(c)}" ${c===cur?'selected':''}>${esc(c)}</option>`).join("");
  $("#ctxMsg").textContent=`${(r.contexts||[]).length} context(s) found`;
};
$("#ctxApply").onclick=async()=>{
  const cfg={kube_context:$("#cfgContext").value, kubeconfig_path:$("#cfgKubeconfig").value.trim()};
  const r=await post("/api/config",{config:cfg});
  if(!r.ok){ $("#ctxMsg").innerHTML=`<span class="ko">${esc(r.error||'error')}</span>`; return; }
  $("#ctxMsg").textContent = cfg.kube_context? ("Context “"+cfg.kube_context+"” applied."): "Current context in use.";
  await initApp();   // recharge en-tête + namespaces sur le nouveau cluster
};
function csv(s){return (s||"").split(",").map(x=>x.trim()).filter(Boolean);}
$("#cfgSave").onclick=async()=>{
  const cfg={kubectl_path:$("#cfgKubectl").value.trim()||"kubectl",
    volume_handle_prefix:$("#cfgVhPrefix").value.trim(),
    allowed_contexts:csv($("#cfgCtx").value), namespace_filter:csv($("#cfgNs").value), allowed_hosts:csv($("#cfgHosts").value),
    namespace_label_selector:$("#cfgLabelSel").value.trim(),
    audit_retention_days:Math.max(0,parseInt($("#cfgAuditDays").value)||0),
    storage_min_free_mb:Math.max(0,parseInt($("#cfgMinFree").value)||0),
    storage_quota_gb:Math.max(0,parseInt($("#cfgQuota").value)||0),
    allow_dr_restore:$("#cfgDr").checked,
    wait_timeout:parseInt($("#cfgWait").value)||120,
    require_context_confirm:$("#cfgConfirm").checked, strip_claimref:$("#cfgStrip").checked,
    simulation_mode_available:$("#cfgSim").checked};
  const r=await post("/api/config",{config:cfg});
  $("#cfgMsg").textContent = r.ok? "Saved.": ("Error: "+(r.error||""));
  if(r.ok) applySimAvailability(cfg.simulation_mode_available);   // bandeau simulation affiché/masqué sans rechargement
  ctxInfo=await get("/api/context");
};

// --------- Connexions HYCU / Nutanix ---------
let conn = {hycu:{connected:false}, nutanix:{connected:false}};
function connDot(on){ return `<span class="conn-dot ${on?'on':''}"></span>`; }
async function loadConnStatus(){
  let s = await get("/api/conn_status");
  if(!s || !s.hycu) s = {hycu:{}, nutanix:{}, prismcentral:{}, vault:(s&&s.vault)||{}};  // réponse d'erreur: ne pas casser l'init
  conn = s;
  ntAllVgs=null;   // invalide le cache des VG Nutanix après tout (dé)connexion
  const st=(x)=>connDot(x.connected)+(x.connected?"connected":"not connected");
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
// Pastilles d'état permanentes dans l'en-tête: HYCU / Prism Element / Prism Central.
// Un clic ouvre l'onglet Connexions (l'opérateur voit AVANT d'agir s'il est connecté).
function renderHdrConn(){
  $("#hdrConn").innerHTML=[["HYCU",conn.hycu],["PE",conn.nutanix],["PC",conn.prismcentral]]
    .map(([l,x])=>`<span class="hc">${connDot(!!(x&&x.connected))}${l}</span>`).join("");
  renderSourcesTable();
}
function loadVaultStatus(){
  const present = conn && conn.vault && conn.vault.present;
  $("#vaultStatus").innerHTML = connDot(present) + (present? "vault present": "no vault");
  $("#vaultLoad").style.display = present? "inline-block": "none";
  $("#vaultForget").style.display = present? "inline-block": "none";
}
function renderKubeBanner(){
  const el=$("#kubeBanner");
  if(ctxInfo.kubectl_ok){ el.style.display="none"; el.innerHTML=""; return; }
  const tips={
    kubectl_missing:"<b>kubectl not found.</b> Install kubectl and add it to PATH, or set its binary/path in ⚙ Settings (e.g. “microk8s kubectl”).",
    no_context:"<b>No kubectl context selected.</b> Choose the target cluster: <code>kubectl config use-context &lt;name&gt;</code>, then reload the page.",
    no_kubeconfig:"<b>No kubectl configuration found.</b> Check <code>%USERPROFILE%\\.kube\\config</code> (or the <code>KUBECONFIG</code> variable), then reload.",
    other:"<b>Cluster unreachable via kubectl.</b> Check network connectivity and your RBAC rights on the API server."
  };
  const tip=tips[ctxInfo.kubectl_hint]||tips.other;
  el.innerHTML=`<div class="warnbox" style="margin-bottom:14px">⚠ ${tip}
    <div class="hint" style="margin-top:6px">The <b>Back up</b>, <b>Restore</b> (Kubernetes sequence) and <b>Verify</b> operations require kubectl. The <b>HYCU / Nutanix</b> connections work without kubectl.${ctxInfo.error?`<br><code style="color:#7a221b">${esc(ctxInfo.error)}</code>`:''}</div></div>`;
  el.style.display="block";
}
async function vaultAction(url, needPass){
  $("#vaultErr").innerHTML="";
  const body = needPass? {passphrase:$("#vaultPass").value}: {};
  const r = await post(url, body);
  $("#vaultPass").value="";
  return r;
}
$("#vaultSave").onclick=async()=>{
  const r=await vaultAction("/api/creds/save", true);
  $("#vaultErr").innerHTML = r.ok? `<div class="note">Connections encrypted: ${esc((r.saved||[]).join(', ')||"—")}.`+
      ((r.clusters||[]).length?`<br>Kubernetes clusters encrypted: ${esc(r.clusters.join(', '))}.`:"")+`</div>`
                                : errBox(r.error);
  await loadConnStatus();
};
$("#vaultLoad").onclick=async()=>{
  const r=await vaultAction("/api/creds/load", true);
  $("#vaultErr").innerHTML = r.ok? `<div class="note">Connections loaded: ${esc((r.loaded||[]).join(', ')||"—")}.`+
      ((r.clusters||[]).length?`<br>Kubernetes clusters loaded: ${esc(r.clusters.join(', '))}.`:"")+`</div>`
                                : errBox(r.error);
  await loadConnStatus();
  if(r.ok) await afterVaultLoad();
};
$("#vaultForget").onclick=async()=>{
  if(!confirm("Delete the encrypted vault from disk?")) return;
  const r=await vaultAction("/api/creds/forget", false);
  $("#vaultErr").innerHTML = r.ok? '<div class="note">Vault deleted.</div>': `<div class="err">${esc(r.error||'')}</div>`;
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
  if(!url){ $(P+'Err').innerHTML='<div class="err">Enter the URL.</div>'; return; }
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
  const b=$("#s3Connect"); b.disabled=true; b.innerHTML='<span class="spin"></span>Testing bucket…';
  const r=await post("/api/s3/connect",{s3_url:$("#s3Url").value.trim(), s3_bucket:$("#s3Bucket").value.trim(),
    s3_region:$("#s3Region").value.trim()||"us-east-1", s3_verify_tls:$("#s3Tls").checked,
    s3_path_style:$("#s3PathStyle").checked, s3_auto_upload:$("#s3Auto").checked,
    s3_encrypt:$("#s3Enc").checked, enc_passphrase:$("#s3EncPass").value,
    access:$("#s3Access").value.trim(), secret:$("#s3Secret").value});
  $("#s3Secret").value=""; $("#s3EncPass").value=""; b.disabled=false; b.textContent="Test & connect";
  if(!r.ok){ $("#s3Err").innerHTML=errBox(r.error); }
  else { $("#s3Err").innerHTML=`<div class="note">Bucket “${esc(r.bucket||"")}” accessible.`+
    (r.auto_upload?" Automatic export enabled.":" Automatic export disabled (tick the box to enable it).")+`</div>`; }
  await loadConnStatus();
};
$("#s3Enc").onchange=()=>{ $("#s3EncWrap").style.display=$("#s3Enc").checked?"block":"none"; };
function s3ImpSync(){ $("#s3ImportBtn").disabled = !document.querySelectorAll(".s3ImpChk:checked").length; }
$("#s3ListBtn").onclick=async()=>{
  const w=$("#s3ImportWrap");
  if(w.style.display!=="none"){ w.style.display="none"; return; }
  w.style.display="block"; $("#s3ImpRes").innerHTML="";
  $("#s3ListOut").innerHTML='<div class="hint"><span class="spin"></span>Listing bucket…</div>';
  const r=await get("/api/s3/list");
  if(!r.ok){ $("#s3ListOut").innerHTML=errBox(r.error); return; }
  const o=r.objects||[];
  $("#s3ListOut").innerHTML = o.length? `<div class="tcard" style="box-shadow:none;border:1px solid var(--rule)"><table class="ht"><thead><tr><th class="cb"><input type="checkbox" id="s3ImpAll"></th><th>Cluster</th><th>Application</th><th>Timestamp</th><th>Size</th><th>Encrypted</th></tr></thead><tbody>`+
    o.map((x,i)=>`<tr><td class="cb"><input type="checkbox" class="s3ImpChk" data-i="${i}"></td><td>${esc(x.cluster)}</td><td style="color:var(--strong)">${esc(x.namespace)}</td><td>${esc(x.timestamp)}</td><td>${esc(fmtBytes(x.size))}</td><td>${x.encrypted?"yes":"—"}</td></tr>`).join("")+
    `</tbody></table></div>`: '<div class="hint">No tool export in this bucket.</div>';
  window.s3Objs=o;
  document.querySelectorAll(".s3ImpChk").forEach(c=>c.onchange=s3ImpSync);
  const all=$("#s3ImpAll"); if(all) all.onchange=()=>{ document.querySelectorAll(".s3ImpChk").forEach(c=>c.checked=all.checked); s3ImpSync(); };
  s3ImpSync();
};
// ----- Sauvegarde de l'outil (kit: configuration, politiques, coffre chiffré) -----
$("#tkUpload").onclick=async()=>{
  const b=$("#tkUpload"); b.disabled=true;
  const r=await post("/api/tool_kit/upload",{});
  b.disabled=false;
  $("#tkOut").innerHTML = r.ok ? `<div class="note" style="margin-top:8px">Kit exported: <code>${esc(r.key)}</code></div>`: errBox(r.error);
};
$("#tkDownload").onclick=async()=>{
  try{
    const resp=await fetch("/api/tool_kit/download",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":CSRF,"X-HYCU-Cluster":ACTIVE_CID},body:"{}"});
    if(!resp.ok) throw new Error("HTTP "+resp.status);
    const blob=await resp.blob(), a=document.createElement("a");
    a.href=URL.createObjectURL(blob); a.download="hycu-tool-"+new Date().toISOString().slice(0,10)+".zip";
    document.body.appendChild(a); a.click(); setTimeout(()=>{ URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }catch(e){ $("#tkOut").innerHTML=errBox("Download failed: "+(e&&e.message||e)); }
};
$("#tkList").onclick=async()=>{
  $("#tkOut").innerHTML='<div class="hint" style="margin-top:8px"><span class="spin"></span></div>';
  const r=await get("/api/tool_kit/list");
  if(!r.ok){ $("#tkOut").innerHTML=errBox(r.error); return; }
  const k=r.kits||[];
  if(!k.length){ $("#tkOut").innerHTML='<div class="hint" style="margin-top:8px">No tool kit in this bucket.</div>'; return; }
  $("#tkOut").innerHTML=`<div class="tcard" style="box-shadow:none;border:1px solid var(--rule);margin-top:8px"><table class="ht"><thead><tr><th class="cb"></th><th>Kit</th><th>Size</th></tr></thead><tbody>`+
    k.map((x,i)=>`<tr><td class="cb"><input type="radio" name="tkPick" value="${esc(x.key)}" data-enc="${x.encrypted?1:0}" ${i===0?"checked":""}></td><td>${esc(x.name)}</td><td>${esc(fmtBytes(x.size))}</td></tr>`).join("")+
    `</tbody></table></div>
    <div class="row" style="margin-top:8px"><div><label class="fld">Encryption passphrase (.enc kits only)</label><input type="password" id="tkPass" autocomplete="off"></div>
    <div style="flex:none;align-self:flex-end"><button class="btn danger" id="tkRestore" type="button">Restore the tool</button></div></div><div id="tkRes"></div>`;
  $("#tkRestore").onclick=async()=>{
    const pick=document.querySelector('input[name="tkPick"]:checked'); if(!pick) return;
    if(!(await confirmDanger({title:"Restore the tool", lines:[
      "The current configuration (policies, filters, sources) and the vault will be replaced by those of kit <b>"+esc(pick.value.split("/").pop())+"</b>.",
      "A copy of the current state is kept in <code>hycu-backups/_tool_restore_backup/</code>."]}))) return;
    const b=$("#tkRestore"); b.disabled=true;
    const res=await post("/api/tool_kit/restore",{key:pick.value, passphrase:$("#tkPass").value});
    $("#tkPass").value=""; b.disabled=false;
    if(!res.ok){ $("#tkRes").innerHTML=errBox(res.error); return; }
    $("#tkRes").innerHTML=`<div class="note" style="margin-top:8px">Tool restored${res.vault?" — then unlock the vault with your passphrase":""}. Reloading…</div>`;
    setTimeout(()=>location.reload(), 1800);
  };
};
$("#s3ImportBtn").onclick=async()=>{
  const items=[...document.querySelectorAll(".s3ImpChk:checked")].map(c=>({key:(window.s3Objs||[])[+c.dataset.i].key}));
  if(!items.length) return;
  const b=$("#s3ImportBtn"); b.disabled=true; b.innerHTML='<span class="spin"></span>Import…';
  const r=await post("/api/s3/import",{items, enc_passphrase:$("#s3ImpPass").value});
  $("#s3ImpPass").value=""; b.disabled=false; b.textContent="Import selection"; s3ImpSync();
  const res=r.results||[];
  $("#s3ImpRes").innerHTML=(r.error&&!res.length?errBox(r.error):"")+(res.length?`<ul class="dlist" style="margin-top:10px">`+res.map(x=>
    `<li><span class="k" style="display:flex;gap:10px;align-items:center">${stIc(x.ok?"ok":"ko")}${esc(x.key)}</span>`+
    `<span class="v" style="font-weight:400">${x.ok? x.files+" file(s)": esc(x.error||"")}</span></li>`).join("")+"</ul>":"");
};
$("#s3Disconnect").onclick=async()=>{ await post("/api/disconnect",{system:"s3"}); $("#s3Err").innerHTML=""; await loadConnStatus(); };
$("#hyConnect").onclick=()=>connectSystem("hycu");
$("#ntConnect").onclick=()=>connectSystem("nutanix");
$("#pcConnect").onclick=()=>connectSystem("prismcentral");
$("#hyDisconnect").onclick=()=>disconnectSystem("hycu");
$("#ntDisconnect").onclick=()=>disconnectSystem("nutanix");
$("#pcDisconnect").onclick=()=>disconnectSystem("prismcentral");

// Nutanix: recherche instantanée d'un VG et remplissage de sa RÉFÉRENCE (VG UUID).
// Les VG sont chargés une fois (pagination serveur) puis filtrés côté navigateur.
let ntAllVgs=null;
async function ntFindRef(pvc){
  const box=document.querySelector(`.ntpick[data-pvc="${CSS.escape(pvc)}"]`);
  if(box.dataset.open==="1"){ box.dataset.open=""; box.innerHTML=""; return; }  // 2e clic = refermer
  box.dataset.open="1";
  box.innerHTML='<div class="hint">Loading Volume Groups…</div>';
  if(ntAllVgs===null){
    const r=await get("/api/nutanix/vgs");
    if(!r.ok){ box.innerHTML=errBox(r.error); return; }
    ntAllVgs=r.vgs||[];
  }
  box.innerHTML=`<div style="border:1px solid var(--line);border-radius:8px;padding:8px;margin-top:6px;background:#fff">
    <input type="text" class="ntSearch" placeholder="search the cloned VG by name…">
    <div class="ntResults" style="max-height:200px;overflow:auto;margin-top:6px"></div>
    <div class="hint ntCount" style="margin-top:4px"></div></div>`;
  const inp=box.querySelector(".ntSearch"), res=box.querySelector(".ntResults"), cnt=box.querySelector(".ntCount");
  function render(){
    const t=(inp.value||"").toLowerCase();
    let list=t? ntAllVgs.filter(v=>(v.name||"").toLowerCase().includes(t)): ntAllVgs;
    const total=list.length, capped=list.length>200; list=list.slice(0,200);
    res.innerHTML=list.length? list.map(v=>`<div class="logline ntRow" data-uuid="${esc(v.uuid)}" style="cursor:pointer">
       <span><b>${esc(v.name||v.uuid)}</b> <span class="hint">UUID ${esc(v.uuid||'?')}</span></span></div>`).join("")
      : '<div class="hint">No Volume Group matches.</div>';
    cnt.textContent=`${total} VG${total>1?'s':''} of ${ntAllVgs.length}`+(capped?' (200 shown — refine the search)':'');
    res.querySelectorAll(".ntRow").forEach(row=>row.onclick=()=>{
      // NKP moderne: l'VG UUID suffit (= suffixe du volumeHandle). Pas d'appel IQN.
      const ref=row.dataset.uuid;
      if(!ref){ box.innerHTML='<div class="err">VG UUID unavailable.</div>'; box.dataset.open=""; return; }
      const ta=document.querySelector(`.rsRef[data-pvc="${CSS.escape(pvc)}"]`); if(ta) ta.value=ref;
      box.innerHTML='<div class="note" style="margin-top:6px">VG reference (UUID) filled from Nutanix.</div>'; box.dataset.open="";
    });
  }
  inp.oninput=render; render(); inp.focus();
}

// Suivi générique d'un job HYCU: barre de progression + polling (backup ou restore).
async function pollJobBar(id, target){
  const el=(typeof target==="string")?$(target):target; if(!el) return false;
  let errs=0;
  for(let i=0;i<240;i++){                       // ~12 min max (240 * 3s)
    const r=await post("/api/hycu/job",{job_id:id});
    if(!r.ok){
      if((r.http_status===0 || r.http_status>=500) && ++errs<=10){     // coupure passagère: on réessaie
        el.innerHTML=`<div class="hint">Job tracking: retrying (${errs}/10)…</div>`;
        await new Promise(s=>setTimeout(s,3000)); continue;
      }
      el.innerHTML=`<div class="hint">Job tracking unavailable: ${esc(r.error||'')}</div>`; return false; }
    errs=0;
    const pct=(r.progress!=null)?r.progress:0, status=r.status||"?";
    el.innerHTML=`<div class="hint" style="margin-top:8px">Job <code>${esc(id)}</code> — ${esc(status)}${r.progress!=null?(' · '+pct+'%'):''}</div>
       <div class="jbar"><span style="width:${pct}%"></span></div>`;
    if(/^(OK|DONE|SUCCESS|SUCCEEDED|COMPLETED?|FINISHED|WARNING)$/i.test(status)){ el.innerHTML+='<div class="note" style="margin-top:6px">Job finished successfully.</div>'; return true; }
    if(/^(FAILED|ERROR|FATAL|ABORTED?|CANCEL+ED|TIMEOUT)$/i.test(status)){ el.innerHTML+='<div class="err" style="margin-top:6px">Job failed — check in HYCU.</div>'; return false; }
    await new Promise(s=>setTimeout(s,3000));
  }
  el.innerHTML+='<div class="hint">Tracking stopped (timeout) — the job continues on the HYCU side.</div>';
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
  if($("#nsAll").checked){ $("#nsCount").textContent="all"; return; }
  const allManual = nsAllList.length>0 && nsChecked.size===nsAllList.length;
  $("#nsCount").textContent = nsChecked.size+" / "+nsAllList.length+" selected"
    + (allManual? " · future namespaces excluded (tick “All”)": "");
}
function renderNsList(){
  const vis=nsVisible();
  $("#nsList").innerHTML = vis.length? ('<ul class="pvc-list" style="margin:0">'+vis.map(n=>`<li><label style="display:flex;gap:10px;align-items:center;cursor:pointer;width:100%">
      <input type="checkbox" class="nsChk" value="${esc(n)}" ${nsChecked.has(n)?'checked':''} style="width:auto">
      <span class="nm">${esc(n)}</span></label></li>`).join("")+'</ul>')
   : '<div class="hint">No namespace matches.</div>';
  $("#nsList").querySelectorAll(".nsChk").forEach(c=>c.onchange=()=>{ c.checked? nsChecked.add(c.value):nsChecked.delete(c.value); nsUpdateCount(); });
  nsUpdateCount();
}
async function openNsFilter(){
  // Normalisation systématique: on repart d'un état propre à chaque ouverture,
  // et la sauvegarde reste désactivée tant que le filtre réel n'est pas chargé
  // (sinon, kubectl en panne -> on enregistrerait [] = écrasement de la whitelist).
  $("#nsFilterErr").innerHTML=""; $("#nsAll").checked=false;
  nsAllList=[]; nsChecked=new Set(); $("#nsSearch").value="";
  $("#nsSave").disabled=true;
  nsTogglePick(); renderNsList();
  $("#nsFilter").style.display="flex";
  const r=await get("/api/ns_filter");
  if(!r.ok){ $("#nsFilterErr").innerHTML=`<div class="err">${esc(r.error||'kubectl unavailable')} — could not load the list; saving disabled.</div>`; return; }
  nsAllList=r.all||[]; const filt=r.filter||[], noFilter=filt.length===0;
  $("#nsAll").checked=noFilter;
  nsChecked=new Set(noFilter? nsAllList: filt);
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
  const filter = $("#nsAll").checked? []: [...nsChecked];
  const r=await post("/api/ns_filter",{filter});
  if(!r.ok){ $("#nsFilterErr").innerHTML=`<div class="err">${esc(r.error||'error')}</div>`; return; }
  $("#nsFilter").style.display="none";
  await refreshNamespaces();
  $("#cfgNs").value=(r.filter||[]).join(", ");   // garder l'onglet Réglages cohérent
  onPageShown(curPage);                          // Applications / tableau de bord à jour
};
refreshDry();

// ============================================================================
// Interface “HYCU Enterprise Cloud”: pages (Tableau de bord, Applications,
// Politiques, Tâches) et modales d'opération (Sauvegarde, Set Policy,
// Restauration, Sources). Les blocs d'origine (mêmes IDs, même logique testée)
// sont hébergés dans ces modales: ce code se contente de les piloter.
// ============================================================================
var rsAutoCheck=false;            // assistant ouvert: volumes présélectionnés (cf. renderRsPvcs)
var pageTimer=null;
const MODALS=["mBackup","mPolicy","mRestore","mSources","mBulk","mPurge"];
const FOCUSABLE='a[href],button:not([disabled]),input:not([disabled]):not([type=hidden]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';
let modalReturnFocus={};
function openModal(id){
  const m=$("#"+id); if(!m) return;
  const box=m.querySelector(".hmodal")||m;
  box.setAttribute("role","dialog"); box.setAttribute("aria-modal","true");
  const h=box.querySelector("h2,h3"); if(h){ if(!h.id) h.id=id+"-title"; box.setAttribute("aria-labelledby",h.id); }
  modalReturnFocus[id]=document.activeElement;
  m.style.display="flex";
  const first=box.querySelector(FOCUSABLE); if(first) setTimeout(()=>first.focus(),30);
}
function closeModal(id){
  const m=$("#"+id); if(!m || m.style.display==="none") return;
  if(id==="mRestore" && rsRunning){
    $("#rsLog").insertAdjacentHTML("afterbegin",'<div class="warnbox">Operation in progress: it keeps running server-side. You can resume tracking from the banner at the top of the page.</div>');
  }
  m.style.display="none";
  if(id==="mRestore") rsAutoCheck=false;
  if(id==="mSources"){ const k=$("#clKc"); if(k) k.value=""; const n=$("#clName"); if(n) n.value=""; }   // kubeconfig = secret
  const rf=modalReturnFocus[id]; if(rf && rf.focus) try{ rf.focus(); }catch(e){}
  if(id!=="mSources") onPageShown(curPage);        // l'opération a pu changer l'état affiché
}
// Piège de focus: Tab reste dans la modale ouverte la plus haute.
document.addEventListener("keydown", e=>{
  if(e.key!=="Tab") return;
  const open=MODALS.map(id=>$("#"+id)).filter(m=>m && m.style.display!=="none");
  const m=open[open.length-1]; if(!m) return;
  const f=[...m.querySelectorAll(FOCUSABLE)].filter(el=>el.offsetParent!==null); if(!f.length) return;
  if(e.shiftKey && document.activeElement===f[0]){ e.preventDefault(); f[f.length-1].focus(); }
  else if(!e.shiftKey && document.activeElement===f[f.length-1]){ e.preventDefault(); f[0].focus(); }
});
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
// Engrenage: petit menu (Sources / Réglages), même style que le menu des clusters.
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
const AGO={now:"just now", min:"%d min ago", h:"%d h ago", d:"%d d ago"};
function fmtAgo(ts){
  if(!ts) return "";
  const s=Math.max(0, Date.now()/1000-ts);
  if(s<60) return AGO.now;
  if(s<3600) return AGO.min.replace("%d", Math.round(s/60));
  if(s<86400) return AGO.h.replace("%d", Math.round(s/3600));
  return AGO.d.replace("%d", Math.round(s/86400));
}
let DATE_FMT=null;   // créé à la première utilisation
function fmtTs(iso){
  if(!iso) return "—"; const d=new Date(iso); if(isNaN(d)) return String(iso);
  if(!DATE_FMT) DATE_FMT=new Intl.DateTimeFormat("en-GB", {dateStyle:"short", timeStyle:"medium"});
  return DATE_FMT.format(d);
}
const ST_LABEL={ok:"OK", ko:"Failed", wn:"Warning", na:"Unknown", sim:"Simulation", run:"Running"};
function stIc(kind, title){
  const g={ok:"✓", ko:"✕", wn:"!", na:"?", sim:"○", run:"▸"}[kind]||"?";
  const lab=title||ST_LABEL[kind]||"";
  return `<span class="st ${kind}" role="img" aria-label="${esc(lab)}" title="${esc(lab)}">${g}</span>`;
}
function dnums(l1, v1, l2, v2){
  return `<div class="dnums"><div><div class="l">${l1}</div><div class="v">${v1}</div></div>`+
         `<div><div class="l">${l2}</div><div class="v">${v2}</div></div></div>`;
}
// Anneaux “à la HYCU”: extérieur (épais) = première mesure, intérieur (fin) = seconde.
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

// ----- Pages: chargement des données à l'affichage (+ rafraîchissement) -----
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
// Clé de sélection = cluster|namespace (vue “All clusters”: un même nom de
// namespace peut exister sur plusieurs clusters).
// Clé d'une ligne: cluster | namespace | application (plusieurs applications par namespace).
const appKey=a=>(a.cluster_id||ACTIVE_CID)+"|"+(a.namespace||a.name)+"|"+a.name;
const appNs=a=>a.namespace||a.name;
// Libellé du type d'application (stateful = monte des volumes; stateless = configuration seule).
function appTypeCell(a){
  if(a.missing) return '<span class="badge b-lost">Deleted — restorable</span>'+(a.type==="stateless"?' <span class="hint">stateless</span>':"");
  if(a.type==="stateful") return '<span class="badge b-bound">Stateful</span> <span class="hint">'+(a.volumes||0)+' volume(s)</span>'+(a.unassigned?' <span class="hint">· no workload</span>':"");
  if(a.type==="stateless") return '<span class="badge b-pending">Stateless</span> <span class="hint">'+((a.workloads||[]).length)+' workload(s)</span>';
  if(a.type==="empty") return '<span class="badge b-na">Empty</span>';
  return '<span class="badge b-na">Namespace</span>';
}
function updateScopeSeg(){
  const multi=CLUSTERS.length>1;
  $("#appsScope").style.display = multi ? "": "none";
  if(!multi) appsScope="one";
  else if(prefs().appsScope==="all") appsScope="all";
  document.querySelectorAll("#appsScope button").forEach(b=>b.classList.toggle("on", b.dataset.scope===appsScope));
}
document.querySelectorAll("#appsScope button").forEach(b=>b.onclick=()=>{
  appsScope=b.dataset.scope; savePref("appsScope", appsScope); appsSel.clear();
  document.querySelectorAll("#appsScope button").forEach(x=>x.classList.toggle("on", x===b));
  loadApps();
});
// `fresh` (bouton Actualiser): ignore le cache serveur de l'inventaire (apps_cache_ttl_s).
async function loadApps(fresh){
  $("#appsRefresh").classList.add("busy");
  const all = appsScope==="all";
  const r=await get("/api/applications?"+(all ? "scope=all": "scope=one")+(fresh ? "&fresh=1": ""));
  $("#appsRefresh").classList.remove("busy");
  apps=(r.apps||[]).map(a=>all ? a: Object.assign({}, a, {cluster_id:ACTIVE_CID}));
  appsFresh=r.freshness_hours||24; appsPolicy=r.policy||{};
  appsClErr = all ? (r.clusters||[]).filter(c=>!c.ok && !c.skipped): [];
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
function appPolicyLabel(a){
  const p=(a && a.policy) || null;
  if(p && p.name) return p.name+" · "+(p.enabled ? (+p.interval_hours)+" h": "paused");
  const d = p || appsPolicy;
  return d.enabled ? ("Automatic configuration · "+Math.round(d.interval_hours||24)+" h"): "None";
}
function appsVisible(){
  const q=($("#appsSearch").value||"").trim().toLowerCase();
  const hideDel=$("#appsHideDel").checked;
  return apps.filter(a=>!(hideDel && a.missing) && (!q || a.name.toLowerCase().includes(q) || appNs(a).toLowerCase().includes(q)
                           || (a.cluster||"").toLowerCase().includes(q) || (a.workspace||"").toLowerCase().includes(q)));
}
// Pagination: au-delà de APPS_PAGE_SIZE lignes (grands clusters), le tableau est
// découpé en pages; la recherche s'applique à toutes les lignes, la sélection persiste.
const APPS_PAGE_SIZE=100; let appsPage=0;
function appsPageRows(rows){
  const nPages=Math.max(1, Math.ceil(rows.length/APPS_PAGE_SIZE));
  if(appsPage>=nPages) appsPage=nPages-1;
  const pg=$("#appsPager");
  if(rows.length<=APPS_PAGE_SIZE){ pg.style.display="none"; pg.innerHTML=""; return rows; }
  const from=appsPage*APPS_PAGE_SIZE, to=Math.min(rows.length, from+APPS_PAGE_SIZE);
  pg.style.display="";
  pg.innerHTML=`<button class="pact" type="button" id="appsPrev" ${appsPage===0?"disabled":""} title="Previous page">‹</button> `+
    `<span>${from+1}–${to} / ${rows.length}</span> `+
    `<button class="pact" type="button" id="appsNext" ${appsPage>=nPages-1?"disabled":""} title="Next page">›</button>`;
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
                             `<span class="ge">${stIc("ko")} ${esc(c.error||"unreachable")}</span></td></tr>`; });
  if(!rows.length){
    h+=`<tr><td colspan="11" class="tempty">${apps.length
      ? "No application matches the search."
     : "No namespace to display — check the kubectl context or the namespace filter."}</td></tr>`;
  } else {
    let grp=null;
    h+=rows.map(a=>{
      let g="";
      const gk=(a.workspace||"")+"|"+(a.cluster_id||"");
      if(all && gk!==grp){ grp=gk;
        g=`<tr class="grp"><td colspan="11">${a.workspace?esc(a.workspace)+'<span class="gs">›</span>':""}${esc(a.cluster||"")}`+
          `${a.cluster_id===ACTIVE_CID?'<span class="tag">ACTIVE</span>':''}</td></tr>`; }
      const k=appKey(a), sel=appsSel.has(k);
      const comp = a.missing ? stIc("na","Namespace deleted from the cluster")
                : a.compliant ? stIc("ok","Recent configuration backup")
                : (a.protected ? stIc("ko","Last backup older than its policy interval")
                               : stIc("na","Never backed up"));
      // Protection = sauvegardes du NAMESPACE; un volume de l'application absent de la
      // dernière sauvegarde (PVC créé depuis) rend sa protection incomplète.
      const unb=(a.unbacked_pvcs||[]);
      const prot = !a.protected ? stIc("na","No configuration backup")
                : (unb.length && !a.missing) ? stIc("wn", "Volume(s) missing from the latest backup: "+unb.join(", ")+" — run a backup again")
                : stIc("ok", a.backups+" configuration backup(s) of the namespace");
      const last = a.last_backup ? esc(fmtAgo(a.last_backup)): '<span style="color:var(--muted)">Never</span>';
      const nameCell = (a.unassigned ? '<i>'+esc(a.name)+'</i>': esc(a.name))
        + (a.whole_ns && !a.missing && a.type!=="empty" ? ' <span class="hint">(whole namespace)</span>': '');
      return g+`<tr class="clk${sel?' sel':''}" data-k="${esc(k)}"${a.missing?' style="opacity:.75"':''}>
        <td class="cb"><input type="checkbox" tabindex="-1" ${sel?"checked":""}></td>
        <td style="color:var(--strong);font-weight:500">${nameCell}</td><td>${esc(appNs(a))}</td>
        <td class="mc">${esc(a.workspace||"—")}</td><td class="mc">${esc(a.cluster||"")}</td>
        <td>${appTypeCell(a)}</td><td>${esc(appPolicyLabel(a))}</td>
        <td class="ctr">${comp}</td><td class="ctr">${prot}</td><td>${last}</td>
        <td class="ctr">${a.backups||0}</td></tr>`;
    }).join("");
  }
  $("#appsBody").innerHTML=h;
  // Sélection: on met à jour LA ligne cliquée (pas de reconstruction du tableau —
  // coûteuse à 1 000 lignes), puis les actions et la case “tout”.
  document.querySelectorAll("#appsBody tr.clk").forEach(tr=>tr.onclick=()=>{
    const k=tr.dataset.k, on=!appsSel.has(k);
    on ? appsSel.add(k): appsSel.delete(k);
    tr.classList.toggle("sel", on); const c=tr.querySelector('input[type="checkbox"]'); if(c) c.checked=on;
    $("#appsAll").checked = rows.length>0 && rows.every(a=>appsSel.has(appKey(a)));
    updateAppActs(); });
  $("#appsAll").checked = rows.length>0 && rows.every(a=>appsSel.has(appKey(a)));
  updateAppActs();
}
function selAppObjs(){ return apps.filter(a=>appsSel.has(appKey(a))); }
// Namespaces distincts de la sélection (la sauvegarde est par namespace: deux
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
  $("#actVerify").disabled = n!==1 || anyMissing;
  // Purger: les versions d'UN namespace (une ou plusieurs applications de ce namespace).
  $("#actPurge").disabled = !(n>=1 && new Set(objs.map(a=>(a.cluster_id||ACTIVE_CID)+"|"+appNs(a))).size===1 && objs.some(a=>a.backups));
  // Set Policy: une ou PLUSIEURS applications (du même cluster) en une fois.
  const oneCluster = n>=1 && new Set(objs.map(a=>a.cluster_id||ACTIVE_CID)).size===1;
  $("#actPolicy").disabled = !oneCluster || anyMissing || anyEmpty;
  // Restaurer: une application, OU plusieurs applications du MÊME namespace (= tout le
  // namespace, ex. mariadb + wordpress séparés par leurs étiquettes). Un namespace vide
  // reste restaurable s'il a des sauvegardes (application supprimée mais namespace
  // conservé) — restaurer une app SUPPRIMÉE est le cas clé.
  const sameNs = n>=1 && new Set(objs.map(a=>(a.cluster_id||ACTIVE_CID)+"|"+appNs(a))).size===1;
  $("#actRestore").disabled = !sameNs || (anyEmpty && !objs[0].protected);
  const rs=$("#actRestore span"); if(rs){ if(!rs.dataset.lbl) rs.dataset.lbl=rs.textContent;
    rs.textContent = (sameNs && n>1) ? "Restore the namespace": rs.dataset.lbl; }
}
// Opération sur UNE application d'un autre cluster (vue “All clusters”): on
// bascule d'abord le cluster actif, pour que confirmations et garde-fous le désignent.
async function ensureCluster(a){ if(a && a.cluster_id && a.cluster_id!==ACTIVE_CID) await setActiveCluster(a.cluster_id); }
$("#appsSearch").oninput=()=>{ appsPage=0; renderApps(); };
$("#appsHideDel").checked=!!prefs().hideDeleted;
$("#appsHideDel").onchange=()=>{ savePref("hideDeleted", $("#appsHideDel").checked); appsPage=0; renderApps(); };
// “Tout sélectionner” porte sur la PAGE affichée (jamais 1 000 lignes d'un coup à l'insu de l'opérateur).
$("#appsAll").onchange=()=>{ const on=$("#appsAll").checked;
  appsVisible().slice(appsPage*APPS_PAGE_SIZE, (appsPage+1)*APPS_PAGE_SIZE).forEach(a=>on ? appsSel.add(appKey(a)): appsSel.delete(appKey(a))); renderApps(); };
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
  openRestoreModal(appNs(a), objs.length>1 ? null: a); };
$("#actPolicy").onclick=async()=>{ const objs=selNsObjs(); await ensureCluster(objs[0]); openPolicyModal(objs.length>1 ? objs.map(a=>a.name): appNs(selAppObjs()[0])); };
// ----- Purge des versions de configuration d'un namespace -----
let purgeNs="", purgeRows=[];
const KIND_LBL={auto:"Automatic", manual:"Manual", pre_restore:"Before restore"};
function purgeSync(){ $("#purgeGo").disabled = !document.querySelectorAll(".purgeChk:checked").length; }
async function openPurgeModal(ns){
  purgeNs=ns; purgeRows=[];
  $("#mPurgeTitle").innerHTML=esc("Saved versions")+'<span class="sep">›</span>'+esc(ns);
  $("#purgeMsg").innerHTML=""; $("#purgeList").innerHTML='<div class="hint"><span class="spin"></span></div>';
  openModal("mPurge");
  const r=await get("/api/backups?ns="+encodeURIComponent(ns));
  purgeRows=r.backups||[];
  if(!purgeRows.length){ $("#purgeList").innerHTML='<div class="hint">No saved version.</div>'; purgeSync(); return; }
  $("#purgeList").innerHTML=`<div class="tcard" style="box-shadow:none;border:1px solid var(--rule)"><table class="ht"><thead><tr><th class="cb"></th><th>Date</th><th>Type</th><th class="ctr">Volumes</th></tr></thead><tbody>`+
    purgeRows.map((b,i)=>{ const ix=b.index||{};
      return `<tr><td class="cb"><input type="checkbox" class="purgeChk" data-i="${i}"></td><td>${esc(ix.created ? new Date(ix.created).toLocaleString(): b.timestamp)}${i===0?' <span class="hint">(most recent)</span>':''}</td>
        <td>${esc(KIND_LBL[ix.kind]||"—")}${ix.partial?' <span class="hint">partial</span>':''}</td><td class="ctr">${(ix.volumes||[]).length}</td></tr>`; }).join("")+`</tbody></table></div>`;
  document.querySelectorAll(".purgeChk").forEach(c=>c.onchange=purgeSync);
  purgeSync();
}
$("#purgeOld").onclick=()=>{ document.querySelectorAll(".purgeChk").forEach(c=>c.checked = +c.dataset.i>0); purgeSync(); };
$("#purgeGo").onclick=async()=>{
  const sel=[...document.querySelectorAll(".purgeChk:checked")].map(c=>purgeRows[+c.dataset.i]);
  if(!sel.length) return;
  const all = sel.length===purgeRows.length;
  if(!(await confirmDanger({title:"Delete versions", lines:[
     "<b>"+sel.length+"</b> configuration version(s) of <b>"+esc(purgeNs)+"</b> will be permanently deleted.",
     all ? "<b>All</b> versions are selected: this application can no longer be restored from the tool.": "The volume data (HYCU) is not touched."]}))) return;
  const b=$("#purgeGo"); b.disabled=true;
  const r=await post("/api/backups/delete",{ns:purgeNs, paths:sel.map(x=>x.path)});
  $("#purgeMsg").innerHTML = r.ok ? `<div class="note" style="margin-top:8px">${esc(r.removed+" version(s) deleted.")}</div>`: errBox(r.error);
  await openPurgeModal(purgeNs);
  if(r.removed) loadApps(true);
};
$("#actPurge").onclick=async()=>{ const a=selAppObjs()[0]; await ensureCluster(a); openPurgeModal(appNs(a)); };
$("#actVerify").onclick=async()=>{ const a=selAppObjs()[0]; await ensureCluster(a); gotoVerify(appNs(a), false); };

// ============================ Modale Sauvegarde ============================
// Actions principales dans le pied de modale (comme HYCU): on y DÉPLACE les boutons
// existants — leurs gestionnaires d'événements suivent l'élément.
$("#mBackupFoot").append($("#bkRunAll"), $("#bkRun"));
let bkSel=[], bkObjs=[];
function openBackupModal(list, objs){
  bkSel=(list||[]).filter(Boolean);
  bkObjs=(objs && objs.length===bkSel.length) ? objs: bkSel.map(n=>({name:n, cluster_id:ACTIVE_CID}));
  const multi=bkSel.length>1, multiCl=new Set(bkObjs.map(o=>o.cluster_id)).size>1;
  $("#bkOut").innerHTML="";
  $("#bkNsRow").style.display = multi ? "none": "";
  $("#bkSelInfo").style.display = multi ? "": "none";
  $("#bkRun").style.display = multi ? "none": "";
  $("#bkRunAll").style.display = multi ? "none": "";
  $("#bkRunSel").style.display = multi ? "": "none";
  if(multi){ $("#bkSelList").textContent=bkObjs.map(o=>multiCl ? o.name+" ("+(o.cluster||o.cluster_id)+")": o.name).join(", ");
             $("#bkRunSel").textContent="Back up the selection ("+bkSel.length+")"; }
  else if(bkSel[0]){ state.ns=bkSel[0]; applyGlobalNs(); }
  openModal("mBackup");
}
$("#bkRunSel").onclick=async()=>{
  const b=$("#bkRunSel"), dest=$("#bkDest").value.trim(); b.disabled=true;
  const multiCl=new Set(bkObjs.map(o=>o.cluster_id)).size>1;
  let lines="", ok=0;
  for(const o of bkObjs){
    const lbl=multiCl ? o.name+" ("+(o.cluster||o.cluster_id)+")": o.name;
    $("#bkOut").innerHTML=`<div class="hint"><span class="spin"></span>${esc(lbl)}…</div><ul class="dlist">${lines}</ul>`;
    const r=await post("/api/backup",{ns:o.name, dest}, o.cluster_id);
    if(r.ok) ok++;
    lines+=`<li><span class="k" style="display:flex;gap:10px;align-items:center">${stIc(r.ok?"ok":"ko")}${esc(lbl)}</span>`+
           `<span class="v" style="font-weight:400">${r.ok ? r.count+" volume(s)": esc(r.error||"")}</span></li>`;
  }
  $("#bkOut").innerHTML=`<div class="note">${ok}/${bkObjs.length} namespace(s) backed up.</div><ul class="dlist" style="margin-top:8px">${lines}</ul>`;
  b.disabled=false;
};

// ============================ Modale Set Policy ============================
// ----- Politique de sauvegarde de la CONFIGURATION du/des namespace(s) de la fenêtre -----
let cfgPolNs=[], cfgPolAll=[];
async function loadCfgPolicy(nsList){
  cfgPolNs=nsList.filter(Boolean);
  const sel=$("#bkCfgPol"); $("#bkCfgPolMsg").textContent="";
  sel.innerHTML='<option value="">…</option>'; sel.disabled=true;
  const [ab, mem]=await Promise.all([get("/api/auto_backup"), get("/api/policy_members")]);
  cfgPolAll=(ab&&ab.policies)||[];
  const members=(mem&&mem.ok)?(mem.members||{}):{};
  const cur=new Set(cfgPolNs.map(ns=>{ for(const k in members){ if((members[k]||[]).includes(ns)) return k; } return ""; }));
  const curOne = cur.size===1 ? [...cur][0]: null;
  const defLbl = "Default"+(ab && ab.enabled ? " · "+Math.round(ab.interval_hours||24)+" h": " (disabled)");
  sel.innerHTML=(curOne===null?'<option value="__mixed">(different policies)</option>':"")+
    `<option value="">${esc(defLbl)}</option>`+
    cfgPolAll.map(p=>`<option value="${esc(p.name)}">${esc(p.name+" · "+(+p.interval_hours)+" h · "+p.keep+" versions")}</option>`).join("");
  sel.value = curOne===null ? "__mixed": curOne;
  sel.disabled=false;
}
$("#bkCfgPolSave").onclick=async()=>{
  const choice=$("#bkCfgPol").value;
  if(choice==="__mixed" || !cfgPolNs.length) return;
  const list=cfgPolAll.map(p=>{
    const nss=(p.namespaces||[]).filter(n=>!cfgPolNs.includes(n));
    if(p.name===choice) cfgPolNs.forEach(n=>{ if(!nss.includes(n)) nss.push(n); });
    return {name:p.name, namespaces:nss, label_selector:p.label_selector||"", interval_hours:+p.interval_hours,
            keep:+p.keep, enabled:p.enabled!==false, hycu_policy:p.hycu_policy||"", hycu_policy_name:p.hycu_policy_name||""};
  }).filter(p=>p.namespaces.length || p.label_selector);
  const dropped=cfgPolAll.filter(p=>!list.some(x=>x.name===p.name)).map(p=>p.name);
  if(dropped.length && !(await confirmDanger({title:"Policy without namespace", lines:[
      "Policy <b>"+esc(dropped.join(", "))+"</b> would no longer have any namespace or selector: it will be deleted."]}))) return;
  const b=$("#bkCfgPolSave"); b.disabled=true;
  const r=await post("/api/config",{config:{backup_policies:list}});
  b.disabled=false;
  if(!r.ok){ $("#bkCfgPolMsg").innerHTML=errBox(r.error); return; }
  await loadCfgPolicy(cfgPolNs);
  const now=$("#bkCfgPol").value;
  $("#bkCfgPolMsg").textContent = (now===choice) ? "Saved."
   : "Saved — but “"+(now||"Default")+"” still applies through its label selector.";
};
function openPolicyModal(ns){
  // ns: un namespace (chaîne) ou une liste de namespaces (plusieurs applications en une fois).
  bkNsList = Array.isArray(ns) ? ns.slice(): [];
  loadCfgPolicy(bkNsList.length ? bkNsList: [ns || $("#bkNs").value]);
  if(bkNsList.length){
    clearBkProtect();
    $("#mPolicyTitle").innerHTML=esc("Set Policy")+'<span class="sep">›</span>'+esc(bkNsList.length+" applications")
      +' <span class="hint" style="font-weight:400">'+esc(bkNsList.join(", "))+'</span>';
    openModal("mPolicy");
    if(conn.hycu && conn.hycu.connected) setTimeout(()=>$("#bkMatch").click(), 30);
    return;
  }
  if(ns){ state.ns=ns; applyGlobalNs(); $("#bkNs").value=ns;
    if($("#bkNs").value!==ns){                 // namespace disparu / kubectl en panne
      clearBkProtect(); openModal("mPolicy");
      $("#bkMatchOut").innerHTML=errBox("Namespace “"+ns+"” not found in the list — refresh Applications (kubectl unavailable?).");
      return;
    } }
  clearBkProtect();
  $("#mPolicyTitle").innerHTML=esc("Set Policy")+(ns ? '<span class="sep">›</span>'+esc(ns): "");
  openModal("mPolicy");
  if(conn.hycu && conn.hycu.connected) setTimeout(()=>$("#bkMatch").click(), 30);   // analyse: lecture seule
}

// ============================ Bulk restore (same cluster) ============================
// Plan (lecture seule) -> Simuler (journal, arrière-plan) -> Lancer (réel: simulation
// du même plan exigée par le serveur, confirmation du contexte); suivi par polling,
// arrêt propre et reprise (les namespaces déjà recréés ne sont jamais refaits).
let bulkPlan=null, bulkStatus=null, bulkTimer=null, bulkWasRunning=false, bulkPollErrors=0;
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
  $("#bulkReal").title = dry() ? "Turn off the Simulation banner to start the real run.": (!simOk ? "Simulate this plan first (without failure).": "");
  $("#bulkStop").style.display = running ? "": "none";
  $("#bulkResume").style.display = (j && !running && !j.done && j.items.some(it=>it.status!=="done")) ? "": "none";
}
async function bulkMakePlan(){
  const b=$("#bulkPlanBtn"); b.disabled=true;
  $("#bulkPlanOut").innerHTML='<div class="hint"><span class="spin"></span>Analysing backups and cluster…</div>';
  const r=await post("/api/bulk/plan",{as_of:$("#bulkAsOf").value, exclude:bulkExclude()});
  b.disabled=false;
  if(!r.ok){ bulkPlan=null; $("#bulkPlanOut").innerHTML=errBox(r.error); bulkSyncBtns(); return; }
  bulkPlan=r; $("#bulkPlanOut").innerHTML=bulkRenderPlan(r); bulkSyncBtns();
}
$("#bulkPlanBtn").onclick=bulkMakePlan;
function bulkRenderPlan(r){
  const rows=r.items.map(it=>`<tr><td style="color:var(--strong);font-weight:500">${esc(it.ns)}</td><td>${esc((it.created||it.timestamp||"").replace("T"," ").slice(0,16))}</td>
     <td>${it.stateless?'<span class="badge b-pending">Stateless</span>':(it.volumes.length+" volume(s)")}${it.partial?' <span class="badge b-lost">partial</span>':''}</td>
     <td>${(it.warnings||[]).length?'<span class="ko">⚠ '+esc(it.warnings.join(" · "))+'</span>':'<span class="ok">✓</span>'}</td></tr>`).join("");
  const sk=(r.skipped||[]).map(s=>`<li><b>${esc(s.ns)}</b> — ${esc(s.reason)}</li>`).join("");
  const warnN=r.items.filter(it=>(it.warnings||[]).length).length;
  return `<div class="note"><b>${r.items.length}</b> namespace(s) to recreate on <b>${esc(r.context||r.cluster||"?")}</b> · reference time ${esc((r.as_of_iso||"").replace("T"," "))}${warnN?` · <span class="ko">${warnN} with a warning</span>`:""}${r.vault_unlocked?"":' · <span class="ko">vault locked</span>'}${r.hycu?"":' · <span class="hint">HYCU not connected: vanished Volume Groups will not be restored</span>'}</div>
    ${r.items.length?`<div class="tcard" style="box-shadow:none;border:1px solid var(--rule);max-height:300px;overflow:auto"><table class="ht" id="bulkPlanTable"><thead><tr><th>Namespace</th><th>Backup</th><th>Content</th><th>Warnings</th></tr></thead><tbody>${rows}</tbody></table></div>`:'<div class="hint">No deleted namespace with a backup prior to the reference time.</div>'}
    ${sk?`<details style="margin-top:8px"><summary class="hint">${(r.skipped||[]).length} namespace(s) skipped</summary><ul class="dlist" style="margin-top:6px">${sk}</ul></details>`:""}`;
}
async function bulkStart(dryRun){
  let confirmedCtx="";
  if(!dryRun){
    const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||""): null;
    const res=await confirmDanger({title:"Confirm the bulk restore", requireText:needCtx, lines:[
      "<b>"+bulkPlan.items.length+"</b> namespace(s) will be RECREATED on <b>"+esc(ctxInfo.context||"?")+"</b> from their backups.",
      "Sequential, journaled execution; vanished Volume Groups will be restored by HYCU (real operations).",
      "Present namespaces are left untouched."]});
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
    const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||""): null;
    const res=await confirmDanger({title:"Resume the bulk restore", requireText:needCtx, lines:[
      "The remaining namespaces (pending, stopped or failed) will be recreated; those already recreated are not redone."]});
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
  const st=await get("/api/bulk/status");
  if(!st.ok){                                   // coupure passagère: on réessaie (borné), sans figer les boutons
    if(++bulkPollErrors<=30){ bulkTimer=setTimeout(bulkPoll, 3000); }
    else { $("#bulkRunOut").insertAdjacentHTML("beforeend", '<div class="hint">Tracking stopped (server unreachable) — reopen the window to resume tracking.</div>'); }
    return;
  }
  bulkPollErrors=0;
  bulkStatus=st; bulkRenderStatus(st); bulkSyncBtns();
  if(st.running){ bulkWasRunning=true; bulkTimer=setTimeout(bulkPoll, 2000); }
  else if(bulkWasRunning){ bulkWasRunning=false; loadApps(true); }   // namespaces recréés: inventaire à jour
}
function bulkRenderStatus(st){
  const j=st.journal; if(!j){ $("#bulkRunOut").innerHTML=""; return; }
  const c=st.counts, pct=c.total?Math.round(100*(c.done+c.failed)/c.total):0;
  const IC={done:"ok",failed:"ko",running:"run",pending:"na",stopped:"wn"};
  const head = st.running ? '<span class="spin"></span> Running': j.stopped ? "Stopped": j.done ? (c.failed ? "Finished with failures": "Finished"): "Interrupted";
  $("#bulkRunOut").innerHTML=`<div class="${j.dry?'warnbox':'note'}" id="bulkHead"><b>${j.dry?"Simulation":"Live"}</b> · ${head} · ${c.done+c.failed} / ${c.total} (${c.failed} failure(s)) · reference time ${esc((j.as_of||"").replace("T"," "))}${j.started?" · started "+esc(j.started.replace("T"," ")):""}</div>
    <div style="height:6px;background:var(--rule);border-radius:3px;margin:6px 0 10px"><div style="height:6px;width:${pct}%;background:#41327C;border-radius:3px"></div></div>
    <div class="tcard" style="box-shadow:none;border:1px solid var(--rule);max-height:320px;overflow:auto"><table class="ht" id="bulkStatusTable"><thead><tr><th>Namespace</th><th>State</th><th>Detail</th></tr></thead><tbody>${
      j.items.map(it=>`<tr><td style="color:var(--strong);font-weight:500">${esc(it.ns)}</td><td>${stIc(IC[it.status]||"na", it.status)} ${esc(it.status)}</td>
        <td>${it.error?'<span class="ko">'+esc(it.error)+'</span>':''}${(it.run_warnings||[]).length?'<div class="hint">⚠ '+esc(it.run_warnings.join(" · "))+'</div>':''}${(it.log||[]).length?`<details><summary class="hint">${it.log.length} step(s)</summary>${renderLog(it.log)}</details>`:''}</td></tr>`).join("")}</tbody></table></div>`;
}

// ============================ Modale Sources (engrenage) ============================
const SRC=[{key:"hycu", name:"HYCU", type:"Backup & restore (REST API)"},
           {key:"nutanix", name:"Prism Element", type:"Nutanix — Volume Groups (v2 API)"},
           {key:"prismcentral", name:"Prism Central", type:"Nutanix — multi-cluster (v3/v4 API)"},
           {key:"s3", name:"S3 object storage", type:"Backup export (optional)"},
           {key:"vault", name:"Credentials vault", type:"Encrypted storage (optional)"}];
let srcSel="hycu";
const CHK_SVG='<svg width="14" height="14" viewBox="0 0 18 18" aria-hidden="true"><path d="M4.5 9.4l3 3 6-6.4" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>';
function clById(id){ return CLUSTERS.find(c=>c.id===id); }
function clType(c){
  if(c.local) return "Kubernetes — local configuration";
  if(c.source==="nkp") return "Kubernetes — NKP"+(c.workspace?" (workspace "+c.workspace+")":"");
  return "Kubernetes — imported kubeconfig";
}
function clStatusIc(c){
  const h=c.health;
  if(h && !h.ok) return stIc("ko","Cluster unreachable (checked "+fmtAgo(h.at)+"): "+(h.error||""));
  if(c.local) return c.configured ? stIc("ok","Context: "+(c.context||"")): stIc("na","Not configured");
  const a=c.auth||{}, w=(a.warnings||[]).concat(c.warning?[c.warning]:[]).join(" ");
  if(a.level==="error") return stIc("ko", w);
  if(a.level==="warn" || c.warning) return stIc("wn", w);
  if(h && h.ok) return stIc("ok","Reachable ("+fmtAgo(h.at)+") · authentication: "+(a.type||"?"));
  return stIc("ok","Authentication: "+(a.type||"?"));
}
function renderSourcesTable(){
  const body=$("#srcBody"); if(!body) return;
  const row=(key, name, type, url, st)=>`<tr class="clk${key===srcSel?' sel':''}" data-key="${esc(key)}"><td>${name}</td><td>${esc(type)}</td>`+
           `<td><code>${esc(url||"—")}</code></td><td class="ctr">${st}</td></tr>`;
  let h=`<tr class="srcsec"><td colspan="4">HYCU &amp; Nutanix</td></tr>`;
  h+=SRC.map(s=>{
    let url="—", st;
    if(s.key==="vault"){
      st = (conn.vault && conn.vault.present) ? stIc("ok","Vault present"): stIc("na","No vault");
    } else {
      const x=conn[s.key]||{}; url=x.url||"—";
      if(s.key==="s3" && x.url) url=x.url+"/"+(x.bucket||"");
      st = x.connected ? stIc("ok","Connected"): (x.configured ? stIc("wn","Configured, not connected"): stIc("na","Not configured"));
      if(s.key==="s3" && x.connected && !x.auto_upload) st=stIc("wn","Connected — automatic export disabled");
    }
    return row(s.key, esc(s.name), s.type, url, st);
  }).join("");
  h+=`<tr class="srcsec"><td colspan="4">Kubernetes clusters</td></tr>`;
  h+=CLUSTERS.map(c=>row("cluster:"+c.id, esc(c.name)+(c.id===ACTIVE_CID?'<span class="tag">ACTIVE</span>':''),
        clType(c), c.local ? (c.kubeconfig_path||"default kubeconfig"): c.server, clStatusIc(c))).join("");
  body.innerHTML=h;
  body.querySelectorAll("tr.clk").forEach(tr=>tr.onclick=()=>{ srcSel=tr.dataset.key; showSourceCard(); renderSourcesTable(); });
}
function showSourceCard(){
  const card = srcSel.indexOf("cluster:")===0 ? "cluster": srcSel;
  document.querySelectorAll("#tab-connect > .card").forEach(c=>c.style.display = c.dataset.card===card ? "": "none");
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

// ----- Clusters Kubernetes: liste, sélecteur de la barre du haut, cluster actif -----
async function loadClusters(){
  const r=await get("/api/clusters","local");
  if(r && r.ok) CLUSTERS=r.clusters||CLUSTERS;
  if(!clById(ACTIVE_CID)) ACTIVE_CID="local";      // cluster retiré / session verrouillée
  renderClMenu(); renderSourcesTable(); updateScopeSeg();
  return CLUSTERS;
}
function renderCtx(){
  $("#ctx").textContent = ctxInfo.context || "unavailable";
  $("#ctxWarn").innerHTML = (ctxInfo.context && ctxInfo.allowed && ctxInfo.allowed.length && !ctxInfo.context_ok)
    ? ' <span class="bad">⚠ not in allowed list</span>'
   : ((ctxInfo.auth && ctxInfo.auth.level==="error") ? ' <span class="bad">⚠ token expired</span>': '');
  $("#ctxLink").title = "Active Kubernetes cluster"+(ctxInfo.workspace?(" — workspace "+ctxInfo.workspace):"")+" — click to choose another one";
}
function renderClMenu(){
  const m=$("#clMenu");
  m.innerHTML=CLUSTERS.map(c=>`<div class="cli${c.id===ACTIVE_CID?' on':''}" data-cid="${esc(c.id)}" role="menuitem">`+
      `<span class="chk">${c.id===ACTIVE_CID?CHK_SVG:''}</span><span>${esc(c.name)}</span>`+
      `<span class="ws">${esc(c.local ? "local configuration": (c.workspace || "imported kubeconfig"))}</span></div>`).join("")+
    `<div class="msep"></div><div class="cli act" data-act="add" role="menuitem"><span class="chk"></span>Add a Kubernetes cluster…</div>`+
    `<div class="cli act" data-act="manage" role="menuitem"><span class="chk"></span>Manage clusters…</div>`;
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
  if(vfTrack) vfStop();                             // ni à un changement de cluster
  ["mBackup","mPolicy","mRestore"].forEach(closeModal);
  if(appsScope!=="all") appsSel.clear();
  state.ns=null;
  ctxInfo=await get("/api/context");
  renderCtx(); renderKubeBanner(); renderClMenu(); renderSourcesTable();
  if($("#mSources").style.display!=="none") showSourceCard();
  await refreshNamespaces();
  onPageShown(curPage);
}
// Coffre déverrouillé: les clusters mémorisés reviennent -> reprendre le cluster préféré.
async function afterVaultLoad(){
  await loadClusters();
  const p=prefs().cluster;
  if(p && p!==ACTIVE_CID && clById(p)) await setActiveCluster(p);
}
function renderClusterCard(cid){
  const c=clById(cid); $("#clDErr").innerHTML="";
  if(!c){ $("#clDTitle").textContent="Cluster"; $("#clDBody").innerHTML='<div class="hint">Cluster not found.</div>'; return; }
  $("#clDTitle").textContent=c.name;
  const li=(k,v)=>`<li><span class="k">${k}</span><span class="v">${v}</span></li>`;
  let h='<ul class="dlist">';
  h+=li("Type", esc(clType(c)));
  if(c.local){
    h+=li("kubectl context", c.context?`<code>${esc(c.context)}</code>`:"—");
    h+=li("Kubeconfig", `<code>${esc(c.kubeconfig_path||"default kubeconfig")}</code>`);
  } else {
    h+=li("kubectl context", `<code>${esc(c.context)}</code>`);
    h+=li("API server", `<code>${esc(c.server||"—")}</code>`);
    if(c.workspace) h+=li("NKP workspace", esc(c.workspace));
    if(c.management) h+=li("Management cluster", esc(c.management));
    h+=li("Authentication", esc((c.auth||{}).type||"?")+" "+clStatusIc(c));
  }
  h+=li("Backups", c.local ? `<code>hycu-backups/_contexts/${esc(c.context||"…")}/&lt;namespace&gt;/</code>`: `<code>hycu-backups/_clusters/${esc(c.id)}/&lt;namespace&gt;/</code>`);
  if(c.health) h+=li("Last health check", (c.health.ok?stIc("ok","Reachable"):stIc("ko",esc(c.health.error||"")))+" "+esc(fmtAgo(c.health.at)));
  h+='</ul>';
  if(c.health && !c.health.ok) h+=`<div class="err" style="margin-top:10px">Cluster unreachable at last check: ${esc(c.health.error||"")}</div>`;
  const w=((c.auth||{}).warnings||[]).concat(c.warning?[c.warning]:[]);
  if(w.length) h+=`<div class="warnbox" style="margin-top:10px">⚠ ${w.map(esc).join("<br>")}</div>`;
  if(c.local && !c.configured) h+=`<div class="warnbox" style="margin-top:10px">No local kubectl context: add a cluster with its kubeconfig, or configure kubectl (Settings).</div>`;
  $("#clDBody").innerHTML=h;
  $("#clUse").disabled = c.id===ACTIVE_CID;
  $("#clUse").textContent = c.id===ACTIVE_CID ? "Active cluster": "Set as active cluster";
  $("#clRemove").style.display = c.local ? "none": "";
  $("#clLocalCfg").style.display = c.local ? "": "none";
  $("#clUse").onclick=()=>setActiveCluster(c.id);
  $("#clLocalCfg").onclick=()=>{ closeModal("mSources"); switchTab("settings"); };
  $("#clRemove").onclick=async()=>{
    if(!confirm("Remove cluster “"+c.name+"”? Its kubeconfig is forgotten; its backups stay on disk.")) return;
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
  $("#clCtxInfo").innerHTML=`<ul class="dlist" style="margin-top:8px"><li><span class="k">API server</span><span class="v"><code>${esc(c.server||"—")}</code></span></li>`+
    `<li><span class="k">Authentication</span><span class="v">${esc(a.type||"?")} ${a.level==="error"?stIc("ko"):a.level==="warn"?stIc("wn"):stIc("ok")}</span></li></ul>`+
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
  if(f.size>1024*1024){ $("#clErr").innerHTML=errBox("Kubeconfig too large (1 MB max)."); return; }
  const rd=new FileReader(); rd.onload=()=>{ $("#clKc").value=rd.result; $("#clFile").value=""; clInspect(); }; rd.readAsText(f);
};
$("#clAdd").onclick=async()=>{
  const b=$("#clAdd"); $("#clErr").innerHTML="";
  if(!$("#clKc").value.trim()){ $("#clErr").innerHTML=errBox("Load or paste a kubeconfig first."); return; }
  b.disabled=true; b.innerHTML='<span class="spin"></span>Testing connection…';
  const r=await post("/api/clusters/add",{name:$("#clName").value.trim(), kubeconfig:$("#clKc").value,
                                          context:$("#clCtx").value||""},"local");
  b.disabled=false; b.textContent="Test & add";
  if(!r.ok){ $("#clErr").innerHTML=errBox(r.error); if(r.need_context) clInspect(); return; }
  $("#clKc").value=""; $("#clName").value=""; $("#clName").dataset.auto=""; $("#clCtxWrap").style.display="none"; clCtxs=[];
  await loadClusters();
  srcSel="cluster:"+r.cluster.id; renderSourcesTable(); showSourceCard();
  $("#clDErr").innerHTML=`<div class="note">Cluster added. Choose “Set as active cluster” to use it, or select it in the top bar.</div>`;
};

// ----- Découverte NKP (workspaces -> clusters) depuis le cluster de management actif -----
let nkpData=null;
function nkpSync(){
  const n=document.querySelectorAll(".nkpChk:checked").length;
  $("#nkpImport").disabled = !(n && $("#nkpAck").checked);
  $("#nkpImport").textContent = n ? "Import selection ("+n+")": "Import selection";
}
$("#nkpAck").onchange=nkpSync;
$("#nkpDiscover").onclick=()=>nkpLoad(false);
async function nkpLoad(keepRes){
  const b=$("#nkpDiscover"); if(!keepRes) $("#nkpRes").innerHTML=""; $("#nkpImportWrap").style.display="none";
  b.disabled=true; $("#nkpOut").innerHTML='<div class="hint"><span class="spin"></span>Reading workspaces…</div>';
  const r=await get("/api/nkp/discover"); b.disabled=false; nkpData=r;
  if(!r.ok){ $("#nkpOut").innerHTML=errBox(r.error); return; }
  const cl=r.clusters||[];
  if(!cl.length){ $("#nkpOut").innerHTML='<div class="hint">No cluster found in the workspaces.</div>'; return; }
  let h=`<div class="tcard" style="box-shadow:none;border:1px solid var(--rule);margin-top:12px"><table class="ht"><thead><tr><th class="cb"></th><th>Cluster</th><th>Phase</th><th>Status</th></tr></thead><tbody>`, ws=null;
  cl.forEach((c,i)=>{
    if(c.workspace!==ws){ ws=c.workspace; h+=`<tr class="grp"><td colspan="4">Workspace <span class="gs">›</span>${esc(ws)}</td></tr>`; }
    const dis=c.host||!!c.registered;
    const st=c.host ? "Management cluster (active)": (c.registered ? "Already imported ("+c.registered+")": "—");
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
    `<span class="v" style="font-weight:400">${x.ok ? "Imported as “"+esc(x.name)+"”"+(x.warning?" — "+esc(x.warning):""): esc(x.error||"")}</span></li>`).join("")+"</ul>":"");
  await loadClusters();
  if(r.imported) await nkpLoad(true);
};

// ============================ Politiques ============================
let polAll=[], polEditIdx=-1, polMembers={};
function polTarget(p){
  const parts=[];
  if((p.namespaces||[]).length) parts.push(p.namespaces.join(", "));
  if(p.label_selector) parts.push("label "+p.label_selector);
  return parts.join(" · ");
}
function polLast(x){ return x.last_run ? esc(fmtAgo(x.last_run))+" "+stIc(x.last_ok?"ok":"ko", x.last_summary||""): "—"; }
function polMemberHint(name){
  const m=polMembers[name];
  return m ? '<div class="hint" style="margin:2px 0 0">'+(m.length ? esc(m.length+" namespace(s): "+m.slice(0,8).join(", ")+(m.length>8?"…":"")): "no namespace currently")+'</div>': "";
}
async function loadPolicies(){
  await loadAutoBackup();
  const s=await get("/api/auto_backup")||{};
  const on=!!s.enabled;
  polAll=s.policies||[];
  const mem=await get("/api/policy_members"); polMembers=(mem&&mem.ok)?(mem.members||{}):{};
  let h=`<tr class="clk" data-i="-1">
    <td style="color:var(--strong);font-weight:500">Default</td>
    <td>Namespaces without another policy${polMemberHint("")}</td>
    <td>${on ? "Every "+Math.round(s.interval_hours||24)+" h": "—"}</td>
    <td>${abRetLabel(s)}</td><td>—</td>
    <td>${s.last_run ? esc(fmtAgo(s.last_run))+" "+stIc(s.last_ok?"ok":"ko", s.last_summary||""): "—"}</td>
    <td class="ctr">${on ? stIc("ok","Enabled"): stIc("na","Disabled")}</td></tr>`;
  h+=polAll.map((p,i)=>`<tr class="clk" data-i="${i}">
    <td style="color:var(--strong);font-weight:500">${esc(p.name)}</td>
    <td>${esc(polTarget(p))}${polMemberHint(p.name)}</td>
    <td>${"Every "+esc(String(+p.interval_hours))+" h"}</td>
    <td>${p.keep===0 ? "unlimited": esc(p.keep+" versions")}</td>
    <td>${esc(p.hycu_policy_name||"—")}</td>
    <td>${polLast(p)}</td>
    <td class="ctr">${p.enabled ? stIc("ok","Enabled"): stIc("na","Paused")}</td></tr>`).join("");
  $("#polBody").innerHTML=h;
  document.querySelectorAll("#polBody tr.clk").forEach(tr=>tr.onclick=()=>{
    const i=+tr.dataset.i;
    if(i<0){ $("#polEdit").style.display="none"; $("#abEnabled").scrollIntoView({behavior:"smooth", block:"center"}); }
    else polOpen(i);
  });
  if(mem && mem.selector_error) $("#polBody").insertAdjacentHTML("beforeend", `<tr><td colspan="7">${errBox(mem.selector_error)}</td></tr>`);
  if(conn.hycu && conn.hycu.connected){
    $("#polHycu").innerHTML='<div class="hint"><span class="spin"></span></div>';
    const p=await get("/api/hycu/policies");
    $("#polHycu").innerHTML = !p.ok ? errBox(p.error): ((p.policies||[]).length
      ? `<div class="tcard" style="box-shadow:none;border:1px solid var(--rule)"><table class="ht"><thead><tr><th>Name</th><th>UUID</th></tr></thead><tbody>`+
        p.policies.map(x=>`<tr><td>${esc(x.name||"—")}</td><td><code>${esc(x.uuid||"")}</code></td></tr>`).join("")+`</tbody></table></div>`
     : '<div class="hint">No HYCU policy.</div>');
  } else {
    $("#polHycu").innerHTML='<div class="hint">Register the HYCU source (⚙ at the top right) to display its policies.</div>';
  }
}
async function polHycuOptions(sel){
  const box=$("#peHycu");
  box.innerHTML='<option value="">(none)</option>';
  if(!(conn.hycu && conn.hycu.connected)){ box.innerHTML='<option value="">(connect HYCU to choose)</option>'; box.disabled=true; return; }
  box.disabled=false;
  const r=await get("/api/hycu/policies");
  (r.ok ? (r.policies||[]): []).forEach(x=>box.insertAdjacentHTML("beforeend", `<option value="${esc(x.uuid)}">${esc(x.name||x.uuid)}</option>`));
  box.value=sel||"";
}
function polOpen(i){
  polEditIdx=i;
  const p = i>=0 ? polAll[i]: {name:"", namespaces:[], label_selector:"", interval_hours:24, keep:15, enabled:true, hycu_policy:""};
  $("#polEditTitle").textContent = i>=0 ? "Policy “"+p.name+"”": "New policy";
  $("#peName").value=p.name; $("#peNs").value=(p.namespaces||[]).join(", "); $("#peSel").value=p.label_selector||"";
  $("#peInterval").value=p.interval_hours; $("#peKeep").value=p.keep; $("#peEnabled").checked=p.enabled!==false;
  $("#peDelete").style.display = i>=0 ? "": "none"; $("#peMsg").innerHTML="";
  $("#polEdit").style.display="block";
  polHycuOptions(p.hycu_policy);
  $("#polEdit").scrollIntoView({behavior:"smooth", block:"start"});
}
function polClean(p){ return {name:p.name, namespaces:p.namespaces||[], label_selector:p.label_selector||"",
  interval_hours:+p.interval_hours, keep:+p.keep, enabled:p.enabled!==false,
  hycu_policy:p.hycu_policy||"", hycu_policy_name:p.hycu_policy_name||""}; }
async function polSaveList(list){
  const r=await post("/api/config",{config:{backup_policies:list.map(polClean)}});
  if(!r.ok){ $("#peMsg").innerHTML=errBox(r.error||"Could not save."); return false; }
  $("#polEdit").style.display="none";
  await loadPolicies();
  return true;
}
$("#polNew").onclick=()=>polOpen(-1);
$("#peCancel").onclick=()=>{ $("#polEdit").style.display="none"; };
$("#peSave").onclick=async()=>{
  const hy=$("#peHycu");
  const p={name:$("#peName").value.trim(), namespaces:csv($("#peNs").value).map(x=>x.toLowerCase()),
    label_selector:$("#peSel").value.trim(),
    interval_hours:Math.max(0.25, parseFloat(String($("#peInterval").value).replace(",","."))||24),
    keep:Math.max(0, parseInt($("#peKeep").value)||0), enabled:$("#peEnabled").checked,
    hycu_policy:hy.value||"", hycu_policy_name:hy.value ? (hy.options[hy.selectedIndex].textContent||""): ""};
  if(!p.name){ $("#peMsg").innerHTML=errBox("Give the policy a name."); return; }
  if(!p.namespaces.length && !p.label_selector){ $("#peMsg").innerHTML=errBox("Enter namespaces or a label selector."); return; }
  const list=polAll.map(polClean);
  if(polEditIdx>=0) list[polEditIdx]=p; else list.push(p);
  await polSaveList(list);
};
$("#peDelete").onclick=async()=>{
  if(polEditIdx<0) return;
  const p=polAll[polEditIdx];
  if(!(await confirmDanger({title:"Delete the policy", lines:["Policy <b>"+esc(p.name)+"</b> will be deleted. Its namespaces will follow the default policy; existing backups are kept."]}))) return;
  await polSaveList(polAll.filter((_,i)=>i!==polEditIdx).map(polClean));
};
$("#abSave").addEventListener("click", ()=>setTimeout(()=>{ if(curPage==="policies") loadPolicies(); }, 900));

// ============================ Tâches ============================
const JOB_LBL={backup:"Configuration backup", backup_all:"Configuration backup (batch)",
  auto_backup:"Automatic backup", restore_end:"Kubernetes restore (PV/PVC)",
  clone_app:"Application clone", orchestrate_inplace:"In-place restore",
  hycu_restore:"HYCU restore (Volume Group)", hycu_protect:"HYCU protection",
  s3_upload:"S3 export (object storage)", s3_import:"S3 import (repatriation)",
  restore_objects:"Configuration objects restore"};
const JOB_ST={success:["ok","Success"], failed:["ko","Failed"], simulation:["sim","Simulation"]};
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
  return cell(c.success||0, stIc("ok"), "Success") + cell(c.failed||0, stIc("ko"), "Failed") +
         cell(c.simulation||0, stIc("sim"), "Simulation") +
         cell((r&&r.running)||0, stIc("run"), "In progress");
}
function jobRowData(j){
  const st=JOB_ST[j.status]||["na", j.status];
  const app = (j.target_namespace && j.target_namespace!==j.namespace)
    ? esc(j.namespace)+" → "+esc(j.target_namespace): esc(j.namespace||"—");
  const det = j.volumes!=null ? j.volumes+" volume(s)": (j.detail||"");
  return {st, app, det, lbl: JOB_LBL[j.event]||j.event};
}
function renderJobs(){
  const r=jobsData||{};
  $("#jobsCounts").innerHTML=jobCounts(r);
  const q=($("#jobsSearch").value||"").trim().toLowerCase();
  const rows=(r.jobs||[]).filter(j=>!q || (JOB_LBL[j.event]||j.event).toLowerCase().includes(q)
                                        || (j.namespace||"").toLowerCase().includes(q)
                                        || (j.cluster||"").toLowerCase().includes(q));
  $("#jobsInfo").textContent=rows.length+" job(s)"
    +((r.total||0)>(r.jobs||[]).length? " · showing the "+(r.jobs||[]).length+" most recent of "+r.total:"")
    +((r.retention_days||0)>0? " · history kept "+r.retention_days+" d (Settings)":"");
  $("#jobsBody").innerHTML = rows.length ? rows.map(j=>{ const d=jobRowData(j);
      return `<tr><td style="color:var(--strong)">${esc(d.lbl)}</td><td>${d.app}</td><td>${esc(j.cluster==="*"?"All":(j.cluster||"—"))}</td><td>${esc(d.det)}</td>`+
             `<td>${esc(fmtTs(j.ts))}</td><td class="ctr">${stIc(d.st[0], d.st[1])}</td></tr>`; }).join("")
   : `<tr><td colspan="6" class="tempty">No job recorded yet.</td></tr>`;
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
  return (i? n.toFixed(1): n)+" "+u[i];
}
function storageBar(pct){
  const col = pct>=90? "var(--red)": pct>=80? "var(--orange)": "var(--green)";
  return `<div style="height:8px;border-radius:4px;background:#EEF0F5;overflow:hidden;margin:4px 0 2px">
    <div style="width:${Math.min(100,pct)}%;height:100%;background:${col}"></div></div>`;
}
async function loadDashboard(){
  const [a, j, ab, st]=(await Promise.allSettled([get("/api/applications"), get("/api/jobs"), get("/api/auto_backup"), get("/api/storage")]))
    .map(x=>x.status==="fulfilled" ? x.value: {ok:false, error:String(x.reason||"error")});
  const alive=(a.apps||[]).filter(x=>!x.missing), n=alive.length;
  const prot=n ? Math.round(100*alive.filter(x=>x.protected).length/n): 0;
  const comp=n ? Math.round(100*alive.filter(x=>x.compliant).length/n): 0;
  const list=a.apps||[];
  $("#dbApps").innerHTML=donutSVG(prot, comp)+dnums("Protection", prot+"%", "Compliance", comp+"%");

  const on=!!ab.enabled;
  $("#dbPolicy").innerHTML=`<div style="display:flex;align-items:center;gap:10px;margin:4px 0 10px">${on ? stIc("ok"): stIc("na")}
      <span class="dbig" style="margin:0">${on ? "Enabled": "Disabled"}</span></div>
    <ul class="dlist">
      <li><span class="k">Frequency</span><span class="v">${on ? "Every "+Math.round(ab.interval_hours||24)+" h": "—"}</span></li>
      <li><span class="k">Retention</span><span class="v">${esc(abRetLabel(ab))}</span></li>
      <li><span class="k">Last run</span><span class="v">${ab.last_run ? esc(fmtAgo(ab.last_run))+" "+stIc(ab.last_ok?"ok":"ko"): "—"}</span></li>
      <li><span class="k">Next run</span><span class="v">${ab.next_due ? esc(new Date(ab.next_due*1000).toLocaleString()): "—"}</span></li>
      ${(ab.policies||[]).length ? `<li><span class="k">Other policies</span><span class="v">${esc((ab.policies||[]).map(p=>p.name).join(", "))}</span></li>`: ""}
    </ul>`;

  const keys=["hycu","nutanix","prismcentral"];
  const nConn=keys.filter(k=>conn[k] && conn[k].connected).length;
  const nConf=keys.filter(k=>conn[k] && conn[k].configured).length;
  $("#dbSources").innerHTML=donutSVG(Math.round(100*nConn/3), Math.round(100*nConf/3))+
    dnums("Connected", nConn+"/3", "Configured", nConf+"/3");
  $("#dbSources").style.cursor="pointer"; $("#dbSources").onclick=()=>openSources();
  $("#dbCluster").style.cursor="pointer"; $("#dbCluster").onclick=()=>openSources("cluster:"+ACTIVE_CID);

  $("#dbCluster").innerHTML=`<div class="dbig" style="font-size:21px;word-break:break-all">${esc(ctxInfo.context||"—")}</div>
    <div class="hint" style="margin:0 0 8px">${ctxInfo.workspace ? "Workspace "+esc(ctxInfo.workspace): "Active cluster"}</div>
    <ul class="dlist">
      <li><span class="k">kubectl</span><span class="v">${ctxInfo.kubectl_ok ? stIc("ok","Operational"): stIc("ko","Unavailable")}</span></li>
      <li><span class="k">Registered clusters</span><span class="v">${CLUSTERS.length}</span></li>
      <li><span class="k">Applications</span><span class="v">${n}</span></li>
      <li><span class="k">Namespaces</span><span class="v">${new Set(alive.map(x=>x.namespace||x.name)).size}</span></li>
      <li><span class="k">Namespace filter</span><span class="v">${a.filtered ? "Active": "None"}</span></li>
      <li><span class="k">Mode</span><span class="v">${dry() ? "Simulation": '<span class="ko">Real</span>'}</span></li>
    </ul>`;

  const roots=(st&&st.roots)||[];
  $("#dbStorage").innerHTML = roots.length? roots.map(x=>{
    if(!x.exists) return `<div class="hint">Folder missing: <code>${esc(x.path)}</code></div>`;
    const pct=x.disk_used_pct||0;
    const alert = pct>=90? ' <span class="bad" style="background:var(--red);color:#fff;border-radius:3px;padding:0 6px;font-size:11px">disk almost full</span>'
               : pct>=80? ' '+stIc("wn","Disk "+pct+"%"): "";
    return `<div style="margin-bottom:10px">
      <div class="hint" style="margin:0" title="${esc(x.path)}"><code>${esc(x.path.length>34? "…"+x.path.slice(-33):x.path)}</code>${alert}</div>
      ${storageBar(pct)}
      <div class="hint" style="margin:0">${pct}% used · ${esc(fmtBytes(x.disk_free))} free of ${esc(fmtBytes(x.disk_total))}</div>
      <ul class="dlist" style="margin-top:6px">
        <li><span class="k">Backups</span><span class="v">${x.backups_count||0} versions · ${esc(fmtBytes(x.backups_bytes))}</span></li>
        <li><span class="k">Audit log</span><span class="v">${esc(fmtBytes(x.audit_bytes))}</span></li>
        ${(st.quota_gb||0)>0? `<li><span class="k">Quota</span><span class="v">${(x.backups_bytes/1024/1024/1024).toFixed(1)} / ${st.quota_gb} Go${x.backups_bytes>st.quota_gb*1073741824? ' '+stIc("wn","Quota exceeded: oldest pruned at next pass"):''}</span></li>`:''}
      </ul></div>`;
  }).join(""): '<div class="tempty">—</div>';
  $("#dbStorage").innerHTML += (st.min_free_mb||0)>0? `<div class="hint" style="margin-top:2px">Guardrail: backup refused below ${st.min_free_mb} MB free.</div>`: "";
  $("#dbJobs").innerHTML=jobsChart(j.days)+`<div class="jcounts">${jobCounts(j)}</div>`;
  const last=(j.jobs||[]).slice(0, 5);
  $("#dbLast").innerHTML = last.length
    ? `<ul class="dlist">`+last.map(x=>{ const d=jobRowData(x);
        const ep=Date.parse(x.ts||"")/1000;
        return `<li><span class="k" style="display:flex;align-items:center;gap:8px;min-width:0">${stIc(d.st[0], d.st[1])}<span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(d.lbl)}`+
               `${x.namespace ? ' <span style="color:var(--muted)">· '+d.app+'</span>': ''}</span></span>`+
               `<span class="v" style="font-weight:400;color:var(--muted);white-space:nowrap">${esc(isNaN(ep)?"":fmtAgo(ep))}</span></li>`; }).join("")+
      `</ul><div style="margin-top:8px"><a href="#" class="lnk" data-go="jobs">View all jobs</a></div>`
   : `<div class="tempty">No job recorded yet.</div>`;
  bindGo($("#dbLast"));
  $("#dbHealth").innerHTML = CLUSTERS.length
    ? `<ul class="dlist">`+CLUSTERS.map(c=>{
        const h=c.health;
        const ic = h? (h.ok? stIc("ok","Reachable"): stIc("ko",h.error||"")): stIc("na","Not checked yet");
        return `<li><span class="k" style="display:flex;align-items:center;gap:8px">${ic}<span>${esc(c.name)}</span></span>`+
               `<span class="v" style="font-weight:400;color:var(--muted)">${h? esc(fmtAgo(h.at)): "—"}</span></li>`;}).join("")+
      `</ul><div style="margin-top:8px"><a href="#" class="lnk" id="dbHealthLnk">Manage clusters</a></div>`
   : '<div class="tempty">—</div>';
  const hl=$("#dbHealthLnk"); if(hl) hl.onclick=e=>{ e.preventDefault(); openSources("cluster:"+ACTIVE_CID); };
}

// ============================ Assistant de restauration ============================
const RS_TITLE="Application restore";
const RS_KINDS={cloneapp:"Restore the whole application (copy)",
                inplace:"Restore storage in place",
                reattach:"Restore storage to new volumes",
                objects:"Restore configuration objects",
                dr:"DR restore (another cluster / context)"};
var rsWizPage="type", rsWizKind=null, rsWizAct=null, rsWizHtml="", rsTgtMode=null;
$("#rsAdvBody").append($("#rsCustomDirLbl"), $("#rsCustomDirWrap"));   // options avancées repliées
function rsKindFromState(){ return state.mode==="inplace" ? "inplace": (state.cloneSub==="cloneapp" ? "cloneapp": "reattach"); }
function rsSyncOpts(){ document.querySelectorAll("#rsPgType .opt").forEach(o=>o.classList.toggle("sel", o.dataset.kind===rsWizKind)); }
function rsSyncTgtOpts(){ document.querySelectorAll("#rsPgTarget .opt").forEach(o=>o.classList.toggle("sel", o.dataset.nsmode===rsTgtMode)); }
// “Next” depuis la page Type: le clone d'application passe d'abord par la page
// “cible du clone” (2 cartes); les autres types vont directement au formulaire.
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
  setRsStep(p==="type" ? 1: p==="plan" ? 3: 2);
  $("#rsPgType").style.display = p==="type" ? "block": "none";
  $("#rsPgTarget").style.display = p==="target" ? "block": "none";
  $("#rsPgObjects").style.display = p==="objects" ? "block": "none";
  $("#rsPgDr").style.display = p==="dr" ? "block": "none";
  $("#rsPgForm").style.display = p==="form" ? "block": "none";
  $("#rsPgPlan").style.display = p==="plan" ? "block": "none";
  // Retour vers le formulaire: re-masquer #rsPlan, sinon le prochain “Next”
  // (qui re-affiche le plan avec la MÊME valeur display:block) ne déclenche aucune
  // mutation -> l'observer ne bascule jamais sur la page 3 (bouton muet).
  if(p!=="plan") $("#rsPlan").style.display="none";
  $("#mRestoreTitle").innerHTML = p==="type" ? esc(RS_TITLE)
   : esc(RS_TITLE)+'<span class="sep">›</span>'+esc(RS_KINDS[rsWizKind]||"");
  $("#rsWizBack").style.display = p==="type" ? "none": "";
  const b=$("#mRestore .hm-body"); if(b) b.scrollTop=0;
  rsWizSync();
}
// Libellé “namespace › application” de l'assistant (application ciblée, ou namespace entier).
function rsAppLabel(){
  const a=state.app;
  if(!a || a.whole_ns) return esc(state.ns||"—");
  // Lien “tout le namespace”: élargit la restauration à toutes les applications du
  // namespace (visible sur chaque page de l'assistant, pas seulement la page Type).
  return esc(state.ns||"—")+' <span class="sep">›</span> '+esc(a.name)+
    (a.type==="stateless" ? ' <span class="badge b-pending">Stateless</span>': a.type==="stateful" ? ' <span class="badge b-bound">Stateful</span>': "")+
    ' <a href="#" class="rsWholeNs" style="margin-left:8px;font-weight:400;font-size:12px">whole namespace</a>';
}
document.addEventListener("click", e=>{ const a=e.target.closest && e.target.closest(".rsWholeNs, #rsWholeNs");
  if(a){ e.preventDefault(); rsTargetWholeNs(); } });
function openRestoreModal(ns, app){
  rsNewSession();
  ns = ns || state.ns || $("#rsNs").value; if(!ns) return;
  state.ns=ns; applyGlobalNs();
  // Application ciblée (page Applications): {name, type, pvcs, whole_ns}. Sans
  // application (whole namespace), l'assistant se comporte comme avant.
  state.app = (app && app.name && !app.whole_ns) ? {ns:ns, name:app.name, type:app.type, pvcs:app.pvcs||[], workloads:app.workloads||[], unassigned:!!app.unassigned}: null;
  rsWizKind=rsKindFromState(); rsSyncOpts();
  $("#rsWizApp").innerHTML=rsAppLabel();
  $("#rsWizCluster").innerHTML=`<b>${esc(ctxInfo.context||"—")}</b>`;
  ["#rsLog","#rsInplaceLog","#rsErr"].forEach(id=>$(id).innerHTML="");
  if($("#rsCustomDir").checked) $("#rsAdvWrap").open=true;
  rsRenderAppNote();
  openModal("mRestore");
  // Application STATELESS: les parcours de stockage n'ont pas de sens -> seules les cartes
  // “copie” (clone des workloads + dépendances) et “objets de configuration” restent,
  // la seconde présélectionnée (restauration = ré-appliquer ses objets).
  // Namespace entier sans aucun volume (que des applications stateless): même règle.
  const nsApps = apps.filter(a=>appNs(a)===ns && (a.cluster_id||ACTIVE_CID)===ACTIVE_CID);
  const nsNoVol = !state.app && nsApps.length>0 && nsApps.every(a=>!(a.pvcs||[]).length && !a.volumes);
  const sl = !!(state.app && state.app.type==="stateless") || nsNoVol;
  // La DR reste proposée: une sauvegarde stateless se restaure aussi sur un autre cluster.
  document.querySelectorAll('#rsPgType .opt').forEach(o=>{ o.style.display = (sl && (o.dataset.kind==="inplace"||o.dataset.kind==="reattach")) ? "none": ""; });
  if(sl){ rsWizKind="objects"; rsSyncOpts(); }
  rsShowPage("type");
}
// Clone d'une application STATELESS (aucun volume): le formulaire n'a pas de volumes à
// cocher; le serveur copie les workloads de l'application (+ dépendances).
function rsStatelessClone(){ return !!(state.app && state.app.type==="stateless" && rsWizKind==="cloneapp"); }
// Note “application ciblée” de l'assistant, avec le lien “tout le namespace”: quand
// une application fonctionnelle est découpée en plusieurs applications par ses étiquettes
// (ex. mariadb + wordpress), l'opérateur élargit la restauration à tout le namespace.
function rsRenderAppNote(){
  const note=$("#rsAppNote"); if(!note) return;
  note.style.display = state.app ? "block": "none";
  const link=`<div style="margin-top:6px"><a href="#" id="rsWholeNs">Rather restore <b>the whole namespace “${esc(state.ns||"")}”</b> (all its applications)</a></div>`;
  note.innerHTML = !state.app ? "": (state.app.type==="stateless"
    ? `Application <b>${esc(state.app.name)}</b>: <b>stateless</b> (no volume). Restoring it = re-applying its configuration objects (workloads, Services, ConfigMaps…) from a backup snapshot — the <b>“configuration objects”</b> path, preselected.`
   : `Application <b>${esc(state.app.name)}</b>: <b>stateful</b> — its volumes (${esc(state.app.pvcs.join(", ")||"—")}) will be preselected; the other volumes of the namespace stay unticked.`)+link;
}
function rsTargetWholeNs(){
  state.app=null; rsRenderAppNote();
  document.querySelectorAll('#rsPgType .opt').forEach(o=>o.style.display="");   // tous les parcours de nouveau
  $("#rsWizApp").innerHTML=rsAppLabel(); const oa=$("#objApp"); if(oa) oa.innerHTML=rsAppLabel();
  if(rsWizPage==="form"){ rsToForm().then(()=>{ rsAutoCheck=true; document.querySelectorAll(".rsChk").forEach(c=>c.checked=true); rebuildVolCfgs(); }); }
  else if(rsWizPage==="objects"){ objLoadList(); }
  rsWizSync();
}
async function rsToForm(){
  if(!rsWizKind) return;
  const k=rsWizKind, clk=sel=>{ const b=document.querySelector(sel); if(b) b.click(); };
  if(k==="inplace") clk('#rsMode button[data-mode="inplace"]');
  else { clk('#rsMode button[data-mode="clone"]');
         clk('#rsCloneSub button[data-sub="'+(k==="cloneapp" ? "cloneapp": "reattach")+'"]'); }
  rsShowPage("form");
  rsAutoCheck=true;
  $("#rsPlan").style.display="none";
  $("#rsAdvWrap").style.display="";
  if(rsStatelessClone()){
    state.ns=$("#rsNs").value||state.ns; state.backup_path=null; state.selected={};
    // Copie depuis le cluster vivant: ni volumes, ni panneau HYCU, ni choix de sauvegarde.
    hyPanelSeq++; $("#rsVolCfgs").innerHTML=""; const ha=$("#rsHyActions"); if(ha) ha.innerHTML="";
    $("#rsBackupSelWrap").style.display="none"; $("#rsAdvWrap").style.display="none";
    $("#rsPvcs").innerHTML=`<div class="note">Application <b>${esc(state.app.name)}</b>: <b>stateless</b>, no volume to restore. The copy recreates its workloads (${esc((state.app.workloads||[]).map(w=>w.kind+"/"+w.name).join(", ")||"—")}) and their dependencies from the cluster.</div>`;
    $("#rsConfig").style.display="none"; setRsStep(2); rsWizSync(); return;
  }
  $("#rsPvcs").innerHTML='<div class="hint"><span class="spin"></span>Loading volumes…</div>';
  await loadPvcs();
  rsWizSync();
}
// UNE action principale dans le pied de modale, qui relaie le bouton d'origine adapté
// à l'étape (clone HYCU groupé, restauration sur place, construction du plan, lancement).
function rsWizSync(){
  const go=$("#rsWizGo"); let lbl="Next", dis=false, act=null, src=null;
  $("#rsWizBack").style.display = (rsDone || rsWizPage==="type" || rsWizKind==="recover") ? "none": "";
  if(rsDone){ lbl="Verify the application →"; act=()=>gotoVerify(rsDoneTarget, true); }
  else if(rsWizPage==="type"){ dis=!rsWizKind; act=rsNextFromType; }
  else if(rsWizPage==="dr"){
    const n=document.querySelectorAll(".drRef").length, nNfs=document.querySelectorAll(".drNfs").length;
    const filled=[...document.querySelectorAll(".drRef")].filter(t=>t.value.trim()).length;
    // Réutilisation des volumes d'origine: aucun UUID requis (le serveur les déduit
    // de la sauvegarde). Sinon, tous les volumes doivent avoir une référence. Une
    // sauvegarde STATELESS (aucun volume, workloads dans l'instantané) se restaure sans volume.
    const needRefs = !drRecoverReuse();
    const b=drSel(), noVol = !n && !!(b && b.stateless);
    lbl=dry()? "Restore (simulation)": "Restore";
    dis=!drAllowed || (!n && !nNfs && !noVol) || (needRefs && filled<n) || drBusy || !$("#drTargetNs").value.trim();
    act=drRun;
  }
  else if(rsWizPage==="objects"){
    const n=document.querySelectorAll(".objChk:checked").length;
    if(objPhase==="pick"){ lbl="Preview differences"; dis=!n || objBusy; act=objToDiff; }
    else { lbl=dry()? "Apply (simulation)": "Apply"; dis=!n || objBusy; act=objApply; }
  }
  else if(rsWizPage==="target"){ dis=!rsTgtMode; act=rsTargetToForm; }
  else if(rsWizPage==="form"){
    const n=document.querySelectorAll(".rsChk:checked").length;
    const hyOn=!!(conn.hycu && conn.hycu.connected);
    if(isCloneApp()){
      // Clone d'application: lancement DIRECT depuis cette étape (une seule confirmation),
      // clones HYCU compris; en simulation, aperçu sans rien créer.
      const items=collectItems(), filled=items.length>0 && items.every(refOk);
      const batch=$("#hyBatchGo"), pending=!!batch && !filled;
      lbl = dry() ? "Check the copy": "Launch the application clone";
      dis = cloneBusy || (!rsStatelessClone() && (!n || (pending && batch.disabled)));
      act = cloneAppDirect;
    }
    else if(state.mode==="inplace" && hyOn){ src=$("#rsInplaceRun"); lbl="Restore in place"; }
    else {
      const items=collectItems(), filled=items.length>0 && items.every(refOk);
      const batch=$("#hyBatchGo");
      if(batch && !filled){ src=batch; lbl="Clone the VGs in HYCU →"; }
      else { dis=!n; act=()=>$("#rsPreview").click(); }
    }
    if(src){ dis=!n || src.disabled; act=()=>src.click(); }
  } else { src=$("#rsGo"); lbl=(src.textContent||"").trim() || "Launch"; dis=src.disabled || cloneBusy; act=()=>src.click(); }
  const busy = src && src.querySelector(".spin");
  const html = busy ? '<span class="spin"></span>'+esc((src.textContent||"").trim()): esc(lbl);
  if(html!==rsWizHtml){ go.innerHTML=html; rsWizHtml=html; }
  go.disabled=dis; rsWizAct=act;
  const live=!dry(), m=$("#rsWizMode");
  m.textContent = live ? "": "Simulation";       // la production est le mode normal: rien à signaler
  m.className="badge sim"; m.style.display = live ? "none": "";
}
$("#rsWizGo").onclick=()=>{ if(rsWizAct && !$("#rsWizGo").disabled) rsWizAct(); };
$("#rsWizBack").onclick=()=>{
  if(rsWizPage==="dr") return rsShowPage("type");
  if(rsWizPage==="objects"){
    if(objPhase==="diff"){ objPhase="pick"; $("#objDiffWrap").style.display="none"; $("#objPick").style.display="block"; $("#objLog").innerHTML=""; rsWizSync(); return; }
    return rsShowPage("type");
  }
  rsShowPage(rsWizPage==="plan" ? "form"
   : (rsWizPage==="form" && rsWizKind==="cloneapp") ? "target": "type");
};

// ----- DR restore: reprise sur CE cluster depuis une sauvegarde étrangère -----
var drAllowed=false, drBusy=false, drBackups=[], drMode="dr", drRecoverNs=null;
// Application SUPPRIMÉE du cluster: récupération sur le MÊME cluster/contexte —
// mêmes mécanismes que la page DR (sources depuis la sauvegarde seule), mais SANS
// la dérogation allow_dr_restore (le serveur vérifie que la sauvegarde est d'ici).
function openRecoverModal(ns){
  rsNewSession();
  state.ns=ns; state.app=null;         // la récupération recrée tout le namespace
  document.querySelectorAll('#rsPgType .opt').forEach(o=>{ o.style.display=""; });   // (masquées pour une app stateless)
  const note=$("#rsAppNote"); if(note){ note.style.display="none"; note.innerHTML=""; }
  rsWizKind="recover"; rsSyncOpts();   // kind dédié: “Retour” puis “Next” ne devient jamais une DR
  ["#rsLog","#rsInplaceLog","#rsErr"].forEach(id=>{ const e=$(id); if(e) e.innerHTML=""; });
  openModal("mRestore");
  drOpen("recover", ns);
}
$("#drOpenCfg").onclick=()=>{ closeModal("mRestore"); switchTab("settings"); };
async function drOpen(mode, recoverNs){
  drMode = mode==="recover" ? "recover": "dr";
  drRecoverNs = drMode==="recover" ? (recoverNs||null): null;
  // Rien de l'ouverture précédente ne doit rester cliquable pendant le chargement :
  // occupé + listes vidées, jusqu'au rendu des sauvegardes fraîches.
  drBusy=true; drBackups=[]; $("#drVols").innerHTML=""; $("#drBackupSel").innerHTML=""; $("#drTargetNs").value="";
  $("#drLog").innerHTML=""; $("#drErr").innerHTML="";
  $("#drSc").value="";                 // jamais de remap hérité d'un parcours précédent
  $("#drRefs").checked=true;
  rsShowPage("dr");
  if(drMode==="recover"){
    $("#mRestoreTitle").innerHTML=esc(RS_TITLE)+'<span class="sep">›</span>'+esc("Restore the deleted application “"+recoverNs+"”");
    $("#drWarnDr").style.display="none"; $("#drWarnRec").style.display="block";
    $("#drReuseWrap").style.display="block"; $("#drReuse").checked=true;
  } else {
    $("#drWarnDr").style.display="block"; $("#drWarnRec").style.display="none";
    $("#drReuseWrap").style.display="none";
  }
  $("#drCluster").textContent=ctxInfo.context||"—";
  $("#drClusterRec").textContent=ctxInfo.context||"—";
  const r=await get("/api/dr/backups");
  // Récupération même-cluster: pas de dérogation requise — le serveur re-vérifie.
  drAllowed = drMode==="recover" ? !!r.ok: !!(r.ok && r.allowed);
  $("#drGate").style.display = drAllowed? "none":"block";
  $("#drForm").style.display = drAllowed? "block":"none";
  if(!drAllowed){ drBusy=false; rsWizSync(); return; }
  drBackups=(r.backups||[]).filter(b=> drMode==="recover"
    ? (b.restorable_here && b.namespace===drRecoverNs): true);
  $("#drBackupSel").innerHTML = drBackups.length? drBackups.map((b,i)=>
    `<option value="${i}">${esc(b.cluster)}${b.context&&b.cluster_id==="local"?" ("+esc(b.context)+")":""} › ${esc(b.namespace)} › ${esc(b.timestamp)}${b.imported?" · S3 import":""}</option>`).join("")
   : '<option value="">(no backup)</option>';
  drBusy=false;
  drRenderVols();
  rsWizSync();
}
$("#drBackupSel").onchange=()=>drRenderVols();
function drSel(){ return drBackups[+$("#drBackupSel").value]||null; }
// Récupération: par défaut on réutilise les volumes d'origine (case cochée) -> aucune
// saisie. La grille d'UUID n'apparaît que pour la reprise d'activité, ou si l'humain a
// restauré les données sur de NOUVEAUX volumes (case décochée).
function drRecoverReuse(){ return drMode==="recover" && $("#drReuse").checked; }
function drRenderVols(){
  const b=drSel();
  $("#drTargetNs").value=b? b.namespace: "";
  // Honnêteté: sauvegarde sans instantané de ressources -> volumes uniquement.
  $("#drNoRes").style.display = (b && b.has_resources===false)? "block":"none";
  // Secrets de la sauvegarde: masqués (non recréés) ou chiffrés (coffre à déverrouiller).
  const sn=$("#drSecretsNote"), sm=b&&b.secrets;
  if(sn){ sn.style.display = (sm==="redacted"||sm==="encrypted") ? "block": "none";
    sn.innerHTML = sm==="redacted" ? "The <b>Secrets</b> of this backup are <b>redacted</b>: they will not be recreated (recreate them by hand after the restore)."
     : sm==="encrypted" ? "The <b>Secrets</b> of this backup are <b>encrypted</b> with the vault passphrase: unlock the vault (⚙ → Sources) before starting, otherwise they will not be recreated.": ""; }
  const refs=(b&&b.vol_refs)||{};
  // En récupération, chaque champ est PRÉ-REMPLI avec l'UUID d'origine (issu de la
  // sauvegarde): l'humain n'a rien à taper. En DR, les champs restent vides (nouveaux VG).
  const nfsOf=(b&&b.vol_nfs)||{};
  $("#drVols").innerHTML = b && b.volumes.length? b.volumes.map(v=> nfsOf[v]
    ? `<div class="drVol drNfs" data-pvc="${esc(v)}"><div class="drVolNm">${esc(v)} <span class="badge b-na">NAS</span></div>
       <div class="hint" style="margin:0">${esc("Same NFS export ("+nfsOf[v]+"): nothing to enter, the data stays on the NAS.")}</div></div>`
   : `<div class="drVol"><div class="drVolNm">${esc(v)}</div>
     <input type="text" class="drRef" data-pvc="${esc(v)}" spellcheck="false" autocomplete="off"
       value="${drMode==="recover"&&refs[v]?esc(refs[v]):""}"
       placeholder="${esc(drMode==="recover"?"Volume Group UUID (8-4-4-4-12)":"UUID of the VG restored/cloned on the target site (8-4-4-4-12)")}"></div>`).join("")
   : (b && b.stateless ? '<div class="note"><b>Stateless</b> backup (no volume): the workloads'+((b.apps||[]).length?' ('+esc((b.apps||[]).join(", "))+')':'')+' and their dependencies will be recreated from the snapshot.</div>'
                       : '<div class="hint">No volume in this backup.</div>');
  document.querySelectorAll(".drRef").forEach(t=>t.oninput=rsWizSync);
  drSyncReuse();
}
// Bascule d'affichage de la grille selon “réutiliser les volumes d'origine”.
function drSyncReuse(){
  const reuse=drRecoverReuse(), bsel=drSel(), stateless=!!(bsel && bsel.stateless);
  // Sauvegarde STATELESS: aucun champ de volume (StorageClass, réutilisation, UUID, HYCU).
  $("#drScRow").style.display = stateless ? "none": "";
  $("#drReuseWrap").style.display = (drMode==="recover" && !stateless) ? "block": "none";
  $("#drVols").style.display = (reuse && !stateless)? "none":"block";
  $("#drVolsLabel").style.display = stateless ? "none": ((drMode==="recover")? (reuse?"none":"block"): "block");
  if(drMode==="recover") $("#drVolsLabel").textContent="New volumes — paste the ID (UUID) provided by HYCU";
  else $("#drVolsLabel").textContent="Volumes — paste the UUID of the VG restored/cloned on the target site";
  // Bouton “auto HYCU”: seulement quand la grille est visible ET HYCU + Prism connectés.
  const autoOk = !reuse && !stateless && !rsDone && (conn.hycu&&conn.hycu.connected)
                 && ((conn.prismcentral&&conn.prismcentral.connected)||(conn.nutanix&&conn.nutanix.connected));
  $("#drAutoWrap").style.display = autoOk? "block":"none";
  rsWizSync();
}
$("#drReuse").onchange=drSyncReuse;
// Auto-provisionnement: HYCU clone les VG et l'outil découvre leurs nouveaux UUID,
// qu'il inscrit dans la grille (aucune saisie). Simulation = plan seulement.
$("#drAuto").onclick=async()=>{
  const b=drSel(); if(!b) return;
  const refs=(b&&b.vol_refs)||{}, hy=(b&&b.vol_hycu)||{}, names=(b&&b.vol_names)||{};
  // Source pour HYCU = l'identité HYCU du VG (contrat) si disponible, sinon l'UUID Nutanix ;
  // le nom du VG aide à retrouver un VG SUPPRIMÉ du cluster dans le catalogue HYCU.
  const volumes=[...document.querySelectorAll(".drRef")].map(t=>({pvc:t.dataset.pvc,
    source_vg_uuid:hy[t.dataset.pvc]||refs[t.dataset.pvc]||"", vg_name:names[t.dataset.pvc]||""}));
  if(!volumes.length || volumes.some(v=>!v.source_vg_uuid)){
    $("#drErr").innerHTML=errBox("Source VG UUID missing from the backup: automation not possible, enter the UUIDs manually."); return; }
  if(!dry() && !(await confirmDanger({title:"Confirm the HYCU clones", lines:[
      "Clone in HYCU <b>"+volumes.length+"</b> Volume Group(s) (new VGs are created)?",
      "The new IDs will be filled into the grid automatically."]}))) return;
  const btn=$("#drAuto"); btn.disabled=true; drBusy=true; rsWizSync();
  $("#drErr").innerHTML=""; $("#drLog").innerHTML='<div class="hint"><span class="spin"></span>HYCU: creating the volumes…</div>';
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
  // Réutilisation des volumes d'origine: on n'envoie PAS d'UUID, le serveur le déduit
  // de la sauvegarde (source de vérité). Sinon on transmet ce que l'humain a saisi.
  const reuse=drRecoverReuse();
  const items=[...document.querySelectorAll(".drRef")].map(t=>({pvc:t.dataset.pvc, new_ref:reuse?"":t.value.trim()}))
    .concat([...document.querySelectorAll(".drNfs")].map(d=>({pvc:d.dataset.pvc, new_ref:""})));   // NAS: même export
  const live=!dry();
  let confirmedCtx="";
  if(live){
    const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||""): null;
    const res=await confirmDanger({title:(drMode==="recover"?"Confirm the deleted application restore":"Confirm the DR restore"), requireText:needCtx, lines:[
      "Source backup: <b>"+esc(b.cluster)+" › "+esc(b.namespace)+" › "+esc(b.timestamp)+"</b>",
      "TARGET cluster: <b>"+esc(ctxInfo.context||"?")+"</b> · target namespace: <b>"+esc($("#drTargetNs").value)+"</b>",
      drMode==="recover"
        ? "The application will be RECREATED on this cluster from the backup (namespace, PV/PVC, workloads, non-redacted dependencies)."
       : "The cross-cluster guard is LIFTED for this operation: the application will be recreated on this cluster from the backup (PV/PVC, workloads, non-redacted dependencies).",
      ...((drMode==="recover" && !b.stateless && drRecoverReuse() && conn.hycu && conn.hycu.connected)
        ? ["If an original volume has disappeared from the cluster, HYCU will restore it automatically before recreating."]: [])]});
    if(!res) return;
    if(typeof res==="string") confirmedCtx=res;
  }
  drBusy=true; rsWizSync();
  $("#drLog").innerHTML='<div class="hint"><span class="spin"></span>'+(drMode==="recover"?"Restoring the application…":"DR restore…")+'</div>';
  const body={namespace:b.namespace, target_namespace:$("#drTargetNs").value.trim(),
              backup_path:b.path, items, dry:dry(),
              dr_storageclass:$("#drSc").value.trim(), clone_refs:$("#drRefs").checked};
  if(drMode==="recover") body.from_backup_only=true; else body.dr_restore=true;
  if(live && ctxInfo.require_confirm) body.confirm_context=confirmedCtx;
  const sess=rsSession;
  const r=await runOp("/api/clone_app", body, log=>{ if(sess===rsSession) $("#drLog").innerHTML=renderLog(log); });
  if(sess!==rsSession) return;
  drBusy=false; rsWizSync();
  const reprot = b.stateless ? "": " Remember to re-protect its Volume Groups in HYCU.";
  const done = (drMode==="recover" ? "Application restore finished.": "DR restore finished.") + reprot;
  const head = r.ok? (r.dry? '<div class="note">Simulation — sequence that would be run.</div>'
                          : '<div class="note">'+done+'</div>')
                  : errBox(r.error || "Some steps failed — see details.");
  $("#drLog").innerHTML=head+cloneWarnings(r.warnings)+renderLog(r.log);
  if(r.ok && !r.dry) rsFinish(body.target_namespace || b.namespace, false, sess, true);
}

// ----- Restauration guidée des OBJETS de configuration (resources.json) -----
var objItems=[], objPhase="pick", objBusy=false, objBackups=[];
function objBody_(){ return {namespace:$("#rsNs").value||state.ns,
  backup_path:($("#objBackupSel").value||null), backup_root:state.backup_root||null,
  app:(state.app && !state.app.unassigned) ? state.app.name: null}; }
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
  $("#objBackupSel").innerHTML=objBackups.map(x=>`<option value="${esc(x.path)}">${esc(x.timestamp)} — ${((x.index||{}).volumes||[]).length} volume(s)${(x.index||{}).resources_count!=null?(" · "+(x.index||{}).resources_count+" objects"):""}</option>`).join("")
    || '<option value="">(no backup)</option>';
  await objLoadList();
}
$("#objBackupSel").onchange=()=>objLoadList();
async function objLoadList(){
  objBusy=true;
  // Nouvelle liste = retour à la sélection: jamais appliquer des objets d'une autre
  // sauvegarde que celle dont les différences sont affichées.
  objPhase="pick"; $("#objDiffWrap").style.display="none"; $("#objPick").style.display="block"; setRsStep(2);
  rsWizSync();
  $("#objErr").innerHTML=""; $("#objLog").innerHTML="";
  if(!$("#objBackupSel").value){
    $("#objBody").innerHTML='<tr><td colspan="4" class="tempty">No backup for this namespace — run a backup first (Applications → Back up).</td></tr>';
    objItems=[]; objBusy=false; rsWizSync(); return;
  }
  const r=await post("/api/objects/list", objBody_());
  objBusy=false;
  if(!r.ok){ $("#objBody").innerHTML=""; $("#objErr").innerHTML=errBox(r.error); objItems=[]; rsWizSync(); return; }
  objItems=r.items||[];
  // Application ciblée: ses objets sont marqués (in_app) et PRÉCOCHÉS; les objets des
  // autres applications du namespace sont masqués par défaut (case “seulement…”).
  const appOn = !!(r.app);
  $("#objOnlyAppWrap").style.display = appOn ? "": "none";
  $("#objInfo").textContent="("+objItems.length+" object(s) in the snapshot"+(appOn?(" · "+(r.app_count||0)+" of the application “"+r.app+"”"):"")+")";
  $("#objBody").innerHTML=objItems.length? objItems.map(o=>`<tr class="clk${o.redacted?'':' '}${appOn&&!o.in_app?' objOther':''}" data-i="${o.i}">
     <td class="cb"><input type="checkbox" class="objChk" data-i="${o.i}" ${o.redacted?"disabled":""} ${appOn&&o.in_app&&!o.redacted?"checked":""}></td>
     <td>${esc(o.kind)}</td><td style="color:var(--strong);font-weight:500">${esc(o.name)}</td>
     <td>${o.encrypted?'<span class="badge b-pending">Secret encrypted — unlock the vault</span>':o.redacted?'<span class="badge b-pending">Secret redacted — not restorable</span>':(appOn&&!o.in_app?'<span class="hint">other application / shared</span>':"")}</td></tr>`).join("")
   : '<tr><td colspan="4" class="tempty">Empty snapshot.</td></tr>';
  document.querySelectorAll("#objBody tr.clk").forEach(tr=>tr.onclick=e=>{
    if(e.target.classList.contains("objChk")) return rsWizSync();
    const c=tr.querySelector(".objChk"); if(c && !c.disabled){ c.checked=!c.checked; rsWizSync(); } });
  document.querySelectorAll(".objChk").forEach(c=>c.onchange=rsWizSync);
  $("#objAll").checked=false; objSyncOnlyApp(); rsWizSync();
}
function objSyncOnlyApp(){
  const only = $("#objOnlyAppWrap").style.display!=="none" && $("#objOnlyApp").checked;
  document.querySelectorAll("#objBody tr.objOther").forEach(tr=>{ tr.style.display = only ? "none": "";
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
  $("#objDiff").innerHTML='<div class="hint"><span class="spin"></span>Comparing with the live state…</div>';
  $("#objDiffWrap").style.display="block"; setRsStep(3);
  const r=await post("/api/objects/diff", Object.assign(objBody_(), {indexes:objSelIdx()}));
  objBusy=false;
  if(!r.ok){ $("#objDiffWrap").style.display="none"; $("#objErr").innerHTML=errBox(r.error); rsWizSync(); return; }
  const ST={identical:["ok","Identical to live — apply is a no-op"], differs:["wn","Differs from live"],
            absent:["run","Absent from live — will be (re)created"], error:["ko","Cannot read live state"],
            redacted:["ko","Secret redacted"]};
  $("#objDiff").innerHTML=(r.results||[]).map(x=>{
    const st=ST[x.status]||["na",x.status];
    const body = x.status==="differs" ? `<pre class="box" style="margin:6px 0 0;max-height:260px;overflow:auto">${esc(x.diff)}</pre>`
     : (x.error? `<div class="hint" style="color:var(--red)">${esc(x.error)}</div>`: "");
    return `<div class="repl" style="margin-bottom:10px"><div class="nm" style="display:flex;gap:10px;align-items:center">${stIc(st[0],st[1])}<b>${esc(x.kind)}/${esc(x.name)}</b><span class="hint">${esc(st[1])}</span></div>${body}</div>`;
  }).join("") || '<div class="hint">Nothing to compare.</div>';
  $("#objPick").style.display="none"; objPhase="diff"; rsWizSync();
}
async function objApply(){
  const live=!dry();
  let confirmedCtx="";
  if(live){
    const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||""): null;
    const res=await confirmDanger({title:"Confirm the object restore", requireText:needCtx, lines:[
      "Namespace: <b>"+esc($("#rsNs").value||state.ns||"?")+"</b>",
      "Target cluster: <b>"+esc(ctxInfo.context||"?")+"</b>",
      "<b>"+objSelIdx().length+"</b> configuration object(s) will be OVERWRITTEN by the backup version (kubectl apply). Volumes and data are untouched."]});
    if(!res) return;
    if(typeof res==="string") confirmedCtx=res;
  }
  objBusy=true; rsWizSync();
  $("#objLog").innerHTML='<div class="hint"><span class="spin"></span>Applying…</div>';
  const body=Object.assign(objBody_(), {indexes:objSelIdx(), dry:dry()});
  if(live && ctxInfo.require_confirm) body.confirm_context=confirmedCtx;
  const sess=rsSession;
  const r=await post("/api/objects/restore", body);
  if(sess!==rsSession) return;
  objBusy=false; rsWizSync();
  const head = r.ok? (r.dry? '<div class="warnbox">Simulation — commands that would be run.</div>'
                          : `<div class="note">${"Object restore finished: "+r.applied+" object(s) applied"}${r.skipped?(" · "+r.skipped+" skipped"):""}.</div>`)
                  : errBox(r.error);
  $("#objLog").innerHTML=head+renderLog(r.log);
  if(r.ok && !r.dry) rsFinish(body.namespace, !!r.skipped, sess);
}
setInterval(()=>{ if($("#mRestore").style.display!=="none") rsWizSync(); }, 300);
</script>
</body>
</html>"""
# <<< UI-END

# Mode développement : HYCU_DEV_UI=1 assemble l'interface depuis ui/ (index.html,
# styles.css, app.js) à chaque démarrage, sans passer par build.py.
# Le `.py` reste 100 % autonome : sans cette variable, l'UI embarquée est utilisée.
if os.environ.get("HYCU_DEV_UI") == "1":
    try:
        import importlib.util as _ilu
        _spec = _ilu.spec_from_file_location("hycu_build", os.path.join(os.path.dirname(os.path.abspath(__file__)), "build.py"))
        _b = _ilu.module_from_spec(_spec); _spec.loader.exec_module(_b)
        HTML = _b.assemble(os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui"))
        print("UI assembled from ui/ (development mode).")
    except Exception as _e:                      # pragma: no cover
        print("ui/ unusable (%s): embedded UI used." % _e)

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
    # Console Windows en cp1252 : les messages (⚠, accents) ne doivent jamais faire planter le démarrage.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    load_config()
    os.makedirs(CONFIG["backup_root"], exist_ok=True)
    host, port = CONFIG["host"], CONFIG["port"]
    url = "http://%s:%d" % (host, port)

    if _port_in_use(host, port):
        print("=" * 64)
        print("  ⚠ A server is ALREADY answering on %s" % url)
        print("  It is most likely an OLD instance still running:")
        print("  the browser talks to it and shows the old page.")
        print("  -> Close it first, then start this program again:")
        print("       Windows : taskkill /F /IM python.exe  (or close the other window)")
        print("       Linux/Mac: pkill -f hycu_k8s_nutanix.py")
        print("=" * 64)
        return

    print("=" * 64)
    print("  HYCU / Kubernetes / Nutanix tool (v2)  ·  version v:%s" % VERSION)
    print("  Open your browser at: %s" % url)
    print("  (Ctrl+C to stop)")
    print("  Backups & audit written to: %s" % CONFIG["backup_root"])
    print("  Configuration: %s" % CONFIG_PATH)
    if CONFIG.get("allowed_hosts"):
        print("  ⚠ Allowed host names (exposed beyond loopback): %s" % ", ".join(CONFIG["allowed_hosts"]))
        print("    The tool has NO authentication: protect access (SSO / oauth2-proxy, IP, TLS).")
    print("  Tip: on first display, press Ctrl+Shift+R to clear the cache.")
    print("=" * 64)
    # Déverrouillage automatique du coffre au démarrage (phrase secrète via
    # HYCU_VAULT_PASSPHRASE[_FILE]) : les connexions et clusters mémorisés
    # reviennent sans intervention — utile en Pod pour la sauvegarde auto.
    _audit_compact()                    # rétention du journal appliquée dès le démarrage
    if auto_unlock_vault("startup"):
        print("  Vault unlocked automatically (connections/clusters reloaded).")
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
            # Arrêt propre sur SIGTERM (kubectl delete pod, docker stop) : on arrête
            # d'accepter des requêtes, on laisse finir une opération destructive en
            # cours (au plus wait_timeout + marge), puis atexit nettoie les kubeconfigs.
            import signal

            def _stop(signum, _frame):
                print("Signal %s received: stopping the server…" % signum, flush=True)
                threading.Thread(target=httpd.shutdown, daemon=True).start()
            for sig in (getattr(signal, "SIGTERM", None), getattr(signal, "SIGINT", None)):
                if sig is not None:
                    try:
                        signal.signal(sig, _stop)
                    except (ValueError, OSError):
                        pass
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                pass
            deadline = time.time() + int(CONFIG["wait_timeout"]) + int(CONFIG["subprocess_margin"])
            while (ACTION_LOCK.locked() or _operations_running()) and time.time() < deadline:
                print("  … an operation is running, waiting before stopping.", flush=True)
                time.sleep(2)
            audit("shutdown")
            print("\nStopped.")
    except OSError as e:
        print("Cannot start the server on %s: %s" % (url, e))
        print("The port may already be in use. Close the other instance and try again.")


if __name__ == "__main__":
    import sys as _sys
    if "--decrypt" in _sys.argv:
        _i = _sys.argv.index("--decrypt")
        raise SystemExit(cli_decrypt(_sys.argv[_i + 1] if _i + 1 < len(_sys.argv) else ""))
    main()
