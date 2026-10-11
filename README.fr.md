# HYCU · Kubernetes sur Nutanix

> 🇬🇧 English: **[README.md](README.md)** · Référence complète : [docs/reference.fr.md](docs/reference.fr.md)

Une page web pour **sauvegarder, protéger et restaurer** les applications Kubernetes dont
les volumes (PVC) sont des Volume Groups Nutanix protégés par **HYCU**. Un seul fichier
Python (bibliothèque standard uniquement), livré aussi en image conteneur.

## Ce que ça fait

- **Sauvegarde** la configuration des namespaces : manifestes PV/PVC, Deployments, Services,
  ConfigMaps, Secrets (chiffrés). À la demande ou **automatiquement** via des **politiques**
  (cible par namespaces ou étiquettes, fréquence, rétention, politique HYCU), avec export
  optionnel vers un stockage **S3** et purge manuelle des anciennes versions.
- **Se sauvegarde lui-même** : configuration, politiques et coffre exportés chaque jour dans le
  bucket, restaurables sur une nouvelle instance (⚙ Sources → Stockage objet S3).
- **Protège** les volumes dans HYCU : correspondance PVC ↔ Volume Group, politique HYCU.
  Les volumes **NAS (NFS)** — Nutanix Files ou NAS générique — sont associés à leur
  **partage HYCU** (politique + sauvegarde immédiate) et recréés à l'identique lors d'une
  récupération. Une **copie** d'application fait restaurer par HYCU la dernière sauvegarde du
  partage dans un dossier au nom du namespace cible.
- **Restaure** : vers de **nouveaux volumes** (clone HYCU), **sur place** (restore HYCU
  in-place), une **application supprimée**, **en masse**, ou sur un **autre cluster** (DR).
  L'outil enchaîne arrêt de l'application → recréation des PV/PVC → redémarrage →
  vérification, avec préflight, protection (Retain) des volumes et reprise après interruption.
- **Vérifie** l'état (PVC liés, pods, événements) et journalise tout (audit, page Tâches).
- **Multi-cluster** (kubeconfigs importés, workspaces NKP), interface **FR/EN**.

> ⚠ **Outil destructif en mode réel** : il supprime et recrée des PV/PVC. Garde-fous :
> préflight, confirmation par ressaisie du nom du cluster, Retain systématique des volumes.
> Testez d'abord sur un namespace de test.

## Prérequis

- Un cluster Kubernetes avec le **CSI Nutanix** (NKP) ; `kubectl` ≥ 1.23 (embarqué dans l'image).
- **HYCU** (API REST, port 8443) et **Prism Central / Element** joignables depuis l'outil.
  Les identifiants se saisissent dans l'interface (⚙ Sources), jamais dans un fichier.
- Les droits RBAC nécessaires sont fournis par `deploy/k8s/rbac.yaml`.

## Déployer

### Dans le cluster (recommandé)

```bash
kubectl create namespace hycu
kubectl apply -f deploy/k8s/rbac.yaml                 # ServiceAccount hycu-operator + droits
./deploy/k8s/make-kubeconfig.sh                       # écrit ./kubeconfig (token du SA, sans exec-plugin)
kubectl -n hycu create secret generic hycu-kubeconfig --from-file=config=./kubeconfig
kubectl apply -f deploy/k8s/hycu.yaml                 # PVC + Deployment (image ghcr.io, :latest) + Service
```

Accès par tunnel (pas d'Ingress par défaut) :

```bash
kubectl -n hycu port-forward svc/hycu 8765:8765        # puis http://127.0.0.1:8765
```

Au premier lancement, un assistant crée la configuration. Un seul réplica (état global +
PVC `hycu-data`). Pas-à-pas détaillé : [docs/kubernetes-demarrage.md](docs/kubernetes-demarrage.md).

### Avec Docker (sur un poste)

```bash
cp ~/.kube/config ./kubeconfig                         # kubeconfig autonome (token/certs, sans exec-plugin)
docker compose -f deploy/docker-compose.yml up -d      # puis http://127.0.0.1:8765
```

Données dans `./hycu-data`. Guide : [docs/docker-demarrage.md](docs/docker-demarrage.md).

### Avec Python seul

```bash
python3 hycu_k8s_nutanix.py                            # Python 3.7+, kubectl sur le poste
```

## Mettre à jour

L'image `ghcr.io/cabsalon93/hycu-nkp-plugin:latest` est republiée à chaque version ; le
manifeste et le fichier Compose l'utilisent. Les données (PVC `hycu-data`, `./hycu-data`)
sont conservées. Ne lancez pas de mise à jour pendant une restauration.

```bash
# Kubernetes : récupère la nouvelle image et redémarre
kubectl -n hycu rollout restart deployment/hycu
kubectl -n hycu rollout status deployment/hycu
kubectl -n hycu rollout undo deployment/hycu           # retour arrière si besoin
```

```bash
# Docker Compose
docker compose -f deploy/docker-compose.yml pull
docker compose -f deploy/docker-compose.yml up -d
```

Mode Python : remplacez `hycu_k8s_nutanix.py` et relancez. Ensuite, rechargez la page
(Ctrl+Shift+R) : la version s'affiche en bas de la barre latérale. Pour figer une version
précise, chaque build existe aussi sous le tag `vAAAAMMJJ-HHMM`.

## Paramètres

Tout se règle dans l'interface (⚙ **Réglages**, ⚙ **Sources**) ou dans `hycu_config.json`
(modèle : [hycu_config.example.json](hycu_config.example.json)). Les plus utiles :

| Clé | Défaut | Rôle |
|---|---|---|
| `namespace_filter` | `[]` | Namespaces visibles (vide = tous). `namespace_label_selector` pour un filtre par étiquettes. |
| `allowed_contexts` | `[]` | Clusters/contextes autorisés en mode réel (vide = tous, avec confirmation). |
| `allowed_hosts` | `[]` | Noms DNS acceptés en plus de `127.0.0.1` (Ingress / reverse-proxy, à protéger par une authentification). |
| `auto_backup_enabled` | `false` | Politique par défaut : sauvegarde automatique des namespaces sans autre politique. |
| `backup_policies` | `[]` | Politiques nommées (page Politiques) : namespaces et/ou sélecteur d'étiquettes, intervalle, versions à conserver, politique HYCU optionnelle. Un namespace nommé explicitement l'emporte sur un sélecteur ; sinon la première qui correspond. |
| `auto_backup_interval_hours` | `24` | Intervalle de la sauvegarde automatique. |
| `auto_backup_keep` | `15` | Versions conservées par namespace (`0` = illimité). `auto_backup_retention: "gfs"` pour une rétention jour/semaine/mois. |
| `storage_quota_gb` / `storage_min_free_mb` | `0` / `500` | Quota du dossier de sauvegardes et plancher d'espace libre. |
| `backup_secrets` | `"auto"` | Secrets chiffrés avec la phrase du coffre si disponible (`encrypted`, `clear`, `redacted`). |
| `allow_dr_restore` | `false` | Autoriser la restauration sur un autre cluster (mode DR). |
| `require_context_confirm` | `true` | Ressaisie du nom du cluster avant toute action réelle. |
| `simulation_mode_available` | `false` | Proposer l'interrupteur « mode simulation » (dry-run). |
| `default_lang` | `"en"` | Langue par défaut de l'interface (`en` / `fr`). |
| `hycu_url`, `prismcentral_url`, `nutanix_url` | `""` | Adresses des systèmes (`*_verify_tls`, `*_ca_bundle` pour TLS). |
| `s3_url`, `s3_bucket`, `s3_auto_upload`, `s3_encrypt` | `""`, `""`, `false`, `false` | Export des sauvegardes vers un bucket S3 (Nutanix Objects, MinIO, AWS). |
| `kubectl_path`, `kube_context` | `"kubectl"`, `""` | Binaire et contexte kubectl du cluster local. |
| `wait_timeout` | `120` | Attente max (s) d'une suppression ou d'un PVC `Bound`. |

En conteneur, quelques variables d'environnement priment sur le fichier :
`HYCU_HOST`, `HYCU_PORT`, `HYCU_BACKUP_ROOT`, `HYCU_KUBECTL_PATH`, `HYCU_ALLOWED_HOSTS`
(liste séparée par des virgules) et `HYCU_VAULT_PASSPHRASE` ou `HYCU_VAULT_PASSPHRASE_FILE`
(déverrouillage automatique du coffre d'identifiants au démarrage).

## Sécurité en bref

- Écoute sur la boucle locale ; tout autre `Host`/`Origin` est refusé sauf s'il figure dans
  `allowed_hosts`. L'outil n'a **pas d'authentification** : derrière un nom DNS, placez un
  SSO / oauth2-proxy / liste d'IP et TLS devant lui.
- Dans le cluster, la frontière est le **RBAC du namespace `hycu`** : qui peut
  `port-forward` ou `exec` vers le Pod est opérateur complet.
- Identifiants HYCU/Prism/S3 en mémoire, ou dans un **coffre chiffré** (phrase secrète).
- Mode réel : préflight bloquant, sauvegarde de sécurité avant restauration, Retain des
  volumes, transaction de reprise, journal d'audit.

## Pour aller plus loin

- [docs/reference.fr.md](docs/reference.fr.md) — référence complète (tous les paramètres,
  parcours de restauration, endpoints HYCU/Nutanix, dépannage).
- [docs/kubernetes-demarrage.md](docs/kubernetes-demarrage.md) · [docs/docker.md](docs/docker.md) — déploiement détaillé.
- [docs/audit-2026-10-09.md](docs/audit-2026-10-09.md) — audit et chantier de durcissement.
- Développement : `python build.py --check --lint` (interface dans `ui/`), `python -m pytest tests`.
