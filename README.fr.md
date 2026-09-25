# Outil HYCU · Restauration Kubernetes sur Nutanix

> 🇬🇧 English version: **[README.md](README.md)**

Interface web guidée pour **sauvegarder et restaurer** les applications Kubernetes
dont les volumes (PVC = Volume Groups Nutanix) sont protégés par **HYCU**.

L'outil clone/restaure les Volume Groups dans HYCU, récupère leurs références,
régénère les manifestes PV/PVC et enchaîne `scale-down → delete → patch finalizer →
apply → scale-up → vérification`. **Sans lui** (flux manuel), la seule saisie est la
**référence du Volume Group** cloné/restauré — son **UUID** (CSI Nutanix moderne /
NKP : le VG est attaché directement à la VM worker, **plus d'IQN**), un
`volumeHandle`, ou un **IQN** (clusters iSCSI hérités) ; l'outil en dérive le
`volumeHandle`.

> ⚠️ **Outil destructif.** Il supprime et recrée des PV/PVC. Le mode **Simulation
> (dry-run) est activé par défaut**. Testez toujours sur un namespace de test avant
> la production, et relisez l'aperçu avant de désactiver la simulation.

---

## 1. Fonctionnement (How it works)

```
   HYCU (sauvegardes)                                  Cluster Kubernetes / NKP
   Volume Groups Nutanix protégés                      application + PVC/PV « live »
          │                                                     ▲
          │ 1. Clone ou restore du VG au point choisi           │ 6. Redémarrage (scale-up,
          │    (API HYCU — ou manuellement dans l'UI HYCU)      │    réplicas d'origine) puis
          ▼                                                     │    vérification : PVC Bound,
   Nouveau VG Nutanix restauré/cloné                            │    pods Running
          │                                                     │
          │ 2. Référence (UUID) du VG récupérée via Prism       │
          ▼                                                     │
   Manifeste PV régénéré depuis la sauvegarde de config         │
   (volumeHandle dérivé, attributs runtime purgés,              │
    disque du VG cloné réécrit via Prism Central v4)            │
          │                                                     │
          │ 3. Arrêt de l'app (scale-down, réplicas mémorisés)  │
          │ 4. delete PV/PVC + patch des finalizers             │
          ▼                                                     │
   5. apply des nouveaux PV/PVC → pointent le VG cloné ─────────┘
```

L'outil n'invente rien : il **orchestre `kubectl`** (manifestes JSON) et les **API REST
HYCU / Prism** (stdlib Python uniquement, aucune dépendance). La **sauvegarde de
configuration** (Applications → Sauvegarder) fournit le « squelette » PV/PVC ; **HYCU fournit les données**
(les Volume Groups). Chaque étape est journalisée, la séquence s'arrête au premier
échec (l'app reste arrêtée, jamais redémarrée à 0 réplica), et le **mode simulation**
(défaut) montre toute la séquence sans rien exécuter.

## 2. Prérequis

**Communs aux deux modes de lancement :**

- Un **kubeconfig** avec des droits RBAC suffisants sur le cluster cible :
  `get/list/delete` sur `pv`, `pvc`, `pods` ; `get/patch/scale` sur
  `deployments`/`statefulsets` ; `patch` sur `pv`/`pvc` (déblocage des finalizers).
- **kubectl ≥ 1.23** (l'outil utilise `kubectl wait --for=jsonpath`).
- Côté HYCU/Nutanix : le Volume Group restauré/cloné doit exister et sa **référence**
  (UUID) être connue — **automatique** avec les connecteurs HYCU/Prism (⚙
  Sources) ; sinon copiez-la depuis l'UI HYCU ou Prism (`NutanixVolumes-<uuid>`,
  cible `ntnx-k8s-<uuid>`, ou IQN sur les clusters iSCSI hérités).

**Selon le mode de lancement (voir §3) :**

- **Option A — mode Python (sur le poste)** : **Python 3.7+** (stdlib uniquement,
  aucune librairie à installer) et **`kubectl`** installés sur le poste, configurés
  sur le bon contexte (affiché en haut de la page).
- **Option B — application Kubernetes** : **rien à installer sur le poste** — Python
  et `kubectl` sont **embarqués dans l'image**. Il faut seulement les droits pour
  déployer dans un namespace du cluster (et `kubectl` quelque part pour faire le
  `port-forward` d'accès).

## 3. Installation & lancement — deux façons de lancer l'outil

|  | **Option A — Mode Python** | **Option B — Application Kubernetes** |
|---|---|---|
| Où ça tourne | Sur votre poste de travail | Dans le cluster (Deployment) |
| Prérequis | Python 3.7+ et `kubectl` sur le poste | Droits d'admin sur un namespace du cluster |
| Pour qui | Essai rapide, opérateur unique | Outil d'équipe, allumé en continu (sauvegarde auto) |
| Données | `./hycu-backups/` à côté du script | PVC `hycu-data` (persistant) |

### Option A — Mode Python (sur votre poste)

1. Prérequis : **Python 3.7+** (stdlib uniquement — aucune librairie à installer) et
   **`kubectl`** configuré sur le bon contexte.
2. Récupérez le fichier `hycu_k8s_nutanix.py`, puis lancez :
   ```bash
   python3 hycu_k8s_nutanix.py
   ```
3. Le navigateur s'ouvre sur <http://127.0.0.1:8765> (sinon, ouvrez-le manuellement).
   `Ctrl+C` pour arrêter.

Les sauvegardes et le journal d'audit sont écrits dans `./hycu-backups/`, la
configuration dans `hycu_config.json` (à côté du script).

> **Variante poste sans Python** : la même image conteneur se lance avec **Docker** —
> `docker compose -f deploy/docker-compose.yml up` puis <http://127.0.0.1:8765>.
> Guides : [docs/docker.md](docs/docker.md) · [docs/docker-demarrage.md](docs/docker-demarrage.md).

### Option B — Application Kubernetes (déployée dans le cluster)

La **même image** (`ghcr.io/cabsalon93/hycu-nkp-plugin:latest`, publique) empaquette le
script **et** `kubectl` : rien à installer sur les postes, l'outil tourne en continu
dans le cluster. Déploiement en **5 étapes** — guide détaillé pas-à-pas :
**[docs/kubernetes-demarrage.md](docs/kubernetes-demarrage.md)**.

**Étape 1 — Namespace + identité RBAC.** Crée le ServiceAccount `hycu-operator` et ses
droits ([deploy/k8s/rbac.yaml](deploy/k8s/rbac.yaml)) :
```bash
kubectl create namespace hycu
kubectl apply -f deploy/k8s/rbac.yaml
```

**Étape 2 — Fabriquer un kubeconfig autonome.** Token de ServiceAccount + CA, **sans**
exec-plugin type `aws`/`gcloud`/`oidc` (qui ne fonctionne pas dans un conteneur). Le
script [deploy/k8s/make-kubeconfig.sh](deploy/k8s/make-kubeconfig.sh) écrit `./kubeconfig` :
```bash
./deploy/k8s/make-kubeconfig.sh          # cluster local ; ou passez l'URL d'une API distante
```

**Étape 3 — Fournir ce kubeconfig via un Secret.** Dans l'image, `kubectl` lit
`KUBECONFIG=/home/app/.kube/config` : le Secret y est monté, la **clé** doit être `config` :
```bash
kubectl -n hycu create secret generic hycu-kubeconfig --from-file=config=./kubeconfig
```
Pour **remplacer** un kubeconfig existant :
```bash
kubectl -n hycu create secret generic hycu-kubeconfig \
  --from-file=config=./kubeconfig --dry-run=client -o yaml | kubectl apply -f -
```

**Étape 4 — Déployer l'outil.** PVC + Deployment + Service ([deploy/k8s/hycu.yaml](deploy/k8s/hycu.yaml)),
image tirée automatiquement depuis ghcr.io — rien à construire :
```bash
kubectl apply -f https://raw.githubusercontent.com/cabsalon93/HYCU-NKP-plugin/main/deploy/k8s/hycu.yaml
# ou, depuis un clone local du dépôt :
kubectl apply -f deploy/k8s/hycu.yaml
```

**Étape 5 — Accéder à l'interface.** Pas d'Ingress (volontaire : le serveur n'accepte
que la boucle locale) ; chaque opérateur ouvre son tunnel :
```bash
kubectl -n hycu port-forward svc/hycu 8765:8765      # puis http://127.0.0.1:8765
```

> ⚠ **1 réplica obligatoire** (état global + PVC ReadWriteOnce) — ne jamais scaler.
> Les sauvegardes vivent dans le PVC `hycu-data`. La frontière de sécurité est le
> **RBAC du namespace `hycu`** : quiconque peut `port-forward`/`exec` vers le Pod est
> opérateur complet.

**Premier lancement** : si `hycu_config.json` n'existe pas encore, un **assistant
de configuration** s'affiche automatiquement (binaire kubectl, contextes/namespaces
autorisés, garde-fous) et génère le fichier pour vous. Vous pouvez aussi le créer à
la main à partir du modèle :

```bash
cp hycu_config.example.json hycu_config.json   # puis éditer (voir §6)
```

Tout reste modifiable ensuite via la page **Réglages**.

### Langue / Language

L'interface est **bilingue français / anglais** : le bouton **EN** / **FR** dans
l'en-tête bascule la langue (page **et** messages du serveur). Le choix est mémorisé
par navigateur (cookie `hycu_lang`) ; le français est la langue par défaut.

*The UI is bilingual French / English: the **EN** / **FR** button in the header
switches the language (page **and** server messages). The choice is remembered per
browser (`hycu_lang` cookie); French is the default.*

## 4. Utilisation — interface HYCU Enterprise Cloud

L'interface reprend le **look et la logique de HYCU Enterprise Cloud** : couleurs
HYCU, **barre du haut** (logo HYCU, **sélecteur du cluster actif**, ⚙ **Sources**, `?` **À propos**,
EN/FR), **menu latéral** de pages, et chaque opération part d'une **liste
d'entités** : on sélectionne une ligne, on clique une **action en haut à droite**,
puis un **assistant** guide l'opération. Un bandeau rappelle en permanence si le
**mode simulation** (par défaut) ou le **mode réel** est actif.

| Page / élément | Rôle |
|---|---|
| **Tableau de bord** | Tuiles façon HYCU : *Applications* (anneaux protection / conformité), *Politique* (sauvegarde automatique), *Sources*, *Cluster*, *Stockage* (espace disque du dossier des sauvegardes, volume occupé, quota, alerte de saturation), graphique des *Tâches* sur 7 jours et *Dernières tâches*. |
| **Applications** | Une ligne par namespace autorisé (= application Kubernetes) : politique, **Conformité**, **Protection**, dernière sauvegarde, versions. Actions : **Sauvegarder**, **Restaurer**, **Définir la politique**, **Vérifier** ; l'entonnoir = filtre des namespaces. Bascule **Cluster actif / Tous les clusters** (regroupement workspace NKP → cluster). Un namespace **supprimé** du cluster reste listé tant que ses sauvegardes existent (badge « Supprimée — restaurable ») : **Restaurer** ouvre la récupération depuis la sauvegarde. |
| **Politiques** | La politique de sauvegarde automatique de la **configuration** (fréquence, rétention, cible) et les **politiques HYCU** (données), en lecture. |
| **Tâches** | Historique des opérations (sauvegardes, restaurations, clones, protection HYCU) avec compteurs **Succès / Échec / Simulation / En cours** et le **cluster** de chaque tâche. Boutons **Rapport HTML** (rapport de conformité autonome : applications, RPO, santé des clusters) et **CSV** (Excel). |
| **Cluster (barre du haut)** | Sélecteur du **cluster actif** : changer de cluster, en ajouter, les gérer (voir ci-dessous). |
| **⚙ (en haut à droite)** | Menu à deux entrées : **Sources** (HYCU, Prism Element, Prism Central, **clusters Kubernetes**, stockage objet S3, coffre chiffré) et **Réglages** (cluster local, réglages par client). |
| **? (en haut à droite)** | Menu **Aide** (guide/tutoriel embarqué, servi sur `/help` — fonctionne hors-ligne, bilingue) et **À propos** (version, chemins). |

Les icônes d'état suivent HYCU : **✓ vert** OK, **✕ rouge** échec / non conforme,
**? gris** inconnu / jamais sauvegardé. Une application est **protégée** dès
qu'elle a au moins une sauvegarde de configuration, et **conforme** quand sa
dernière sauvegarde date de moins que l'intervalle de la politique (24 h si la
sauvegarde automatique est désactivée).

### Plusieurs clusters (kubeconfigs) & workspaces NKP
Le **cluster affiché dans la barre du haut est le cluster actif** : toutes les
pages et toutes les opérations le ciblent. Cliquez dessus pour changer de cluster,
en ajouter un ou les gérer.

- **Cluster local** — celui de la configuration (`kubeconfig_path` /
  `kube_context`, ou la résolution par défaut de kubectl) : comportement inchangé,
  réglé dans **Réglages**.
- **Ajouter un cluster Kubernetes** (⚙ Sources, ou le menu des clusters) : chargez
  un fichier **kubeconfig** ou collez-le (YAML ou JSON), choisissez le **contexte**
  s'il y en a plusieurs, puis **Tester & ajouter** (test de connexion en lecture
  seule, 10 s max). L'outil **analyse l'authentification** du contexte et vous
  avertit en cas de :
  - **plugin exec** (`kubelogin`, `kubectl-oidc_login`…) : la commande doit être
    installée là où tourne l'outil — elle est absente de l'image conteneur — et une
    connexion OIDC interactive (navigateur) ne peut pas être pilotée par l'outil ;
  - **jeton OIDC / JWT** : expiration détectée — avertissement sous 24 h, erreur une
    fois expiré (les sauvegardes planifiées échoueraient ensuite) ;
  - **auth-provider** déprécié, **fichiers** locaux de certificat/jeton,
    `insecure-skip-tls-verify`.

  Pour un usage durable (sauvegarde automatique), préférez un **jeton de
  ServiceAccount** ou un certificat client.
- **Les kubeconfigs sont des secrets** : comme les mots de passe, ils restent **en
  mémoire** le temps de la session navigateur (plus un fichier temporaire privé
  `0600` — en RAM, `/dev/shm`, si disponible — supprimé au retrait, au verrouillage
  de session et à l'arrêt). Ils ne sont écrits sur disque que **chiffrés**, dans le
  coffre, si vous le choisissez : **Enregistrer (chiffrer)** mémorise aussi les
  clusters ajoutés, **Charger** les restaure.
- **Sauvegardes séparées par cluster ET par contexte** — une vraie hiérarchie, car
  deux clusters (prod/dev) portent souvent les **mêmes namespaces** :
  `hycu-backups/_contexts/<contexte>/<namespace>/…` pour le cluster local (basculer
  `kube_context` ne mélange jamais les sauvegardes ; les anciennes sauvegardes à la
  racine restent lisibles, filtrées par contexte), et
  `hycu-backups/_clusters/<cluster>/<namespace>/…` pour chaque cluster ajouté.
  Chaque sauvegarde enregistre son cluster **et son contexte**, et restaurer une
  sauvegarde sur un autre cluster **ou un autre contexte** est refusé.
- **Garde-fous et audit par cluster** : les confirmations en mode réel nomment le
  **cluster ciblé** (re-saisie de son nom), `allowed_contexts` accepte aussi les
  noms de cluster, chaque entrée d'audit enregistre le `cluster`, la page **Tâches**
  a une colonne *Cluster*, et le **filtre des namespaces est propre à chaque
  cluster** (`cluster_namespace_filters`).
- La **sauvegarde automatique** couvre **tous les clusters connus** à chaque
  passage (un cluster local non configuré est ignoré).
- **Applications → Tous les clusters** liste les applications de tous les clusters
  d'un coup, **regroupées par workspace NKP → cluster**. Une action sur la ligne
  d'un autre cluster bascule d'abord le cluster actif ; **Sauvegarder** fonctionne
  sur plusieurs clusters en une fois.

**Découverte des workspaces NKP (optionnelle).** NKP organise les clusters en
**workspaces**, gérés depuis le **cluster de management**. Rendez le cluster de
management actif, puis ⚙ Sources → **Découvrir les workspaces NKP** : l'outil liste
les objets `Workspace` et leurs `KommanderCluster` (lecture seule), regroupés par
workspace. Cochez les clusters, acquittez l'avertissement, puis **Importer la
sélection** : le kubeconfig de chaque cluster est lu dans son Secret
(`spec.kubeconfigRef`), testé et enregistré avec son workspace. Un kubeconfig importé
reposant sur un **plugin exec** est **refusé** (l'outil exécuterait une commande
décrite dans le Secret).

> ⚠️ La découverte exige des **droits élevés** sur le cluster de management
> (lecture des Workspaces, des KommanderClusters et des **Secrets** kubeconfig des
> namespaces de workspace), et les kubeconfigs importés donnent généralement un
> accès **administrateur** aux clusters. Ne l'utilisez que si c'est compatible avec
> votre politique de sécurité ; sinon ajoutez chaque cluster avec un kubeconfig
> dédié et restreint.

### Sauvegarder (Applications → Sauvegarder)
Sélectionnez une ou plusieurs applications → **Sauvegarder**. L'outil exporte et
nettoie tous les PV/PVC (équivaut aux boucles `kubectl get … -o yaml` + nettoyage
manuel des manifestes décrit dans la procédure HYCU).

- **Instantané de configuration étendue** : en plus des manifestes PV/PVC, la
  sauvegarde capture aussi les autres ressources du namespace (Deployments,
  StatefulSets, Services, ConfigMaps, Secrets, Ingress…) dans `resources.json` —
  lecture seule, n'échoue jamais la sauvegarde PV/PVC. **Les données des Secrets
  sont masquées par défaut** (structure conservée, valeurs remplacées par
  `__REDACTED__` ; `config_backup_include_secret_data` pour les conserver). C'est
  un **instantané de config** (référence / restore manuel) — la restauration
  automatique reste centrée PV/PVC. Désactivable via `config_backup_full: false`.
- **Sauvegarder tous (filtrés)** : sauvegarde en une fois **tous les namespaces
  autorisés** par le filtre, ou **tous** les namespaces du cluster si aucun filtre.
  Un namespace sans PVC est **ignoré** (pas une erreur).
- **Dossier de destination (optionnel)** : par défaut `hycu-backups/` (à côté du
  programme) ; tout dossier de la machine qui exécute l'outil est possible, p. ex.
  `D:\sauvegardes\hycu` ou `/mnt/backups`.

**Copiez le dossier de sauvegarde hors du cluster** (autre stockage) : c'est votre
filet de sécurité.

### Sauvegarde automatique de la configuration (Politiques)
Activez-la pour sauvegarder les **manifestes** PV/PVC (pas les données des volumes
— c'est le rôle de HYCU) de **tous les namespaces autorisés par le filtre** à
intervalle régulier (24 h par défaut), tant que l'outil est lancé. Le dernier
passage est persisté : une sauvegarde en retard est rattrapée au démarrage, et
seules les versions les plus récentes sont conservées par namespace (15 par
défaut) — ou, en mode **GFS**, la plus récente de chaque jour/semaine/mois
(7 j / 4 sem / 12 mois par défaut). Clés : `auto_backup_enabled`,
`auto_backup_interval_hours`, `auto_backup_keep`, `auto_backup_retention`,
`auto_backup_keep_daily|_weekly|_monthly`, `auto_backup_dest`.

### Protéger les données dans HYCU (Applications → Définir la politique)
Associe les PVC de l'application à leurs Volume Groups HYCU (analyse lancée
d'office), assigne une politique HYCU et lance une sauvegarde HYCU.

### Restaurer (Applications → Restaurer) — l'assistant de restauration
Sélectionnez **une** application → **Restaurer**. Comme l'*Application Restore* de
HYCU :

1. **Type de restauration** (cartes au choix) :
   - **Restaurer toute l'application (copie)** — volumes **et** objets
     (workloads, dépendances) dans le même namespace (suffixe) ou dans un autre ;
     l'original n'est pas modifié.
   - **Restaurer le stockage sur place** — les données reviennent dans les volumes
     d'origine ; l'application est arrêtée puis redémarrée.
   - **Restaurer le stockage vers de nouveaux volumes** — de nouveaux Volume Groups
     sont clonés et l'application y est rattachée ; les volumes d'origine sont
     conservés.
   - **Restaurer des objets de configuration** — ré-applique des objets choisis
     (Deployments, Services, ConfigMaps…) depuis l'instantané `resources.json`
     d'une sauvegarde, avec **aperçu des différences** (live → sauvegarde) avant
     tout `apply`. Ne touche ni aux volumes ni aux données ; un Secret **masqué**
     à la sauvegarde n'est jamais restauré (il écraserait le vrai secret).
2. **Options** : application et cluster cibles, **sauvegarde de configuration** à
   partir de laquelle reconstruire (la plus récente par défaut), **volumes** (tous
   présélectionnés) et un **point de restauration HYCU** par volume (**le plus
   récent présélectionné**). Les noms générés et la saisie manuelle de référence
   restent dans le volet **Avancé** replié de chaque volume ; un dossier de
   sauvegardes personnalisé est dans **Avancé**, en bas.
3. **Récapitulatif** : `volumeHandle` dérivé, purge des attributs runtime du VG
   source, passage du PV source en **Retain**, séquence prévue.

Le pied de l'assistant porte **une seule** action principale
(**Suivant → Restaurer → Lancer**), plus *Fermer* et *Retour*, et un badge qui
rappelle **Simulation** / **Mode réel**. En mode réel, chaque étape destructive
demande confirmation (re-saisie du nom du contexte). Après une restauration réelle,
l'outil ouvre automatiquement la **Vérification**. Un namespace cible créé par un
clone d'application est **ajouté automatiquement au filtre des namespaces**.

**Sans HYCU** (flux manuel) : restaurez/clonez chaque VG dans HYCU vous-même,
collez son **UUID** par volume dans le volet **Avancé** (ou « Rechercher le VG dans
Prism »), puis **Suivant** construit le récapitulatif.

> Si une étape échoue, la séquence **s'arrête** et l'application est **laissée
> arrêtée** (réplicas à 0) pour ne pas redémarrer sur des volumes incohérents. Le
> message indique l'étape en cause. Corrigez puis **relancez** : les réplicas cibles
> d'origine sont mémorisés (jamais redémarrés à 0).

### Vérifier (Applications → Vérifier)
Confirme que les PVC sont **Bound** et que les pods tournent. Le **Suivi auto**
rafraîchit toutes les ~3 s jusqu'à l'état stable (tous les PVC Bound, pods
Running ; plafond ~10 min — recliquez pour arrêter).

## 5. Sécurité

- Le serveur **n'écoute que sur `127.0.0.1`** (jamais exposé au réseau).
- Protection **anti-CSRF / anti-DNS-rebinding** : vérification des en-têtes `Host`
  et `Origin`/`Referer`, et **jeton anti-CSRF** exigé sur chaque action.
- **Dry-run par défaut** ; confirmation du cluster/contexte ciblé avant toute action réelle.
- **Identifiants liés à la session navigateur** : les identifiants HYCU/Nutanix sont
  liés à **une session de navigateur** (cookie de session `hycu_sess`). Ouvrir la page
  depuis un navigateur relancé, un autre navigateur ou une fenêtre privée **verrouille
  les connexions** — identifiants effacés de la mémoire, la phrase secrète du coffre
  (ou les mots de passe) sont redemandés. Un simple rechargement (F5) dans le même
  navigateur conserve la session. Les **kubeconfigs des clusters ajoutés** suivent la
  même règle (effacés à une nouvelle session navigateur, restaurés en déverrouillant
  le coffre).
- **Isolation des clusters** : chaque requête désigne son cluster ; un cluster
  inconnu n'exécute **aucune commande** (jamais de repli silencieux sur le cluster
  local), les sauvegardes sont rangées par cluster et une sauvegarde ne peut être
  restaurée que sur le cluster dont elle provient.
- **Journal d'audit** append-only : `hycu-backups/audit.log` (horodaté : namespace,
  volumes, mode, dry/réel, résultat).
- **Lecture des sauvegardes bornée** : par défaut, seuls les chemins **sous
  `hycu-backups/`** sont lisibles (défense contre une lecture hors zone). Un **dossier
  personnalisé** n'est ouvert que si **vous le désignez explicitement** dans l'assistant
  de restauration (Avancé) ; un chemin hors de cette zone reste refusé.
- **Déverrouillage automatique du coffre (optionnel, mode conteneur)** : si la phrase
  secrète est fournie via `HYCU_VAULT_PASSPHRASE_FILE` (fichier monté depuis un Secret
  Kubernetes — préférable) ou `HYCU_VAULT_PASSPHRASE`, le coffre est déverrouillé au
  démarrage et après chaque verrouillage de session : connexions et clusters mémorisés
  reviennent sans intervention (indispensable pour la sauvegarde automatique des
  clusters ajoutés après un redémarrage du Pod). Contrepartie assumée : quiconque lit
  ce Secret peut déchiffrer le coffre — réservez ce mode à un namespace verrouillé.
- **Santé des clusters** : un contrôle périodique en lecture seule (liste des
  namespaces, 10 s max par cluster, toutes les `cluster_health_minutes` minutes)
  alimente une pastille par cluster dans ⚙ Sources et la métrique
  `hycu_cluster_reachable` — un jeton expiré ou un cluster injoignable se voit
  AVANT la prochaine sauvegarde planifiée.
- **Supervision** (`GET /metrics`) : un endpoint Prometheus expose des indicateurs
  d'état (outil actif, opération en cours, sauvegarde auto activée/dernière
  exécution/dernier succès, état des connexions) — **aucune donnée sensible**.
  Comme le reste de l'outil, il est **local uniquement** (même garde `Host`/`Origin`) :
  scrutez-le via un `kubectl port-forward` ou un sidecar sur la loopback, jamais
  directement sur le réseau.

## 6. Configuration (`hycu_config.json`) — adaptation par client

Copiez `hycu_config.example.json` → `hycu_config.json`. Modifiable aussi via
la page **Réglages** de l'interface. Toutes les clés sont optionnelles.

| Clé | Défaut | Rôle |
|---|---|---|
| `kubectl_path` | `"kubectl"` | Binaire kubectl. Ex. `"microk8s kubectl"`, `"k3s kubectl"`, ou chemin complet. |
| `allowed_contexts` | `[]` | Liste blanche de contextes kubectl (ou de noms de clusters ajoutés dans ⚙ Sources). `[]` = tous. En mode réel, un contexte hors liste est **refusé**. |
| `namespace_filter` | `[]` | Liste blanche de namespaces du cluster **local**. `[]` = tous. |
| `cluster_namespace_filters` | `{}` | Listes blanches de namespaces des clusters **ajoutés dans ⚙ Sources**, par nom de cluster : `{"prod-paris": ["shop"]}`. Tenu à jour par l'éditeur de filtre. |
| `wait_timeout` | `120` | Attente max (s) d'une suppression / d'un passage `Bound` / de l'arrêt des pods. |
| `subprocess_margin` | `30` | Marge (s) du timeout subprocess au-dessus de `wait_timeout` (pour ne pas tuer `kubectl wait` avant son verdict). |
| `clone_name_suffix` | `"0000"` | Convention HYCU pour le nom du PV cloné (suggestion pré-remplie, modifiable). |
| `volume_handle_prefix` | `""` | **Vide = auto-détecté** depuis le PV existant (suit le driver CSI du client). Ne renseigner que pour forcer un préfixe. |
| `strip_claimref` | `false` | `true` = retirer entièrement `claimRef` du PV (laisse le PVC recréé rebinder). `false` = conserver `claimRef` (name+namespace) sans uid/resourceVersion. |
| `auto_backup_enabled` | `false` | Sauvegarde automatique planifiée de tous les namespaces autorisés par le filtre, tant que l'outil tourne. |
| `auto_backup_interval_hours` | `24` | Intervalle entre deux sauvegardes automatiques (heures, minimum 0,25). |
| `auto_backup_keep` | `15` | Rétention « compteur » : versions conservées par namespace. |
| `auto_backup_retention` | `"count"` | `"gfs"` = rétention grand-père/père/fils : la plus récente de chaque **jour** / **semaine** / **mois** est conservée. |
| `auto_backup_keep_daily` / `_weekly` / `_monthly` | `7` / `4` / `12` | Fenêtres GFS (jours / semaines ISO / mois). La sauvegarde la plus récente est toujours conservée. |
| `namespace_label_selector` | `""` | Sélecteur d'étiquettes appliqué à la liste des namespaces (tous clusters), ex. `hycu.io/backup=true` : les équipes s'incluent via leurs manifestes (GitOps). Vide = inactif. |
| `audit_retention_days` | `31` | Rétention du journal d'audit / historique des Tâches (compaction quotidienne atomique). `0` = illimité. |
| `storage_min_free_mb` | `500` | **Plancher d'espace libre** : toute sauvegarde est refusée (erreur claire, auditée) si le disque est en dessous — jamais de disque saturé par l'outil. `0` = désactivé. |
| `storage_quota_gb` | `0` | **Quota global** du dossier de sauvegardes : au-delà, les plus anciennes sont purgées (la plus récente de chaque application×cluster et la sauvegarde d'une restauration en cours sont toujours gardées). `0` = illimité. |
| `config_backup_full` | `true` | Capturer aussi les ressources non-PV/PVC du namespace (Deployments, Services, Secrets…) dans `resources.json`. |
| `recover_restore_deleted_vg` | `true` | Récupération d'une application supprimée : si son Volume Group d'origine n'existe plus sur le cluster mais reste « Protected deleted » dans HYCU, le restaurer automatiquement (en un clic « Restaurer »). Requiert HYCU + Prism connectés. |
| `recover_deleted_vg_mode` | `restore` | Mode de récupération d'un VG supprimé : `restore` = restauration **in-place** via HYCU (le VG revient à son UUID d'origine, le PV est réutilisé tel quel) ; `clone` = HYCU crée un **nouveau** VG (nouvel UUID) que l'outil découvre. |
| `backup_collect_restore_contract` | `true` | À chaque sauvegarde, collecter *best-effort* (sans jamais échouer le backup) le « contrat de restauration » — nom/UUID du Volume Group côté HYCU, disque(s), Prism Element, dernier point de restauration HYCU — pour permettre une restauration ultérieure **sans saisie manuelle d'UUID**, y compris en reprise d'activité. Ignoré si HYCU/Prism ne sont pas connectés. |
| `config_backup_kinds` | *(liste par défaut)* | Types de ressources namespacées exportés par l'instantané de config étendue. |
| `config_backup_include_secret_data` | `false` | `false` = données des Secrets masquées sur disque ; `true` = conservées en clair (uniquement si le dossier de sauvegarde est lui-même protégé). |
| `auto_backup_dest` | `""` | Dossier de destination des sauvegardes automatiques (vide = `hycu-backups/`). |
| `require_context_confirm` | `true` | Exiger la re-saisie du contexte avant toute action réelle. |
| `cluster_health_minutes` | `5` | Intervalle (min) du contrôle de santé des clusters (lecture seule). `0` = désactivé. |
| `s3_url` / `s3_bucket` / `s3_region` | `""` / `""` / `us-east-1` | Export S3 **optionnel** des sauvegardes (voir §9). Vide = désactivé. |
| `s3_prefix` | `hycu-backups` | Préfixe des clés d'objets. |
| `s3_path_style` | `true` | `true` = URL de type chemin (`endpoint/bucket/clé` — Nutanix Objects, MinIO) ; `false` = bucket en sous-domaine (AWS). |
| `s3_verify_tls` | `false` | Vérifier le certificat TLS de l'endpoint S3. |
| `s3_auto_upload` | `false` | `true` = chaque sauvegarde réussie est aussi envoyée en `.zip` vers le bucket. |
| `s3_encrypt` | `false` | `true` = les exports sont **chiffrés** avant l'envoi (phrase saisie dans ⚙ Sources) ; déchiffrement : `python3 hycu_k8s_nutanix.py --decrypt <fichier>.zip.enc`. |
| `allow_dr_restore` | `false` | **Mode reprise d'activité** : autorise la restauration inter-cluster/inter-contexte — uniquement sur demande explicite « restauration DR » (sources lues depuis la seule sauvegarde, avertissement, audit dédié). À activer le temps d'un exercice ou d'un sinistre. |
| `host` / `port` | `127.0.0.1` / `8765` | Adresse d'écoute. **Ne pas exposer** `host` hors de la boucle locale. |
| `open_browser` | `true` | Ouvrir le navigateur au démarrage. |
| `hycu_url` | `""` | URL du contrôleur HYCU, ex. `https://hycu.exemple.com:8443` (port 8443). Vide = connecteur HYCU désactivé. |
| `hycu_api_base` | `/rest/v1.0` | Base de l'API REST HYCU (**dépend de la version** — voir §9). |
| `hycu_test_path` | `/vms` | Endpoint GET utilisé pour tester la connexion (relevez-le dans le REST API Explorer). |
| `hycu_verify_tls` | `false` | Vérifier le certificat TLS HYCU (souvent auto-signé → `false`). |
| `nutanix_url` | `""` | URL de Prism **Element**, ex. `https://prism.exemple.com:9440`. Vide = désactivé. |
| `nutanix_api_base` | `/PrismGateway/services/rest/v2.0` | Base de l'API Prism Element v2. |
| `nutanix_verify_tls` | `false` | Vérifier le certificat TLS Prism Element. |
| `prismcentral_url` | `""` | URL de Prism **Central**, ex. `https://pc.exemple.com:9440`. Vide = désactivé. |
| `prismcentral_api_base` | `/api/nutanix/v3` | Base de l'API Prism Central v3. |
| `prismcentral_verify_tls` | `false` | Vérifier le certificat TLS Prism Central. |

> Les **identifiants** HYCU/Nutanix et les **kubeconfigs** des clusters ajoutés ne
> sont **jamais** dans la config : ils sont saisis dans **⚙ Sources** et gardés en
> mémoire le temps de la session uniquement (ou dans le coffre chiffré).

### Exemple — un client « microk8s », 2 namespaces, cluster de prod verrouillé
```json
{
  "kubectl_path": "microk8s kubectl",
  "allowed_contexts": ["prod-cluster"],
  "namespace_filter": ["wordpress", "bo-dev"],
  "require_context_confirm": true
}
```

## 7. À valider sur le cluster du client avant la prod

Ces points dépendent de l'environnement et **ne peuvent pas être vérifiés sans le
vrai cluster** :

1. **`hypervisorAttachedDiskUUIDs` (point #1)** : sur le CSI Nutanix moderne (NKP), le
   VG est attaché à la VM worker et le PV porte `volumeAttributes.hypervisorAttachedDiskUUIDs`
   = UUID du **disque attaché du VG source**. L'outil le **purge** du PV cloné (option
   `clone_strip_runtime_attrs`, défaut `true`) pour que le driver le repeuple à l'attach.
   **À confirmer sur un PV cloné réel** : le driver localise bien le volume par
   `volumeHandle` seul (montage OK) — sinon il faudra réécrire ce champ avec l'UUID du
   disque **cloné** plutôt que le purger.
2. **`Retain` du PV source (perte de données)** : avant de supprimer l'ancien PV/PVC,
   l'outil passe le PV source en `persistentVolumeReclaimPolicy: Retain` (option
   `retain_source_pv`, défaut `true`) pour que le CSI **ne supprime pas** le Volume
   Group Nutanix (reclaim=Delete par défaut). Vérifier que le VG source survit bien.
3. **UUID ↔ VG cloné** : l'UUID saisi doit être celui du VG **cloné**, pas du source
   (avertissement si identique) ni le **nom** du VG `pvc-<uuid>` (avertissement dédié).
4. **Re-protection HYCU** : après un clone, ré-assigner la politique de protection
   au nouveau Volume Group (rappelé dans le plan ; non automatisé).
5. **Scénarios de test** : restore mono-PVC, restore **multi-PVC**, et surtout
   **abort → relance** (vérifier que l'app revient à son nombre de réplicas
   d'origine, pas à 0), et un PVC bloqué en `Terminating`.
6. `kubectl wait --for=jsonpath` nécessite **kubectl ≥ 1.23**.
7. **Découverte des workspaces NKP** : les ressources utilisées
   (`workspaces.kommander.mesosphere.io`, `kommanderclusters.kommander.mesosphere.io`,
   `spec.kubeconfigRef`, clé de Secret `value` ou `kubeconfig`) suivent la
   documentation NKP — à valider sur votre version de NKP, avec le RBAC que vous
   comptez accorder.

## 8. Dépannage

| Symptôme | Piste |
|---|---|
| « Contexte : indisponible » | `kubectl` absent du PATH ou contexte non configuré. |
| « Namespace non autorisé » | Le namespace n'est pas dans `namespace_filter`. Dans la page Vérification, le bouton **« Autoriser « ns » et réessayer »** l'ajoute en un clic ; un namespace créé par un clone d'application est ajouté automatiquement. |
| « Contexte non autorisé » | Le contexte courant n'est pas dans `allowed_contexts`. |
| Namespace détruit, application absente ? | Elle reste listée tant qu'une sauvegarde existe (badge « Supprimée — restaurable ») : **Restaurer** → récupération depuis la sauvegarde (namespace, PV/PVC, workloads, dépendances non masquées), sans dérogation DR — restaurez d'abord les Volume Groups dans HYCU et collez leurs UUID. |
| PVC/PV reste `Terminating` | L'outil patche les finalizers automatiquement ; sinon vérifier qu'aucun pod ne monte encore le volume. |
| « Jeton anti-CSRF invalide » | Rechargez la page (le jeton est régénéré à chaque démarrage). |
| Les connexions redemandent le déverrouillage | Comportement attendu : une nouvelle session navigateur (navigateur relancé, fenêtre privée) verrouille les identifiants — re-saisissez la phrase secrète du coffre. |
| Séquence « interrompue » | Lire l'étape en cause dans le log, corriger, **relancer** (réplicas mémorisés). |
| « Cluster « x » inconnu » | Le cluster actif a été retiré, ou une nouvelle session navigateur a effacé les clusters ajoutés : déverrouillez le coffre (ils reviennent) ou choisissez un autre cluster dans la barre du haut. |
| Avertissement « plugin exec » / « jeton expiré » sur un cluster | Le kubeconfig dépend d'une commande de connexion externe ou d'un jeton à courte durée : régénérez-le, ou utilisez un jeton de ServiceAccount (voir §4, *Plusieurs clusters*). |
| « Cette sauvegarde provient du cluster « x »… » | La restauration inter-clusters est refusée : sélectionnez le cluster d'origine de la sauvegarde dans la barre du haut. |
| Découverte NKP : « ne semble pas être un cluster de management NKP » | Le cluster actif n'est pas le cluster de management, ou votre RBAC ne permet pas de lire les Workspaces/KommanderClusters. |

## 9. Sources HYCU / Nutanix (⚙ en haut à droite)

Connexions **optionnelles** (en stdlib, aucune dépendance) : sans elles, le flux
manuel (coller la référence du VG) reste pleinement utilisable.

- **Nutanix Prism (lecture seule)** — deux zones de connexion : **Prism Element** (API v2)
  et **Prism Central** (API v3, multi-cluster). Dans l'assistant de restauration, le
  flux HYCU groupé s'appuie sur Prism pour **remplir automatiquement les UUID des VG
  clonés** (plus de copier-coller), et le volet **Avancé** de chaque volume propose un
  bouton **« Rechercher le VG dans Prism »** pour le flux manuel. Il utilise la source
  connectée — Prism Element en priorité, sinon Prism Central.
- **HYCU (actions)** — lister les **Volume Groups protégés** et leurs **points de
  restauration**, choisir **Clone** ou **Restauration sur place**, puis **déclencher**
  et suivre le job. **Mode simulation par défaut** : l'appel exact (méthode + URL + corps)
  est affiché **avant** tout envoi réel.

**Identifiants** : saisis dans ⚙ Sources, **gardés en mémoire** le temps de la **session
navigateur**, **jamais écrits** sur disque ni dans la config (mode par défaut, le plus
sûr). Effacés à la déconnexion, à l'arrêt, et dès qu'une **nouvelle session navigateur**
ouvre la page (navigateur relancé, fenêtre privée — voir §5).

### Export des sauvegardes vers un stockage objet S3 (optionnel)

Désactivé par défaut. ⚙ Sources → **Stockage objet S3** : renseignez l'endpoint
(Nutanix Objects, MinIO, AWS S3…), le bucket, la région et les clés d'accès, puis
**Tester & connecter** (test en lecture seule : liste du bucket limitée à 1 objet).
Cochez **Export automatique** pour que chaque sauvegarde réussie (manuelle et
planifiée) soit aussi envoyée en `.zip` vers le bucket, sous la clé
`<préfixe>/<cluster>/<namespace>/<horodatage>.zip` : le filet de sécurité vit alors
**hors du cluster** qu'il protège.

- Signature **AWS SigV4** implémentée en stdlib pure (aucune dépendance), vérifiée
  contre le vecteur de test officiel AWS.
- Les clés d'accès suivent les mêmes règles que les autres identifiants : **RAM** le
  temps de la session, coffre chiffré en option, jamais dans `hycu_config.json`.
- **Best-effort** : un échec d'export (bucket plein, réseau) n'échoue jamais la
  sauvegarde locale ; chaque export est tracé dans l'audit et visible dans **Tâches**.
- SigV4 exige une **horloge juste** sur la machine de l'outil (erreur 403 sinon).
- **Chiffrement optionnel** (`s3_encrypt` + phrase saisie dans ⚙ Sources) : les objets
  sont chiffrés **avant** l'envoi (même schéma que le coffre : PBKDF2 + scellé
  d'intégrité, itérations encodées dans le fichier) — le bucket peut être un stockage
  non maîtrisé. Déchiffrement hors interface :
  `python3 hycu_k8s_nutanix.py --decrypt sauvegarde.zip.enc`.

### Reprise d'activité (mode DR)

Le scénario : le cluster (ou le site) primaire est perdu ; HYCU détient toujours les
sauvegardes des Volume Groups. Le déroulé complet est dans l'aide en ligne (**? →
Aide → Reprise d'activité**) ; en résumé :

1. **Avant** (kit DR) : export S3 automatique activé (chiffré de préférence) ; copies
   sûres de `hycu_config.json`, `hycu_secrets.enc`, des phrases du coffre et des exports.
2. **Le jour J** : relancer l'outil ailleurs, reconnecter les sources, ajouter le
   cluster cible, puis **carte S3 → Importer depuis le bucket** (les exports
   reviennent sous `hycu-backups/_imports/…`).
3. Restaurer les **Volume Groups** dans HYCU vers le site cible, noter leurs UUID.
4. Activer **Autoriser la restauration DR** (Réglages), puis assistant →
   **Restauration DR** : sauvegarde source (cluster disparu ou import S3), namespace
   cible, UUID des VG restaurés, **remap de StorageClass** optionnel — simulation puis
   réel (re-saisie du cluster cible). Tout provient de la **seule sauvegarde**
   (aucune lecture du cluster d'origine) ; un Secret masqué n'est jamais restauré.
5. **Après** : vérifier, re-protéger les VG dans HYCU, désactiver la dérogation.

### Mémoriser les connexions (coffre chiffré, optionnel)

⚙ Sources propose un coffre chiffré pour ne pas re-saisir les identifiants à
chaque session :

- Les identifiants sont chiffrés dans **`hycu_secrets.enc`** (à côté du programme), protégé
  par une **phrase secrète maîtresse** que **vous seul connaissez** — elle n'est jamais
  stockée. À chaque **nouvelle session navigateur**, l'outil redemande cette phrase pour
  déverrouiller les connexions.
- Boutons : **Enregistrer (chiffrer)** · **Charger (déchiffrer)** · **Oublier** (supprime le fichier).
- **Pourquoi pas MD5 ?** MD5 (comme tout hachage) est **à sens unique** : on ne pourrait jamais
  récupérer le mot de passe pour se reconnecter. Le coffre utilise donc un **chiffrement
  réversible** : clé dérivée de la phrase par **PBKDF2-HMAC-SHA256** (200 000 itérations),
  flux HMAC-SHA256, et **scellé d'intégrité** (détecte une mauvaise phrase ou une altération).
- Construction en **stdlib pure** (aucune dépendance) ; pragmatique mais robuste pour un outil
  local mono-opérateur. Si une assurance cryptographique maximale est requise, **gardez le mode
  RAM seulement** (n'utilisez pas le coffre) et re-saisissez les identifiants à chaque session.

> Config : `remember_credentials` passe à `true` quand un coffre existe ; `pbkdf2_iterations`
> règle le coût de dérivation. Aucun secret n'est jamais écrit dans `hycu_config.json`.

### HYCU 5.2 (R-Cloud Hybrid Cloud Edition) — endpoints vérifiés

API REST sur le **port 8443**, base `/rest/v1.0`. Endpoints **vérifiés sur 5.2** (Swagger
`/rest/v1.0/api-docs`) et utilisés par l'outil :

| Action | Appel HYCU 5.2 |
|---|---|
| Lister les Volume Groups protégés | `GET /rest/v1.0/volumegroups` |
| Lister les points de restauration d'un VG | `GET /rest/v1.0/volumegroups/{vgUuid}/backups` |
| Déclencher restore/clone | `POST /rest/v1.0/volumegroups/vgrestore` (corps `RestoreSpecDTO`) |
| État d'un job | `GET /rest/v1.0/jobs/{jobUuid}` |

- **Authentification** (⚙ Sources) :
  - **Basic** : utilisateur/mot de passe d'un administrateur du groupe d'infrastructure.
  - **Clé API** : générée dans HYCU via **Aide → API Keys** ; **obligatoire si le 2FA est
    activé**. Transmise en `Authorization: Bearer <clé>` (schéma confirmé).
- Corps `vgrestore` envoyé : `backupUuid` (= point de restauration), `createVolumeGroup`
  (`true` = clone / `false` = sur place), `vgName` (clone), `startVgRestore`, `restoreSource`
  (`AUTO`). Le **mode simulation** montre ce corps avant envoi.

> Si votre version diffère, tous les chemins se relèvent dans **Aide → REST API Explorer**
> de l'appliance et s'ajustent via `hycu_api_base` / `hycu_test_path` + le mode simulation.
> Sécurité : `*_verify_tls` à `false` accepte les certificats auto-signés des appliances ;
> passez à `true` avec une PKI interne valide.
