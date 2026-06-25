# Outil HYCU · Restauration Kubernetes sur Nutanix

Interface web guidée pour **sauvegarder et restaurer** les applications Kubernetes
dont les volumes (PVC = Volume Groups Nutanix) sont protégés par **HYCU**.

L'outil remplace la procédure manuelle (≈ 20 commandes `kubectl` + édition de YAML)
par quelques clics. À la restauration, la **seule saisie** est la **référence du
Volume Group** cloné/restauré — son **UUID** (CSI Nutanix moderne / NKP : le VG est
attaché directement à la VM worker, **plus d'IQN**), un `volumeHandle`, ou un **IQN**
(clusters iSCSI hérités). L'outil en dérive le `volumeHandle`, régénère le manifeste
du PV, puis enchaîne `scale-down → delete → patch finalizer → apply → scale-up →
vérification`.

> ⚠️ **Outil destructif.** Il supprime et recrée des PV/PVC. Le mode **Simulation
> (dry-run) est activé par défaut**. Testez toujours sur un namespace de test avant
> la production, et relisez l'aperçu avant de désactiver la simulation.

---

## 1. Prérequis

- **Python 3.7+** (aucune librairie à installer — un seul fichier, stdlib uniquement).
- **`kubectl`** installé et configuré sur le **bon contexte** (le cluster cible).
  Le contexte courant est affiché en haut de la page.
- Droits RBAC suffisants : `get/list/delete` sur `pv`, `pvc`, `pods` ;
  `get/patch/scale` sur `deployments`/`statefulsets` ; `patch` sur `pv`/`pvc`
  (déblocage des finalizers).
- Côté HYCU/Nutanix : le Volume Group restauré/cloné doit exister, et vous devez
  pouvoir copier sa **référence** depuis l'UI HYCU ou Prism — l'**UUID du VG**
  (suffixe du `volumeHandle` `NutanixVolumes-<uuid>` et de la cible `ntnx-k8s-<uuid>`),
  ou l'**IQN** sur les clusters iSCSI hérités.

## 2. Installation & lancement

```bash
python3 hycu_k8s_nutanix.py
```

Le navigateur s'ouvre sur <http://127.0.0.1:8765> (sinon, ouvrez-le manuellement).
`Ctrl+C` pour arrêter. Les sauvegardes et le journal d'audit sont écrits dans
`./hycu-backups/`.

**Premier lancement** : si `hycu_config.json` n'existe pas encore, un **assistant
de configuration** s'affiche automatiquement (binaire kubectl, contextes/namespaces
autorisés, garde-fous) et génère le fichier pour vous. Vous pouvez aussi le créer à
la main à partir du modèle :

```bash
cp hycu_config.example.json hycu_config.json   # puis éditer (voir §5)
```

Tout reste modifiable ensuite via l'onglet **⚙ Réglages**.

## 3. Déroulé d'une restauration (les 3 onglets)

### Onglet 1 — Sauvegarder
Choisissez un namespace → **Sauvegarder ce namespace**. L'outil exporte et nettoie
tous les PV/PVC (équivaut aux boucles `kubectl get … -o yaml` + nettoyage manuel des
manifestes décrit dans la procédure HYCU).

- **Sauvegarder tous (filtrés)** : sauvegarde en une fois **tous les namespaces
  autorisés** par le filtre (`namespace_filter`), ou **tous** les namespaces du cluster
  si aucun filtre. Un namespace sans PVC est **ignoré** (pas une erreur) ; un récapitulatif
  par namespace est affiché.
- **Dossier de destination (optionnel)** : par défaut, les sauvegardes vont dans
  `hycu-backups/` (à côté du programme). Vous pouvez indiquer un **autre dossier** (sur la
  machine qui exécute l'outil), p. ex. `D:\sauvegardes\hycu` ou `/mnt/backups` ; le
  sous-dossier `<namespace>/<horodatage>/` y est créé automatiquement.

**Copiez le dossier de sauvegarde hors du cluster** (autre stockage) : c'est votre filet
de sécurité.

### Onglet 2 — Restaurer
1. Côté **HYCU** : restaurez ou clonez le Volume Group (suffixe « 0000 »).
2. Dans l'outil : choisissez le namespace, le **type d'opération** (Clone ou
   Restauration sur place), puis **cochez le(s) PVC** à restaurer (plusieurs
   volumes d'une même app = une seule transaction : un arrêt, un redémarrage).
3. **Sauvegarde de configuration à restaurer** : l'outil reconstruit les PV/PVC (le
   « squelette ») à partir d'une **sauvegarde de config** (onglet 1). S'il en existe
   plusieurs, un **menu déroulant** permet de **choisir laquelle** (horodatage + nombre
   de volumes + contexte) ; par défaut la **plus récente**. C'est indépendant du **point
   de restauration HYCU** (les *données* du Volume Group), qui se choisit séparément.
   - Cas du **namespace détruit** : il n'y a plus de PVC « live » à lire — la
     reconstruction s'appuie **entièrement** sur la sauvegarde de config sélectionnée.
   - **Dossier personnalisé** : cochez « Lire les sauvegardes depuis un dossier
     personnalisé » et indiquez le chemin si vos sauvegardes ne sont pas dans
     `hycu-backups/` (p. ex. recopiées sur un partage). La liste et la lecture des
     manifestes viennent alors de ce dossier.
4. Pour chaque volume coché, indiquez la **référence du VG** correspondant — l'**UUID
   du VG** (ou un `volumeHandle`, ou un IQN legacy). Le bouton **« Réf. VG auto »** la
   récupère depuis Prism ; l'orchestration HYCU la remplit automatiquement. En clone,
   le nom du nouveau PV est pré-rempli et modifiable.
5. **Prévisualiser le plan** : vérifiez les remplacements dérivés (`volumeHandle`,
   UUID du VG), la **purge des attributs runtime** du VG source, le passage du PV
   source en **Retain**, et la séquence.
6. En **mode réel** : retapez le nom du contexte pour confirmer, puis **Lancer**.

> Si une étape échoue, la séquence **s'arrête** et l'application est **laissée
> arrêtée** (réplicas à 0) pour ne pas redémarrer sur des volumes incohérents. Le
> message indique l'étape en cause. Corrigez puis **relancez** : les réplicas cibles
> d'origine sont mémorisés (jamais redémarrés à 0).

### Onglet 3 — Vérifier
Confirme que les PVC sont **Bound** et que les pods tournent. Le bouton
**Suivi auto** rafraîchit jusqu'à 10 fois.

## 4. Sécurité

- Le serveur **n'écoute que sur `127.0.0.1`** (jamais exposé au réseau).
- Protection **anti-CSRF / anti-DNS-rebinding** : vérification des en-têtes `Host`
  et `Origin`/`Referer`, et **jeton anti-CSRF** exigé sur chaque action.
- **Dry-run par défaut** ; confirmation du contexte avant toute action réelle.
- **Journal d'audit** append-only : `hycu-backups/audit.log` (horodaté : namespace,
  volumes, mode, dry/réel, résultat).
- **Lecture des sauvegardes bornée** : par défaut, seuls les chemins **sous
  `hycu-backups/`** sont lisibles (défense contre une lecture hors zone). Un **dossier
  personnalisé** n'est ouvert que si **vous le désignez explicitement** dans l'onglet
  Restaurer ; un chemin hors de cette zone reste refusé.

## 5. Configuration (`hycu_config.json`) — adaptation par client

Copiez `hycu_config.example.json` → `hycu_config.json`. Modifiable aussi via
l'onglet **⚙ Réglages** de l'interface. Toutes les clés sont optionnelles.

| Clé | Défaut | Rôle |
|---|---|---|
| `kubectl_path` | `"kubectl"` | Binaire kubectl. Ex. `"microk8s kubectl"`, `"k3s kubectl"`, ou chemin complet. |
| `allowed_contexts` | `[]` | Liste blanche de contextes kubectl. `[]` = tous. En mode réel, un contexte hors liste est **refusé**. |
| `namespace_filter` | `[]` | Liste blanche de namespaces. `[]` = tous. |
| `wait_timeout` | `120` | Attente max (s) d'une suppression / d'un passage `Bound` / de l'arrêt des pods. |
| `subprocess_margin` | `30` | Marge (s) du timeout subprocess au-dessus de `wait_timeout` (pour ne pas tuer `kubectl wait` avant son verdict). |
| `clone_name_suffix` | `"0000"` | Convention HYCU pour le nom du PV cloné (suggestion pré-remplie, modifiable). |
| `volume_handle_prefix` | `""` | **Vide = auto-détecté** depuis le PV existant (suit le driver CSI du client). Ne renseigner que pour forcer un préfixe. |
| `strip_claimref` | `false` | `true` = retirer entièrement `claimRef` du PV (laisse le PVC recréé rebinder). `false` = conserver `claimRef` (name+namespace) sans uid/resourceVersion. |
| `require_context_confirm` | `true` | Exiger la re-saisie du contexte avant toute action réelle. |
| `host` / `port` | `127.0.0.1` / `8765` | Adresse d'écoute. **Ne pas exposer** `host` hors de la boucle locale. |
| `open_browser` | `true` | Ouvrir le navigateur au démarrage. |
| `hycu_url` | `""` | URL du contrôleur HYCU, ex. `https://hycu.exemple.com:8443` (port 8443). Vide = connecteur HYCU désactivé. |
| `hycu_api_base` | `/rest/v1.0` | Base de l'API REST HYCU (**dépend de la version** — voir §8). |
| `hycu_test_path` | `/vms` | Endpoint GET utilisé pour tester la connexion (relevez-le dans le REST API Explorer). |
| `hycu_verify_tls` | `false` | Vérifier le certificat TLS HYCU (souvent auto-signé → `false`). |
| `nutanix_url` | `""` | URL de Prism **Element**, ex. `https://prism.exemple.com:9440`. Vide = désactivé. |
| `nutanix_api_base` | `/PrismGateway/services/rest/v2.0` | Base de l'API Prism Element v2. |
| `nutanix_verify_tls` | `false` | Vérifier le certificat TLS Prism Element. |
| `prismcentral_url` | `""` | URL de Prism **Central**, ex. `https://pc.exemple.com:9440`. Vide = désactivé. |
| `prismcentral_api_base` | `/api/nutanix/v3` | Base de l'API Prism Central v3. |
| `prismcentral_verify_tls` | `false` | Vérifier le certificat TLS Prism Central. |

> Les **identifiants** HYCU/Nutanix ne sont **jamais** dans la config : ils sont saisis
> dans l'onglet **Connexions** et gardés en mémoire le temps de la session uniquement.

### Exemple — un client « microk8s », 2 namespaces, cluster de prod verrouillé
```json
{
  "kubectl_path": "microk8s kubectl",
  "allowed_contexts": ["prod-cluster"],
  "namespace_filter": ["wordpress", "bo-dev"],
  "require_context_confirm": true
}
```

## 6. À valider sur le cluster du client avant la prod

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

## 7. Dépannage

| Symptôme | Piste |
|---|---|
| « Contexte : indisponible » | `kubectl` absent du PATH ou contexte non configuré. |
| « Namespace non autorisé » | Le namespace n'est pas dans `namespace_filter`. |
| « Contexte non autorisé » | Le contexte courant n'est pas dans `allowed_contexts`. |
| PVC/PV reste `Terminating` | L'outil patche les finalizers automatiquement ; sinon vérifier qu'aucun pod ne monte encore le volume. |
| « Jeton anti-CSRF invalide » | Rechargez la page (le jeton est régénéré à chaque démarrage). |
| Séquence « interrompue » | Lire l'étape en cause dans le log, corriger, **relancer** (réplicas mémorisés). |

## 8. Connexions HYCU / Nutanix (onglet « Connexions »)

Connexions **optionnelles** (en stdlib, aucune dépendance) : sans elles, le flux
manuel (coller la référence du VG) reste pleinement utilisable.

- **Nutanix Prism (lecture seule)** — deux zones de connexion : **Prism Element** (API v2)
  et **Prism Central** (API v3, multi-cluster). Dans l'onglet Restaurer, le bouton
  **« Réf. VG auto (Nutanix) »** recherche le Volume Group cloné et **remplit son UUID**
  automatiquement (plus de copier-coller). Il utilise la source connectée — Prism Element
  en priorité, sinon Prism Central.
- **HYCU (actions)** — lister les **Volume Groups protégés** et leurs **points de
  restauration**, choisir **Clone** ou **Restauration sur place**, puis **déclencher**
  et suivre le job. **Mode simulation par défaut** : l'appel exact (méthode + URL + corps)
  est affiché **avant** tout envoi réel.

**Identifiants** : saisis dans l'onglet, **gardés en mémoire** le temps de la session,
**jamais écrits** sur disque ni dans la config (mode par défaut, le plus sûr). Effacés à la
déconnexion / à l'arrêt.

### Mémoriser les connexions (coffre chiffré, optionnel)

L'onglet Connexions propose un coffre chiffré pour ne pas re-saisir les identifiants à
chaque session :

- Les identifiants sont chiffrés dans **`hycu_secrets.enc`** (à côté du programme), protégé
  par une **phrase secrète maîtresse** que **vous seul connaissez** — elle n'est jamais stockée.
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

- **Authentification** (onglet Connexions) :
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
