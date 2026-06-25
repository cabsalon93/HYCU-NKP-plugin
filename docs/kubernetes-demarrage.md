# Démarrage rapide — Kubernetes

Faire tourner l'outil **HYCU / Kubernetes / Nutanix** comme un **Pod** dans un cluster
Kubernetes partagé. C'est le **même produit** que la version Python / Docker, à partir de
la **même image**. Plusieurs opérateurs peuvent l'utiliser (chacun via son `port-forward`).

> Pour le mode poste (Docker), voir [`docs/docker-demarrage.md`](docker-demarrage.md).

---

## 0. Le modèle (à lire une fois)

- L'outil tourne comme **un Pod** (1 réplica **obligatoire** : état global + PVC).
- Il pilote un cluster via un **kubeconfig monté** (sous forme de **Secret**). 
  👉 **C'est ce kubeconfig qui décide quel cluster est piloté** :
  - le **cluster où il tourne** (cas courant), **ou**
  - un **autre cluster** (ex. l'outil sur un cluster *d'administration*, et il pilote un
    cluster *de production* distant).
- **Accès = `kubectl port-forward`** (pas d'Ingress : une protection interne n'accepte que
  les accès en boucle locale).
- **Tout persiste sur un PVC** : configuration, coffre chiffré des identifiants, et
  sauvegardes. Le Pod peut redémarrer sans rien perdre.
- **Accès = sécurité** : il n'y a pas d'authentification applicative. La frontière réelle,
  c'est le **RBAC** du namespace `hycu` : quiconque peut `port-forward`/`exec` vers le Pod
  devient **opérateur complet**.

---

## 1. Prérequis

1. **`kubectl`** configuré et un accès au cluster cible (`kubectl get ns` répond).
2. **Un kubeconfig « autonome »** à monter dans le Pod : authentification par **token de
   ServiceAccount** ou **certificats**, **sans** exec-plugin OIDC/SSO. Pour vérifier :

   ```bash
   kubectl config view --minify
   ```

   - `client-certificate-data` / `client-key-data` ou `token:` → ✅ utilisable tel quel.
   - une section `exec:` / `command:` (kubelogin, oidc-login, aws/gke…) → ⚠️ **non**
     utilisable dans un Pod. Fabriquez un kubeconfig autonome (voir `deploy/k8s/rbac.yaml`
     et `deploy/k8s/make-kubeconfig.sh` dans le dépôt).
3. Une **StorageClass** capable de provisionner un volume **ReadWriteOnce** (par défaut
   sur le cluster, sinon à préciser — cf. dépannage).

---

## 2. Déploiement — chemin rapide

> Hypothèse simple : l'outil tourne dans le cluster qu'il pilote, avec un kubeconfig
> existant. (Pour une identité à droits limités ou un cluster distant, voir
> `deploy/k8s/rbac.yaml` et `deploy/k8s/make-kubeconfig.sh` dans le dépôt.)

**1. Créer le namespace dédié :**
```bash
kubectl create namespace hycu
```

**2. Monter ton kubeconfig (sous forme de Secret) :**
```bash
kubectl -n hycu create secret generic hycu-kubeconfig --from-file=config=<chemin-vers-ton-kubeconfig>
```
*(Windows : `--from-file=config=C:\Users\<toi>\.kube\config`.)*

**3. Déployer l'outil.** L'image est tirée **automatiquement depuis ghcr.io**
(`ghcr.io/cabsalon93/hycu-nkp-plugin:latest`, publique) — rien à construire. Deux façons
d'appliquer le manifeste, **au choix** :

- **Sans cloner le dépôt** (directement depuis l'URL publique GitHub) :
  ```bash
  kubectl apply -f https://raw.githubusercontent.com/cabsalon93/HYCU-NKP-plugin/main/deploy/k8s/hycu.yaml
  ```
  *(Remplacez `main` par un tag de version, ex. `v0.1.0`, pour épingler une version.)*

- **Depuis une copie locale** (dépôt cloné) :
  ```bash
  git clone https://github.com/cabsalon93/HYCU-NKP-plugin.git
  cd HYCU-NKP-plugin
  kubectl apply -f deploy/k8s/hycu.yaml
  ```

**4. Vérifier que le Pod démarre :**
```bash
kubectl -n hycu get pods -w
```
Attends **`Running`** / `1/1`, puis `Ctrl + C`.

**5. Accéder à l'interface :**
```bash
kubectl -n hycu port-forward svc/hycu 8765:8765
```
Laisse cette fenêtre **ouverte**, puis ouvre ton navigateur sur **http://127.0.0.1:8765**.

**6. Vérifier la connexion au cluster :** dans l'en-tête, **« Contexte kubectl »** doit
afficher **ton cluster** (et non « indisponible »). ✅ L'outil pilote bien Kubernetes.

---

## 3. Mettre à jour vers une nouvelle version de l'image

Le déploiement utilise l'image `:latest`. Pour récupérer une nouvelle version :

```bash
kubectl -n hycu rollout restart deployment hycu
kubectl -n hycu rollout status deployment hycu      # attendre "successfully rolled out"
```

Le Pod se recrée en ~30 s (tes données restent sur le PVC). ⚠️ Le `port-forward` se coupe
quand le Pod redémarre : **relance-le** (`Ctrl + C` puis la commande de l'étape 5).

> En production, préférez une **image versionnée** (ex. `:v0.1.0`) à `:latest`, pour
> maîtriser les montées de version.

---

## 4. Récupérer une sauvegarde sur ton poste

En mode conteneur/K8s, les sauvegardes s'écrivent **dans le Pod** (sur le PVC) : le serveur
ne peut pas écrire sur ton PC. Pour récupérer une sauvegarde **localement** :

- **Le plus simple** — dans l'outil, clique sur **⬇ Télécharger (.zip)** à côté d'une
  sauvegarde (onglet *Sauvegarde* ou *Restauration*) : ton navigateur la dépose sur **ton
  PC**. Le bouton **⬇ Tout télécharger** récupère l'ensemble.
- **En ligne de commande** (alternative) :
  ```bash
  pod=$(kubectl -n hycu get pod -l app=hycu -o jsonpath='{.items[0].metadata.name}')
  kubectl -n hycu cp "$pod:/data/hycu-backups/<namespace>" ./export-<namespace>
  ```

> ⚠️ Tout vit sur le PVC `hycu-data`. **Ne le supprime pas** sans avoir récupéré ce qui
> compte — ou place-le sur un stockage lui-même sauvegardé.

---

## 5. Dépannage

| Symptôme | Cause probable | Solution |
|---|---|---|
| Pod **`Pending`** longtemps | PVC non lié (pas de StorageClass par défaut) | `kubectl get storageclass` ; décommentez `storageClassName:` dans `hycu.yaml` (PVC) avec votre classe RWO |
| **`ImagePullBackOff`** | Image inaccessible au cluster | Vérifiez l'accès internet des nœuds (ghcr.io), ou utilisez un registre interne / une image chargée hors-ligne |
| **« Contexte kubectl : indisponible »** | Kubeconfig OIDC, ou API injoignable depuis le Pod | Utilisez un kubeconfig autonome (`deploy/k8s/rbac.yaml` + `make-kubeconfig.sh`) ; pour le cluster local, pointez le `server:` sur `https://kubernetes.default.svc` |
| `port-forward` coupé | Le Pod a redémarré | Relancez la commande de l'étape 5 |
| Page inaccessible | Mauvaise URL | Ouvrez bien `http://127.0.0.1:8765` (pas `https`) |
