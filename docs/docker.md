# Exécution en conteneur (Docker) ou sur Kubernetes

L'outil est **un seul produit** (`hycu_k8s_nutanix.py`). Il se lance de deux façons à
partir du **même code** :

- **Mode python** : `python hycu_k8s_nutanix.py` (cf. README).
- **Mode conteneur** : la même image tourne en **Docker** ou comme **Pod Kubernetes**.

Le comportement est piloté par **variables d'environnement** (aucun fork de code) :

| Variable | Défaut (mode python) | Valeur conteneur | Rôle |
|---|---|---|---|
| `HYCU_HOST` | `127.0.0.1` | `0.0.0.0` | interface d'écoute (publiée sur la loopback de l'hôte) |
| `HYCU_PORT` | `8765` | `8765` | port |
| `HYCU_OPEN_BROWSER` | `1` | `0` | ouverture auto du navigateur (impossible en conteneur) |
| `HYCU_BACKUP_ROOT` | `./hycu-backups` | `/data/hycu-backups` | dossier des sauvegardes/coffre/état (volume) |
| `HYCU_KUBECTL_PATH` | `kubectl` | `kubectl` | binaire kubectl |
| `TZ` | (système) | `Europe/Paris` | fuseau des horodatages de sauvegarde |

---

## 1. Docker (poste / serveur)

```bash
mkdir -p hycu-data
cp /chemin/vers/mon-kubeconfig ./kubeconfig     # kubeconfig AUTONOME (voir §4)
docker compose -f deploy/docker-compose.yml up   # ou: docker run … (ci-dessous)
# Ouvrir : http://127.0.0.1:8765
```

`docker run` équivalent :
```bash
docker run --rm -p 127.0.0.1:8765:8765 \
  -v "$PWD/hycu-data:/data" \
  -v "$PWD/kubeconfig:/home/app/.kube/config:ro" \
  -e TZ=Europe/Paris \
  ghcr.io/cabsalon93/hycu-nkp-plugin:latest
```

## 2. Kubernetes

```bash
kubectl create namespace hycu
kubectl -n hycu create secret generic hycu-kubeconfig --from-file=config=./kubeconfig
kubectl apply -f deploy/k8s/hycu.yaml
kubectl -n hycu port-forward svc/hycu 8765:8765
# Ouvrir : http://127.0.0.1:8765
```

## 3. Site isolé (air-gap)

```bash
# Côté éditeur (connecté) :
docker save ghcr.io/cabsalon93/hycu-nkp-plugin:<version> | gzip > hycu-nkp.tar.gz
# Côté client (isolé) :
docker load -i hycu-nkp.tar.gz
```

---

## 4. Les 4 pièges à connaître

1. **kubeconfig autonome obligatoire.** Le conteneur n'a **pas** les exec-plugins
   (`aws eks get-token`, `gke-gcloud-auth-plugin`, `kubelogin`/OIDC…). Fournissez un
   kubeconfig à **token de ServiceAccount** ou à **certs clients**. Vérifiez aussi que
   l'URL de l'API du cluster est **joignable** depuis le conteneur (pas un `127.0.0.1`
   de type kind/minikube).

2. **Publier sur la loopback de l'hôte UNIQUEMENT** : `-p 127.0.0.1:8765:8765`.
   **Jamais** `-p 8765:8765` (cela exposerait l'outil au réseau). La garde anti-DNS-
   rebinding refuse de toute façon les accès dont l'en-tête `Host` n'est pas loopback.

3. **« Dossier personnalisé » = chemin DANS le conteneur.** Les champs « dossier de
   destination » (sauvegarde) et « dossier personnalisé » (restauration) désignent un
   chemin **du conteneur**, jamais le disque du client. Pour récupérer une sauvegarde sur
   votre poste, le plus simple est le bouton **⬇ Télécharger (.zip)** de l'UI (le
   navigateur la dépose localement ; marche en Docker **et** en K8s, sans montage). En
   Docker, vous pouvez aussi monter un dossier de l'hôte
   (`-v D:\sauvegardes:/backups-externe`) et saisir le chemin **conteneur**
   (`/backups-externe`).

4. **Accès = sécurité.** Aucune authentification applicative : quiconque peut
   `port-forward`/`exec` vers le Pod (ou atteindre `127.0.0.1:8765` sur l'hôte) devient
   **opérateur complet**. En K8s, la frontière réelle est le **RBAC** du namespace `hycu`.

---

## 5. Instance partagée (multi-opérateurs)

Une seule instance peut servir plusieurs opérateurs (port-forward chacun de leur côté) :
- **connexion HYCU/Nutanix unique partagée** : tout le monde agit sous les identifiants
  saisis par la première personne connectée ; l'audit n'identifie **pas** la personne ;
- **opérations sérialisées** (verrou global) : une opération à la fois, tous confondus ;
- **1 réplica obligatoire** en K8s (ne pas scaler).

## 6. Notes

- **Persistance** : tout vit sous `/data` (config `hycu_config.json`, coffre chiffré
  `hycu_secrets.enc`, `hycu-backups/`, état txn/réplicas). Montez ce volume, sinon tout
  est perdu au `docker rm` / recréation du Pod.
- **Proxy d'entreprise** : `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` sont respectées (urllib).
- **Parité** : l'image et le `.py` portent le même numéro de `VERSION` (visible dans
  l'en-tête de l'UI).
