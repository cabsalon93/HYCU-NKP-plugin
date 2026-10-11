# Installation rapide (test)

Installe l'outil HYCU · Kubernetes sur Nutanix dans un cluster, en 5 commandes.

## Prérequis

- `kubectl` configuré sur le cluster cible.
- Un kubeconfig **autonome** (jeton ou certificat). Les kubeconfigs à plugin `exec`
  (OIDC, aws, gcloud) ne fonctionnent pas dans le conteneur.
- Une StorageClass par défaut sur le cluster (sur NKP : `nutanix-volume`, en général).

## Installation

```bash
kubectl create namespace hycu
kubectl -n hycu create secret generic hycu-kubeconfig --from-file=config=$HOME/.kube/config
kubectl apply -f https://raw.githubusercontent.com/cabsalon93/HYCU-NKP-plugin/main/deploy/k8s/hycu.yaml
kubectl -n hycu rollout status deployment hycu
kubectl -n hycu port-forward svc/hycu 8765:8765
```

Ouvrir ensuite <http://127.0.0.1:8765>.

Sous Windows PowerShell, remplacer `$HOME/.kube/config` par `$env:USERPROFILE\.kube\config`.

## Plusieurs clusters

L'outil pilote d'abord le cluster où il est installé. Les autres clusters s'ajoutent
depuis l'interface : **⚙ Sources → ajouter un cluster** (kubeconfig collé ou workspace NKP).

## Mise à jour

```bash
kubectl -n hycu rollout restart deployment/hycu
kubectl -n hycu rollout status deployment/hycu
```

Relancer ensuite le `port-forward` et recharger la page (Ctrl+Shift+R).

## Désinstallation

```bash
kubectl delete namespace hycu
```

⚠ Cette commande supprime aussi le PVC `hycu-data` (configuration, coffre, sauvegardes de
configuration). Les données des volumes protégées par HYCU ne sont pas touchées.

## À savoir

- L'outil utilise les droits du kubeconfig fourni, souvent administrateur : acceptable pour
  un essai, pas pour la production (voir `deploy/k8s/rbac.yaml` pour un compte dédié).
- Tant que le `port-forward` tourne, l'interface n'est accessible que depuis le poste local.
