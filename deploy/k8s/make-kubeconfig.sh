#!/usr/bin/env bash
# Fabrique un kubeconfig AUTONOME (token de ServiceAccount + CA, SANS exec-plugin)
# à partir du SA hycu-operator créé par rbac.yaml. C'est ce kubeconfig que l'outil
# montera pour piloter le cluster.
#
# Usage :
#   ./make-kubeconfig.sh                     # cible le cluster où tourne l'outil (API interne)
#   ./make-kubeconfig.sh https://api.mon-cluster:6443   # cible un cluster distant joignable
set -euo pipefail

NS=hycu
SA_SECRET=hycu-operator-token
OUT=./kubeconfig

# URL de l'API : argument fourni, sinon l'API interne (cas « l'outil protège SON cluster »).
SERVER="${1:-https://kubernetes.default.svc}"

echo "Attente du token du ServiceAccount ${NS}/${SA_SECRET}…"
for _ in $(seq 1 30); do
  if kubectl -n "$NS" get secret "$SA_SECRET" -o jsonpath='{.data.token}' >/dev/null 2>&1; then break; fi
  sleep 1
done

TOKEN="$(kubectl -n "$NS" get secret "$SA_SECRET" -o jsonpath='{.data.token}' | base64 -d)"
kubectl -n "$NS" get secret "$SA_SECRET" -o jsonpath='{.data.ca\.crt}' | base64 -d > /tmp/hycu-ca.crt

kubectl config --kubeconfig="$OUT" set-cluster target \
  --server="$SERVER" --certificate-authority=/tmp/hycu-ca.crt --embed-certs=true
kubectl config --kubeconfig="$OUT" set-credentials hycu-operator --token="$TOKEN"
kubectl config --kubeconfig="$OUT" set-context target \
  --cluster=target --user=hycu-operator --namespace=default
kubectl config --kubeconfig="$OUT" use-context target
rm -f /tmp/hycu-ca.crt

echo "OK -> kubeconfig autonome écrit : $OUT  (serveur: $SERVER)"
echo "Vérif rapide : KUBECONFIG=$OUT kubectl get ns"
