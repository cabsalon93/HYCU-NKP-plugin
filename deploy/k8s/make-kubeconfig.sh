#!/usr/bin/env bash
# Builds a STANDALONE kubeconfig (ServiceAccount token + CA, NO exec plugin) for the
# hycu-operator ServiceAccount created by rbac.yaml. The tool mounts this kubeconfig to
# drive the cluster.
#
# The token comes from the TokenRequest API (`kubectl create token`): it is time-limited,
# nothing long-lived is stored in the cluster. Run the script again before it expires and
# update the hycu-kubeconfig Secret.
#
# Usage:
#   ./make-kubeconfig.sh                                  # the cluster the tool runs in (internal API)
#   ./make-kubeconfig.sh https://api.my-cluster:6443      # a remote cluster reachable from the Pod
# Environment:
#   DURATION=8760h   token lifetime (default 1 year; the API server may cap it)
#   OUT=./kubeconfig output file
#   CA_FILE=...      CA bundle to embed (default: the cluster CA, ConfigMap kube-root-ca.crt)
#   NS=hycu SA=hycu-operator   namespace and ServiceAccount
set -euo pipefail
umask 077

NS="${NS:-hycu}"
SA="${SA:-hycu-operator}"
OUT="${OUT:-./kubeconfig}"
DURATION="${DURATION:-8760h}"
SERVER="${1:-https://kubernetes.default.svc}"

kubectl -n "$NS" get serviceaccount "$SA" >/dev/null \
  || { echo "ServiceAccount $NS/$SA not found: run 'kubectl apply -f deploy/k8s/rbac.yaml' first." >&2; exit 1; }

TOKEN="$(kubectl -n "$NS" create token "$SA" --duration="$DURATION")"
[ -n "$TOKEN" ] || { echo "No token returned by the TokenRequest API." >&2; exit 1; }

TMP_CA="$(mktemp)"
trap 'rm -f "$TMP_CA"' EXIT
if [ -n "${CA_FILE:-}" ]; then
  cp "$CA_FILE" "$TMP_CA"
else
  kubectl -n "$NS" get configmap kube-root-ca.crt -o jsonpath='{.data.ca\.crt}' > "$TMP_CA"
fi
[ -s "$TMP_CA" ] || { echo "Cluster CA not found (ConfigMap $NS/kube-root-ca.crt); set CA_FILE." >&2; exit 1; }

rm -f "$OUT"
kubectl config --kubeconfig="$OUT" set-cluster target \
  --server="$SERVER" --certificate-authority="$TMP_CA" --embed-certs=true >/dev/null
kubectl config --kubeconfig="$OUT" set-credentials "$SA" --token="$TOKEN" >/dev/null
kubectl config --kubeconfig="$OUT" set-context target \
  --cluster=target --user="$SA" --namespace=default >/dev/null
kubectl config --kubeconfig="$OUT" use-context target >/dev/null

# Real expiry (the API server may shorten the requested duration).
EXP="$(printf '%s' "$TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | sed -n 's/.*"exp":\([0-9]*\).*/\1/p' || true)"
echo "OK -> standalone kubeconfig written: $OUT (server: $SERVER)"
[ -n "$EXP" ] && echo "Token valid until: $(date -u -d "@$EXP" '+%Y-%m-%d %H:%M UTC' 2>/dev/null || echo "$EXP (epoch)")"
echo "Next: kubectl -n $NS create secret generic hycu-kubeconfig --from-file=config=$OUT --dry-run=client -o yaml | kubectl apply -f -"
