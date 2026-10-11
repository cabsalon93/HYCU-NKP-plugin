# Quick installation (test)

Installs the HYCU · Kubernetes on Nutanix tool in a cluster, in 5 commands.

## Prerequisites

- `kubectl` configured for the target cluster.
- A **standalone** kubeconfig (token or certificate). Kubeconfigs with an `exec` plugin
  (OIDC, aws, gcloud) do not work in the container.
- A default StorageClass on the cluster (on NKP: usually `nutanix-volume`).

## Installation

```bash
kubectl create namespace hycu
kubectl -n hycu create secret generic hycu-kubeconfig --from-file=config=$HOME/.kube/config
kubectl apply -f https://raw.githubusercontent.com/cabsalon93/HYCU-NKP-plugin/main/deploy/k8s/hycu.yaml
kubectl -n hycu rollout status deployment hycu
kubectl -n hycu port-forward svc/hycu 8765:8765
```

Then open <http://127.0.0.1:8765>.

On Windows PowerShell, replace `$HOME/.kube/config` with `$env:USERPROFILE\.kube\config`.

## Multiple clusters

The tool first drives the cluster it is installed in. Other clusters are added
from the interface: **⚙ Sources → Add a Kubernetes cluster** (pasted kubeconfig or NKP workspace).

## Update

```bash
kubectl -n hycu rollout restart deployment/hycu
kubectl -n hycu rollout status deployment/hycu
```

Then restart the `port-forward` and reload the page (Ctrl+Shift+R).

## Uninstall

```bash
kubectl delete namespace hycu
```

⚠ This command also deletes the `hycu-data` PVC (configuration, vault, configuration
backups). Volume data protected by HYCU is not affected.

## Good to know

- The tool uses the permissions of the provided kubeconfig, often administrator: fine for
  a trial, not for production (see `deploy/k8s/rbac.yaml` for a dedicated account).
- While the `port-forward` is running, the interface is only reachable from the local workstation.
