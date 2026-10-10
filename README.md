# HYCU · Kubernetes on Nutanix

> 🇫🇷 Version française : **[README.fr.md](README.fr.md)** · Full reference: [docs/reference.md](docs/reference.md)

A single web page to **back up, protect and restore** Kubernetes applications whose
volumes (PVCs) are Nutanix Volume Groups protected by **HYCU**. One Python file (standard
library only), also shipped as a container image.

## What it does

- **Backs up** namespace configuration: PV/PVC manifests, Deployments, Services,
  ConfigMaps, Secrets (encrypted). On demand or **automatically** (schedule, retention,
  quota), with optional export to **S3** object storage.
- **Protects** volumes in HYCU: PVC ↔ Volume Group matching, HYCU policy.
- **Restores**: to **new volumes** (HYCU clone), **in place** (HYCU in-place restore), a
  **deleted application**, **in bulk**, or onto **another cluster** (DR). The tool runs
  stop the application → recreate PV/PVC → restart → verify, with a preflight, volume
  protection (Retain) and resume after an interruption.
- **Verifies** state (bound PVCs, pods, events) and logs everything (audit, Jobs page).
- **Multi-cluster** (imported kubeconfigs, NKP workspaces), **EN/FR** interface.

> ⚠ **Destructive tool in live mode**: it deletes and recreates PV/PVCs. Guardrails:
> preflight, confirmation by retyping the cluster name, systematic Retain on volumes.
> Try it on a test namespace first.

## Prerequisites

- A Kubernetes cluster with the **Nutanix CSI** (NKP); `kubectl` ≥ 1.23 (bundled in the image).
- **HYCU** (REST API, port 8443) and **Prism Central / Element** reachable from the tool.
  Credentials are entered in the UI (⚙ Sources), never in a file.
- The required RBAC rights are provided by `deploy/k8s/rbac.yaml`.

## Deploy

### In the cluster (recommended)

```bash
kubectl create namespace hycu
kubectl apply -f deploy/k8s/rbac.yaml                 # ServiceAccount hycu-operator + rights
./deploy/k8s/make-kubeconfig.sh                       # writes ./kubeconfig (SA token, no exec plugin)
kubectl -n hycu create secret generic hycu-kubeconfig --from-file=config=./kubeconfig
kubectl apply -f deploy/k8s/hycu.yaml                 # PVC + Deployment (ghcr.io image, :latest) + Service
```

Access through a tunnel (no Ingress by default):

```bash
kubectl -n hycu port-forward svc/hycu 8765:8765        # then http://127.0.0.1:8765
```

On first launch a wizard creates the configuration. One replica only (global state +
`hycu-data` PVC). Detailed walkthrough: [docs/kubernetes-demarrage.md](docs/kubernetes-demarrage.md) (French).

### With Docker (on a workstation)

```bash
cp ~/.kube/config ./kubeconfig                         # self-contained kubeconfig (token/certs, no exec plugin)
docker compose -f deploy/docker-compose.yml up -d      # then http://127.0.0.1:8765
```

Data lives in `./hycu-data`. Guide: [docs/docker.md](docs/docker.md).

### With Python only

```bash
python3 hycu_k8s_nutanix.py                            # Python 3.7+, kubectl on the workstation
```

## Update

The image `ghcr.io/cabsalon93/hycu-nkp-plugin:latest` is republished with every version;
the manifest and the Compose file use it. Data (`hycu-data` PVC, `./hycu-data`) is kept.
Do not update while a restore is running.

```bash
# Kubernetes: pull the new image and restart
kubectl -n hycu rollout restart deployment/hycu
kubectl -n hycu rollout status deployment/hycu
kubectl -n hycu rollout undo deployment/hycu           # roll back if needed
```

```bash
# Docker Compose
docker compose -f deploy/docker-compose.yml pull
docker compose -f deploy/docker-compose.yml up -d
```

Python mode: replace `hycu_k8s_nutanix.py` and start it again. Then reload the page
(Ctrl+Shift+R): the version is shown at the bottom of the sidebar. To pin an exact
version, every build also exists under the tag `vYYYYMMDD-HHMM`.

## Settings

Everything is set from the UI (⚙ **Settings**, ⚙ **Sources**) or in `hycu_config.json`
(template: [hycu_config.example.json](hycu_config.example.json)). The most useful keys:

| Key | Default | Purpose |
|---|---|---|
| `namespace_filter` | `[]` | Visible namespaces (empty = all). `namespace_label_selector` for a label-based filter. |
| `allowed_contexts` | `[]` | Clusters/contexts allowed in live mode (empty = all, with confirmation). |
| `allowed_hosts` | `[]` | DNS names accepted besides `127.0.0.1` (Ingress / reverse proxy; put authentication in front). |
| `auto_backup_enabled` | `false` | Automatic backup of all visible namespaces. |
| `auto_backup_interval_hours` | `24` | Automatic backup interval. |
| `auto_backup_keep` | `15` | Versions kept per namespace (`0` = unlimited). `auto_backup_retention: "gfs"` for daily/weekly/monthly retention. |
| `storage_quota_gb` / `storage_min_free_mb` | `0` / `500` | Backup folder quota and free-space floor. |
| `backup_secrets` | `"auto"` | Secrets encrypted with the vault passphrase when available (`encrypted`, `clear`, `redacted`). |
| `allow_dr_restore` | `false` | Allow restoring onto another cluster (DR mode). |
| `require_context_confirm` | `true` | Retype the cluster name before any live action. |
| `simulation_mode_available` | `false` | Offer the “simulation mode” (dry-run) switch. |
| `default_lang` | `"en"` | Default UI language (`en` / `fr`). |
| `hycu_url`, `prismcentral_url`, `nutanix_url` | `""` | System addresses (`*_verify_tls`, `*_ca_bundle` for TLS). |
| `s3_url`, `s3_bucket`, `s3_auto_upload`, `s3_encrypt` | `""`, `""`, `false`, `false` | Backup export to an S3 bucket (Nutanix Objects, MinIO, AWS). |
| `kubectl_path`, `kube_context` | `"kubectl"`, `""` | kubectl binary and context of the local cluster. |
| `wait_timeout` | `120` | Max wait (s) for a deletion or a `Bound` PVC. |

In a container, a few environment variables take precedence over the file:
`HYCU_HOST`, `HYCU_PORT`, `HYCU_BACKUP_ROOT`, `HYCU_KUBECTL_PATH`, `HYCU_ALLOWED_HOSTS`
(comma-separated) and `HYCU_VAULT_PASSPHRASE` or `HYCU_VAULT_PASSPHRASE_FILE` (automatic
unlock of the credentials vault at startup).

## Security in short

- Listens on the loopback; any other `Host`/`Origin` is refused unless listed in
  `allowed_hosts`. The tool has **no authentication**: behind a DNS name, put an SSO /
  oauth2-proxy / IP allowlist and TLS in front of it.
- In the cluster, the boundary is the **RBAC of the `hycu` namespace**: whoever can
  `port-forward` or `exec` into the Pod is a full operator.
- HYCU/Prism/S3 credentials stay in memory, or in an **encrypted vault** (passphrase).
- Live mode: blocking preflight, safety backup before a restore, Retain on volumes,
  resumable transaction, audit log.

## Going further

- [docs/reference.md](docs/reference.md) — full reference (all settings, restore paths,
  HYCU/Nutanix endpoints, troubleshooting).
- [docs/kubernetes-demarrage.md](docs/kubernetes-demarrage.md) · [docs/docker.md](docs/docker.md) — detailed deployment (French).
- [docs/audit-2026-10-09.md](docs/audit-2026-10-09.md) — audit and hardening work (French).
- Development: `python build.py --check --lint` (UI sources in `ui/`), `python -m pytest tests`.
