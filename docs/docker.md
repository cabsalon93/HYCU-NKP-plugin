# Running in a container (Docker) or on Kubernetes

The tool is **a single product** (`hycu_k8s_nutanix.py`). It runs in two ways from
the **same code**:

- **Python mode**: `python hycu_k8s_nutanix.py` (see README).
- **Container mode**: the same image runs in **Docker** or as a **Kubernetes Pod**.

Behavior is controlled by **environment variables** (no code fork):

| Variable | Default (Python mode) | Container value | Purpose |
|---|---|---|---|
| `HYCU_HOST` | `127.0.0.1` | `0.0.0.0` | listen interface (published on the host loopback) |
| `HYCU_PORT` | `8765` | `8765` | port |
| `HYCU_OPEN_BROWSER` | `1` | `0` | open the browser automatically (not possible in a container) |
| `HYCU_BACKUP_ROOT` | `./hycu-backups` | `/data/hycu-backups` | folder for backups/vault/state (volume) |
| `HYCU_KUBECTL_PATH` | `kubectl` | `kubectl` | kubectl binary |
| `TZ` | (system) | `Europe/Paris` | time zone of backup timestamps |

---

## 1. Docker (workstation / server)

```bash
mkdir -p hycu-data
cp /path/to/my-kubeconfig ./kubeconfig     # STANDALONE kubeconfig (see §4)
docker compose -f deploy/docker-compose.yml up   # or: docker run … (below)
# Open: http://127.0.0.1:8765
```

Equivalent `docker run`:
```bash
docker run --rm -p 127.0.0.1:8765:8765 \
  -v "$PWD/hycu-data:/data" \
  -v "$PWD/kubeconfig:/home/app/.kube/config:ro" \
  -e TZ=Europe/Paris \
  ghcr.io/cabsalon93/hycu-nkp-plugin:latest
```

## 2. Kubernetes

> Step-by-step user guide: **[docs/kubernetes.md](kubernetes.md)**
> (prerequisites, updates, least-privilege RBAC, remote cluster, troubleshooting).

```bash
kubectl create namespace hycu
kubectl -n hycu create secret generic hycu-kubeconfig --from-file=config=./kubeconfig
kubectl apply -f deploy/k8s/hycu.yaml
kubectl -n hycu port-forward svc/hycu 8765:8765
# Open: http://127.0.0.1:8765
```

## 3. Isolated site (air-gap)

```bash
# Vendor side (connected):
docker save ghcr.io/cabsalon93/hycu-nkp-plugin:<version> | gzip > hycu-nkp.tar.gz
# Customer side (isolated):
docker load -i hycu-nkp.tar.gz
```

---

## 4. The 4 pitfalls to know

1. **A standalone kubeconfig is required.** The container does **not** have the exec plugins
   (`aws eks get-token`, `gke-gcloud-auth-plugin`, `kubelogin`/OIDC…). Provide a
   kubeconfig with a **ServiceAccount token** or **client certs**. Also check that the
   cluster API URL is **reachable** from the container (not a kind/minikube-style
   `127.0.0.1`).

2. **Publish on the host loopback ONLY**: `-p 127.0.0.1:8765:8765`.
   **Never** `-p 8765:8765` (it would expose the tool to the network). The DNS-rebinding
   guard rejects any request whose `Host` header is not loopback anyway.

3. **"Custom folder" = path INSIDE the container.** The "Destination folder" (backup)
   and "custom folder" (restore) fields refer to a **container** path, never the client's
   disk. To get a backup onto your workstation, the simplest way is the UI's
   **⬇ Download (.zip)** button (the browser saves it locally; works in Docker **and** K8s,
   no mount needed). In Docker, you can also mount a host folder
   (`-v D:\backups:/backups-externe`) and enter the **container** path
   (`/backups-externe`).

4. **Access = security.** No application-level authentication: anyone who can
   `port-forward`/`exec` to the Pod (or reach `127.0.0.1:8765` on the host) becomes a
   **full operator**. In K8s, the boundaries are the manifest's **NetworkPolicy**
   (no inbound traffic from pods) and **RBAC** on the `hycu` namespace.
   The image `HEALTHCHECK` and the K8s probes use `GET /healthz`, which never touches
   the session (probing `/` would evict the operator).

---

## 5. Shared instance (multiple operators)

A single instance can serve several operators (each with their own port-forward):
- **one shared HYCU/Nutanix connection**: everyone acts under the credentials entered
  by the first person to connect; the audit log does **not** identify the person;
- **serialized operations** (global lock): one operation at a time, across all operators;
- **1 replica required** in K8s (do not scale).

## 6. Notes

- **Persistence**: everything lives under `/data` (config `hycu_config.json`, encrypted vault
  `hycu_secrets.enc`, `hycu-backups/`, txn/replica state). Mount this volume, otherwise
  everything is lost on `docker rm` / Pod re-creation.
- **Corporate proxy**: `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` are honored (urllib).
- **Parity**: the image and the `.py` carry the same `VERSION` number (shown in
  the UI header).
