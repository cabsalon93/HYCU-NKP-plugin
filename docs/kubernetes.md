# Quick start — Kubernetes

Run the **HYCU / Kubernetes / Nutanix** tool as a **Pod** in a shared Kubernetes
cluster. It is the **same product** as the Python / Docker version, built from the
**same image**. Several operators can use it (each through their own `port-forward`).

> For workstation mode (Docker), see [`docs/docker-quickstart.md`](docker-quickstart.md).

---

## 0. The model (read once)

- The tool runs as **one Pod** (1 replica **required**: global state + PVC).
- It drives a cluster through a **mounted kubeconfig** (stored as a **Secret**).
  👉 **This kubeconfig decides which cluster is driven**:
  - the **cluster it runs in** (common case), **or**
  - **another cluster** (e.g. the tool runs on a *management* cluster and drives a
    remote *production* cluster).
- **Access = `kubectl port-forward`** by default. To expose the tool under a **DNS name**
  (Ingress, reverse proxy), declare that name in `HYCU_ALLOWED_HOSTS` (or `allowed_hosts`
  in Settings), open the NetworkPolicy to the Ingress controller, and protect the Ingress
  with authentication (SSO, oauth2-proxy, IP allow list) and TLS: see the commented example
  in `deploy/k8s/hycu.yaml`. Any other host name is rejected.
- **Everything persists on a PVC**: configuration, encrypted credential vault, and
  backups. The Pod can restart without losing anything.
- **Access = security**: there is no application-level authentication. Two boundaries:
  the manifest's **NetworkPolicy** (no inbound traffic from the pod network; only
  `kubectl port-forward` gets through) and **RBAC** on the `hycu` namespace: anyone who can
  `port-forward`/`exec` to the Pod becomes a **full operator**. Do not remove the
  NetworkPolicy: without it, any pod in the cluster could drive the tool.
- **Probes**: `GET /healthz` (already configured in the manifest); never probe `/`.

---

## 1. Prerequisites

1. **`kubectl`** configured with access to the target cluster (`kubectl get ns` responds).
2. **A "standalone" kubeconfig** to mount in the Pod: authentication by **ServiceAccount
   token** or **certificates**, **without** an OIDC/SSO exec plugin. To check:

   ```bash
   kubectl config view --minify
   ```

   - `client-certificate-data` / `client-key-data` or `token:` → ✅ usable as is.
   - an `exec:` / `command:` section (kubelogin, oidc-login, aws/gke…) → ⚠️ **not**
     usable in a Pod. Build a standalone kubeconfig (see `deploy/k8s/rbac.yaml`
     and `deploy/k8s/make-kubeconfig.sh` in the repository).
3. A **StorageClass** able to provision a **ReadWriteOnce** volume (the cluster default,
   otherwise specify it — see Troubleshooting).

---

## 2. Deployment — fast path

> Simple assumption: the tool runs in the cluster it drives, with an existing
> kubeconfig. (For a least-privilege identity or a remote cluster, see
> `deploy/k8s/rbac.yaml` and `deploy/k8s/make-kubeconfig.sh` in the repository.)

**1. Create the dedicated namespace:**
```bash
kubectl create namespace hycu
```

**2. Mount a kubeconfig (as a Secret):**

> ⚠️ **Do not mount your personal kubeconfig** (often `cluster-admin`, sometimes with an
> `exec` plugin that does not work in a container). Create the dedicated least-privilege
> identity (`deploy/k8s/rbac.yaml` + `deploy/k8s/make-kubeconfig.sh`, time-limited token,
> to be renewed) and mount **that** kubeconfig:
```bash
kubectl apply -f deploy/k8s/rbac.yaml            # ServiceAccount + permissions (see the per-namespace Secrets RoleBindings)
./deploy/k8s/make-kubeconfig.sh                  # writes ./kubeconfig (umask 077, 1-year token by default)
kubectl -n hycu create secret generic hycu-kubeconfig --from-file=config=./kubeconfig
```

**3. Deploy the tool.** The image is pulled **automatically from ghcr.io**
(`ghcr.io/cabsalon93/hycu-nkp-plugin:latest`, public) — nothing to build. Two ways to
apply the manifest, **either one**:

- **Without cloning the repository** (straight from the public GitHub URL):
  ```bash
  kubectl apply -f https://raw.githubusercontent.com/cabsalon93/HYCU-NKP-plugin/main/deploy/k8s/hycu.yaml
  ```
  *(Replace `main` with a release tag, e.g. `v0.1.0`, to pin a version.)*

- **From a local copy** (cloned repository):
  ```bash
  git clone https://github.com/cabsalon93/HYCU-NKP-plugin.git
  cd HYCU-NKP-plugin
  kubectl apply -f deploy/k8s/hycu.yaml
  ```

**4. Check that the Pod starts:**
```bash
kubectl -n hycu get pods -w
```
Wait for **`Running`** / `1/1`, then `Ctrl + C`.

**5. Open the interface:**
```bash
kubectl -n hycu port-forward svc/hycu 8765:8765
```
Leave this window **open**, then point your browser to **http://127.0.0.1:8765**.

**6. Check the cluster connection:** in the header, the active cluster (kubectl context)
must show **your cluster** (not "unavailable"). ✅ The tool is driving Kubernetes.

---

## 3. Update to a new image version

The manifest uses the `:latest` image (republished with every release, `imagePullPolicy:
Always`): no version number to know. To move to the latest version:

```bash
kubectl -n hycu rollout restart deployment/hycu
kubectl -n hycu rollout status deployment/hycu      # wait for "successfully rolled out"
# roll back if needed:
kubectl -n hycu rollout undo deployment/hycu
```

If you prefer to pin a specific version, each build also exists under a
`:vYYYYMMDD-HHMM` tag (the version shown at the bottom left of the interface):
`kubectl -n hycu set image deployment/hycu hycu=ghcr.io/cabsalon93/hycu-nkp-plugin:vYYYYMMDD-HHMM`.

The Pod is recreated in ~30 s (your data stays on the
PVC). ⚠️ The `port-forward` drops when the Pod restarts: **restart it** (`Ctrl + C`
then the command from step 5).

### Optional — unlock the vault automatically at startup

So that saved connections and clusters (encrypted vault) come back on their own
after a Pod restart (required for automatic backup of added clusters):

```bash
kubectl -n hycu create secret generic hycu-vault-pass --from-literal=passphrase='MySecretPassphrase'
```

then, in the Deployment, mount this Secret and point the variable to it:

```yaml
        env:
          - { name: HYCU_VAULT_PASSPHRASE_FILE, value: /home/app/.vault/passphrase }
        volumeMounts:
          - { name: vaultpass, mountPath: /home/app/.vault, readOnly: true }
      volumes:
        - name: vaultpass
          secret: { secretName: hycu-vault-pass }
```

> ⚠️ Anyone who can read this Secret can decrypt the vault: use this mode only in a
> properly locked-down `hycu` namespace (RBAC).

---

## 4. Get a backup onto your workstation

In container/K8s mode, backups are written **inside the Pod** (on the PVC): the server
cannot write to your PC. To get a backup **locally**:

- **Simplest** — in the tool, click **⬇ Download (.zip)** next to a backup
  (*Back up* or *Restore* flow): your browser saves it on **your PC**.
  **⬇ Download all (.zip)** gets everything.
- **Command line** (alternative):
  ```bash
  pod=$(kubectl -n hycu get pod -l app=hycu -o jsonpath='{.items[0].metadata.name}')
  kubectl -n hycu cp "$pod:/data/hycu-backups/<namespace>" ./export-<namespace>
  ```

> ⚠️ Everything lives on the `hycu-data` PVC. **Do not delete it** before retrieving what
> matters — or put it on storage that is itself backed up.

---

## 5. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Pod **`Pending`** for a long time | PVC not bound (no default StorageClass) | `kubectl get storageclass`; uncomment `storageClassName:` in `hycu.yaml` (PVC) with your RWO class |
| **`ImagePullBackOff`** | Image not reachable from the cluster | Check the nodes' internet access (ghcr.io), or use an internal registry / an image loaded offline |
| **Cluster shown as "unavailable"** | OIDC kubeconfig, or API unreachable from the Pod | Use a standalone kubeconfig (`deploy/k8s/rbac.yaml` + `make-kubeconfig.sh`); for the local cluster, point `server:` to `https://kubernetes.default.svc` |
| `port-forward` dropped | The Pod restarted | Run the step 5 command again |
| Page not reachable | Wrong URL | Make sure you open `http://127.0.0.1:8765` (not `https`) |
