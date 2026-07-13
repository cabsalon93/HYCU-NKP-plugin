# HYCU Tool · Kubernetes Restore on Nutanix

> 🇫🇷 Version française : **[README.fr.md](README.fr.md)**

Guided web interface to **back up and restore** Kubernetes applications whose
volumes (PVC = Nutanix Volume Groups) are protected by **HYCU**.

The tool replaces the manual procedure (≈ 20 `kubectl` commands + hand-editing
YAML) with a few clicks. At restore time, the **only input** required is the
**reference of the cloned/restored Volume Group** — its **UUID** (modern Nutanix
CSI / NKP: the VG is attached directly to the worker VM, **no more IQN**), a
`volumeHandle`, or an **IQN** (legacy iSCSI clusters). The tool derives the
`volumeHandle` from it, regenerates the PV manifest, then runs
`scale-down → delete → patch finalizer → apply → scale-up → verification`.

> ⚠️ **Destructive tool.** It deletes and recreates PVs/PVCs. **Simulation
> (dry-run) mode is enabled by default**. Always test on a test namespace before
> production, and review the preview before disabling simulation.

---

## 1. Prerequisites

- **Python 3.7+** (no library to install — a single file, stdlib only).
- **`kubectl`** installed and configured on the **right context** (the target
  cluster). The current context is displayed at the top of the page.
- Sufficient RBAC rights: `get/list/delete` on `pv`, `pvc`, `pods`;
  `get/patch/scale` on `deployments`/`statefulsets`; `patch` on `pv`/`pvc`
  (finalizer unblocking).
- On the HYCU/Nutanix side: the restored/cloned Volume Group must exist, and you
  must be able to copy its **reference** from the HYCU UI or Prism — the **VG
  UUID** (suffix of the `volumeHandle` `NutanixVolumes-<uuid>` and of the
  `ntnx-k8s-<uuid>` target), or the **IQN** on legacy iSCSI clusters.

## 2. Installation & launch

**Python mode** (default):
```bash
python3 hycu_k8s_nutanix.py
```

The browser opens at <http://127.0.0.1:8765> (otherwise, open it manually).
`Ctrl+C` to stop. Backups and the audit log are written to `./hycu-backups/`.

**Container mode** (Docker or Kubernetes): the **same image** packages this
script and bundles `kubectl`, for workstations without Python. Behaviour is
driven by environment variables (same code, two packagings). Guides: overview
**[docs/docker.md](docs/docker.md)** · getting started
**[Docker](docs/docker-demarrage.md)** · getting started
**[Kubernetes](docs/kubernetes-demarrage.md)**.
```bash
docker compose -f deploy/docker-compose.yml up      # then http://127.0.0.1:8765
```

#### Providing the kubeconfig in Kubernetes mode

In the image, `kubectl` is bundled and reads `KUBECONFIG=/home/app/.kube/config`:
there is therefore **no command-line option** to pass. The kubeconfig is provided
via a **Secret** mounted at that location.

Use a **self-contained** kubeconfig (ServiceAccount token + CA, **without**
`aws`/`gcloud`/`oidc`-style exec-plugins, which do not work inside the
container). The script
[deploy/k8s/make-kubeconfig.sh](deploy/k8s/make-kubeconfig.sh) builds one from
the `hycu-operator` ServiceAccount created by
[deploy/k8s/rbac.yaml](deploy/k8s/rbac.yaml).

Then create the Secret (name and namespace expected by
[deploy/k8s/hycu.yaml](deploy/k8s/hycu.yaml)):

```bash
kubectl -n hycu create secret generic hycu-kubeconfig --from-file=config=./kubeconfig
```

- `-n hycu`: namespace where the tool runs.
- `hycu-kubeconfig`: name of the Secret referenced by the deployment.
- `--from-file=config=./kubeconfig`: the **key** must be `config` (mounted as
  `/home/app/.kube/config`); `./kubeconfig` is your local file.

To **replace** an existing kubeconfig, add `--dry-run=client -o yaml | kubectl apply -f -`:

```bash
kubectl -n hycu create secret generic hycu-kubeconfig \
  --from-file=config=./kubeconfig --dry-run=client -o yaml | kubectl apply -f -
```

Full guide: **[docs/kubernetes-demarrage.md](docs/kubernetes-demarrage.md)**.

**First launch**: if `hycu_config.json` does not exist yet, a **configuration
wizard** is shown automatically (kubectl binary, allowed contexts/namespaces,
guardrails) and generates the file for you. You can also create it by hand from
the template:

```bash
cp hycu_config.example.json hycu_config.json   # then edit (see §5)
```

Everything remains editable afterwards via the **⚙ Settings** tab.

### Language / Langue

The UI is **bilingual French / English**: the **EN** / **FR** button in the
header switches the language (page **and** server messages). The choice is
remembered per browser (`hycu_lang` cookie); French is the default.

*L'interface est bilingue français / anglais : le bouton **EN** / **FR** dans
l'en-tête bascule la langue (page **et** messages du serveur). Le choix est
mémorisé par navigateur (cookie `hycu_lang`) ; le français est la langue par
défaut.*

## 3. Restore walkthrough (the 3 tabs)

### Tab 1 — Back up
Pick a namespace → **Back up this namespace**. The tool exports and cleans all
PVs/PVCs (equivalent to the `kubectl get … -o yaml` loops + manual manifest
cleanup described in the HYCU procedure).

- **Back up all (filtered)**: backs up in one go **all namespaces allowed** by
  the filter (`namespace_filter`), or **all** namespaces of the cluster if no
  filter. A namespace without PVCs is **skipped** (not an error); a per-namespace
  summary is displayed.
- **Destination folder (optional)**: by default, backups go to `hycu-backups/`
  (next to the program). You can specify a **different folder** (on the machine
  running the tool), e.g. `D:\backups\hycu` or `/mnt/backups`; the
  `<namespace>/<timestamp>/` subfolder is created there automatically.

- **Automatic configuration backup (scheduled)**: enable it to back up the
  PV/PVC **manifests** (not the volume data — that is HYCU's job) of **all
  namespaces allowed by the filter** at a regular interval (default 24 h), for
  as long as the tool is running. The last run is persisted, so an overdue
  backup is caught up at startup, and only the most recent versions are kept
  per namespace (15 by default). Keys: `auto_backup_enabled`,
  `auto_backup_interval_hours`, `auto_backup_keep`, `auto_backup_dest`.

**Copy the backup folder off the cluster** (separate storage): it is your safety
net.

### Tab 2 — Restore
1. Pick the namespace, the **operation type** (Clone or In-place restore), then
   **tick the volume(s)** to restore (several volumes of the same app = a
   single transaction: one stop, one restart).
2. **Configuration backup to restore from**: the tool rebuilds the PVs/PVCs (the
   “skeleton”) from a **config backup** (tab 1). If several exist, a **dropdown**
   lets you **choose which one**; the **most recent** is the default. This is
   independent from the **HYCU restore point** (the Volume Group *data*).
   - **Destroyed namespace** case: there are no more “live” PVCs to read — the
     rebuild relies **entirely** on the selected config backup.
   - **Custom folder**: tick “Read backups from a custom folder” if your
     backups are not in `hycu-backups/` (e.g. copied to a share).
3. **With HYCU connected**, a grouped panel lists every ticked volume with its
   matched Volume Group and its restore points (**most recent pre-selected**):
   - **Clone**: one single click on **“Restore the VGs from HYCU”** clones every
     VG at the chosen point, fills the references automatically, and the plan is
     displayed — ready to launch.
   - **In-place restore**: nothing else to select — **“Launch the in-place
     restore”** is ready immediately (stop → HYCU in-place restore → restart).
4. **Without HYCU** (manual flow): restore/clone each VG in HYCU yourself,
   paste its **UUID** per volume in the **Advanced** section (or use “Search the
   VG in Prism”), then click **“Continue: review and launch”**.
5. Review the plan (derived `volumeHandle`, purge of the source VG's runtime
   attributes, switch of the source PV to **Retain**, sequence). In **real
   mode**: retype the context name to confirm, then **Launch**. The tool then
   opens the **Verify** tab automatically. A target namespace created by an
   application clone is **added to the namespace filter automatically**, so
   Verify/Restore accept it right away.

> If a step fails, the sequence **stops** and the application is **left
> stopped** (replicas at 0) so it does not restart on inconsistent volumes. The
> message states the failing step. Fix, then **relaunch**: the original target
> replicas are remembered (never restarted at 0).

> A floating **“next action” bar** guides you through the flow (fill the VG
> references → preview → launch) without having to scroll the page, and the
> step indicator stays visible while scrolling.

### Tab 3 — Verify
Confirms the PVCs are **Bound** and the pods are running. **Auto-track**
refreshes every ~3 s until the state is stable (all PVCs Bound, pods Running;
~10 min cap — click again to stop). After a **real** restore or clone, the tool
switches to this tab automatically and starts tracking.

## 4. Security

- The server **only listens on `127.0.0.1`** (never exposed to the network).
- **Anti-CSRF / anti-DNS-rebinding** protection: `Host` and `Origin`/`Referer`
  header checks, and an **anti-CSRF token** required on every action.
- **Dry-run by default**; context confirmation before any real action.
- **Browser-session-bound credentials**: HYCU/Nutanix credentials are tied to
  **one browser session** (`hycu_sess` session cookie). Opening the page from a
  restarted browser, another browser, or a private window **locks the
  connections** — credentials are wiped from memory and the vault master
  passphrase (or the passwords) must be entered again. A simple reload (F5) in
  the same browser keeps the session.
- Append-only **audit log**: `hycu-backups/audit.log` (timestamped: namespace,
  volumes, mode, dry/real, result).
- **Bounded backup reads**: by default, only paths **under `hycu-backups/`** are
  readable (defence against out-of-zone reads). A **custom folder** is only
  opened if **you explicitly designate it** in the Restore tab; a path outside
  that zone is still refused.

## 5. Configuration (`hycu_config.json`) — per-customer adaptation

Copy `hycu_config.example.json` → `hycu_config.json`. Also editable via the
**⚙ Settings** tab of the UI. All keys are optional.

| Key | Default | Role |
|---|---|---|
| `kubectl_path` | `"kubectl"` | kubectl binary. E.g. `"microk8s kubectl"`, `"k3s kubectl"`, or full path. |
| `allowed_contexts` | `[]` | Whitelist of kubectl contexts. `[]` = all. In real mode, a context outside the list is **refused**. |
| `namespace_filter` | `[]` | Whitelist of namespaces. `[]` = all. |
| `wait_timeout` | `120` | Max wait (s) for a deletion / a `Bound` transition / pod shutdown. |
| `subprocess_margin` | `30` | Margin (s) of the subprocess timeout above `wait_timeout` (so `kubectl wait` is not killed before its verdict). |
| `clone_name_suffix` | `"0000"` | HYCU convention for the cloned PV name (pre-filled suggestion, editable). |
| `volume_handle_prefix` | `""` | **Empty = auto-detected** from the existing PV (follows the customer's CSI driver). Only set to force a prefix. |
| `strip_claimref` | `false` | `true` = remove `claimRef` entirely from the PV (lets the recreated PVC rebind). `false` = keep `claimRef` (name+namespace) without uid/resourceVersion. |
| `auto_backup_enabled` | `false` | Scheduled automatic backup of all namespaces allowed by the filter, while the tool runs. |
| `auto_backup_interval_hours` | `24` | Interval between automatic backups (hours, minimum 0.25). |
| `auto_backup_keep` | `15` | Retention: number of backup versions kept per namespace (oldest pruned after each automatic run). |
| `auto_backup_dest` | `""` | Destination folder for automatic backups (empty = `hycu-backups/`). |
| `require_context_confirm` | `true` | Require retyping the context before any real action. |
| `host` / `port` | `127.0.0.1` / `8765` | Listen address. **Do not expose** `host` outside the local loopback. |
| `open_browser` | `true` | Open the browser at startup. |
| `hycu_url` | `""` | HYCU controller URL, e.g. `https://hycu.example.com:8443` (port 8443). Empty = HYCU connector disabled. |
| `hycu_api_base` | `/rest/v1.0` | HYCU REST API base (**version-dependent** — see §8). |
| `hycu_test_path` | `/vms` | GET endpoint used to test the connection (look it up in the REST API Explorer). |
| `hycu_verify_tls` | `false` | Verify the HYCU TLS certificate (often self-signed → `false`). |
| `nutanix_url` | `""` | Prism **Element** URL, e.g. `https://prism.example.com:9440`. Empty = disabled. |
| `nutanix_api_base` | `/PrismGateway/services/rest/v2.0` | Prism Element v2 API base. |
| `nutanix_verify_tls` | `false` | Verify the Prism Element TLS certificate. |
| `prismcentral_url` | `""` | Prism **Central** URL, e.g. `https://pc.example.com:9440`. Empty = disabled. |
| `prismcentral_api_base` | `/api/nutanix/v3` | Prism Central v3 API base. |
| `prismcentral_verify_tls` | `false` | Verify the Prism Central TLS certificate. |

> HYCU/Nutanix **credentials** are **never** in the config: they are entered in
> the **Connections** tab and kept in memory for the session only.

### Example — a “microk8s” customer, 2 namespaces, locked-down prod cluster
```json
{
  "kubectl_path": "microk8s kubectl",
  "allowed_contexts": ["prod-cluster"],
  "namespace_filter": ["wordpress", "bo-dev"],
  "require_context_confirm": true
}
```

## 6. To validate on the customer's cluster before production

These points depend on the environment and **cannot be verified without the real
cluster**:

1. **`hypervisorAttachedDiskUUIDs` (point #1)**: on the modern Nutanix CSI
   (NKP), the VG is attached to the worker VM and the PV carries
   `volumeAttributes.hypervisorAttachedDiskUUIDs` = UUID of the **source VG's
   attached disk**. The tool **purges** it from the cloned PV (option
   `clone_strip_runtime_attrs`, default `true`) so the driver repopulates it at
   attach time. **To confirm on a real cloned PV**: the driver locates the
   volume by `volumeHandle` alone (mount OK) — otherwise this field will need to
   be rewritten with the **cloned** disk's UUID rather than purged.
2. **`Retain` on the source PV (data loss)**: before deleting the old PV/PVC,
   the tool switches the source PV to `persistentVolumeReclaimPolicy: Retain`
   (option `retain_source_pv`, default `true`) so the CSI **does not delete**
   the Nutanix Volume Group (reclaim=Delete by default). Verify the source VG
   does survive.
3. **UUID ↔ cloned VG**: the UUID entered must be that of the **cloned** VG, not
   the source (warning if identical) nor the VG **name** `pvc-<uuid>` (dedicated
   warning).
4. **HYCU re-protection**: after a clone, re-assign the protection policy to the
   new Volume Group (reminded in the plan; not automated).
5. **Test scenarios**: single-PVC restore, **multi-PVC** restore, and above all
   **abort → relaunch** (verify the app comes back to its original replica
   count, not 0), and a PVC stuck in `Terminating`.
6. `kubectl wait --for=jsonpath` requires **kubectl ≥ 1.23**.

## 7. Troubleshooting

| Symptom | Lead |
|---|---|
| “Context: unavailable” | `kubectl` missing from PATH or context not configured. |
| “Namespace not allowed” | The namespace is not in `namespace_filter`. |
| “Context not allowed” | The current context is not in `allowed_contexts`. |
| PVC/PV stuck in `Terminating` | The tool patches finalizers automatically; otherwise check no pod still mounts the volume. |
| “Invalid anti-CSRF token” | Reload the page (the token is regenerated at each startup). |
| Connections ask to be unlocked again | Expected: a new browser session (restarted browser, private window) locks the credentials — enter the vault passphrase again. |
| “Interrupted” sequence | Read the failing step in the log, fix, **relaunch** (replicas remembered). |

## 8. HYCU / Nutanix connections (“Connections” tab)

**Optional** connections (stdlib only, no dependency): without them, the manual
flow (pasting the VG reference) remains fully usable.

- **Nutanix Prism (read-only)** — two connection zones: **Prism Element** (v2
  API) and **Prism Central** (v3 API, multi-cluster). In the Restore tab, the
  **“Auto VG ref (Nutanix)”** button searches for the cloned Volume Group and
  **fills in its UUID** automatically (no more copy-paste). It uses the
  connected source — Prism Element first, otherwise Prism Central.
- **HYCU (actions)** — list the **protected Volume Groups** and their **restore
  points**, choose **Clone** or **In-place restore**, then **trigger** and track
  the job. **Simulation mode by default**: the exact call (method + URL + body)
  is displayed **before** anything is actually sent.

**Credentials**: entered in the tab, **kept in memory** for the duration of the
**browser session**, **never written** to disk nor to the config (default mode,
the safest). Wiped on disconnect, on shutdown, and whenever a **new browser
session** opens the page (restarted browser, private window — see §4).

### Remembering connections (encrypted vault, optional)

The Connections tab offers an encrypted vault so you don't have to re-enter
credentials every session:

- Credentials are encrypted into **`hycu_secrets.enc`** (next to the program),
  protected by a **master passphrase** that **only you know** — it is never
  stored. At each **new browser session**, the tool asks for this passphrase
  again to unlock the connections.
- Buttons: **Save (encrypt)** · **Load (decrypt)** · **Forget** (deletes the
  file).
- **Why not MD5?** MD5 (like any hash) is **one-way**: the password could never
  be recovered to reconnect. The vault therefore uses **reversible encryption**:
  key derived from the passphrase with **PBKDF2-HMAC-SHA256** (200,000
  iterations), HMAC-SHA256 stream, and an **integrity seal** (detects a wrong
  passphrase or tampering).
- Built in **pure stdlib** (no dependency); pragmatic but robust for a local
  single-operator tool. If maximum cryptographic assurance is required, **stay
  in RAM-only mode** (do not use the vault) and re-enter credentials each
  session.

> Config: `remember_credentials` switches to `true` when a vault exists;
> `pbkdf2_iterations` tunes the derivation cost. No secret is ever written to
> `hycu_config.json`.

### HYCU 5.2 (R-Cloud Hybrid Cloud Edition) — verified endpoints

REST API on **port 8443**, base `/rest/v1.0`. Endpoints **verified on 5.2**
(Swagger `/rest/v1.0/api-docs`) and used by the tool:

| Action | HYCU 5.2 call |
|---|---|
| List protected Volume Groups | `GET /rest/v1.0/volumegroups` |
| List a VG's restore points | `GET /rest/v1.0/volumegroups/{vgUuid}/backups` |
| Trigger restore/clone | `POST /rest/v1.0/volumegroups/vgrestore` (body `RestoreSpecDTO`) |
| Job status | `GET /rest/v1.0/jobs/{jobUuid}` |

- **Authentication** (Connections tab):
  - **Basic**: user/password of an administrator of the infrastructure group.
  - **API key**: generated in HYCU via **Help → API Keys**; **required if 2FA is
    enabled**. Sent as `Authorization: Bearer <key>` (confirmed scheme).
- `vgrestore` body sent: `backupUuid` (= restore point), `createVolumeGroup`
  (`true` = clone / `false` = in-place), `vgName` (clone), `startVgRestore`,
  `restoreSource` (`AUTO`). **Simulation mode** shows this body before sending.

> If your version differs, all paths can be looked up in the appliance's
> **Help → REST API Explorer** and adjusted via `hycu_api_base` /
> `hycu_test_path` + simulation mode. Security: `*_verify_tls` at `false`
> accepts appliances' self-signed certificates; switch to `true` with a valid
> internal PKI.
