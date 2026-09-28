# HYCU Tool · Kubernetes Restore on Nutanix

> 🇫🇷 Version française : **[README.fr.md](README.fr.md)**

Guided web interface to **back up and restore** Kubernetes applications whose
volumes (PVC = Nutanix Volume Groups) are protected by **HYCU**.

The tool clones/restores the Volume Groups in HYCU, retrieves their
references, rebuilds the PV/PVC manifests and runs
`scale-down → delete → patch finalizer → apply → scale-up → verification`.
**Without it** (manual flow), the only input is the **reference of the
cloned/restored Volume Group** — its **UUID** (modern Nutanix CSI / NKP: the VG
is attached directly to the worker VM, **no more IQN**), a `volumeHandle`, or
an **IQN** (legacy iSCSI clusters); the tool derives the `volumeHandle` from it.

> ⚠️ **Destructive tool.** It deletes and recreates PVs/PVCs. **Simulation
> (dry-run) mode is enabled by default**. Always test on a test namespace before
> production, and review the preview before disabling simulation.

---<img width="1905" height="935" alt="image" src="https://github.com/user-attachments/assets/1770cae5-38f3-473f-9d0f-498bbccfa1ab" />


## 1. How it works

```
   HYCU (backups)                                      Kubernetes / NKP cluster
   protected Nutanix Volume Groups                     application + "live" PVC/PV
          │                                                     ▲
          │ 1. Clone or restore the VG at the chosen point      │ 6. Restart (scale-up,
          │    (HYCU API — or manually in the HYCU UI)          │    original replicas) then
          ▼                                                     │    verification: PVC Bound,
   New restored/cloned Nutanix VG                               │    pods Running
          │                                                     │
          │ 2. VG reference (UUID) fetched via Prism            │
          ▼                                                     │
   PV manifest rebuilt from the config backup                   │
   (derived volumeHandle, runtime attributes purged,            │
    cloned VG disk rewritten via Prism Central v4)              │
          │                                                     │
          │ 3. Stop the app (scale-down, replicas remembered)   │
          │ 4. delete PV/PVC + patch finalizers                 │
          ▼                                                     │
   5. apply the new PV/PVC → they point to the cloned VG ───────┘
```

The tool invents nothing: it **orchestrates `kubectl`** (JSON manifests) and the
**HYCU / Prism REST APIs** (pure Python stdlib, no dependency). The **configuration
backup** (Applications → Back up) provides the PV/PVC "skeleton"; **HYCU provides the data** (the
Volume Groups). Every step is logged, the sequence stops at the first failure (the
app stays stopped, never restarted at 0 replicas), and **simulation mode** (default)
shows the whole sequence without executing anything.

## 2. Prerequisites

**Common to both launch modes:**

- A **kubeconfig** with sufficient RBAC rights on the target cluster:
  `get/list/delete` on `pv`, `pvc`, `pods`; `get/patch/scale` on
  `deployments`/`statefulsets`; `patch` on `pv`/`pvc` (finalizer unblocking);
  **cluster-wide** `list` on `deployments`, `statefulsets`, `daemonsets`, `cronjobs`
  and `pvc` (Applications page: 2 calls for the whole cluster; without it, a
  per-namespace fallback bounded by `apps_fallback_max`).
- **kubectl ≥ 1.23** (the tool uses `kubectl wait --for=jsonpath`).
- On the HYCU/Nutanix side: the restored/cloned Volume Group must exist and its
  **reference** (UUID) be known — **automatic** with the HYCU/Prism connectors
  (⚙ Sources); otherwise copy it from the HYCU UI or Prism
  (`NutanixVolumes-<uuid>`, `ntnx-k8s-<uuid>` target, or IQN on legacy iSCSI
  clusters).

**Depending on the launch mode (see §3):**

- **Option A — Python mode (on the workstation)**: **Python 3.7+** (stdlib only,
  no library to install) and **`kubectl`** installed on the workstation,
  configured on the right context (displayed at the top of the page).
- **Option B — Kubernetes application**: **nothing to install on the
  workstation** — Python and `kubectl` are **bundled in the image**. You only
  need the rights to deploy into a cluster namespace (and `kubectl` somewhere to
  run the access `port-forward`).

## 3. Installation & launch — two ways to run the tool

|  | **Option A — Python mode** | **Option B — Kubernetes application** |
|---|---|---|
| Where it runs | On your workstation | Inside the cluster (Deployment) |
| Prerequisites | Python 3.7+ and `kubectl` on the workstation | Admin rights on a cluster namespace |
| Best for | Quick trial, single operator | Team tool, always on (scheduled auto-backup) |
| Data | `./hycu-backups/` next to the script | `hycu-data` PVC (persistent) |

### Option A — Python mode (on your workstation)

1. Prerequisites: **Python 3.7+** (stdlib only — no library to install) and
   **`kubectl`** configured on the right context.
2. Grab the `hycu_k8s_nutanix.py` file, then run:
   ```bash
   python3 hycu_k8s_nutanix.py
   ```
3. The browser opens at <http://127.0.0.1:8765> (otherwise, open it manually).
   `Ctrl+C` to stop.

Backups and the audit log are written to `./hycu-backups/`, the configuration to
`hycu_config.json` (next to the script).

> **Workstation without Python**: the same container image runs with **Docker** —
> `docker compose -f deploy/docker-compose.yml up` then <http://127.0.0.1:8765>.
> Guides: [docs/docker.md](docs/docker.md) · [docs/docker-demarrage.md](docs/docker-demarrage.md).

### Option B — Kubernetes application (deployed in the cluster)

The **same image** (`ghcr.io/cabsalon93/hycu-nkp-plugin:latest`, public) packages
the script **and** `kubectl`: nothing to install on workstations, the tool runs
continuously inside the cluster. Deployment in **5 steps** — detailed
step-by-step guide: **[docs/kubernetes-demarrage.md](docs/kubernetes-demarrage.md)**.

**Step 1 — Namespace + RBAC identity.** Creates the `hycu-operator`
ServiceAccount and its rights ([deploy/k8s/rbac.yaml](deploy/k8s/rbac.yaml)):
```bash
kubectl create namespace hycu
kubectl apply -f deploy/k8s/rbac.yaml
```

**Step 2 — Build a self-contained kubeconfig.** ServiceAccount token + CA,
**without** `aws`/`gcloud`/`oidc`-style exec-plugins (they do not work inside a
container). The script
[deploy/k8s/make-kubeconfig.sh](deploy/k8s/make-kubeconfig.sh) writes `./kubeconfig`:
```bash
./deploy/k8s/make-kubeconfig.sh          # local cluster; or pass a remote API URL
```

**Step 3 — Provide that kubeconfig via a Secret.** In the image, `kubectl` reads
`KUBECONFIG=/home/app/.kube/config`: the Secret is mounted there, the **key**
must be `config`:
```bash
kubectl -n hycu create secret generic hycu-kubeconfig --from-file=config=./kubeconfig
```
To **replace** an existing kubeconfig:
```bash
kubectl -n hycu create secret generic hycu-kubeconfig \
  --from-file=config=./kubeconfig --dry-run=client -o yaml | kubectl apply -f -
```

**Step 4 — Deploy the tool.** PVC + Deployment + Service
([deploy/k8s/hycu.yaml](deploy/k8s/hycu.yaml)), image pulled automatically from
ghcr.io — nothing to build:
```bash
kubectl apply -f https://raw.githubusercontent.com/cabsalon93/HYCU-NKP-plugin/main/deploy/k8s/hycu.yaml
# or, from a local clone of the repo:
kubectl apply -f deploy/k8s/hycu.yaml
```

**Step 5 — Access the UI.** No Ingress (by design: the server only accepts the
local loopback); each operator opens their own tunnel:
```bash
kubectl -n hycu port-forward svc/hycu 8765:8765      # then http://127.0.0.1:8765
```

> ⚠ **1 replica mandatory** (global state + ReadWriteOnce PVC) — never scale.
> Backups live in the `hycu-data` PVC. The security boundary is the **RBAC of
> the `hycu` namespace**: anyone who can `port-forward`/`exec` to the Pod is a
> full operator.

**First launch**: if `hycu_config.json` does not exist yet, a **configuration
wizard** is shown automatically (kubectl binary, allowed contexts/namespaces,
guardrails) and generates the file for you. You can also create it by hand from
the template:

```bash
cp hycu_config.example.json hycu_config.json   # then edit (see §6)
```

Everything remains editable afterwards via the **Settings** page.

### Language / Langue

The UI is **bilingual French / English**: the **EN** / **FR** button in the
header switches the language (page **and** server messages). The choice is
remembered per browser (`hycu_lang` cookie); French is the default.

*L'interface est bilingue français / anglais : le bouton **EN** / **FR** dans
l'en-tête bascule la langue (page **et** messages du serveur). Le choix est
mémorisé par navigateur (cookie `hycu_lang`) ; le français est la langue par
défaut.*

## 4. Using the tool — HYCU Enterprise Cloud interface

The interface follows the **HYCU Enterprise Cloud** look and workflow: HYCU
colours, a **top bar** (HYCU logo, **active cluster selector**, ⚙ **Sources**, `?` **About**,
EN/FR), a **left menu** of pages, and every operation starts from an **entity
list**: select a row, click an **action at the top right**, and a **wizard**
guides you. A slim banner always shows whether **simulation mode** (default) or
**real mode** is active.

| Page / element | What it does |
|---|---|
| **Dashboard** | HYCU-style tiles: *Applications* (protection / compliance rings), *Policy* (automatic backup), *Sources*, *Cluster*, *Storage* (disk space of the backup folder, used volume, quota, saturation alert), 7-day *Jobs* chart and *Recent jobs*. |
| **Applications** | One row per **application** — a namespace can hold several: workloads (Deployments, StatefulSets, DaemonSets, CronJobs) are grouped by the `app.kubernetes.io/instance`, `app.kubernetes.io/name` or `app` label (otherwise the workload name). Columns: namespace, **Type** (**Stateful** = mounts volumes, **Stateless** = configuration only, *volumes without workload*, *empty*), policy, **Compliance**, **Protection** (namespace backups; an application volume missing from the latest backup is flagged), last backup, versions. Actions: **Back up** (per namespace: two applications of the same namespace = one backup), **Restore** (targets the application: volumes preselected if stateful, configuration objects pre-ticked if stateless), **Set Policy**, **Verify**; funnel icon = namespace filter. **Active cluster / All clusters** toggle (grouped by NKP workspace → cluster). A namespace **deleted** from the cluster stays listed as long as its backups exist (“Deleted — restorable” badge): **Restore** opens the recovery from the backup. |
| **Policies** | The automatic **configuration** backup policy (frequency, retention, target) and the **HYCU policies** (data), read-only. |
| **Jobs** | History of operations (backups, restores, clones, HYCU protection) with **Success / Failed / Simulation / In progress** counters and the **cluster** of each job. **HTML report** (standalone compliance report: applications, RPO, cluster health) and **CSV** (Excel) buttons. |
| **Cluster (top bar)** | **Active cluster** selector: switch cluster, add one, manage them (see below). |
| **⚙ (top right)** | Two-entry menu: **Sources** (HYCU, Prism Element, Prism Central, **Kubernetes clusters**, S3 object storage, encrypted vault) and **Settings** (local cluster, per-customer settings). |
| **? (top right)** | **Help** menu (embedded guide/tutorial served at `/help` — works offline, bilingual) and **About** (version, paths). |

Status icons follow HYCU: **green ✓** OK, **red ✕** failed / not compliant,
**grey ?** unknown / never backed up. An application is **protected** once it has
at least one configuration backup, and **compliant** when its latest backup is
within the policy interval (24 h when the automatic backup is disabled).

### Multiple clusters (kubeconfigs) & NKP workspaces
The **cluster shown in the top bar is the active cluster**: every page and every
operation targets it. Click it to switch cluster, add one, or manage them.

- **Local cluster** — the one from the configuration (`kubeconfig_path` /
  `kube_context`, or kubectl's default resolution): unchanged behaviour, set in
  **Settings**.
- **Add a Kubernetes cluster** (⚙ Sources, or the cluster menu): load a
  **kubeconfig** file or paste it (YAML or JSON), pick the **context** if it has
  several, then **Test & add** (read-only connection test, 10 s max). The tool
  **analyses the authentication** of the context and warns you about:
  - an **exec plugin** (`kubelogin`, `kubectl-oidc_login`…): the command must be
    installed where the tool runs — it is absent from the container image — and an
    interactive OIDC browser login cannot be driven by the tool;
  - an **OIDC / JWT token**: expiry detected — warning under 24 h, error once
    expired (scheduled backups would then fail);
  - a deprecated **auth-provider**, local certificate/token **files**,
    `insecure-skip-tls-verify`.

  For long-lived use (automatic backup), prefer a **ServiceAccount token** or a
  client certificate.
- **Kubeconfigs are secrets**: like passwords, they stay **in memory** for the
  browser session (plus a private `0600` temporary file — in RAM, `/dev/shm`, when
  available — deleted on removal, session lock and shutdown). They are written to
  disk only **encrypted**, in the vault, if you choose to: **Save (encrypt)** also
  stores the added clusters and **Load** brings them back.
- **Backups separated per cluster AND per context** — a real hierarchy, because two
  clusters (prod/dev) often carry the **same namespaces**:
  `hycu-backups/_contexts/<context>/<namespace>/…` for the local cluster (switching
  `kube_context` never mixes backups; older backups at the root stay readable,
  filtered by context), and `hycu-backups/_clusters/<cluster>/<namespace>/…` for
  each added cluster. Every backup records its cluster **and context**, and
  restoring onto another cluster **or another context** is refused.
- **Safeguards and audit per cluster**: real-mode confirmations name the **target
  cluster** (retype its name), `allowed_contexts` also accepts cluster names, every
  audit entry records the `cluster`, the **Jobs** page has a *Cluster* column, and
  the **namespace filter is kept per cluster** (`cluster_namespace_filters`).
- The **automatic backup** covers **all known clusters** at each run (an
  unconfigured local cluster is skipped).
- **Applications → All clusters** lists the applications of every cluster at once,
  **grouped by NKP workspace → cluster**. An action on a row of another cluster
  switches the active cluster first; **Back up** works across clusters in one go.

**NKP workspace discovery (optional).** NKP organises clusters into
**workspaces**, managed from the **management cluster**. Make the management
cluster active, then ⚙ Sources → **Discover NKP workspaces**: the tool lists the
`Workspace` objects and their `KommanderCluster`s (read-only), grouped by
workspace. Tick the clusters, acknowledge the warning, then **Import selection**:
each cluster's kubeconfig is read from its Secret (`spec.kubeconfigRef`), tested and
registered with its workspace. An imported kubeconfig relying on an **exec plugin**
is **refused** (it would make the tool run a command described in the Secret).

> ⚠️ Discovery requires **elevated rights** on the management cluster (read
> Workspaces, KommanderClusters and the kubeconfig **Secrets** of the workspace
> namespaces), and the imported kubeconfigs usually grant **admin** access to the
> clusters. Use it only if this fits your security policy; otherwise add each
> cluster with a dedicated, restricted kubeconfig.

### Back up (Applications → Back up)
Select one or several applications → **Back up**. The tool exports and cleans
all PVs/PVCs (equivalent to the `kubectl get … -o yaml` loops + manual manifest
cleanup described in the HYCU procedure).

- **Extended configuration snapshot**: alongside the PV/PVC manifests, the backup
  also captures the namespace's other resources (Deployments, StatefulSets,
  Services, ConfigMaps, Secrets, Ingresses…) into `resources.json` — read-only,
  never fails the PV/PVC backup. **Secret data is encrypted** into `secrets.enc`
  with the vault passphrase (vault unlocked, or `HYCU_VAULT_PASSPHRASE[_FILE]`);
  without an available passphrase it is kept in clear and the backup says so
  (`backup_secrets` to choose another mode). This snapshot drives object restore,
  the recovery of a deleted application and DR. Disable with
  `config_backup_full: false`.
- **Back up all (filtered)**: backs up in one go **all namespaces allowed** by
  the filter, or **all** namespaces of the cluster if no filter. A namespace
  with no PVC **and no workload** is **skipped** (not an error). A **stateless**
  namespace (workloads without volume) is backed up: its `resources.json` snapshot is
  enough to restore its applications (`apps` index: applications, workloads, PVCs, type).
- **Catalog**: each cluster/context folder carries a `_catalog.json` (summary per
  namespace and version: timestamp, volumes, VG identities, applications, size).
  It is a **derived database**, rebuilt automatically when missing or corrupt;
  restores always read `index.json` and the manifests, never the catalog. It
  avoids re-reading thousands of `index.json` files on every display
  (Applications page, dashboard, DR inventory, quota).
- **Partial backup**: if a bound PV could not be read (API unavailable, RBAC),
  the backup is kept with an `index.partial` marker and the error list, the
  operation is reported as failed and **no older version is pruned** (an
  incomplete backup never replaces a complete one).
- **Destination folder (optional)**: by default `hycu-backups/` (next to the
  program); any folder on the machine running the tool can be used, e.g.
  `D:\backups\hycu` or `/mnt/backups`.

**Copy the backup folder off the cluster** (separate storage): it is your safety
net.

### Automatic configuration backup (Policies)
Enable it to back up the PV/PVC **manifests** (not the volume data — that is
HYCU's job) of **all namespaces allowed by the filter** at a regular interval
(default 24 h), for as long as the tool is running. The last run is persisted,
so an overdue backup is caught up at startup, and only the most recent versions
are kept per namespace (15 by default) — or, in **GFS** mode, the most recent of
each day/week/month (7 d / 4 wk / 12 mo by default). Keys: `auto_backup_enabled`,
`auto_backup_interval_hours`, `auto_backup_keep`, `auto_backup_retention`,
`auto_backup_keep_daily|_weekly|_monthly`, `auto_backup_dest`.

### Protect the data in HYCU (Applications → Set Policy)
Matches the application's PVCs with their HYCU Volume Groups (analysis launched
automatically), assigns a HYCU policy and starts a HYCU backup.

### Restore (Applications → Restore) — the restore wizard
Select **one** application → **Restore**. As in HYCU's *Application Restore*:

1. **Restore type** (option cards):
   - **Restore the whole application (copy)** — volumes **and** objects
     (workloads, dependencies) into the same namespace (suffix) or another one;
     the original is not modified. The application's workloads **without volume**
     (frontend, workers…) are copied along with those mounting the volumes: an
     application = all its workloads.
   - **Restore storage in place** — the data returns into the original volumes;
     the application is stopped, then restarted.
   - **Restore storage to new volumes** — new Volume Groups are cloned and the
     application is re-attached to them; the original volumes are kept.
   - **Restore configuration objects** — re-applies selected objects (Deployments,
     Services, ConfigMaps…) from a backup's `resources.json` snapshot, with a
     **diff preview** (live → backup) before any `apply`. Volumes and data are
     untouched; a Secret **redacted** at backup time is never restored (it would
     overwrite the real secret).
     **Stateless application**: **Restore** on its row offers only the **copy** (clone
     of its workloads and dependencies, as for a stateful application) and this
     path, preselected, with **its** objects pre-ticked (workloads, Services, referenced
     ConfigMaps/Secrets) — the “Only the application's objects” box hides the rest
     of the namespace. A **deleted** stateless namespace can be recovered too
     (workloads + dependencies recreated from the snapshot, no volume).
     **Whole namespace** (one functional application split by its labels, e.g.
     `mariadb` + `wordpress`): tick several applications of the same namespace then
     **Restore the namespace**, or click “whole namespace” in the wizard — every
     volume / object is then preselected.
2. **Options**: target application and cluster, **configuration backup** to
   rebuild from (most recent by default), **volumes** (all pre-selected) and one
   **HYCU restore point** per volume (**most recent pre-selected**). Generated
   names and manual references stay in each volume's collapsed **Advanced**
   section; a custom backup folder is under **Advanced** at the bottom.
3. **Summary**: derived `volumeHandle`, purge of the source VG's runtime
   attributes, switch of the source PV to **Retain**, planned sequence.

The footer holds **one** primary action (**Next → Restore → Launch**), plus
*Close* and *Back*, and a badge reminding **Simulation** / **Real mode**. In real
mode every destructive step asks for confirmation (retype the context name).
After a real restore the tool opens **Verification** automatically. A target
namespace created by an application clone is **added to the namespace filter
automatically**.

**Without HYCU** (manual flow): restore/clone each VG in HYCU yourself, paste its
**UUID** per volume in the **Advanced** section (or use “Search for the VG in
Prism”), then **Next** builds the summary.

> If a step fails, the sequence **stops** and the application is **left
> stopped** (replicas at 0) so it does not restart on inconsistent volumes. The
> message states the failing step. Fix, then **relaunch**: the original target
> replicas are remembered (never restarted at 0).

### Verify (Applications → Verify)
Confirms the PVCs are **Bound** and the pods are running. **Auto-track**
refreshes every ~3 s until the state is stable (all PVCs Bound, pods Running;
~10 min cap — click again to stop).

## 5. Security

- The server **only listens on `127.0.0.1`** (never exposed to the network).
- **Anti-CSRF / anti-DNS-rebinding** protection: `Host` and `Origin`/`Referer`
  header checks, and an **anti-CSRF token** required on every action.
- **Dry-run by default**; confirmation of the target cluster/context before any real action.
- **Browser-session-bound credentials**: HYCU/Nutanix credentials are tied to
  **one browser session** (`hycu_sess` session cookie). Opening the page from a
  restarted browser, another browser, or a private window **locks the
  connections** — credentials are wiped from memory and the vault master
  passphrase (or the passwords) must be entered again. A simple reload (F5) in
  the same browser keeps the session. **Kubeconfigs of added clusters** follow the
  same rule (wiped at a new browser session, restored by unlocking the vault).
- **Cluster isolation**: each request names its cluster; an unknown cluster runs
  **no command** (never a silent fallback to the local cluster), backups are stored
  per cluster and a backup can only be restored onto the cluster it comes from.
- Append-only **audit log**: `hycu-backups/audit.log` (timestamped: namespace,
  volumes, mode, dry/real, result).
- **Bounded backup reads**: by default, only paths **under `hycu-backups/`** are
  readable (defence against out-of-zone reads). A **custom folder** is only
  opened if **you explicitly designate it** in the restore wizard (Advanced); a path outside
  that zone is still refused.
- **Automatic vault unlock (optional, container mode)**: if the master passphrase is
  provided via `HYCU_VAULT_PASSPHRASE_FILE` (file mounted from a Kubernetes Secret —
  preferred) or `HYCU_VAULT_PASSPHRASE`, the vault is unlocked at startup and after
  each session lock: remembered connections and clusters come back without
  interaction (required for the automatic backup of added clusters to survive a Pod
  restart). Accepted trade-off: anyone who can read that Secret can decrypt the
  vault — reserve this mode for a locked-down namespace.
- **Cluster health**: a periodic read-only check (namespace list, 10 s max per
  cluster, every `cluster_health_minutes` minutes) feeds a per-cluster status dot in
  ⚙ Sources and the `hycu_cluster_reachable` metric — an expired token or an
  unreachable cluster is caught BEFORE the next scheduled backup.
- **Monitoring** (`GET /metrics`): a Prometheus endpoint exposes state gauges
  (tool up, operation in progress, auto-backup enabled/last run/last success,
  connection status) — **no sensitive data**. Like the rest of the tool it is
  **local-only** (same `Host`/`Origin` guard): scrape it through a
  `kubectl port-forward` or a loopback sidecar, not directly over the network.

## 6. Configuration (`hycu_config.json`) — per-customer adaptation

Copy `hycu_config.example.json` → `hycu_config.json`. Also editable via the
**Settings** page of the UI. All keys are optional.

| Key | Default | Role |
|---|---|---|
| `kubectl_path` | `"kubectl"` | kubectl binary. E.g. `"microk8s kubectl"`, `"k3s kubectl"`, or full path. |
| `allowed_contexts` | `[]` | Whitelist of kubectl contexts (or names of clusters added in ⚙ Sources). `[]` = all. In real mode, a context outside the list is **refused**. |
| `namespace_filter` | `[]` | Whitelist of namespaces of the **local** cluster. `[]` = all. |
| `cluster_namespace_filters` | `{}` | Namespace whitelists of the clusters **added in ⚙ Sources**, by cluster name: `{"prod-paris": ["shop"]}`. Maintained by the filter editor. |
| `wait_timeout` | `120` | Max wait (s) for a deletion / a `Bound` transition / pod shutdown. |
| `subprocess_margin` | `30` | Margin (s) of the subprocess timeout above `wait_timeout` (so `kubectl wait` is not killed before its verdict). |
| `clone_name_suffix` | `"0000"` | HYCU convention for the cloned PV name (pre-filled suggestion, editable). |
| `volume_handle_prefix` | `""` | **Empty = auto-detected** from the existing PV (follows the customer's CSI driver). Only set to force a prefix. |
| `strip_claimref` | `false` | `true` = remove `claimRef` entirely from the PV (lets the recreated PVC rebind). `false` = keep `claimRef` (name+namespace) without uid/resourceVersion. |
| `auto_backup_enabled` | `false` | Scheduled automatic backup of all namespaces allowed by the filter, while the tool runs. |
| `auto_backup_interval_hours` | `24` | Interval between automatic backups (hours, minimum 0.25). |
| `auto_backup_keep` | `15` | “Count” retention: versions kept per namespace. `0` = unlimited (no pruning). Partial backups are never pruned automatically. |
| `auto_backup_retention` | `"count"` | `"gfs"` = grandfather-father-son retention: the most recent backup of each **day** / **week** / **month** is kept. |
| `auto_backup_keep_daily` / `_weekly` / `_monthly` | `7` / `4` / `12` | GFS windows (days / ISO weeks / months). The most recent backup is always kept. |
| `namespace_label_selector` | `""` | Label selector applied to the namespace list (all clusters), e.g. `hycu.io/backup=true`: app teams opt in through their manifests (GitOps). Empty = inactive. |
| `audit_retention_days` | `31` | Audit log / Jobs history retention (atomic daily compaction). `0` = unlimited. |
| `apps_fallback_max` | `50` | Large clusters: if the **cluster-wide** list of workloads/PVCs is refused (RBAC), the tool falls back to one call per namespace **up to** this count; beyond it gives up (one row per namespace) and reports that a cluster-wide list permission is required. |
| `apps_cache_ttl_s` | `45` | Applications inventory cache (page, dashboard, report) in seconds; one computation at a time per cluster. Cleared after any write; **Refresh** forces a recompute. `0` = disabled. |
| `backup_parallel` | `4` | Namespaces backed up in parallel during an “all namespaces” pass (manual or automatic). |
| `backup_pv_prefetch_min` | `20` | From this number of namespaces, PVs (cluster-scoped) are read **once** per pass instead of one call per volume. |
| `storage_min_free_mb` | `500` | **Free-space floor**: every backup is refused (clear, audited error) when the disk is below it — the tool never fills the disk. `0` = disabled. |
| `storage_quota_gb` | `0` | **Global quota** of the backup folder: above it, the oldest backups are pruned (the most recent of each application×cluster and the backup of an in-progress restore are always kept). `0` = unlimited. |
| `config_backup_full` | `true` | Also capture the namespace's non-PV/PVC resources (Deployments, Services, Secrets…) into `resources.json`. |
| `recover_restore_deleted_vg` | `true` | Recovering a deleted application: if its original Volume Group no longer exists on the cluster but remains “Protected deleted” in HYCU, restore it automatically (one-click “Restore”). Requires HYCU + Prism connected. |
| `recover_deleted_vg_mode` | `restore` | Deleted-VG recovery mode: `restore` = **in-place** restore via HYCU (the VG returns to its original UUID, the PV is reused as-is); `clone` = HYCU creates a **new** VG (new UUID) that the tool discovers. |
| `backup_collect_restore_contract` | `true` | On each backup, collect *best-effort* (never failing the backup) the “restore contract” — Volume Group name/UUID on the HYCU side, disk(s), Prism Element, latest HYCU restore point — to enable a later restore **without manually entering any UUID**, disaster recovery included. Skipped when HYCU/Prism are not connected. |
| `config_backup_kinds` | *(curated list)* | Namespaced resource kinds exported by the extended config snapshot. |
| `backup_secrets` | `"auto"` | **Secret** data in the backup (required to recreate an application): `auto` = **encrypted** into `secrets.enc` with the vault passphrase when available (vault unlocked in the UI, or `HYCU_VAULT_PASSPHRASE[_FILE]`), otherwise **in clear with a warning**; `encrypted` = encrypted, otherwise redacted; `clear` = in clear; `redacted` = redacted. On restore, encrypted Secrets are recomposed when the vault is unlocked; a redacted or locked Secret is **never** applied. |
| `config_backup_include_secret_data` | `false` | Legacy setting: `true` is equivalent to `backup_secrets: clear`. |
| `auto_backup_dest` | `""` | Destination folder for automatic backups (empty = `hycu-backups/`). |
| `require_context_confirm` | `true` | Require retyping the context before any real action. |
| `cluster_health_minutes` | `5` | Interval (min) of the read-only cluster health check. `0` = disabled. |
| `s3_url` / `s3_bucket` / `s3_region` | `""` / `""` / `us-east-1` | **Optional** S3 export of backups (see §9). Empty = disabled. |
| `s3_prefix` | `hycu-backups` | Object key prefix. |
| `s3_path_style` | `true` | `true` = path-style URL (`endpoint/bucket/key` — Nutanix Objects, MinIO); `false` = bucket as subdomain (AWS). |
| `s3_verify_tls` | `false` | Verify the S3 endpoint TLS certificate. |
| `s3_auto_upload` | `false` | `true` = every successful backup is also sent as a `.zip` to the bucket. |
| `s3_encrypt` | `false` | `true` = exports are **encrypted** before upload (passphrase entered in ⚙ Sources); decryption: `python3 hycu_k8s_nutanix.py --decrypt <file>.zip.enc`. |
| `allow_dr_restore` | `false` | **Disaster-recovery mode**: allows cross-cluster/cross-context restore — only on an explicit “DR restore” request (sources read from the backup alone, warning, dedicated audit). Enable it for the duration of a drill or a disaster. |
| `host` / `port` | `127.0.0.1` / `8765` | Listen address. **Do not expose** `host` outside the local loopback. |
| `open_browser` | `true` | Open the browser at startup. |
| `hycu_url` | `""` | HYCU controller URL, e.g. `https://hycu.example.com:8443` (port 8443). Empty = HYCU connector disabled. |
| `hycu_api_base` | `/rest/v1.0` | HYCU REST API base (**version-dependent** — see §9). |
| `hycu_test_path` | `/vms` | GET endpoint used to test the connection (look it up in the REST API Explorer). |
| `hycu_verify_tls` | `false` | Verify the HYCU TLS certificate (often self-signed → `false`). |
| `nutanix_url` | `""` | Prism **Element** URL, e.g. `https://prism.example.com:9440`. Empty = disabled. |
| `nutanix_api_base` | `/PrismGateway/services/rest/v2.0` | Prism Element v2 API base. |
| `nutanix_verify_tls` | `false` | Verify the Prism Element TLS certificate. |
| `prismcentral_url` | `""` | Prism **Central** URL, e.g. `https://pc.example.com:9440`. Empty = disabled. |
| `prismcentral_api_base` | `/api/nutanix/v3` | Prism Central v3 API base. |
| `prismcentral_verify_tls` | `false` | Verify the Prism Central TLS certificate. |

> HYCU/Nutanix **credentials** and the **kubeconfigs** of added clusters are
> **never** in the config: they are entered in **⚙ Sources** and kept in memory for
> the session only (or in the encrypted vault).

### Example — a “microk8s” customer, 2 namespaces, locked-down prod cluster
```json
{
  "kubectl_path": "microk8s kubectl",
  "allowed_contexts": ["prod-cluster"],
  "namespace_filter": ["wordpress", "bo-dev"],
  "require_context_confirm": true
}
```

## 7. To validate on the customer's cluster before production

These points depend on the environment and **cannot be verified without the real
cluster**:

1. **`hypervisorAttachedDiskUUIDs` (point #1)**: **mirror-the-source-PV** policy.
   If the original PV carries `volumeAttributes.hypervisorAttachedDiskUUIDs` (UUID of
   the source VG's attached disk), the tool **rewrites** it on the cloned PV with the
   **cloned** VG's disk (read through Prism Central v4; `clone_fix_disk_uuids`, abort
   if not found with `clone_require_disk_uuids`). If the original PV **does not carry
   it**, the tool **does not add it**: observed on an NKP cluster, adding it makes the
   Nutanix attachment fail (`FailedAttachVolume … hypervisor Attach Client failed`)
   while the driver attaches the VG perfectly without it, as for the original PV.
   **IQN**: a VG created by HYCU carries an iSCSI target `hycu-clone-vg-<uuid>` whereas
   the CSI expects `ntnx-k8s-<uuid>`; the tool reads the real `targetName` through Prism
   Central and aligns the PV's `volumeAttributes.iqn` (clone, new volumes, recovery, and
   PV refresh after an in-place restore). Without Prism Central the derived IQN is kept
   and reported (`iscsiadm: No records found` if the target differs).
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
7. **NKP workspace discovery**: the resources used (`workspaces.kommander.mesosphere.io`,
   `kommanderclusters.kommander.mesosphere.io`, `spec.kubeconfigRef`, Secret key
   `value` or `kubeconfig`) follow the NKP documentation — validate on your NKP
   version, with the RBAC you intend to grant.

## 8. Troubleshooting

| Symptom | Lead |
|---|---|
| “Context: unavailable” | `kubectl` missing from PATH or context not configured. |
| “Namespace not allowed” | The namespace is not in `namespace_filter`. On the Verification page, the **“Allow « ns » and retry”** button adds it in one click; a namespace created by an application clone is added automatically. |
| “Context not allowed” | The current context is not in `allowed_contexts`. |
| Namespace destroyed, application gone? | It stays listed as long as a backup exists (“Deleted — restorable” badge): **Restore** → recovery from the backup (namespace, PV/PVC, workloads, non-redacted dependencies), no DR override needed. The original Volume Group is reused if it still exists; if it was deleted but remains “Protected deleted” in HYCU, the tool restores it **in-place** automatically (`recover_restore_deleted_vg`). Recovery is **refused** if the namespace still exists (use Restore/Clone) or if its state cannot be checked. |
| PVC/PV stuck in `Terminating` | The tool patches finalizers automatically; otherwise check no pod still mounts the volume. |
| “Invalid anti-CSRF token” | Reload the page (the token is regenerated at each startup). |
| Connections ask to be unlocked again | Expected: a new browser session (restarted browser, private window) locks the credentials — enter the vault passphrase again. |
| “Interrupted” sequence | Read the failing step in the log, fix, **relaunch** (replicas remembered). |
| “Cluster « x » unknown” | The active cluster was removed, or a new browser session wiped the added clusters: unlock the vault (they come back) or pick another cluster in the top bar. |
| Warning “exec plugin” / “token expired” on a cluster | The kubeconfig relies on an external login command or a short-lived token: regenerate it, or use a ServiceAccount token (see §4, *Multiple clusters*). |
| “This backup comes from cluster « x »…” | Cross-cluster restore is refused: select the backup's source cluster in the top bar. |
| NKP discovery: “does not look like an NKP management cluster” | The active cluster is not the management cluster, or your RBAC cannot read Workspaces/KommanderClusters. |

## 9. HYCU / Nutanix sources (⚙ at the top right)

**Optional** connections (stdlib only, no dependency): without them, the manual
flow (pasting the VG reference) remains fully usable.

- **Nutanix Prism (read-only)** — two connection zones: **Prism Element** (v2
  API) and **Prism Central** (v3 API, multi-cluster). In the restore wizard, the
  HYCU batch flow uses Prism to **fill in the cloned VG UUIDs** automatically
  (no more copy-paste), and each volume's **Advanced** section offers a
  **“Search for the VG in Prism”** button for the manual flow. It uses the
  connected source — Prism Element first, otherwise Prism Central.
- **HYCU (actions)** — list the **protected Volume Groups** and their **restore
  points**, choose **Clone** or **In-place restore**, then **trigger** and track
  the job. **Simulation mode by default**: the exact call (method + URL + body)
  is displayed **before** anything is actually sent.

**Credentials**: entered in ⚙ Sources, **kept in memory** for the duration of the
**browser session**, **never written** to disk nor to the config (default mode,
the safest). Wiped on disconnect, on shutdown, and whenever a **new browser
session** opens the page (restarted browser, private window — see §5).

### Exporting backups to S3 object storage (optional)

Disabled by default. ⚙ Sources → **S3 object storage**: enter the endpoint (Nutanix
Objects, MinIO, AWS S3…), bucket, region and access keys, then **Test & connect**
(read-only test: bucket listing capped at 1 object). Tick **Automatic export** so
every successful backup (manual and scheduled) is also sent as a `.zip` to the
bucket, under `<prefix>/<cluster>/<namespace>/<timestamp>.zip`: the safety net then
lives **outside the cluster** it protects.

- **AWS SigV4** signing implemented in pure stdlib (no dependency), verified against
  the official AWS test vector.
- Access keys follow the same rules as other credentials: **RAM** for the session,
  optional encrypted vault, never in `hycu_config.json`.
- **Best-effort**: a failed export (full bucket, network) never fails the local
  backup; every export is audited and visible in **Jobs**.
- SigV4 requires an **accurate clock** on the machine running the tool (403 otherwise).
- **Optional encryption** (`s3_encrypt` + passphrase entered in ⚙ Sources): objects
  are encrypted **before** upload (same scheme as the vault: PBKDF2 + integrity
  seal, iterations encoded in the file) — the bucket can be untrusted storage.
  Decryption outside the UI: `python3 hycu_k8s_nutanix.py --decrypt backup.zip.enc`.

### Bulk restore (same cluster)
**Applications → Bulk restore** recreates at once **every deleted namespace** of the
active cluster from its latest backup prior to a **reference time**: namespace,
PV/PVC, workloads, dependencies, Secrets (vault unlocked), Volume Groups restored
in place by HYCU if they are gone, stateless applications. Namespaces **still
present** are skipped: a live application is restored from its own row, never in bulk.

1. **Prepare the plan**: selected namespaces (chosen backup, content, warnings:
   redacted Secrets or encrypted with a locked vault, partial backup, no snapshot)
   and skipped namespaces with the reason. Exclusions are possible.
2. **Simulate**: runs the plan in simulation, in the background, with a journal per
   namespace.
3. **Start (real)**: only after a complete, failure-free simulation of the **same**
   plan (same namespaces, same time), with the Simulation banner off and the
   cluster confirmed.

**Sequential** execution (each HYCU restore takes minutes: expect hours for hundreds
of namespaces), `_bulk_restore.json` journal in the cluster folder (survives a
restart), **Stop** finishes the current namespace, **Resume** replays only the
remaining or failed namespaces. The automatic backup is suspended during the run;
every namespace is audited in Jobs.

### Disaster recovery (DR mode)

The scenario: the primary cluster (or site) is lost; HYCU still holds the Volume
Group backups. The full walkthrough is in the online help (**? → Help → Disaster
recovery**); in short:

1. **Beforehand** (DR kit): automatic S3 export enabled (preferably encrypted); safe
   copies of `hycu_config.json`, `hycu_secrets.enc`, the vault and export passphrases.
2. **On the day**: relaunch the tool elsewhere, reconnect the sources, add the target
   cluster, then **S3 card → Import from the bucket** (exports come back under
   `hycu-backups/_imports/…`).
3. Restore the **Volume Groups** in HYCU to the target site, note their UUIDs.
4. Enable **Allow DR restore** (Settings), then wizard → **DR restore**: source
   backup (lost cluster or S3 import), target namespace, restored VG UUIDs, optional
   **StorageClass remap** — simulation then real (target cluster retyped). Everything
   comes from the **backup alone** (no read from the origin cluster); a redacted
   Secret is never restored.
5. **Afterwards**: verify, re-protect the VGs in HYCU, disable the override.

### Remembering connections (encrypted vault, optional)

⚙ Sources offers an encrypted vault so you don't have to re-enter
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

- **Authentication** (⚙ Sources):
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
