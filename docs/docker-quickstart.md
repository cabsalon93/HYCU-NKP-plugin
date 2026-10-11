# Quick start — Docker

Run the **HYCU / Kubernetes / Nutanix** tool in a Docker container, on a workstation
or a server. It is the **same product** as the Python version, packaged in a
ready-to-use image.

> For a deployment **inside** a Kubernetes cluster, see
> [`docs/kubernetes.md`](kubernetes.md) (step by step) and [`docs/docker.md`](docker.md) (reference).

---

## 0. What you need

1. **Docker Desktop** installed and **running** (the whale icon must be active).
2. **A "standalone" kubeconfig**: the file `kubectl` already uses to reach your
   cluster, provided it authenticates with a **token** or **certificates**
   (and **not** through an OIDC/SSO browser login). To check:

   ```powershell
   kubectl config view --minify
   ```

   - You see `client-certificate-data` / `client-key-data` or `token:` → ✅ you are good.
   - You see an `exec:` / `command:` section (kubelogin, oidc-login, aws/gke…) → ⚠️ this
     kubeconfig **will not work** in the container. See pitfall #1 below.

   On Windows, the file is usually `C:\Users\<you>\.kube\config`.

---

## 1. Get the image

**Normal case (workstation with internet access):**

```powershell
docker pull ghcr.io/cabsalon93/hycu-nkp-plugin:latest
```

**Isolated site (air-gap)**: you are given a `.tar.gz` file; load it:

```powershell
docker load -i hycu-nkp.tar.gz
```

---

## 2. Prepare a working folder

Create a folder for your config and backups, then move into it:

```powershell
mkdir hycu ; cd hycu
mkdir hycu-data
```

> Everything you configure (credentials, namespaces, backups) is stored in
> `hycu-data`. **Do not delete this folder**: it is the tool's memory.

---

## 3. Start the container

One command. It does three things: publishes the tool on your machine
(`127.0.0.1:8765`), mounts your `hycu-data` folder, and gives your kubeconfig to the tool.

**Windows (PowerShell)** — adjust the kubeconfig path if needed:

```powershell
docker run --rm -p 127.0.0.1:8765:8765 -v ${PWD}/hycu-data:/data -v $env:USERPROFILE/.kube/config:/home/app/.kube/config:ro ghcr.io/cabsalon93/hycu-nkp-plugin:latest
```

**Linux / macOS**:

```bash
docker run --rm -p 127.0.0.1:8765:8765 \
  -v "$PWD/hycu-data:/data" \
  -v "$HOME/.kube/config:/home/app/.kube/config:ro" \
  ghcr.io/cabsalon93/hycu-nkp-plugin:latest
```

The window stays open and shows the logs: this is expected, **leave it open**
while you use the tool.

---

## 4. Open and check

Point your browser to:

```
http://127.0.0.1:8765
```

- The tool's page appears → 🎉
- In the header, the active cluster (kubectl context) must show **your cluster** (not
  "unavailable"). If so, the tool is talking to your cluster. ✅

> First time? A 7-step setup wizard guides you (HYCU address, Nutanix,
> namespaces…). Your answers are saved in `hycu-data`.

---

## 5. Stop and restart

- **Stop**: go back to the container window and press **Ctrl + C**.
- **Restart**: from the same folder, run **the same command** as in step 3.
  All your config is still there (thanks to `hycu-data`).

### Tip: a double-click launcher (Windows)

Create a file **`start-hycu.bat`** in your `hycu` folder, with this content:

```bat
@echo off
docker run --rm -p 127.0.0.1:8765:8765 ^
  -v "%CD%\hycu-data:/data" ^
  -v "%USERPROFILE%\.kube\config:/home/app/.kube/config:ro" ^
  ghcr.io/cabsalon93/hycu-nkp-plugin:latest
pause
```

From now on, **double-clicking** `start-hycu.bat` starts the tool. Nothing left to type.

---

## 6. The 3 pitfalls to know

1. **OIDC/SSO kubeconfig.** If `kubectl config view --minify` shows an `exec:` section
   (kubelogin, oidc-login, aws/gke…), the container **cannot** run it. You need a
   kubeconfig with a **ServiceAccount token** or **certificates**. Ask your admin for one,
   or generate it (see `deploy/k8s/` in the repository). Also check that the cluster's
   `server: https://…` address is **reachable from your workstation**.

2. **Always publish on `127.0.0.1`.** Keep `-p 127.0.0.1:8765:8765`.
   **Never** plain `-p 8765:8765`: it would expose the tool to the network. (In any
   case, a built-in guard rejects access that does not come from the local machine.)

3. **"Custom folder" = path INSIDE the container.** If the tool asks for a
   destination/source folder, it is a **container** path, not a Windows one: a
   `D:\backups` entered there does **not** reach your PC (the server writes to its own
   disk). Two options:
   - **Simplest** — keep the default folder and click **⬇ Download (.zip)** next to the
     backup: your browser saves it on **your PC** (works in Docker **and** Kubernetes,
     nothing to mount).
   - In Docker only, you can also mount a folder from your workstation
     (`-v D:/backups:/backups`) and enter the **container** path `/backups`.

---

## 7. If something goes wrong

| Symptom | Likely cause | Fix |
|---|---|---|
| `docker : ... daemon is running?` | Docker Desktop is not running | Start Docker Desktop, wait until the whale is active |
| `port is already allocated` | A container is already running on 8765 | Close the other window (Ctrl + C) or `docker ps` then `docker stop <id>` |
| Cluster shown as "unavailable" | Missing kubeconfig, OIDC, or cluster unreachable | Go back over step 0 and pitfall #1 |
| Page not reachable | Wrong URL | Make sure you open `http://127.0.0.1:8765` (not `https`) |
