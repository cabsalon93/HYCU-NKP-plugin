# Démarrage rapide — Docker

Faire tourner l'outil **HYCU / Kubernetes / Nutanix** dans un conteneur Docker, sur un
poste ou un serveur. C'est le **même produit** que la version Python, lancé dans une
image prête à l'emploi.

> Pour un déploiement **dans** un cluster Kubernetes, voir [`docs/docker.md`](docker.md).

---

## 0. Ce dont tu as besoin

1. **Docker Desktop** installé et **démarré** (l'icône baleine doit être active).
2. **Un kubeconfig « autonome »** : le fichier que `kubectl` utilise déjà pour joindre
   ton cluster, à condition qu'il s'authentifie par **token** ou **certificats**
   (et **pas** par connexion navigateur OIDC/SSO). Pour vérifier :

   ```powershell
   kubectl config view --minify
   ```

   - Tu vois `client-certificate-data` / `client-key-data` ou `token:` → ✅ c'est bon.
   - Tu vois une section `exec:` / `command:` (kubelogin, oidc-login, aws/gke…) → ⚠️ ce
     kubeconfig **ne marchera pas** dans le conteneur. Voir le piège n°1 plus bas.

   Sous Windows, le fichier est en général `C:\Users\<toi>\.kube\config`.

---

## 1. Récupérer l'image

**Cas normal (poste connecté à internet) :**

```powershell
docker pull ghcr.io/cabsalon93/hycu-nkp-plugin:latest
```

**Cas site isolé (air-gap)** : on te fournit un fichier `.tar.gz`, tu le charges :

```powershell
docker load -i hycu-nkp.tar.gz
```

---

## 2. Préparer un dossier de travail

Crée un dossier où vivront ta config et tes sauvegardes, puis place-toi dedans :

```powershell
mkdir hycu ; cd hycu
mkdir hycu-data
```

> Tout ce que tu configures (identifiants, namespaces, sauvegardes) est stocké dans
> `hycu-data`. **Ne supprime pas ce dossier** : c'est ta mémoire.

---

## 3. Lancer le conteneur

Une seule commande. Elle fait trois choses : publie l'outil sur ta machine
(`127.0.0.1:8765`), branche ton dossier `hycu-data`, et donne ton kubeconfig à l'outil.

**Windows (PowerShell)** — adapte le chemin du kubeconfig si besoin :

```powershell
docker run --rm -p 127.0.0.1:8765:8765 -v ${PWD}/hycu-data:/data -v $env:USERPROFILE/.kube/config:/home/app/.kube/config:ro ghcr.io/cabsalon93/hycu-nkp-plugin:latest
```

**Linux / macOS** :

```bash
docker run --rm -p 127.0.0.1:8765:8765 \
  -v "$PWD/hycu-data:/data" \
  -v "$HOME/.kube/config:/home/app/.kube/config:ro" \
  ghcr.io/cabsalon93/hycu-nkp-plugin:latest
```

La fenêtre reste ouverte et affiche les journaux : c'est normal, **laisse-la ouverte**
tant que tu utilises l'outil.

---

## 4. Ouvrir et vérifier

Ouvre ton navigateur sur :

```
http://127.0.0.1:8765
```

- La page de l'outil s'affiche → 🎉
- Dans l'en-tête, **« Contexte kubectl »** doit montrer **ton cluster** (et non
  « indisponible »). Si c'est le cas, l'outil parle bien à ton cluster. ✅

> Première fois ? Un assistant de configuration en 7 étapes te guide (adresse HYCU,
> Nutanix, namespaces…). Tes réponses sont enregistrées dans `hycu-data`.

---

## 5. Arrêter et relancer

- **Arrêter** : reviens dans la fenêtre du conteneur et fais **Ctrl + C**.
- **Relancer** : depuis le même dossier, relance **la même commande** qu'à l'étape 3.
  Tu retrouves toute ta config (grâce à `hycu-data`).

### Astuce : un lanceur en double-clic (Windows)

Crée un fichier **`lancer-hycu.bat`** dans ton dossier `hycu`, avec ce contenu :

```bat
@echo off
docker run --rm -p 127.0.0.1:8765:8765 ^
  -v "%CD%\hycu-data:/data" ^
  -v "%USERPROFILE%\.kube\config:/home/app/.kube/config:ro" ^
  ghcr.io/cabsalon93/hycu-nkp-plugin:latest
pause
```

Désormais, un **double-clic** sur `lancer-hycu.bat` démarre l'outil. Plus rien à taper.

---

## 6. Les 3 pièges à connaître

1. **Kubeconfig OIDC/SSO.** Si `kubectl config view --minify` montre une section
   `exec:` (kubelogin, oidc-login, aws/gke…), le conteneur ne sait **pas** l'exécuter.
   Il te faut un kubeconfig à **token de ServiceAccount** ou à **certificats**. Demande-le
   à ton admin, ou génère-le (cf. `deploy/k8s/` dans le dépôt). Vérifie aussi que
   l'adresse `server: https://…` du cluster est **joignable depuis ton poste**.

2. **Toujours publier sur `127.0.0.1`.** Garde bien `-p 127.0.0.1:8765:8765`.
   **Jamais** `-p 8765:8765` tout court : ça exposerait l'outil au réseau. (De toute
   façon, une protection interne refuse les accès qui ne viennent pas de la machine.)

3. **« Dossier personnalisé » = chemin DANS le conteneur.** Si l'outil te demande un
   dossier de destination/source, c'est un chemin **du conteneur**, pas de Windows : un
   `D:\sauvegardes` saisi ici n'atteint **pas** ton PC (le serveur écrit sur son propre
   disque). Deux solutions :
   - **Le plus simple** — laisse le dossier par défaut et clique sur **⬇ Télécharger
     (.zip)** à côté de la sauvegarde : ton navigateur la dépose sur **ton PC**
     (fonctionne en Docker **et** en Kubernetes, sans rien monter).
   - En Docker uniquement, tu peux aussi monter un dossier de ton poste
     (`-v D:/sauvegardes:/backups`) puis saisir le chemin **conteneur** `/backups`.

---

## 7. En cas de souci

| Symptôme | Cause probable | Solution |
|---|---|---|
| `docker : ... daemon is running?` | Docker Desktop n'est pas démarré | Lance Docker Desktop, attends que la baleine soit active |
| `port is already allocated` | Un conteneur tourne déjà sur 8765 | Ferme l'autre fenêtre (Ctrl + C) ou `docker ps` puis `docker stop <id>` |
| « Contexte kubectl : indisponible » | Kubeconfig absent, OIDC, ou cluster injoignable | Revois l'étape 0 et le piège n°1 |
| Page inaccessible | Mauvaise URL | Ouvre bien `http://127.0.0.1:8765` (pas `https`) |
