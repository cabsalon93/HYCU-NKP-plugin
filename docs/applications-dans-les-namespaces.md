# Applications dans les namespaces — stateful / stateless

*Décision et conséquences sur l'ensemble du projet (2026-09-25).*

## Réponse à la question « lister les applications à l'intérieur des namespaces ? »

**Oui.** Un namespace Kubernetes peut héberger plusieurs applications (ex. `wordpress`
et un `redis` de cache, ou deux outils indépendants déployés côte à côte). Lister le
namespace comme « application » masquait ce découpage : impossible de restaurer *une*
application sans toucher l'autre, et impossible de voir qu'une application n'a pas de
volume (stateless) et se restaure autrement.

## Modèle retenu

| Notion | Définition |
| --- | --- |
| **Application** | Groupe de workloads (Deployment, StatefulSet, DaemonSet, CronJob) d'un namespace portant la même étiquette d'application : `app.kubernetes.io/instance` (release Helm) → `app.kubernetes.io/name` → `app` → sinon le nom du workload. Les objets dérivés (Job d'un CronJob, ReplicaSet) sont ignorés. |
| **Stateful** | Au moins un PVC monté : `volumes[].persistentVolumeClaim` du pod template, ou `volumeClaimTemplates` d'un StatefulSet (`<template>-<sts>-<n>`, rapprochés des PVC existants). |
| **Stateless** | Aucun PVC : l'application se restaure en ré-appliquant ses objets de configuration. |
| **volumes sans workload** | Pseudo-application : PVC qu'aucun workload ne monte (restaurables comme stockage). |
| **vide** | Namespace sans workload ni PVC : rien à protéger (sauvegarde refusée, ligne informative). |

Le **namespace reste l'unité de sauvegarde** : une seule « recette » cohérente
(PV/PVC + `resources.json`), une seule rétention, un seul export S3. L'application
sert à **cibler la restauration**.

## Conséquences, module par module

- **Sauvegarde** (`action_backup`) : l'index mémorise `apps` (nom, workloads, PVC, type)
  pour cibler la restauration plus tard — y compris quand le namespace n'existe plus.
  Un namespace **sans PVC mais avec workloads** est désormais sauvegardé (0 volume,
  instantané seul) ; un namespace sans PVC ni workload est ignoré, aucun dossier créé.
- **Page Applications** (`action_applications`) : une ligne par application, colonne
  Namespace, colonne Type. Protection/Conformité restent celles du namespace ; un volume
  de l'application absent de la dernière sauvegarde (`unbacked_pvcs`) est signalé.
  Deux appels cluster-wide (`-A`) pour les workloads et les PVC, repli par namespace
  sans droits, et repli « une ligne par namespace » si rien n'est lisible.
  Namespace supprimé : applications lues dans `apps` de sa dernière sauvegarde.
- **Sauvegarder** : la sélection est ramenée aux namespaces distincts (deux applications
  du même namespace = une sauvegarde).
- **Restaurer** (assistant) : `state.app` cible l'application. Stateful : seuls **ses**
  volumes sont précochés dans les parcours de stockage. Stateless : l'assistant ouvre
  directement le parcours « objets de configuration » avec **ses** objets précochés
  (`/api/objects/list` + `app` → `in_app`, case « seulement les objets de
  l'application »). Changement de namespace dans l'assistant → application oubliée.
- **Restauration d'objets** (`_app_object_indexes`) : objets étiquetés, workloads du
  groupe, Secrets/ConfigMaps/ServiceAccount référencés, Services dont le sélecteur cible
  ses pods. Les Secrets masqués restent non restaurables.
- **Récupération d'un namespace supprimé / DR** : inchangées dans le principe (tout le
  namespace est recréé). Nouveauté : une sauvegarde **stateless** (aucun volume) est
  acceptée — workloads et dépendances recréés, aucun PV/PVC (`stateless` dans
  `/api/dr/backups`).
- **Définir la politique / Vérifier** : au niveau du namespace (HYCU protège des
  Volume Groups ; protéger tout le namespace est le choix sûr).
- **Rapport HTML/CSV** : colonnes Namespace, Application, Type.
- **Tableau de bord** : compteurs Applications et Namespaces.
- **Tests** : `_test_apps.py` (regroupement, filtre d'objets, sauvegarde stateless,
  récupération stateless), mocks navigateur (clé `cluster|namespace|application`),
  faux kubectl avec `-A` et workloads.

## Limites connues

- Le regroupement dépend des étiquettes : un workload sans étiquette est une application
  à lui seul (fusion manuelle impossible pour l'instant).
- Le clone d'application (copie) reste piloté par les volumes sélectionnés : pour une
  application stateless, utiliser le parcours objets (ou la récupération si le namespace
  a disparu).
