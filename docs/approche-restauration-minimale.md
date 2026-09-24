# Approche produit — Restauration & DR à saisie humaine minimale

> Document de conception. Objectif : qu'un opérateur qui **ne connaît ni Kubernetes
> ni Nutanix/HYCU** puisse restaurer une application (copie, sur place, nouveaux
> volumes, objets, reprise d'activité) **sans jamais recopier un UUID à la main**.
> Corollaire imposé : la **sauvegarde de configuration** doit collecter, dès sa
> création, **toutes** les informations qui rendent cette simplification possible
> au moment de la restauration.

---

## 1. Le problème, en une phrase

Aujourd'hui, plusieurs parcours de restauration demandent à l'humain de **coller
l'UUID (8-4-4-4-12) du Volume Group** restauré/cloné dans HYCU. C'est l'unique
étape « experte » qui reste — et c'est précisément celle qu'un utilisateur non
technique ne sait pas faire. Or **l'outil possède déjà tout ce qu'il faut** pour
obtenir cet UUID lui-même : il parle à HYCU (API `vgrestore`, jobs) et à Prism
(liste des Volume Groups par nom/UUID, disques). Le seul « chaînon manquant » est
qu'on ne **referme pas la boucle** : on déclenche le clone HYCU, on renvoie un
`job_id`, et on laisse l'humain retrouver le nouvel UUID.

## 2. Principe directeur

> **L'humain ne copie jamais un UUID. L'outil orchestre HYCU et lit le résultat.**

Décliné en trois règles :

1. **Ce que l'outil peut déduire, il le déduit** (depuis la sauvegarde ou via les
   API HYCU/Prism) — il ne le demande pas.
2. **Ce que l'outil doit demander, il le pose en langage métier** (« restaurer à
   quelle date ? », « où : ici ou sur le site de secours ? ») — jamais en jargon.
3. **Ce que l'outil déclenche, il le suit jusqu'au bout** (job HYCU → nouvel UUID →
   reconstruction du PV/PVC → vérification), en simulation d'abord.

## 3. Ce que l'outil sait déjà faire (inventaire honnête des primitives)

| Primitive (code) | Rôle | Utilisable pour l'auto-découverte ? |
|---|---|---|
| `action_hycu_restore(payload)` | POST `/volumegroups/vgrestore` : **clone** (`createVolumeGroup=true`, `vgName` **choisi par nous**) ou **restore sur place**. Renvoie un `job_id`. | Oui — c'est nous qui nommons le VG cloné. |
| `action_hycu_job(job_id)` | GET `/jobs/{id}` : statut + progression. | Oui — pour attendre la fin du clone. |
| `action_hycu_restore_points(source_uuid)` | Points de restauration (backups) d'un VG HYCU, horodatés. | Oui — pour choisir « la date ». |
| `_hycu_list_vgs()` | Tous les VG protégés HYCU (name ↔ uuid ↔ externalId). | Oui — retrouver un VG **par nom**. |
| `action_nutanix_vgs(query)` | VG côté Prism (Element v2 / Central v3), filtrables par **nom ou UUID**. | Oui — retrouver le VG cloné par le nom qu'on lui a donné. |
| `action_nutanix_iqn(uuid)` / `action_nutanix_vg_v4(uuid)` | Détail d'un VG : UUID (= `ref` du volumeHandle), IQN, disques. | Oui — valider et enrichir. |
| `_clone_vg_disk_uuids(vg_uuid)` | Disque(s) (extId) d'un VG via Prism v4. | Oui — remplir `hypervisorAttachedDiskUUIDs`. |
| `_set_clone_disk_uuids(...)` | Écrit `hypervisorAttachedDiskUUIDs` sur le PV avant l'apply. | Déjà branché dans le flux clone. |
| `_refresh_pv_disk(...)` | Après restore **sur place**, recrée le PV si le disque a changé. | Déjà automatique. |
| `action_hycu_match(ns)` | Associe chaque PVC ↔ VG HYCU (pivot = **UUID exact**, nom = suggestion). | Oui — sur le cluster **vivant**. |
| `build_new_pv(old_pv, new_ref, ...)` | Reconstruit le manifeste du PV pointé sur un VG donné. | Cœur de la reconstruction. |

**Conclusion :** aucune brique n'est à inventer. Il faut **les enchaîner** et
**stocker à la sauvegarde** ce que `action_hycu_match` ne peut plus recalculer
quand le cluster/site d'origine a disparu (cas DR).

## 4. Le chaînon manquant (pourquoi on saisit encore à la main)

Quand HYCU **clone** un VG (`createVolumeGroup=true`), il crée un **nouveau** VG
avec un **nouvel UUID**. Or `action_hycu_restore` ne renvoie **que** le `job_id` :
personne ne lit l'UUID du VG créé, donc l'humain va le chercher dans Prism et le
recopie dans l'assistant. **C'est la seule raison** de la saisie manuelle.

La boucle à refermer (déjà entièrement outillée) :

```
1. new_name = nom déterministe et unique choisi PAR l'outil
              (ex. "hycurestore-<ns>-<pvc>-<horodatage>")
2. job_id  = action_hycu_restore({mode:"clone", vgName:new_name, restore_point_id, ...})
3. attendre action_hycu_job(job_id) == terminé
4. new_uuid = action_nutanix_vgs(query=new_name)  ->  le VG dont name==new_name
              (repli : _hycu_list_vgs() filtré par name)
5. build_new_pv(old_pv, new_ref=new_uuid, ...)    ->  reconstruction automatique
6. _set_clone_disk_uuids(...) (déjà fait) + apply + vérification
```

Restore **sur place** : pas de nouvel UUID (le VG garde le sien) → **zéro** UUID à
saisir, déjà géré par `_refresh_pv_disk`. **Récupération d'une app supprimée**
(livré en P0, cf. §9) : on **réutilise le VG d'origine**, son UUID est déjà dans la
sauvegarde → zéro saisie.

## 5. Le « contrat de restauration » : ce qu'il FAUT collecter à la sauvegarde

Pour que la restauration soit sans saisie, la **sauvegarde de config** doit être un
**contrat auto-suffisant**. Audit de l'existant et des manques :

| Donnée | Pourquoi elle est nécessaire à la restauration | Déjà collectée ? | Où / comment la collecter |
|---|---|---|---|
| Manifeste PV (nettoyé) | Reconstruire le PV | ✅ `pv_<name>.json` | — |
| Manifeste PVC (nettoyé) | Reconstruire le PVC | ✅ `pvc_<name>.json` | — |
| `old_volume_handle` / UUID du VG source | Réutiliser (récup.) ou retrouver le VG | ✅ `analysis` | — |
| Objets du namespace (Deploy, SVC, CM, SA, Secrets masqués…) | Recréer l'app sans lecture live | ✅ `resources.json` | — |
| **Nom du VG côté Nutanix** (`hycu_vg_name`) | Repli d'appariement par nom (Prism/HYCU) | ❌ | `action_hycu_match(ns)` au moment du backup |
| **UUID source côté HYCU** (`hycu_source_uuid`/`externalId`) | Lister les points de restauration **même cluster disparu** | ❌ | `action_hycu_match(ns)` |
| **extId du/des disque(s)** au moment du backup | Validation + diagnostic (le disque courant est relu à la restauration) | ❌ | `_clone_vg_disk_uuids(vg_uuid)` |
| **Identité du Prism Element / cluster Nutanix** (PE uuid) | Cibler le bon Prism en multi-PE | ❌ | `action_nutanix_vg_v4` / Prism |
| **Système HYCU/Prism** rattaché à ce cluster K8s | Savoir à **quelle** appliance parler en DR | ❌ (implicite = config courante) | Enregistrer l'endpoint/`api_base` utilisé |
| **Dernier point de restauration HYCU par VG** {uuid, horodatage} au moment du backup config | **Aligner les deux lignes de temps** (voir §8) | ❌ | `action_hycu_restore_points(source_uuid)` |
| StorageClass, capacité, accessModes, volumeMode, fsType | Reproduire le volume à l'identique | ✅ (dans les manifestes) | — |

> **Ces ajouts sont purement additifs** : de nouveaux champs `index.json`
> (bloc `restore_contract` par volume), écrits **best-effort** (si HYCU/Prism sont
> connectés au moment du backup), qui **n'échouent jamais** la sauvegarde PV/PVC.
> Rétro-compatibles : une sauvegarde ancienne sans ces champs continue de
> fonctionner via l'appariement live (cluster vivant) ou la réutilisation du VG
> d'origine (récupération).

Forme proposée dans `index.json` :

```json
"volumes": [{
  "pvc": "data", "pv": "pvc-abc…", "pv_file": "...", "pvc_file": "...",
  "analysis": { "old_volume_handle": "NutanixVolumes-<uuid>", ... },
  "restore_contract": {
    "vg_uuid": "<uuid>",
    "vg_name": "pvc-abc…",
    "hycu_source_uuid": "<uuid>",
    "disk_extids": ["<extid>", ...],
    "pe_uuid": "<prism-element-uuid>",
    "hycu_latest_backup": { "uuid": "<backupUuid>", "at": "2026-09-25T01:00:00Z" }
  }
}],
"systems": { "hycu": {"url": "...", "api_base": "..."},
             "nutanix": {"kind": "prismcentral|nutanix", "url": "..."} }
```

## 6. Découverte automatique du nouvel UUID — les trois cas

**Cas A — Restore sur place (in-place).** Le VG garde son UUID. Rien à découvrir.
`_refresh_pv_disk` relit le disque courant via Prism et recrée le PV si besoin.
**Saisie humaine : 0.**

**Cas B — Copie / nouveaux volumes / clone (même site).** L'outil pilote le clone :
il **choisit `vgName`**, attend le job, puis retrouve le VG par ce nom
(`action_nutanix_vgs(query=vgName)`, repli `_hycu_list_vgs()`), en déduit l'UUID,
reconstruit le PV. **Saisie humaine : 0** (au plus : choisir la date du point de
restauration, sinon « la plus récente » par défaut).

**Cas C — Reprise d'activité (autre cluster/site).** Le cluster d'origine n'existe
plus, mais le **contrat de restauration** (§5) fournit `hycu_source_uuid` → on
liste ses points de restauration sur l'appliance HYCU du **site cible**, on clone
(en nommant le VG), on découvre l'UUID comme au cas B. **Saisie humaine :** choisir
le point de restauration (par défaut le plus récent), confirmer le cluster cible.

Dans les trois cas, la reconstruction PV/PVC/workloads est **déjà** couverte par
`build_new_pv` + `action_clone_app` (sources depuis la sauvegarde seule) et la
vérification post-restauration (`/api/verify`).

## 7. Application à CHAQUE menu de restauration

| Menu | Saisie **aujourd'hui** | Saisie **cible** | Ce qui change |
|---|---|---|---|
| Restaurer toute l'application (copie) | UUID(s) du VG cloné | **0** — l'outil clone via HYCU et découvre l'UUID | Orchestration HYCU + découverte par nom |
| Restaurer le stockage **sur place** | Point de restauration/volume | Point de restauration (défaut : le plus récent) | Déjà quasi-nul ; garder l'auto-refresh disque |
| Restaurer vers **de nouveaux volumes** | UUID(s) du VG cloné | **0** (idem copie) | Idem copie |
| Restaurer des **objets** de config | Aucune (déjà) | Aucune | RAS |
| **Reprise d'activité** (autre cluster) | UUID(s) + StorageClass | Point de restauration + confirmation cluster | Contrat de restauration + orchestration HYCU côté site cible |
| **Récupérer une app supprimée** (P0, livré) | Aucune (réutilise le VG d'origine) | Aucune | ✅ déjà fait |

Ligne directrice commune : **une seule question métier** au maximum par
restauration (« à quelle date ? » / « où ? »), tout le reste est déduit.

## 8. Aligner les deux lignes de temps (config ↔ données)

Deux historiques coexistent : les **sauvegardes de config** (cet outil : PV/PVC +
objets) et les **backups de données** (HYCU : snapshots de VG). Restaurer « l'app
telle qu'au 24/09 08:00 » suppose de choisir **le bon couple** (config T, données
≈ T). Aujourd'hui c'est à l'humain de faire coïncider. En enregistrant dans le
contrat, à chaque backup de config, le **dernier point de restauration HYCU** par
VG (`hycu_latest_backup`), l'assistant peut **proposer automatiquement** le point
de données le plus proche de la sauvegarde de config choisie — et n'afficher la
liste complète que « pour les experts ».

## 9. Phasage d'implémentation

- **P0 — livré (v20260925-0130).** Récupération d'une **application supprimée**
  sans saisie : réutilisation du VG d'origine (UUID déduit de la sauvegarde),
  case « réutiliser les volumes d'origine » cochée par défaut, grille d'UUID
  masquée. Backend `action_clone_app` mode `recover`, `action_dr_backups.vol_refs`.

- **P1 — Contrat de restauration à la sauvegarde — LIVRÉ (v20260925…).**
  Bloc `restore_contract` (vg_uuid, vg_name, hycu_source_uuid, disk_extids,
  pe_uuid, hycu_latest_backup) + `systems` écrits dans `index.json` au backup,
  **best-effort** (n'échoue jamais le backup, ignoré si HYCU/Prism absents).
  Réglage `backup_collect_restore_contract`. Tests `_test_contract`.

- **P2 — Découverte automatique de l'UUID — LIVRÉ (moteur + endpoint + UI opt-in).**
  `action_hycu_provision_clone` : clone le VG via HYCU (nom imposé, unique),
  attend le job (`_await_hycu_job`), puis **découvre l'UUID** du nouveau VG par
  son nom (`_discover_vg_uuid_by_name` : Prism d'abord, repli HYCU, ambiguïté
  jamais tranchée au hasard). Endpoint `/api/hycu/provision_clone`. Bouton
  **« Créer les volumes automatiquement via HYCU »** dans l'assistant (visible
  si HYCU + Prism connectés) : simulation-first, remplit la grille tout seul,
  **repli** vers la saisie manuelle sur tout échec. Tests `_test_provision` +
  parcours navigateur. **À valider sur ton appliance** (cf. §11) avant d'en faire
  le défaut silencieux — pour l'instant c'est un bouton explicite et sûr.

- **P3 — Alignement des lignes de temps + un seul écran.** Sélecteur unique
  « restaurer à la date… » qui choisit config **et** données ; liste détaillée
  repliée « pour experts ». Uniformiser les 5 menus derrière ce principe.

Ordre de valeur/risque : **P1 (sûr, prépare tout) → P2 (supprime la saisie, gros
gain) → P3 (finition UX)**.

## 10. Garde-fous conservés (non négociables)

- **Simulation par défaut** partout ; en réel, re-saisie du nom du cluster.
- **Idempotence** des séquences (réplicas mémorisés, reprise après échec).
- **Anti-stale / anti-mauvais-volume** : `_reject_stale_vgs`, pivot **UUID exact**,
  ambiguïté (`match_kind=="ambiguous"`) → jamais tranchée au hasard, on demande.
- **Secrets masqués** jamais réappliqués (re-provisionnés depuis la source).
- **Garde inter-cluster/contexte** maintenue hors reprise d'activité explicite.
- **Protection du VG source** (Retain avant toute suppression de PV/PVC).
- Découverte par nom **sécurisée par l'unicité** du `vgName` que nous imposons
  (horodaté) : si plusieurs VG portent ce nom → ambiguïté → on s'arrête et on
  demande, jamais de choix au hasard.

## 11. Risques & points à valider (avec toi)

1. **`vgrestore` renvoie-t-il l'UUID du VG créé** dans le corps du job ? Si oui, on
   évite même la recherche par nom (plus robuste). À confirmer sur ton appliance
   (une simulation `action_hycu_restore` montre déjà l'appel exact).
2. **Nommage du VG cloné** : HYCU accepte-t-il un `vgName` imposé sans le
   tronquer/renommer ? (sinon, on lit le nom effectif dans le job.)
3. **Multi-PE / Central** : un même nom de VG peut exister sur plusieurs PE →
   d'où l'unicité horodatée + le `pe_uuid` du contrat pour lever l'ambiguïté.
4. **Cross-site (DR réel)** : ton appliance HYCU du site cible voit-elle les
   points de restauration du VG source (réplication) ? C'est la condition du cas C.

## 12. Ce que je propose de faire dès demain

1. Valider avec toi les 4 points du §11 (surtout : l'UUID est-il dans le job HYCU ?).
2. Implémenter **P1** (contrat de restauration à la sauvegarde) — sûr, testable,
   sans toucher aux restaurations. Le mettre sur `main`.
3. Enchaîner **P2** (découverte auto de l'UUID) derrière un faux HYCU/Prism en
   test, pour supprimer la saisie sur copie / nouveaux volumes / DR.

---

*Rédigé pendant la session de nuit. Le socle P0 est déjà en production sur `main`.
Ce document est la base de discussion — rien de P1/P2/P3 n'est encore implémenté.*
