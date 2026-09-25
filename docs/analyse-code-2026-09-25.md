# Analyse complète du code — 25/09/2026

Relecture de `hycu_k8s_nutanix.py` (12 275 lignes) : analyse statique (ruff, jeu de règles
étendu), puis relecture intégrale par zone, chaque point **vérifié dans le code** avant
d'être retenu (numéros de lignes de la version `v20260925-0620`, commit `712e5fc`).
Aucune modification n'a été faite : ce document est le rapport.

Gravités : **critique** = perte/corruption de données ou contournement d'une garde ;
**bug** = comportement faux dans un cas réel ; **incohérence** = code ≠ message/doc/autre
code ; **amélioration** = robustesse, perf, dette.

---

## 1. Critiques (données / gardes de sécurité)

**C1 — La garde `same_uuid` est levée en « récupération » sans vérifier que le namespace a disparu** — l. 5994-6012, 6055-6062, 6099-6102
`recover = from_backup_only and not dr` ; l'exception `same_uuid and not recover` repose sur
« l'app d'origine n'existe plus », mais **rien côté serveur ne le vérifie** (seule l'UI ne
propose le parcours que pour une app `missing`). Un `POST /api/clone_app` avec
`from_backup_only:true` sur un namespace **vivant** (autre cible) recrée PV/PVC/workloads
sur le **même VG** que la production → multi-attach/corruption. Le pré-vol (6246-6261) ne
compare que des noms.
*Correctif* : en mode `recover`, exiger côté serveur `resource_state("namespace", ns) == "absent"`
(ou aucun PVC Bound dans `ns`) avant de lever la garde ; sinon traiter comme un clone
ordinaire.

**C2 — `_vg_exists` confond « VG absent » et « erreur transitoire »** — l. 5111-5120 (appelant 6061-6076)
`bool(action_nutanix_iqn(uuid).get("ok"))` vaut `False` pour **toute** erreur (500/503,
session Prism expirée, timeout), pas seulement 404 — `action_nutanix_iqn` jette le code HTTP
que `_http_json` renvoie pourtant (`status`). Avec `recover_deleted_vg_mode="restore"`
(défaut), un hoquet Prism déclenche un `vgrestore` **in-place** sur un VG encore vivant
(cas Retain) → ses données sont écrasées par la sauvegarde.
*Correctif* : appeler `_rest` directement : `ok → True`, `status == 404 → False`, sinon `None`
(indéterminé, on ne restaure pas).

**C3 — Un PV illisible pendant la sauvegarde est ignoré en silence ; la sauvegarde est déclarée réussie et la rétention purge les anciennes** — l. 1868-1878, 1909
`if pv_data and not perr:` saute l'écriture du `pv_*.json` sans avertissement ; `ok: True`,
audit `backup`, puis `_prune_backups` supprime une version plus ancienne **complète**. Après
`auto_backup_keep` passages (RBAC sur les PV, jeton expiré…) il ne reste plus aucun
manifeste de PV pour restaurer.
*Correctif* : `entry["pv_error"] = perr`, réponse `ok: False` (ou `partial: True` +
`warnings`), et **pas de prune** quand un PV attendu manque.

**C4 — `retain_source_pv=False` + même VG (in-place) : le CSI supprime le VG qu'on s'apprête à re-pointer** — l. 3516, 3551-3562
La protection `Retain` dépend de la config ; à `False`, `delete pvc` puis `delete pv`
(`reclaimPolicy=Delete`) déclenchent `DeleteVolume` → VG détruit, puis nouveau PV créé
dessus et app redémarrée. Perte de données par simple option.
*Correctif* : forcer `retain = True` quand `new_volume_handle == old_volume_handle` (ou
`mode == "inplace"`), quelle que soit la config.

**C5 — Dans l'assistant Restaurer, « nom du VG collé à la place de l'UUID » et « même UUID en clone » ne sont que des avertissements ; l'exécution détruit puis recrée sur un VG inexistant** — l. 3108-3118, JS 8798-8808
`_prepare_one` renvoie `ok: True` + `warn` ; le bouton « Lancer » s'active sur `r.ok` ;
`action_execute_restore` ne relit pas `warn`. In-place : PVC/PV supprimés, PV recréé avec un
`volumeHandle` sans VG, PVC Bound (liaison statique), app redémarrée → FailedMount. Clone :
abandon à 3521-3529 mais PVC/PV déjà détruits.
*Correctif* : refuser dans `_execute_restore_locked` (avant toute destruction) tout résultat
`looks_like_vg_name`, et `same_uuid` en clone, sauf drapeau explicite — comme le fait déjà
`action_clone_app` (6099-6105).

**C6 — « Point de restauration le plus récent » = premier de la liste API, jamais triée** — l. 4951-4971, 5198, 5257, 5492
`action_hycu_restore_points` renvoie l'ordre de l'API et perd `restorePointInMillis` ;
`provision_clone/restore`, `_resolve_source_and_point` et le contrat prennent `[0]`. Si HYCU
renvoie du plus ancien au plus récent, la **restauration in-place automatique** (parcours par
défaut) rejoue la sauvegarde **la plus ancienne**.
*Correctif* : conserver `ms` dans chaque point et trier `out` par `ms` décroissant.

---

## 2. Bugs

**B1 — SigV4 : chaîne de requête non canonicalisée (non triée) → page 2 du listing S3 en 403** — l. 3919-3932, 4017-4020
`continuation-token` est ajouté **après** `prefix` ; AWS/MinIO/Objects trient la canonical
query par nom. Dès > 1000 objets sous le préfixe, la 2ᵉ requête échoue
(`SignatureDoesNotMatch`) — précisément en situation DR.
*Correctif* : construire la query comme couples triés et l'encoder une fois.

**B2 — Double encodage du chemin signé S3** — l. 3927, 3956
`_s3_object_url` quote la clé, puis `_sigv4_auth` re-quote `path` (`%` → `%25`). Se déclenche
dès qu'un `s3_prefix`/nom de cluster contient espace, accent ou `+` → tous les PUT/GET en 403
avec un message trompeur.
*Correctif* : ne quoter qu'une fois (chemin déjà encodé passé tel quel à la signature).

**B3 — Nom du VG cloné tronqué à 60 caractères → collisions et ambiguïté** — l. 5175
`"hycurestore-%s-%s-%d" % (pvc, ts, i)` puis `[:60]` : pour un PVC > 29 caractères
(`data-my-app-postgresql-primary-0`), l'index et une partie de l'horodatage sont coupés ;
deux volumes reçoivent le même nom, le clone HYCU est réellement créé, puis la découverte
échoue (« ambiguïté ») → VG orphelins.
*Correctif* : `"hycurestore-%s-%d-%s" % (ts, i, pvc)` et ne tronquer que la partie `pvc`.

**B4 — Repli HYCU de `_discover_vg_uuid_by_name` : l'uuid interne HYCU pris pour l'UUID Nutanix** — l. 5066
`UUID_RE.search(externalId) or UUID_RE.search(uuid)` : sans `externalId` exploitable, le HYCU
UUID devient `new_ref` → injecté dans le `volumeHandle` du PV → VG inexistant, échec d'attach
incompréhensible. Partout ailleurs seul `externalId` vaut identité Nutanix.
*Correctif* : ne retenir que `externalId` dans ce repli.

**B5 — Pagination tronquée si le serveur plafonne la taille de page** — l. 4904-4931 (`_hycu_list_vgs`), 4590-4624 (`action_nutanix_vgs`)
`break` sur `len(items) < page_size` **avant** de regarder `total` : si HYCU plafonne
`pageSize` à 100 (le docstring le dit), la 1ʳᵉ page (100 < 500) arrête la boucle → liste
silencieusement tronquée → `action_hycu_match` marque « none » des PVC protégés,
`_reject_stale_vgs` refuse des VG légitimes.
*Correctif* : ne sortir sur page courte que si `total is None or len(out) >= total`.

**B6 — `auto_backup_keep = 0` détruit toutes les sauvegardes sauf une ; l'UI affiche « 15 »** — l. 1909, 2036-2039, 2128, 2166
Partout ailleurs 0 = illimité ; ici `max(1, 0)` = 1 → prochaine sauvegarde (manuelle incluse)
supprime toutes les versions précédentes, pendant que `action_auto_backup_status` calcule
`int(0 or 15)` = 15.
*Correctif* : 0 = pas de rétention compteur (retour immédiat), une seule fonction de
normalisation partagée.

**B7 — Clé de protection du quota `cluster_id|namespace` sans contexte → prod/dev confondus** — l. 1534, 1557-1561
Tous les contextes locaux ont `cluster_id="local"` ; la « plus récente par namespace×cluster »
ne conserve qu'une seule entre `prod` et `dev` : la dernière sauvegarde de `app` sur `dev` peut
être purgée, contredisant la hiérarchie `_contexts/<ctx>/`.
*Correctif* : inclure `idx.get("context")` dans la clé quand `cluster_id == "local"`.

**B8 — Le plancher d'espace libre bloque la seule rétention capable de libérer de la place** — l. 1843-1846 vs 1906-1912
Rétention appliquée seulement **après** une sauvegarde réussie ; sous le plancher la
sauvegarde est refusée avant. Sans quota (défaut), aucune purge : toutes les sauvegardes
échouent indéfiniment, et le message conseille de « réduire la rétention » (sans effet).
*Correctif* : appliquer `_prune_backups`/`enforce_storage_quota` avant le test du plancher
(ou re-tester après purge), et dans `_auto_backup_loop` même sans quota.

**B9 — La sauvegarde de sécurité d'une restauration peut supprimer la sauvegarde en cours de restauration** — l. 1909 via 3457, 3466
`action_backup(ns)` crée une `keep+1`-ième version → `_prune_backups` supprime la plus
ancienne — celle choisie comme source si le namespace est à la limite —, **avant**
`_save_txn` (3466) qui seul protège un dossier. Le run courant survit (manifestes en mémoire)
mais une **reprise** avec le même `backup_path` échoue, et l'audit référence un dossier
disparu.
*Correctif* : chemins protégés supplémentaires passés à `_prune_backups` (le `backup_path`
du restore), ou pas de prune pour une sauvegarde `backup_before_restore`.

**B10 — Un échec transitoire de `kubectl config current-context` est mis en cache 15 s → sauvegardes en disposition « legacy », visibles depuis tout contexte** — l. 632-641, 1660-1665, 1729-1734
`_local_context_name` met `None` en cache ; `backup_dir` écrit alors `<root>/<ns>` avec
`index["context"] = None` ; `list_backups` (`bctx in (None, "", ctx)`) la montre sous **tous**
les contextes et n'importe quel contexte peut la purger.
*Correctif* : ne pas mettre `None` en cache, et refuser la sauvegarde si le contexte local est
inconnu.

**B11 — Effets de bord HYCU réels exécutés avant le verrou d'action et avant le pré-vol de collision** — l. 6055-6087 vs 6237-6261
`action_hycu_provision_restore/clone` (job HYCU de plusieurs minutes) tourne dans la boucle de
préparation, hors `ACTION_LOCK` (pris l. 6239) et avant « Objet(s) déjà présent(s) ». Re-run
après échec : en mode `clone`, un VG HYCU orphelin par tentative ; deux requêtes réelles
concurrentes = deux restaurations du même VG.
*Correctif* : lock + pré-vol **avant** le provisionnement HYCU ; en clone, réutiliser un VG
`hycurestore-<pvc>-…` déjà découvert.

**B12 — Échec du scale-up ignoré : app laissée arrêtée, transaction effacée, `error: None`** — l. 3603-3604, 3632-3644
`_restart_workloads` n'inspecte pas ses résultats ; `aborted` reste `False` → `_clear_txn`,
réponse `{"ok": False, "error": None}` : l'UI n'affiche pas la consigne « SÉQUENCE
INTERROMPUE » et la reprise rejouerait toute la destruction/recréation.
*Correctif* : `_restart_workloads` renvoie `(ok, détail)` ; en échec, `error` avec les
`kubectl scale` restants et transaction conservée (`restart_pending`).

**B13 — Transaction `in_progress` écrite avant la première étape destructive ; un abandon précoce bloque la sauvegarde auto du namespace** — l. 3466-3469 vs 3474-3507, 1938
`_save_txn` précède l'inventaire, l'arrêt et l'attente des pods : erreur de
`_resolve_workloads` ou timeout de `_wait_pods_gone` → rien détruit mais `_restore_txn.json`
reste ; `action_backup_all` ignore le namespace (« différée ») et aucune action ne permet
d'annuler.
*Correctif* : écrire la transaction juste avant le premier `delete` ; l'effacer si abandon
avant destruction ; action « abandonner la transaction ».

**B14 — Pré-vol de collision par nom uniquement : aucun contrôle qu'un PV vivant pointe déjà sur le même `volumeHandle`** — l. 6244-6261
DR relancée avec les mêmes UUID vers deux namespaces → deux PV Bound sur le même VG ;
récupération d'un namespace dont le PV `Released` subsiste (Retain) → second PV sur le même
VG ; si l'ancien PV est nettoyé avec une policy Delete rétablie, le VG sous l'app récupérée est
détruit.
*Correctif* : lister les PV et refuser tout `spec.csi.volumeHandle` identique ; en recover,
proposer d'adopter le PV `Released` (patch `claimRef`).

**B15 — `_load_old_pv` retombe sur le cluster LIVE même « depuis la sauvegarde seule »** — l. 3020-3043, 6047, 6107-6109
Si la sauvegarde n'a pas de `pv_file` pour ce PVC (cas réel : C3), on lit le cluster
**cible** : un PVC homonyme (DR partielle précédente) fournit le gabarit et l'UUID de
référence, contrairement au docstring de `_backup_cluster_error` et au commentaire 6107.
*Correctif* : `_load_old_pv(..., no_live=True)` quand `from_backup`/`backup_path` est fourni.

**B16 — Import S3 : aucune borne sur la taille décompressée ; plancher disque testé après téléchargement** — l. 4055-4076, 4100-4120
Export plafonné à 512 Mo (4168) mais `_safe_extract_zip` extrait sans limite un objet venant
d'un « stockage non maîtrisé » (zip bomb → disque du pod plein) ; `_storage_floor_error`
(4116) est vérifié **après** avoir chargé l'objet complet en mémoire (4100).
*Correctif* : refuser si `sum(file_size)` dépasse un plafond, écrire par blocs avec compteur,
tester le plancher avant le GET.

**B17 — `pbkdf2_iterations < 1000` accepté au chiffrement, refusé au déchiffrement → coffre indéchiffrable** — l. 4339, 4357, 4394
`encrypt_*` écrivent la valeur de config sans borne ; `decrypt_*` rejettent `iters < 1000`.
Un `"pbkdf2_iterations": 500` donne un coffre et des `.enc` inutilisables (« phrase
incorrecte »).
*Correctif* : borner à l'écriture (`max(1000, min(iters, 10_000_000))`) ou refuser dans
`save_config`.

**B18 — Bouton « Créer les volumes automatiquement via HYCU » : clone HYCU réel sans confirmation ni verrou** — JS l. 10201-10216
En réel, `#drAuto` poste `/api/hycu/provision_clone` sans `confirmDanger`, sans désactiver le
bouton ni `drBusy` : un double-clic lance deux séries de clones ; pendant le provisionnement,
« Restaurer (réel) » reste cliquable avec des références à moitié remplies. `hyBatchRun`
(8643-8646) fait bien confirmation + désactivation.
*Correctif* : `confirmDanger` en réel, `drBusy=true` + bouton désactivé autour de l'appel.

**B19 — `drOpen` : fenêtre d'état périmé entre deux ouvertures** — JS l. 10132-10161
`rsShowPage("dr")`/`rsWizSync()` (et la boucle 300 ms) s'exécutent **avant**
`await get("/api/dr/backups")` : `drBackups`, les `.drRef`, `#drTargetNs` sont ceux de
l'ouverture précédente ; en recover `#drReuse` est coché (`needRefs=false`) → « Restaurer
(réel) » cliquable sur la sauvegarde précédente. `#drRefs` n'est pas réinitialisé.
*Correctif* : `drBusy=true` + vider `drBackups`/`#drVols`/`#drBackupSel`/`#drTargetNs` avant
le fetch, `drBusy=false` après `drRenderVols()`.

**B20 — « Retour » depuis la récupération transforme le parcours en restauration DR** — JS l. 10109-10117, 10124-10130
`openRecoverModal` force `rsWizKind="dr"` ; « Retour » → page Type avec la carte DR
sélectionnée ; « Suivant » → `drOpen("dr")` : `dr_restore=true` (garde inter-cluster levée,
plus de réutilisation/auto-restauration du VG) ou blocage `drGate` pour une app qui n'a pas
besoin de dérogation.
*Correctif* : kind dédié `rsWizKind="recover"` et `rsNextFromType`/retour → `drOpen("recover",
drRecoverNs)`, ou fermer la modale au « Retour » en recover.

**B21 — Course `loadPvcs()` non attendue après changement de cluster → mauvais `backup_path`** — JS l. 9243-9256, 9508-9510, 9664-9675
`refreshNamespaces` appelle `loadPvcs()` sans `await` ; `state.ns` est fixé au premier
namespace puis écrasé par `openRestoreModal` ; quand le fetch `/api/backups` du premier
namespace revient, `applyBackupSelection()` pose `state.backup_path` sur la sauvegarde d'un
**autre** namespace (« Manifeste du PV introuvable »).
*Correctif* : jeton de séquence dans `loadPvcs` (comme `hyPanelSeq`) ; ignorer le résultat si
`ns !== state.ns`.

**B22 — `int(Content-Length)` non protégé** — l. 6525
`Content-Length: abc` → `ValueError` hors du `try` → traceback `socketserver`, connexion
fermée sans réponse.
*Correctif* : `try/except ValueError → 400`.

---

## 3. Incohérences

**I1 — Trois vocabulaires de statuts terminaux de job HYCU, deux boucles d'attente** — l. 5123-5140 (`_await_hycu_job`), 5574-5597 (`_wait_hycu_job`), JS 9226 (`pollJobBar`)
`_JOB_OK` ignore `COMPLETE`, `_wait_hycu_job` ignore `SUCCEEDED/FINISHED/CANCELED/TIMEOUT`
mais connaît `FATAL/ABORT` ; `WARNING` (terminé avec avertissements) n'est terminal nulle
part → attente jusqu'au délai puis faux échec. `_await_hycu_job` abandonne à la **première**
erreur de lecture de `/jobs/{id}` (hoquet réseau pendant un clone de 10 min → VG orphelin
jamais découvert) ; `_wait_hycu_job` tolère.
*Correctif* : une seule fonction d'attente, ensembles d'états partagés (+ `WARNING` = succès
journalisé), N erreurs consécutives tolérées.

**I2 — Deux résolutions d'identité HYCU différentes, code dupliqué** — l. 5179-5202 vs 5235-5257
`action_hycu_provision_clone` ré-implémente `_resolve_source_and_point` avec une logique
différente (ne résout pas si des points existent sous l'UUID Nutanix ; ignore l'erreur
d'ambiguïté avec `restore_point_id`). Le dry-run affiche une « source HYCU » différente selon
le mode.
*Correctif* : `_resolve_source_and_point(..., restore_point_id=None)` utilisé par les deux.

**I3 — `_reject_stale_vgs` accepte les correspondances par nom (« non trusted »)** — l. 5398-5413 vs 5340-5346
`action_hycu_match` documente que le match par nom est « une SUGGESTION à confirmer, jamais
auto-protégée » (`trusted = kind == "exact"`), mais `allowed` ne filtre que sur `matched` :
`action_hycu_protect`, `action_hycu_restore` et le restore in-place **destructif** acceptent
côté serveur un VG matché uniquement par nom.
*Correctif* : filtrer sur `trusted` pour les opérations destructives.

**I4 — Simulation, journal et bannière ne décrivent pas le mode `recover_deleted_vg_mode="clone"`** — l. 6061-6087, 6117, JS 7468
En dry, `new_ref` reste l'UUID d'origine (aperçu sur l'ancien VG, `same_uuid` levé) alors que
le réel découvre un **nouvel** UUID ; le log dit « restauration automatique » même en clone ;
la bannière annonce « réutilisant ses volumes d'origine » ; aucun warning ni `reprotect` pour
le nouveau VG ; si `_vg_exists` renvoie `None` (Prism absent) on réutilise **silencieusement**
l'UUID d'origine.
*Correctif* : warnings dédiés (« nouvel UUID découvert au réel », « existence du VG non
vérifiable »), champ `reprotect`.

**I5 — Message d'abandon « décochez “réutiliser les volumes d'origine” » placé dans l'assistant Restaurer, où cette case n'existe pas** — l. 3522-3528 (et 6266-6269)
Le message réécrit pour la récupération vit dans `_execute_restore_locked` (namespace
**vivant**, pas de `#drReuse`) ; à l'inverse `action_clone_app` en recover sans HYCU affiche
« Prism Central requis » alors que Prism est connecté (vraie cause : VG supprimé, connectez
HYCU).
*Correctif* : distinguer « PC non connecté » / « VG introuvable » dans `_set_clone_disk_uuids`
et adapter chaque message à son parcours.

**I6 — L'aide contredit le code pour l'application supprimée ; « 4 parcours » vs 5 cartes** — l. 2569, 2578 vs 7457-7461, 7468, 6050-6087
`/help` : « restaurez d'abord ses Volume Groups dans HYCU et collez leurs UUID » alors que
l'UI coche « Réutiliser… » (« rien à saisir ») et restaure automatiquement le VG « Protected
deleted ». Titre « les 4 parcours » face à 5 cartes.
*Correctif* : réécrire le tip et le titre.

**I7 — Flux clone + HYCU : la simulation est une impasse** — JS l. 8590-8600, 8665, 10088-10098, CSS 7044
Avec HYCU connecté, le pied de modale relaie `#hyBatchGo` tant que les références sont
vides ; en simulation `hyBatchRun` s'arrête (`if(dry()) return;`) sans les remplir → bouton
« Restaurer » à l'infini, `#rsContinueWrap` masqué : impossible d'atteindre la page plan,
contrairement au hint (8595) et à l'aide (2576).
*Correctif* : en dry, proposer « Suivant » → aperçu (références = UUID source en simulation,
ou aperçu tolérant les références vides).

**I8 — La confirmation « réel » de la récupération n'annonce pas l'opération HYCU** — JS l. 10228-10233 vs 6061-6087
`confirmDanger` (recover) ne parle que de recréation Kubernetes alors que le serveur peut
déclencher un `vgrestore` in-place ou un clone HYCU réel. Les autres parcours l'annoncent.
*Correctif* : ligne conditionnelle quand `drRecoverReuse()` et HYCU connecté.

**I9 — Vérification finale « volumeHandle conforme » affichée sans vérifier les PVC non liés** — l. 3617-3628
`if got and exp` : un PVC non lié (`volume_handle` absent) n'est pas compté comme anomalie
et le log affiche « conforme pour tous les volumes ».
*Correctif* : `got is None` = anomalie (« PVC non lié »).

**I10 — Docstring de `_replace_in_leaves` interdit ce que fait `build_new_pv` ; `exact_pairs` = code mort** — l. 1380-1387 vs 1433-1450

**I11 — Compteur « N ancienne(s) version(s) supprimée(s) » toujours 0 ; suppressions par rétention jamais auditées** — l. 2124-2130 vs 1906-1910
`action_backup` a déjà pruné ; le second appel de `_auto_backup_one` ne trouve rien ;
`_prune_backups` n'écrit aucun audit (alors que `enforce_storage_quota` le fait) : des
sauvegardes disparaissent sans trace dans les Tâches.

**I12 — Sauvegarde sans horodatage : le quota la supprime EN PREMIER, la GFS la protège** — l. 1535 vs 2013-2016

**I13 — `ui.html` lu depuis `os.getcwd()`, en production** — l. 10352-10363
Tout `ui.html` présent dans le cwd du conteneur remplace l'interface embarquée.
*Correctif* : dossier du programme + activation par `HYCU_DEV_UI=1`.

**I14 — Deux fonctions d'attente/vocabulaires + duplication contrat** : le contrat de
restauration (`_collect_restore_contract`) refait `_hycu_list_vgs()` (pagination complète)
**par namespace** lors d'un `action_backup_all` — l. 5389-5400.
*Correctif* : index HYCU calculé une fois par passage (cache/paramètre).

---

## 4. Améliorations

**i18n** (l. 10367-12196)
- 124 paires **orphelines** (clé FR absente partout ailleurs — ancienne interface) : à supprimer.
- Paires **manquantes** : `" j / "` (→ « GFS 7 j / 4 wk / 12 mo » en EN), `>recommandé<`, et 7
  messages serveur de l'auto-provisionnement (« Aucun volume à provisionner. », « Connectez HYCU
  pour créer… », « Connectez Prism (Element ou Central)… », « UUID du VG source
  manquant/invalide… », « Aucun volume à restaurer. », « Connectez HYCU pour restaurer… »,
  « restauration HYCU refusée : »).
- Clés **trop génériques** (`Sauvegarder`, `Suivant`, ` terminé`, `Suppression `, `Arrêt `,
  `UUID du VG`) : sans dégât aujourd'hui (longest-first) mais fragiles ; à ancrer.

**Sécurité / robustesse serveur**
- Pas d'en-tête anti-framing sur `/` (`X-Frame-Options: DENY`, `CSP frame-ancestors 'none'`,
  `Referrer-Policy`) — l. 6324-6339 : clickjacking possible sur « Confirmer en mode réel ».
- `badge(phase)` n'échappe pas la valeur — JS l. 7822-7826 (seul endroit sans `esc()`).
- `backup_root` fourni par le client (`?root=`, `payload.backup_root`) accepté dès qu'il
  existe — l. 1616-1633 : `_safe_backup_path` n'est plus une défense en profondeur ; à
  restreindre aux racines persistées en config, ou documenter.
- `_NoCredLeakRedirect` ne bloque pas le downgrade https→http (netloc seul) — l. 3722-3739 ;
  `_s3_request` suit les redirections avec l'opener par défaut (réémission de l'ID de clé +
  signature vers un tiers) — l. 3981-3990.

**Sauvegarde / stockage**
- `index.json` écrit sans atomicité ; dossier partiel/corrompu invisible, non purgeable, non
  compté — l. 1902-1903, 1636-1649 : `.tmp` + `os.replace`, nettoyage du dossier en cas
  d'exception, statut « corrompue » dans la liste.
- Avec quota, parcours complet du dépôt (`os.walk` + `getsize`) toutes les 30 s, deux fois —
  l. 2146-2149, 1520-1536, 1564-1572.
- 15 lancements de `kubectl` par namespace pour l'instantané étendu (+1 pour le sélecteur
  d'étiquettes) — l. 1302-1306 : un seul `kubectl get a,b,c -o json`.
- Retrait d'un cluster possible pendant une restauration sur ce cluster — l. 996-1018.
- Échec d'écriture de la compaction d'audit : nouvelle tentative + message toutes les 30 s —
  l. 410-418.

**Restauration / clone**
- En recover, `app.kubernetes.io/managed-by: hycu-clone` écrase le label Helm → `helm
  upgrade` refuse l'adoption — l. 5751, 5824, 6176.
- L'apply du clone continue après un échec et le re-run est refusé (« déjà présent ») —
  l. 6280-6300.
- StatefulSet à `volumeClaimTemplates` non détecté en recover (PVC `data-<sts>-N`) —
  l. 5877-5889, 6135.
- Chiffrement HMAC-CTR octet par octet inadapté à 512 Mo (minutes de CPU dans le crochet
  post-sauvegarde) — l. 4325-4335.

**UI mineur** : `rebuildVolCfgs` lancé sur les volumes de l'app précédente (10050-10062) ;
`#rsPreview` non protégé contre le double clic (8777-8788) ; `loadPolicies` fait deux GET
`/api/auto_backup` (9812-9814).

**Faux positifs ruff écartés** : B023 (`nsm` lié une seule fois), B905 (`_xor` longueurs
égales), les `try/except pass` best-effort du contrat.

---

## 5. Ordre de correction proposé

1. **Lot 1 — critiques** : C1, C2, C4, C5, C6, C3.
2. **Lot 2 — bugs de données/flux** : B9, B11, B12, B13, B14, B15, B6, B7, B8, B10, B3, B4, B5, B1, B2, B16, B17.
3. **Lot 3 — UI/JS** : B18, B19, B20, B21, B22 + incohérences I4-I9.
4. **Lot 4 — cohérence/dette** : I1, I2, I3, I10-I14, i18n, sécurité serveur, perf.
