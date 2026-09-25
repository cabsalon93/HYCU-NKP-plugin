# Grands clusters (centaines à milliers de namespaces)

*Analyse, décisions et garanties (2026-09-25).*

## Le problème

Jusqu'à cette version, chaque écran faisait « une chose par namespace » : lecture JSON
complète de tous les workloads, relecture de chaque `index.json` de chaque sauvegarde
à chaque affichage, passage de sauvegarde séquentiel avec 18 appels kubectl par
namespace et un parcours complet du disque par namespace pour le quota. À 1 000
namespaces : page Applications en dizaines de secondes à minutes, passage de
sauvegarde en heures, mémoire du pod (256 Mi) dépassée par le JSON kubectl.

## Ce qui a été fait

| Point | Mesure | Effet |
| --- | --- | --- |
| 1. Lectures kubectl | Inventaire par `-o jsonpath` (une ligne par workload : namespace, type, nom, 3 étiquettes, réplicas, propriétaires, PVC montés, volumeClaimTemplates) au lieu du JSON complet. | Dizaines de Mo → quelques centaines de Ko ; parsing négligeable. |
| 2. Repli RBAC | Si la liste cluster-wide est refusée : repli par namespace **jusqu'à** `apps_fallback_max` (50), au-delà une ligne par namespace + message explicite. | Plus de boucle de 2 000 appels. |
| 3. Cache | Inventaire Applications mis en cache `apps_cache_ttl_s` (45 s) par cluster, un seul calcul à la fois (single-flight), vidé après toute écriture, **Actualiser** = `?fresh=1`. | Tableau de bord (30 s) et page partagent un calcul. |
| 4. Passage de sauvegarde | PV lus **une fois** par passage (`backup_pv_prefetch_min`), instantané en **un** appel multi-types (repli type par type si un type est refusé), `backup_parallel` namespaces en parallèle, quota global **une fois** en fin de passage. | ~18 → ~3 appels par namespace, passage de 1 000 namespaces sous 15 min (estimation). |
| 5. Interface | Pagination à 100 lignes, sélection qui met à jour la ligne seule, « tout sélectionner » = la page. | Plus de reconstruction de 1 000 lignes à chaque clic. |
| 6. Catalogue | Fichier plat `_catalog.json` par base de sauvegardes (voir ci-dessous) consommé par la page Applications, l'inventaire DR, le quota et la tuile Stockage. | 15 000 lectures d'`index.json` → 1 lecture de catalogue + 1 `stat` par namespace. |

Point 5, volet « traduction EN » : après vérification, la traduction JSON ne touche que
les clés textuelles (`error`, `warning`, `label`…), pas les lignes d'applications ; son
coût était surestimé, aucune modification n'était nécessaire.

## Faut-il une « base » (fichier plat, JSON, NoSQL) ?

**Oui, mais dérivée et locale.** Décision : un **fichier JSON par base de sauvegardes**
(`<root>/_contexts/<ctx>/_catalog.json`, `<root>/_clusters/<id>/_catalog.json`,
`<root>/_imports/<cluster>/_catalog.json`, et `<root>/_catalog.json` pour la
disposition historique).

Pourquoi ce choix plutôt qu'une base SQLite ou NoSQL :

- **Source de vérité inchangée.** Chaque sauvegarde reste un dossier autonome
  (`index.json` + manifestes), copiable, exportable en zip, importable ailleurs. Le
  catalogue est **reconstructible** à tout moment : supprimé ou corrompu, il est
  refait au prochain accès. Une restauration ne le lit **jamais** (elle lit
  `index.json`, `_safe_backup_path`, `_backup_cluster_error`).
- **Aucune dépendance** : l'outil reste un fichier Python stdlib ; SQLite est dans la
  stdlib mais ajoute des verrous de fichier délicats sur un PVC réseau et un format
  opaque pour l'opérateur. Un JSON se lit, se diffe et se supprime à la main.
- **Volume raisonnable** : ~600 octets par version, soit ~9 Mo pour 1 000 namespaces ×
  15 versions, chargé une fois en mémoire puis persisté à chaque changement.
- **Invalidation sûre** : date de modification + nombre d'entrées du dossier du
  namespace, dossiers sans `index.json` revérifiés à chaque accès (sauvegarde en cours
  d'écriture), et **oubli explicite** après chaque écriture de l'outil (sauvegarde,
  rétention, quota, import S3).

Ce qui n'y est **pas** : les manifestes, les Secrets, les contrats de restauration
complets. Seul le résumé nécessaire aux écrans (horodatage, volumes et UUID d'origine,
identité HYCU, applications, taille, marqueur partiel).

Si un jour la liste dépasse ce que JSON tient confortablement (plusieurs dizaines de
milliers de versions), la même interface (`_catalog_all`, `_catalog_ns`, `_catalog_forget`)
peut être portée sur SQLite sans toucher aux consommateurs.

## Garanties « rien ne casse pour la restauration »

- L'extraction légère ne sert **qu'à l'inventaire**. Le clone d'une application stateless
  lit les manifestes **complets** (`_list_namespace_workloads(full=True)`), la sauvegarde
  lit toujours PVC, PV et instantané en JSON complet.
- Le passage parallèle transmet le cluster de l'appelant à chaque thread ; la transaction
  de restauration en cours, la rétention et l'audit sont inchangés par namespace.
- Les tests `_test_scale.py` couvrent l'équivalence léger/JSON du regroupement, le cas
  « objet unique » de kubectl, le repli borné, la construction/réutilisation/invalidation
  du catalogue, les consommateurs, le cache et le passage parallèle.

## Réglages

`apps_fallback_max`, `apps_cache_ttl_s`, `backup_parallel`, `backup_pv_prefetch_min`
(voir README). À 1 000 namespaces, prévoyez aussi une limite mémoire du pod d'au moins
512 Mi et un filtre de namespaces (ou le sélecteur d'étiquettes `namespace_label_selector`)
pour ne voir que ce qui doit être protégé.
