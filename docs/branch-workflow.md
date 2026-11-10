# Organisation des branches (contrôle Git flow)

À chaque audit, SAYTU vérifie que le dépôt suit une organisation de travail saine :

| Contrôle | Conforme | À surveiller | Non conforme |
|---|---|---|---|
| Branche de production | `main` **ou** `master` | les deux coexistent (`main` est retenue) | aucune des deux |
| Branche de travail | `develop` existe | — | pas de `develop` |
| Versions taguées | au moins un tag au format version (`v1.2.3`, `1.2`, `v2.0.0-rc1`…) | des tags, aucun au format version | aucun tag |
| Production alignée sur le dernier tag | `main`/`master` pointe **exactement** sur le commit du dernier tag de version | non vérifiable (pas de production ou pas de tag de version) | des commits sur la production après le dernier tag, ou tag posé ailleurs |

Le statut du dépôt est le pire des quatre. Il apparaît dans **Détail dépôt** (carte « Organisation des
branches », avec le détail de chaque contrôle et les commits comparés), sur la liste des dépôts et les
dépôts prioritaires (pastille « branches : … ») et sur le tableau de bord (« branches bien organisées »).

## Comment c'est mesuré

* Le worker lance `git ls-remote --heads --tags` sur le dépôt, avec le même jeton et les mêmes
  protections que le clonage (jeton jamais en argument ni dans les journaux). Rien n'est exécuté depuis le
  dépôt ; aucune donnée ne sort du serveur.
* Les tags annotés sont « pelés » (`v1.2.0^{}`) : c'est le commit visé par le tag qui est comparé.
* **Dernier tag** = la plus haute version (comparaison numérique : `v1.10.0` > `v1.9.3`), et non le
  plus récent par date ; une pré-version (`-rc1`, `-beta`) n'est retenue que s'il n'existe aucune
  version finale.
* Le contrôle porte sur l'état du dépôt **au moment de l'audit**, quelle que soit la branche auditée.
  Si les références ne peuvent pas être lues (droits, réseau), l'audit continue : le résultat précédent
  est conservé et la raison est affichée.

Implémentation : `saytu-core/.../workflow/WorkflowCheck.java` (règles, testées par `WorkflowCheckTest`),
`saytu-scan/.../git/GitCheckout.listRefs` ; stockage dans `source_repository.workflow_*` (migration V9).

## Limites

* Les conventions sont fixes dans cette version (`main`/`master`, `develop`, tags de version) ; un dépôt
  en *trunk-based development* volontaire apparaîtra « non conforme » sur la branche `develop`.
* Le contrôle n'influence pas les scores de sécurité et de qualité.
* Une branche `develop` en retard sur la production (correctif livré sans report) n'est pas encore
  signalée.
