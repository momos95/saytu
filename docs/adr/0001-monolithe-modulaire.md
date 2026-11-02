# ADR-0001 — Monolithe modulaire (API + worker dans le même artefact)

**Statut** : accepté (phase 1)

## Contexte
Plateforme on-premise exploitée par de petites équipes, souvent sans orchestrateur. Deux charges
très différentes : API interactive (légère) et analyses (CPU/mémoire, longues, code non fiable).

## Décision
* Un monorepo, deux modules Maven : `acs-core` (domaine + ports, sans framework) et `acs-app`
  (Spring Boot).
* Un seul artefact exécuté avec deux profils : `api` et `worker`. Le conteneur `worker` ajoute
  les binaires des scanners et peut être placé sur une autre machine.
* Frontières internes vérifiées par ArchUnit (pas de cycle, cœur sans framework, contrôleurs sans
  entités JPA).

## Conséquences
+ Une seule version, un seul modèle, déploiement Compose simple ; montée en charge par ajout de
  workers.
+ La logique critique (empreintes, expurgation, invariants de commande) est testable sans Spring.
− La discipline modulaire doit être tenue par les tests d'architecture.
