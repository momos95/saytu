# Licences des composants

Objectif : aucun composant commercial ni abonnement **obligatoire**. Ce registre est tenu à jour à
chaque phase ; la colonne « Vérification » indique ce qui a été confirmé sur une source primaire et
ce qui reste à contrôler avant intégration.

Licence proposée pour SAYTU : **Apache-2.0** (modifiable par le porteur du projet ; elle
est compatible avec l'usage de tous les composants ci-dessous tant que les outils LGPL/GPL sont
utilisés comme programmes séparés ou bibliothèques liées dynamiquement, sans modification).

## Plateforme (phase 1)

| Composant | Usage | Licence | Vérification |
|---|---|---|---|
| Eclipse Temurin 21 (OpenJDK) | runtime Java | GPL-2.0 + Classpath Exception | connue |
| Spring Boot / Framework / Security / Data | backend | Apache-2.0 | connue |
| Hibernate ORM 6.6 (via Spring Boot 3.5) | JPA | **LGPL-2.1** — le passage à Apache-2.0 ne concerne que les versions ≥ 7.0 et n'est pas rétroporté sur 6.x | confirmée (annonce Hibernate, mars 2025) |
| Flyway (`flyway-core`, `flyway-database-postgresql`) | migrations | Apache-2.0 (édition communautaire ; aucune fonction payante utilisée) | connue |
| PostgreSQL JDBC | pilote | BSD-2-Clause | connue |
| springdoc-openapi / Swagger UI | doc API | Apache-2.0 | connue |
| JUnit 5 | tests | EPL-2.0 | connue |
| Mockito, Testcontainers | tests | MIT | connue |
| AssertJ, ArchUnit | tests | Apache-2.0 | connue |
| Angular 20, Angular CLI | frontend | MIT | connue |
| RxJS | frontend | Apache-2.0 | connue |
| Karma, Jasmine | tests frontend | MIT | connue |
| Keycloak 26 | IAM | Apache-2.0 | connue |
| PostgreSQL 16 | base | PostgreSQL License | connue |
| nginx (image `nginx-unprivileged`) | serveur web | BSD-2-Clause | connue |
| Ollama (optionnel) | LLM local | MIT | connue |

Phase 2 : **aucune dépendance ajoutée**. Les connecteurs Git (`saytu-git`) n'utilisent que le JDK et
l'authentification de l'interface n'utilise aucune bibliothèque OIDC (ADR-0005, ADR-0006). La locale
française d'Angular (`@angular/common/locales/fr`) fait partie d'Angular (MIT).

## Scanners (phases 4-5)

| Outil | Licence du moteur | Données / règles embarquées | Point d'attention |
|---|---|---|---|
| **Opengrep** | LGPL-2.1 (fork de Semgrep CE) | **Aucun jeu de règles fourni par le projet.** Les règles du registre Semgrep sont sous *Semgrep Rules License v1.0*, qui **n'est pas open source** et interdit l'usage dans un produit concurrent ou un SaaS. | **Bloquant phase 4** : ne pas embarquer `semgrep-rules`. Candidat : `opengrep/opengrep-rules` (fork de semgrep-rules du 13/12/2024) — vérifier son fichier LICENSE et l'en-tête des règles avant intégration ; à défaut, maintenir un jeu de règles SAYTU sous Apache-2.0. |
| **Trivy** | Apache-2.0 | Trivy DB / Java DB agrègent des avis de sécurité de sources multiples (NVD, GitHub Advisory Database, avis des distributions…) chacune avec ses conditions. | Documenter les sources et leurs conditions ; la base n'est pas redistribuée dans l'image, elle est importée par l'exploitant. |
| **Gitleaks** | MIT | règles par défaut incluses dans le binaire (MIT) | — |
| **PMD** | licence de type BSD | règles intégrées (même licence) | — |
| **Checkstyle** | LGPL-2.1+ | configurations `sun_checks.xml` / `google_checks.xml` fournies avec l'outil | utilisé comme programme séparé |
| **OWASP Dependency-Check** (optionnel) | Apache-2.0 | NVD (données du gouvernement américain, domaine public) ; une clé d'API NVD gratuite est recommandée pour la mise à jour | désactiver les analyseurs qui interrogent des services tiers (OSS Index, npm/yarn/pnpm audit, Central) |

## Modèles IA (phase 7, optionnels)

Chaque modèle a sa propre licence, indépendante d'Ollama. Retenir par défaut des modèles sous
licence permissive (par exemple les modèles publiés sous Apache-2.0) et vérifier la licence
**de la taille exacte** choisie : au sein d'une même famille, certaines tailles ont des licences
plus restrictives.

## Procédure de contrôle

1. À chaque ajout de dépendance : licence vérifiée sur le dépôt officiel, ajout dans ce tableau.
2. Phase 8 : génération automatique d'un inventaire (SBOM CycloneDX pour le backend et le
   frontend) et contrôle des licences dans le pipeline de build.
