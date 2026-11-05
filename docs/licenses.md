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

Les binaires sont téléchargés depuis les publications officielles GitHub au moment de la construction
de l'image `worker`, à une **version figée et vérifiée par SHA-256** (`backend/Dockerfile`, étape
`tools`). Ils sont exécutés comme programmes séparés (aucune liaison avec le code SAYTU).

| Outil | Version (phase 4) | Licence du moteur | Données / règles | Statut |
|---|---|---|---|---|
| **Opengrep** | 1.33.1 | LGPL-2.1 (fork de Semgrep CE ; fichier `LICENSE` du dépôt opengrep/opengrep vérifié) | voir « Règles Opengrep » ci-dessous | ✅ intégré |
| **Trivy** | 0.76.1 | Apache-2.0 | La base de vulnérabilités (Trivy DB) agrège des avis de sources multiples (NVD, GitHub Advisory Database, distributions…), chacune avec ses conditions. Elle **n'est pas incluse dans l'image** : le worker la télécharge (avis publics uniquement, aucun code transmis) ou l'exploitant la copie (site isolé). Les contrôles de configuration (Dockerfile, Kubernetes, Terraform…) sont ceux embarqués dans le binaire (Apache-2.0). | ✅ intégré |
| **Gitleaks** | 8.30.1 | MIT | configuration par défaut de la même version copiée dans `scanners/gitleaks/gitleaks.toml` avec son `LICENSE` (MIT) | ✅ intégré |
| **PMD** | — | licence de type BSD | règles intégrées (même licence) | phase 5 |
| **Checkstyle** | — | LGPL-2.1+ | configurations `sun_checks.xml` / `google_checks.xml` fournies avec l'outil | phase 5 |
| **OWASP Dependency-Check** (optionnel) | — | Apache-2.0 | NVD (domaine public) ; clé d'API NVD gratuite recommandée | phase 5 ; désactiver les analyseurs qui interrogent des services tiers |
| git, util-linux (`prlimit`) | paquets Ubuntu 24.04 | GPL-2.0 | — | programmes du système de l'image `worker` |

### Règles Opengrep (décision du 5 novembre 2026)

| Pack | Licence | Embarqué | Justification |
|---|---|---|---|
| `scanners/opengrep/rules/saytu` — 24 règles écrites pour SAYTU (Java, JS/TS, Python, Go), chacune testée par `opengrep --test` | Apache-2.0 | ✅ | règles propres au projet |
| `scanners/opengrep/rules/aikido` — [AikidoSec/opengrep-rules](https://github.com/AikidoSec/opengrep-rules), commit `7ac79af` (2 règles GitHub Actions / npm) | MIT (`LICENSE` copié) | ✅ | licence permissive vérifiée sur le dépôt |
| [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules) (~2 000 règles) | *Semgrep Rules License v1.0* : « usage pour vos propres besoins internes uniquement », sans redistribution ni mise à disposition comme service | ❌ | téléchargeable par chaque installation pour **son** usage interne (`scripts/fetch-opengrep-rules.sh semgrep --accept-semgrep-rules-license`) ; à ne pas intégrer à une offre commerciale ni redistribuer |
| [trailofbits/semgrep-rules](https://github.com/trailofbits/semgrep-rules) | AGPL-3.0 | ❌ | utilisable (`scripts/fetch-opengrep-rules.sh trailofbits`) ; non embarqué pour garder l'image sous licences permissives |

Le dépôt `opengrep/opengrep-rules`, envisagé en phase 1, n'a pas été retenu : la seule source
« opengrep-rules » trouvée avec une licence explicite est celle d'Aikido, qui ne contient que 2 règles.

## Modèles IA (phase 7, optionnels)

Chaque modèle a sa propre licence, indépendante d'Ollama. Retenir par défaut des modèles sous
licence permissive (par exemple les modèles publiés sous Apache-2.0) et vérifier la licence
**de la taille exacte** choisie : au sein d'une même famille, certaines tailles ont des licences
plus restrictives.

## Procédure de contrôle

1. À chaque ajout de dépendance : licence vérifiée sur le dépôt officiel, ajout dans ce tableau.
2. Phase 8 : génération automatique d'un inventaire (SBOM CycloneDX pour le backend et le
   frontend) et contrôle des licences dans le pipeline de build.
