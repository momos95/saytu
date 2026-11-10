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
`tools`). Les outils de la phase 5 viennent de Maven Central (Checkstyle, PMD : versions figées dans
`backend/tools/*.pom.xml`), de npm (`scanners/eslint/package.json`, `npm install --ignore-scripts`),
de PyPI (SQLFluff), d'un clone Git vérifié par commit (PHP_CodeSniffer) et d'Ubuntu (Cppcheck, PHP). Ils sont exécutés comme programmes séparés (aucune liaison avec le code SAYTU).

| Outil | Version | Licence du moteur | Données / règles | Statut |
|---|---|---|---|---|
| **Opengrep** | 1.33.1 | LGPL-2.1 (fork de Semgrep CE ; fichier `LICENSE` du dépôt opengrep/opengrep vérifié) | voir « Règles Opengrep » ci-dessous | ✅ intégré |
| **Trivy** | 0.76.1 | Apache-2.0 | La base de vulnérabilités (Trivy DB) agrège des avis de sources multiples (NVD, GitHub Advisory Database, distributions…), chacune avec ses conditions. Elle **n'est pas incluse dans l'image** : le worker la télécharge (avis publics uniquement, aucun code transmis) ou l'exploitant la copie (site isolé). Les contrôles de configuration (Dockerfile, Kubernetes, Terraform…) sont ceux embarqués dans le binaire (Apache-2.0). | ✅ intégré |
| **Gitleaks** | 8.30.1 | MIT | configuration par défaut de la même version copiée dans `scanners/gitleaks/gitleaks.toml` avec son `LICENSE` (MIT) | ✅ intégré |
| **PMD** (Java) | 7.28.0 | licence de type BSD (BSD-4-clause modifiée, fichier `LICENSE` de pmd/pmd) ; dépendances Apache-2.0 / MIT (picocli, ASM, Saxon-HE MPL-2.0) | jeu `rulesets/java/quickstart.xml` livré avec PMD (même licence) | ✅ phase 5 — `pmd-designer` (JavaFX) exclu |
| **Checkstyle** (Java) | 14.3.0 | LGPL-2.1-or-later ; dépendances Apache-2.0 (Guava, commons), ANTLR BSD, Saxon-HE MPL-2.0 | `scanners/checkstyle/saytu-checks.xml` écrit pour SAYTU (Apache-2.0) | ✅ phase 5 |
| **ESLint** (JS/TS) | 9.39.5 | MIT | configuration SAYTU `scanners/eslint/eslint.config.mjs` (Apache-2.0) | ✅ phase 5 |
| typescript-eslint | 8.69.0 | MIT (parser BSD-2-Clause) | règles `recommended` | ✅ phase 5 |
| eslint-plugin-security | 3.0.1 | Apache-2.0 | règles `recommended` | ✅ phase 5 |
| `globals`, `typescript` (dépendances d'ESLint) | 16.4.0, 5.9.3 | MIT, Apache-2.0 | — | ✅ phase 5 |
| Node.js (exécution d'ESLint) | 22.23.3 (image `node:22-bookworm-slim`) | MIT (+ licences tierces de Node) | — | ✅ phase 5 — binaire `node` seul copié dans l'image |
| **PHP_CodeSniffer** (PHP) | 4.0.2 (commit `74ee2d4` vérifié) | BSD-3-Clause | normes PSR12/PSR2/PSR1/PEAR/Squiz/Zend fournies avec l'outil | ✅ phase 5 ; `php-cli`, `php-xml` (PHP License 3.01) depuis Ubuntu |
| **Cppcheck** (C/C++) | 2.13.0 (paquet Ubuntu 24.04) | GPL-3.0-or-later | vérifications intégrées | ✅ phase 5 — programme séparé, exécuté et non lié : la GPL n'impose rien au code SAYTU ; le code source est celui du paquet Ubuntu |
| **SQLFluff** (SQL) | 4.4.0 (venv Python ; version figée, dépendances résolues par pip à la construction) | MIT ; dépendances MIT/BSD/Apache-2.0 | règles intégrées | ✅ phase 5 |
| C# | — | — | — | ❌ aucun analyseur de qualité libre utilisable sans compiler le projet (les analyseurs Roslyn exigent `dotnet build`, interdit : aucun script de build du dépôt n'est exécuté). La qualité C# est affichée « non couverte ». |
| **OWASP Dependency-Check** (optionnel) | — | Apache-2.0 | NVD (domaine public) ; clé d'API NVD gratuite recommandée | ❌ non intégré : Trivy couvre les dépendances ; affiché « non intégré » |
| git, util-linux (`prlimit`, `setpriv`) | paquets Ubuntu 24.04 | GPL-2.0 | — | programmes du système de l'image `worker` |
| iptables (phase 8) | paquet Ubuntu 24.04 | GPL-2.0 | — | pare-feu des comptes de scanners, appelé par `worker-entrypoint.sh` ; programme séparé, non modifié |

### Règles Opengrep (décision du 5 novembre 2026)

| Pack | Licence | Embarqué | Justification |
|---|---|---|---|
| `scanners/opengrep/rules/saytu` — 24 règles écrites pour SAYTU (Java, JS/TS, Python, Go), chacune testée par `opengrep --test` | Apache-2.0 | ✅ | règles propres au projet |
| `scanners/opengrep/rules/aikido` — [AikidoSec/opengrep-rules](https://github.com/AikidoSec/opengrep-rules), commit `7ac79af` (2 règles GitHub Actions / npm) | MIT (`LICENSE` copié) | ✅ | licence permissive vérifiée sur le dépôt |
| [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules) (~2 000 règles) | *Semgrep Rules License v1.0* : « usage pour vos propres besoins internes uniquement », sans redistribution ni mise à disposition comme service | ❌ | téléchargeable par chaque installation pour **son** usage interne (`scripts/fetch-opengrep-rules.sh semgrep --accept-semgrep-rules-license`) ; à ne pas intégrer à une offre commerciale ni redistribuer |
| [trailofbits/semgrep-rules](https://github.com/trailofbits/semgrep-rules) | AGPL-3.0 | ❌ | utilisable (`scripts/fetch-opengrep-rules.sh trailofbits`) ; non embarqué pour garder l'image sous licences permissives |

Le dépôt `opengrep/opengrep-rules`, envisagé en phase 1, n'a pas été retenu : la seule source
« opengrep-rules » trouvée avec une licence explicite est celle d'Aikido, qui ne contient que 2 règles.

## Rapports (phase 6)

Aucun composant ajouté : PDF, HTML, JSON et SARIF sont produits par du code SAYTU (Apache-2.0,
`saytu-core/report`). Le PDF utilise les polices standard PDF (Helvetica, Courier), référencées et
non embarquées : aucun fichier de police n'est distribué. Le schéma SARIF 2.1.0 est un standard OASIS ;
SAYTU n'en embarque pas de copie.

## Modèles IA (phase 7, optionnels)

Chaque modèle a sa propre licence, indépendante d'Ollama. Retenir par défaut des modèles sous
licence permissive (par exemple les modèles publiés sous Apache-2.0) et vérifier la licence
**de la taille exacte** choisie : au sein d'une même famille, certaines tailles ont des licences
plus restrictives.

| Composant | Licence | Statut |
|---|---|---|
| Ollama (image `ollama/ollama`, profil `ai`) | MIT | ✅ phase 7, optionnel, désactivé par défaut |
| qwen2.5-coder **7B** (modèle proposé par défaut) | Apache-2.0 | téléchargé par l'exploitant (`ollama pull`) ; la taille 3B est sous licence Qwen Research, plus restrictive |

Phase 7 n'ajoute aucune bibliothèque au backend ni au frontend : planification (`CronExpression` de
Spring Framework, Apache-2.0, déjà présent), webhooks et client Keycloak (`java.net.http` du JDK, HMAC
`javax.crypto`), comparaison et réglages en code SAYTU.

## Procédure de contrôle

1. À chaque ajout de dépendance : licence vérifiée sur le dépôt officiel, ajout dans ce tableau.
2. Inventaire automatique : `scripts/sbom.sh` produit, sans réseau, un SBOM CycloneDX par image SAYTU (paquets
   système, JAR y compris ceux de `saytu.jar`, modules Python et Node) et des paquets npm de l'interface, avec
   l'inventaire des licences classées par Trivy (*forbidden*, *restricted*, *reciprocal*, *notice*,
   *permissive*, *unknown*). `--strict` échoue (code 3) si une licence *forbidden* apparaît, pour un pipeline.
3. Lecture attendue : les licences *restricted* / *reciprocal* (GPL, LGPL, MPL) viennent des paquets Ubuntu et
   des outils exécutés comme programmes séparés (git, Cppcheck, iptables…) ; elles n'imposent rien au code
   SAYTU tant que ces programmes ne sont ni modifiés ni liés. Toute licence *forbidden* ou *unknown* nouvelle
   doit être examinée avant diffusion des images.
