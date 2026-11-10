# Feuille de route et état d'avancement

| Phase | Contenu | État |
|---|---|---|
| 1 | Architecture, modèle de données, monorepo, Docker Compose | ✅ livrée (voir détail ci-dessous) |
| 2 | Authentification Keycloak dans l'UI, coffre de tokens AES-GCM, CRUD + test des connexions Git | ✅ livrée (voir détail) |
| 3 | Découverte organisations / dépôts / branches, sélection, configuration des branches | ✅ livrée (voir détail) |
| 4 | Worker, file d'exécution, sandbox, clone sécurisé, Opengrep, Trivy, Gitleaks | ✅ livrée (voir détail) |
| 5 | Détection des langages, outils de qualité par langage (Checkstyle, PMD, ESLint, PHPCS, Cppcheck, SQLFluff), scoring et couverture | ✅ livrée (voir détail) |
| 6 | Dashboard Angular, détail dépôt, liste/détail des vulnérabilités et triage, rapports HTML/PDF/JSON/SARIF | ✅ livrée (voir détail) |
| 7 | Planification cron, historique, comparaison de scans, webhooks, gestion des utilisateurs, recommandations, Ollama | ✅ livrée (voir détail) |
| 8 | Durcissement, tests de bout en bout, SBOM, guides d'exploitation et de mise à jour hors ligne | à faire |

## Renommage AfriCodeShield → SAYTU (4 novembre 2026)

Tous les identifiants ont changé : packages Java `com.saytu`, modules `saytu-core` / `saytu-git` /
`saytu-app`, realm Keycloak `saytu`, clients `saytu-web` / `saytu-api`, base et rôle PostgreSQL
`saytu`, propriétés `saytu.*`, variables `SAYTU_*`, images `saytu/api` et `saytu/web`, préfixe Angular
`saytu-`. Les données chiffrées sous l'ancien nom ne sont plus lisibles (données associées du
chiffrement) : une installation existante doit être réinitialisée.

**Réinitialiser une installation de développement sans Docker**
1. Arrêter l'API et Keycloak.
2. PostgreSQL : `CREATE ROLE saytu LOGIN PASSWORD '...'; CREATE DATABASE saytu OWNER saytu;`
   (l'ancienne base `africodeshield` peut être supprimée).
3. Keycloak : supprimer `data/h2`, copier `infra/keycloak/saytu-realm.json` dans `data/import/`
   (retirer l'ancien fichier), relancer avec `--import-realm` et les variables `SAYTU_PUBLIC_URL`,
   `SAYTU_INITIAL_ADMIN_USERNAME`, `SAYTU_INITIAL_ADMIN_PASSWORD`.
4. API : variables `SAYTU_DB_PASSWORD` et `SAYTU_MASTER_KEY` (au lieu de `ACS_*`), puis
   `mvn -f backend/pom.xml package` et `java -jar backend/saytu-app/target/saytu.jar`.
5. Ressaisir les connexions Git.

**Avec Docker Compose** : `docker compose down -v`, renommer les variables `ACS_*` en `SAYTU_*` dans
`.env` (ou le regénérer avec `scripts/generate-secrets.sh` après l'avoir supprimé), puis
`docker compose up -d --build`.

## Organisation des branches (10 novembre 2026)

Contrôle à chaque audit : branche de production `main`/`master` sur le dernier tag de version, branche
`develop` présente — voir [branch-workflow.md](branch-workflow.md).
* Vérifié ici : règles `WorkflowCheckTest` (5 tests), lecture des références sur un vrai dépôt Git avec
  tag annoté (`GitCheckoutTest`), SQL de stockage et compteurs (`verify-scan-sql.sh`), specs de logique.
* Écrit pour compiler, non exécuté ici : intégration Spring (`ResultWriter`, `InsightService`), carte
  Angular du détail dépôt, pastilles et indicateur du tableau de bord (specs TestBed).

## Phase 7 — détail (8 novembre 2026)

### Livré et vérifié dans l'environnement de développement
* SQL (`AutomationSql`, migration V8) ajouté à `scripts/verify-scan-sql.sh` — **131 contrôles réussis
  sur PostgreSQL 16** : planifications (cibles, échéances verrouillées, blocage si l'audit précédent
  tourne, dernier déclenchement), webhooks (contraintes d'URL et d'événements, abonnements, boîte
  d'envoi : réessai, abandon, point de terminaison désactivé), comparaison, cache des explications IA,
  réglages.
* Règles pures (`AutomationRulesTest`, 6 tests) : contenu des alertes (gravité minimale, aucune preuve),
  format Slack, signature HMAC comparée à `openssl`, délais de réessai, masquage et contrôle des URL,
  validation des webhooks, classement « introduite / corrigée / non vérifiable » (un outil en échec ne
  prouve jamais une correction), périmètre planifié, réglages IA. `UserRulesTest` (2 tests).
* `saytu-core` 86/86, `saytu-git` 89/89, `saytu-scan` 42/42 ; frontend **22 specs** de logique.

### Livré, écrit pour compiler, **non exécuté ici**
* Spring : `ScheduleService`/`ScheduleTrigger` (cron Spring, fuseau, intervalle ≥ 15 min),
  `WebhookService`/`WebhookDispatcher` (secret chiffré comme les jetons Git, HMAC, réessais),
  `JobComparisonService`, `UserService`/`KeycloakAdminClient` (client `saytu-admin-api`, royaume saytu
  seulement), `AiService`/`OllamaRemediationProvider`. Tests Maven : `CronAndAiSpringTest`,
  `AutomationControllerSecurityTest` (rôles, 503 si non configuré).
* Scripts `keycloak-admin-client.ps1` / `.sh` (kcadm dans le conteneur Keycloak).
* Angular : page Utilisateurs & paramètres (4 onglets), page Comparaison, bloc « Explication par IA
  locale » ; specs TestBed. Les dix pages de la spécification sont livrées.

### Limites connues de la phase 7
* « Ignorer les branches inchangées » d'une planification n'est pas implémenté.
* Gestion des utilisateurs : activée automatiquement par le service `keycloak-config` (10 novembre) ;
  pas d'envoi d'e-mail (le mot de passe temporaire est affiché à l'administrateur).
* IA locale : le modèle ne voit pas le code autour de la ligne (non conservé) ; qualité variable selon
  le modèle ; génération synchrone (jusqu'au délai réglé).
* Les envois de webhooks n'utilisent pas `HTTPS_PROXY`, seulement le proxy Java (`SAYTU_JAVA_PROXY_OPTS`).

## Phase 6b — score v2, plan d'action et corrections proposées (6 novembre 2026)

Demandé après les premiers audits réels (scores de sécurité à 0 sur tous les dépôts, secrets en « Moyenne »).

### Livré et vérifié dans l'environnement de développement
* Formule `v2` (`SecurityIssue`, `ScoreCalculator.groups`) : catégories code / secret / dépendance /
  configuration, regroupement par paquet ou par règle avec rendements décroissants, courbe
  `100 / (1 + points / 100)`. `ScoringV2Test` (7 tests) dont un microservice réaliste noté entre 20 et 40 ;
  la v1 reste reproductible (`ScoringFormula.V1`).
* Secrets : jamais sous « Élevée », « Critique » quand l'émetteur est identifiable (adaptateur Gitleaks
  et migration V6 pour l'existant).
* Corrections proposées (`RuleBasedRemediationProvider`, 24 fiches par CWE, dépendances de 9
  écosystèmes, secrets, Kubernetes/Dockerfile, qualité) — **8 tests**.
* Plan d'action (`InsightService.plan`) et lecture de la formule v2 — **3 tests** contre des souches Spring.
* `saytu-core` **86/86**, `saytu-git` **89/89**, `saytu-scan` **42/42** ; SQL **95 contrôles** sur
  PostgreSQL 16 (dont migration V6, requêtes de recalcul) ; frontend **8 specs** de logique.

### Livré, écrit pour compiler, non exécuté ici
* Recalcul des scores sans nouvel audit : au démarrage du worker si la formule a changé
  (`ScoreUpgrade`), après chaque triage, après un changement de formule.
* Angular : bloc « Correction proposée » (étapes, exemples, tests), « Plan d'action sécurité » du dépôt.

## Phase 6 — détail (6 novembre 2026)

### Livré et vérifié dans l'environnement de développement
* Rapports (`saytu-core/report`, JDK seul, sans dépendance) : JSON `saytu-report/1`, SARIF 2.1.0,
  HTML autonome, PDF — **7 tests** (`ReportWritersTest`) ; le PDF de test (120 vulnérabilités,
  26 pages) passe `qpdf --check`, son texte extrait par `pdftotext` contient les accents ; JSON et
  SARIF relus par `python3 -m json`.
* SQL du tableau de bord, du détail dépôt, des rapports et du triage (`InsightSql`) : ajoutés à
  `scripts/verify-scan-sql.sh` — **90 contrôles réussis sur PostgreSQL 16** (dont : triage sans
  justification refusé par la base, risque accepté conservé quand le scanner le retrouve, dépôts retirés
  ignorés, une valeur par jour dans l'évolution).
* `saytu-core` **70/70**, `saytu-git` **89/89**, `saytu-scan` **42/42** ; règles de triage et de rapport
  (`TriageAndReportRulesTest`) **3/3** contre des souches Spring.
* Frontend : logique des filtres (URL ↔ API), répartitions, courbes (trous quand le score manque),
  barres, nom de fichier des rapports — **19 specs exécutées dans Node, 19 réussies**.

### Livré, écrit pour compiler, **non exécuté ici**
* Spring : `InsightService` / `InsightController` (`/dashboard`, `/repositories/{id}/overview`),
  `FindingTriageService` (`PUT /findings/{id}/status`), `ReportService` / `ReportController`
  (`/reports/findings`) ; `FindingAndReportControllerSecurityTest` (rôles, en-têtes de
  téléchargement). Le paquet `app.scan` compile avec `-Werror` contre des souches.
* Angular : pages Tableau de bord, Vulnérabilités (filtres dans l'URL, pagination), détail d'une
  vulnérabilité (preuve, recommandation, références, détections, historique, triage), détail d'un
  dépôt (branches, règles fréquentes, jobs, « Auditer ce dépôt »), boutons de rapport ; specs TestBed.
  Les liens des pages Audits et Organisations & dépôts mènent aux détails.

### Limites connues de la phase 6
* ~~Le triage modifie le score au prochain audit~~ : recalcul immédiat depuis la phase 6b.
* PDF : polices standard non embarquées ; caractères hors Latin-1 remplacés par « ? » (intacts en
  HTML / JSON / SARIF). 2 000 vulnérabilités détaillées au plus en PDF / HTML.
* Pas de triage en masse ni de commentaires sur une vulnérabilité.
* Les rapports ne sont pas conservés côté serveur (seule leur trace l'est) ; pas d'envoi programmé
  (phase 7 avec la planification).
* Recommandations : celles des scanners uniquement ; l'explication détaillée par IA locale arrive en
  phase 7.

## Phase 5 — détail (5 novembre 2026)

### Livré et vérifié dans l'environnement de développement
* Détection des langages (`LanguageDetector`) : Java, TypeScript, JavaScript, SQL, PHP, C, C++, C#
  et 18 autres ; dossiers de dépendances et fichiers générés ignorés ; en-têtes `.h` rattachés au C++
  s'il n'y a pas de C ; étiquette à partir de 1 % du code ou 5 fichiers.
* Chaque outil déclare ses langages ; absent ⇒ `NOT_APPLICABLE` (« aucun fichier PHP »).
* Adaptateurs Checkstyle, PMD, ESLint, PHP_CodeSniffer, Cppcheck, SQLFluff : options qui empêchent le
  dépôt de désactiver l'analyse (configurations locales ignorées, `--no-inline-config`,
  `--ignore-annotations`, `--disable-noqa`, suppressions PMD rapportées), lecture XML sans DOCTYPE.
* Scoring `v1` (`ScoreCalculator`) : sécurité, qualité, global, couverture, fiabilité, agrégation
  dépôt / organisation / global — voir [scoring.md](scoring.md).
* Tests exécutés : `saytu-core` **64/64**, `saytu-git` **89/89**, `saytu-scan` **42/42** dont les
  analyses réelles par **PHP_CodeSniffer 4.0.2, Cppcheck 2.13.0, Opengrep, Trivy et Gitleaks** sur un
  projet d'exemple multi-langages ; `ScannerSettingsTest` 2/2.
* Migration V5 sur PostgreSQL 16 : contrôles de schéma réussis ; requêtes `ScoreSql` / `ScanSql` :
  **65 contrôles réussis** (`scripts/verify-scan-sql.sh`).
* Frontend : logique (raisons traduites, scores « — », étiquettes de langages) — **12 specs exécutées
  dans Node, 12 réussies**.

### Livré, écrit pour compiler, **non exécuté ici** (Maven Central, npm, PyPI bloqués)
* Checkstyle, PMD, ESLint et SQLFluff n'ont pas pu être téléchargés : leurs adaptateurs sont testés sur
  des rapports au format documenté (SQLFluff : vrai rapport 4.4.0 produit hors de cette machine), et
  `QualityToolsTest` les exécute réellement pendant `docker compose build` (outils présents dans l'image).
* Spring : `ScoreService`, `ScoreController` (`GET /api/v1/scores`, `GET|PUT /api/v1/scores/formula`),
  options des scanners, langages des dépôts. Le paquet `app.scan` compile avec `-Werror` contre des
  souches des API Spring.
* Angular : étiquettes de langages et scores (Audits, Organisations & dépôts), options des outils
  (Scanners & branches), specs TestBed mises à jour.
* Image `worker` : étapes `jvmtools` (Maven), `eslint` (Node 22) et SQLFluff ; chaque outil est lancé
  une fois pendant la construction (« smoke test »).

### Limites connues de la phase 5
* **C#** : aucun analyseur de qualité libre sans compilation ; affiché « non couvert » (Opengrep,
  Gitleaks et Trivy analysent quand même le C# pour la sécurité).
* Python, Go, Kotlin… : pas d'outil de qualité dans cette version (qualité non couverte).
* Pas de déduplication entre outils de qualité (par conception : règles non équivalentes).
* Le dialecte SQL est global (un seul par installation) ; un dépôt mêlant plusieurs dialectes aura des
  erreurs d'analyse SQLFluff rapportées comme résultats.
* La construction de l'image est plus longue (≈ 5 à 10 min de plus) et l'image plus lourde
  (JRE-outils, Node, PHP, Python).

## Phase 4 — détail (5 novembre 2026)

### Livré et vérifié dans l'environnement de développement
* Module `saytu-scan` (JDK seul) — **27 tests exécutés, 27 réussis**, dont 3 de bout en bout avec les
  **vrais binaires** Opengrep 1.33.1, Trivy 0.76.1 et Gitleaks 8.30.1 sur un dépôt Git généré :
  * `ProcessSandbox` : environnement vide (vérifié), destruction de l'arbre de processus au délai,
    `prlimit` appliqué (vérifié par `ulimit`), taille des fichiers écrits plafonnée, mémoire résidente
    surveillée (processus de 400 Mo tué sous une limite de 200 Mo), secrets masqués dans les sorties ;
  * `GitCheckout` : clone réel par HTTP « smart » authentifié (serveur `git http-backend` de test) —
    en-tête envoyé, mauvais token refusé sans apparaître dans l'erreur ; branche ciblée, `.git`
    supprimé, liens symboliques neutralisés, sous-modules ignorés, quota, délai, URL refusées
    (`ssh://`, `ext::`, identifiants dans l'URL, `http://`, chemin hors racine), nom de branche en
    forme d'option refusé ;
  * adaptateurs : rapports réels d'Opengrep et de Trivy (configuration), rapports de référence de
    Trivy (vulnérabilités npm et Maven), Gitleaks sur secrets générés ; empreinte stable quand les
    lignes bougent ; chemins hors du dépôt ignorés ; rapport absent ou illisible = erreur, jamais
    « zéro résultat » ;
  * e2e : `.semgrepignore` et `.gitleaks.toml` plantés dans le dépôt n'empêchent pas la détection ;
    Trivy sans base → `FAILED` mais erreurs de configuration conservées ; job `PARTIAL` ; répertoire
    du job supprimé.
* Pack de règles Opengrep SAYTU : **24 règles, 24 tests `opengrep --test` réussis** ; aucun faux
  positif sur le code de SAYTU ; détections réelles sur WebGoat et OWASP Juice Shop.
* SQL du moteur (`ScanSql`) : **52 contrôles réussis sur PostgreSQL 16** (`scripts/verify-scan-sql.sh`) :
  planification, unicité d'un job actif par dépôt × branche, file `SKIP LOCKED`, bail, reprise après
  crash, upsert des findings, résolution uniquement si tous les scanners concernés ont réussi,
  réouverture, triage humain préservé, filtres de l'API, annulation.
* Migration V4 : 39 contrôles de contraintes toujours réussis.
* Frontend : logique de la page Audits — **3 specs exécutées dans Node, 3 réussies**.

### Livré, écrit pour compiler, **non exécuté ici** (pas d'accès à Maven Central ni à npm)
* Spring : `ScanService`, `FindingQueryService`, `JobQueue`, `ScanPlanner`, `ResultWriter`,
  `ScanWorker`, `TrivyDbUpdater`, `ScanEngineConfig`, `ScanSourceService`, contrôleurs
  `/api/v1/scans` et `/api/v1/findings`. Le paquet `app.scan` a été compilé avec `-Werror` contre
  des souches des API Spring utilisées. Tests : `ScanControllerSecurityTest`, `ScanSupportTest`.
* Angular : page Audits (lancement, progression rafraîchie toutes les 5 s, statut par scanner,
  résultats par branche, annulation), spec TestBed.
* Docker : image `worker` (binaires vérifiés par SHA-256, runtime Opengrep pré-extrait, règles testées
  pendant la construction), service `worker`, volumes `trivy-db` et `scan-work`. Les tests du module
  `saytu-scan` s'exécutent avec les vrais scanners pendant `docker compose build`.

### Limites connues de la phase 4
* PMD, Checkstyle, Dependency-Check : affichés « non exécuté » (phase 5) ; pas encore de scores.
* La liste complète et filtrable des vulnérabilités et leur triage arrivent en phase 6 ; la page
  Audits affiche les 50 premiers résultats ouverts de chaque branche.
* Isolation : sous-processus bornés dans un conteneur durci ; pas encore de `bwrap` ni de filtrage
  réseau des scanners (phase 8).
* Base Java de Trivy non téléchargée : les `.jar` contenus dans les dépôts ne sont pas analysés.
* Le token est déchiffré pendant toute la durée d'un job (mémoire du worker uniquement, jamais
  transmis aux scanners).

## Phase 3 — détail

### Livré et vérifié dans l'environnement de développement
* Découverte pour les cinq plateformes (`saytu-git`) — **89 tests exécutés, 89 réussis**, dont 27 nouveaux :
  * GitLab : compte personnel, groupes et sous-groupes (`X-Next-Page`), projets, branches ;
  * GitHub / GHES : compte, organisations (`Link`), dépôts propres privés ou publics, branches ;
  * Bitbucket Cloud : `/user/workspaces` puis `/repositories/{workspace}` (les points d'API
    inter-workspaces ont été supprimés par Atlassian, CHANGE-2770), access tokens par nom ;
  * Bitbucket Data Center : projets, dépôts, branches (`start`/`nextPageStart`) ;
  * dépôts locaux : lecture directe de `HEAD`, `refs/heads` et `packed-refs`, sans git ;
  * ajout par nom (organisation publique, groupe, workspace, projet) ;
  * parcours de toutes les pages avec plafond, détection de boucle et résultats partiels conservés.
* Correction : le test de connexion Bitbucket Cloud n'utilise plus `/repositories?role=member` (supprimé).
* Règles de nom de branche (`BranchNames`, 3 tests) et contrainte SQL équivalente (18 contrôles).
* Migration V3 sur PostgreSQL 16 : 39 contrôles de contraintes réussis au total.
* Frontend : arborescence des organisations, filtres, listes de branches, messages de synchronisation
  — **20 specs exécutées dans Node, 20 réussies**.

### Livré, écrit pour compiler, **non exécuté ici**
* Spring : `DiscoveryService` (synchronisation hors transaction, fusion, marquage « retiré »),
  `SelectionService` (sélection, modes de branches, branches personnalisées et distantes, périmètre),
  `ScannerConfigService`, contrôleurs ; tests `DiscoveryServiceTest`, `ScanTargetRulesTest`,
  `DiscoveryControllerSecurityTest` (exécutables par `mvn test`) et `DiscoveryApiIT` (Docker).
* Angular : pages « Organisations & dépôts » et « Scanners & branches », sélecteur de branches, specs.

### Limites connues de la phase 3
* Synchronisation déclenchée à la main ; la resynchronisation automatique avant chaque scan
  (nouveaux dépôts des organisations « tous les dépôts ») arrive avec le moteur d'audit (phase 4).
* Une synchronisation à la fois par connexion, contrôlée en mémoire : suffisant avec une seule
  instance de l'API.

## Phase 2 — détail

### Livré et vérifié dans l'environnement de développement
* `TokenCipher` (AES-256-GCM, données associées, rotation) — 9 tests.
* Module `saytu-git` (JDK seul) — **62 tests exécutés, 62 réussis**, contre un vrai serveur HTTP local :
  * test de connexion GitLab (identité, version, scopes via `personal_access_tokens/self`, expiration,
    droits d'écriture superflus), GitHub / GHES (scopes classiques, tokens fine-grained, expiration,
    limite de débit), Bitbucket Cloud (API token Basic e-mail, access token Bearer), Bitbucket Data
    Center (Bearer, version, utilisateur), dépôts locaux (racine imposée, liens symboliques) ;
  * politique anti-SSRF, redirections non suivies, corps plafonné, erreurs typées sans token ;
  * normalisation des URL et ressaisie obligatoire du token en cas de changement d'hôte.
* Migration V2 appliquée sur PostgreSQL 16 : 21 contrôles de contraintes réussis.
* Frontend : cœur OIDC (PKCE, état, nonce, échange, rafraîchissement, validation de l'ID token,
  déconnexion) et filtre des URL d'API — **14 specs exécutées dans Node, 14 réussies**, typage strict.

### Livré, écrit pour compiler, **non exécuté** (registres Maven/npm et Docker inaccessibles)
* Spring : `TokenVault`, `GitConnectionService`, `GitConnectionController`, `AuditService`, entités ;
  tests `GitConnectionServiceTest`, `GitConnectionControllerSecurityTest`, `TokenVaultTest`,
  `GitConnectionApiIT` (Testcontainers), règles ArchUnit.
* Angular : `AuthService`, intercepteur, garde, page de connexion, page Connexions Git (liste, test,
  création, modification, suppression), specs Karma correspondantes.

### Validé en conditions réelles (4 novembre 2026, poste Windows sans Docker)
* `mvn package` : compilation de tous les modules et tests unitaires ; démarrage Spring Boot 3.5.7,
  migrations V1 + V2 appliquées, validation Hibernate du schéma réussie (PostgreSQL 13.16).
* Connexion via Keycloak (code + PKCE), affichage de l'utilisateur et des rôles.
* Connexion gitlab.com testée avec un vrai token : identité, version, scopes `read_api` +
  `read_repository`, expiration ; token stocké chiffré.
* Correctif issu de ce test : entité `SourceRepositoryEntity` rendue proxyable (HHH000305).
* Constat : derrière un proxy d'inspection HTTPS, l'autorité du proxy doit être ajoutée
  (`SAYTU_GIT_CA_BUNDLE`) ; message d'erreur et guide complétés.

### Limites connues de la phase 2
* La découverte des organisations, dépôts et branches (phase 3) n'existe pas encore : les méthodes
  correspondantes des connecteurs lèvent `UnsupportedOperationException`.
* Gestion des utilisateurs dans l'interface : phase 7 (en attendant, console Keycloak).
* Pas de déconnexion par iframe de session (voir ADR-0006).

## Phase 1 — détail

### Livré et vérifié
* `saytu-core` : modèle de domaine, ports `GitProvider` / `ScannerAdapter` / `RemediationProvider`,
  empreinte stable, dédoublonnage multi-scanners, expurgation des secrets, invariants de sécurité
  des commandes — **45 tests unitaires exécutés, 45 réussis** (voir « Vérification »).
* Schéma Flyway V1 (20 tables) appliqué sur PostgreSQL 16 réel + 18 contrôles de contraintes
  (`scripts/verify-schema.sh`).
* Script d'initialisation PostgreSQL : base Keycloak isolée de la base applicative (vérifié).
* `docker-compose.yml` validé (`docker compose config`), génération des secrets vérifiée.
* Realm Keycloak (JSON valide) : rôles composites, client PKCE, mapper d'audience, admin initial
  avec mot de passe temporaire + TOTP.

### Livré, écrit pour compiler, **non exécuté dans l'environnement de développement**
(Maven Central, npm et Docker Hub y étaient inaccessibles)
* `saytu-app` : configuration Spring Security (resource server JWT, deny-by-default, CORS, en-têtes),
  OpenAPI, entités JPA connexions/namespaces/dépôts/branches/scanners, endpoint
  `GET /api/v1/system/info`, gestion d'erreurs RFC 9457. Les sources passent l'analyse syntaxique
  `javac` ; la compilation complète et les tests (`KeycloakRealmRoleConverterTest`,
  `SystemInfoControllerSecurityTest`, `ArchitectureTest`, `FlywaySchemaIT`) sont à lancer avec
  `mvn verify`.
* Frontend Angular 20 : coquille responsive, routes des pages, configuration runtime ; sources
  TypeScript valides syntaxiquement ; `npm test` / `ng build` à lancer.
* Dockerfiles multi-stage et configuration nginx (CSP, proxy `/api`).

### Non commencé (phases suivantes)
Page de connexion et garde d'authentification Angular, coffre de tokens, adaptateurs Git,
worker et scanners, scoring, dashboard, rapports, planification, alertes, IA, guides
d'exploitation et procédure hors ligne.
