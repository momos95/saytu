# Feuille de route et état d'avancement

| Phase | Contenu | État |
|---|---|---|
| 1 | Architecture, modèle de données, monorepo, Docker Compose | ✅ livrée (voir détail ci-dessous) |
| 2 | Authentification Keycloak dans l'UI, coffre de tokens AES-GCM, CRUD + test des connexions Git | ✅ livrée (voir détail) |
| 3 | Découverte organisations / dépôts / branches, sélection, configuration des branches | ✅ livrée (voir détail) |
| 4 | Worker, file d'exécution, sandbox, clone sécurisé, Opengrep, Trivy, Gitleaks | à faire |
| 5 | PMD, Checkstyle, normalisation complète, scoring et couverture | à faire |
| 6 | Dashboard Angular, détail dépôt, liste/détail des vulnérabilités, rapports HTML/PDF/JSON/SARIF | à faire |
| 7 | Planification cron, historique, comparaison de scans, webhooks, recommandations, Ollama | à faire |
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
