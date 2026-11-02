# Feuille de route et état d'avancement

| Phase | Contenu | État |
|---|---|---|
| 1 | Architecture, modèle de données, monorepo, Docker Compose | ✅ livrée (voir détail ci-dessous) |
| 2 | Authentification Keycloak dans l'UI, coffre de tokens AES-GCM, CRUD + test des connexions Git | à faire |
| 3 | Découverte organisations / dépôts / branches, sélection, configuration des branches | à faire |
| 4 | Worker, file d'exécution, sandbox, clone sécurisé, Opengrep, Trivy, Gitleaks | à faire |
| 5 | PMD, Checkstyle, normalisation complète, scoring et couverture | à faire |
| 6 | Dashboard Angular, détail dépôt, liste/détail des vulnérabilités, rapports HTML/PDF/JSON/SARIF | à faire |
| 7 | Planification cron, historique, comparaison de scans, webhooks, recommandations, Ollama | à faire |
| 8 | Durcissement, tests de bout en bout, SBOM, guides d'exploitation et de mise à jour hors ligne | à faire |

## Phase 1 — détail

### Livré et vérifié
* `acs-core` : modèle de domaine, ports `GitProvider` / `ScannerAdapter` / `RemediationProvider`,
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
* `acs-app` : configuration Spring Security (resource server JWT, deny-by-default, CORS, en-têtes),
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
