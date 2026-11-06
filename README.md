# SAYTU

Plateforme **on-premise** et open source d'audit automatisé de la sécurité et de la qualité du
code, multi-organisations et multi-dépôts (GitLab, GitHub, Bitbucket, dépôts locaux).
Aucun abonnement, aucun service SaaS : le code analysé ne quitte jamais votre infrastructure.

> **État : phase 6 / 8** — connexion via Keycloak, connexions Git chiffrées, découverte des
> organisations, dépôts et branches, **audits réels** dans un worker isolé (Opengrep, Trivy, Gitleaks et
> l'outil de qualité de chaque langage détecté), scores avec couverture, **tableau de bord**, liste
> filtrable des vulnérabilités avec triage, détail d'un dépôt et rapports **PDF, HTML, JSON, SARIF**.
> Planification, alertes et IA locale : phase 7. Détail : [docs/roadmap.md](docs/roadmap.md).

## Documentation

| Document | Contenu |
|---|---|
| [docs/architecture.md](docs/architecture.md) | vue de déploiement, modules, sécurité, flux, scoring, réseau |
| [docs/data-model.md](docs/data-model.md) | schéma PostgreSQL et règles de cycle de vie |
| [docs/adr/](docs/adr) | décisions d'architecture |
| [docs/licenses.md](docs/licenses.md) | licences des composants et des règles |
| [docs/git-connections.md](docs/git-connections.md) | créer les tokens GitLab, GitHub, Bitbucket ; lire un résultat de test |
| [docs/security.md](docs/security.md) | mesures de sécurité et risques résiduels |
| [docs/reports.md](docs/reports.md) | rapports PDF / HTML / JSON / SARIF, tableau de bord, triage |
| [docs/scoring.md](docs/scoring.md) | formule des scores, couverture, fiabilité, outils par langage |
| [docs/operations.md](docs/operations.md) | exploitation des audits : base Trivy (en ligne / hors ligne), packs de règles, reprises |
| [docs/install-windows.md](docs/install-windows.md) | installation sur Windows avec WSL 2 et Docker Engine |
| [docs/roadmap.md](docs/roadmap.md) | phases et état d'avancement |

## Prérequis

* Linux x86_64, Docker Engine ≥ 24 avec Docker Compose v2, 4 vCPU / 8 Go RAM conseillés
* Pour développer : JDK 21, Maven 3.9, Node.js 22, PostgreSQL 16 (binaires) pour
  `scripts/verify-schema.sh`

## Démarrage

Poste Windows : suivre [docs/install-windows.md](docs/install-windows.md) (WSL 2 + Docker Engine,
proxy d'inspection HTTPS).


```bash
scripts/generate-secrets.sh          # crée .env (mode 600) avec des secrets aléatoires
docker compose up -d --build
docker compose ps                    # postgres, keycloak, api, worker, web doivent être "healthy"
```

* Interface : <http://localhost:8080> — connexion via Keycloak, puis **Connexions Git** pour enregistrer
  et tester vos forges (voir [docs/git-connections.md](docs/git-connections.md)). Les autres pages
  indiquent leur phase de livraison.
* Keycloak : <http://localhost:8180> — realm `saytu`, utilisateur `admin`, mot de passe
  temporaire dans `.env` (`SAYTU_INITIAL_ADMIN_PASSWORD`) ; changement et TOTP exigés à la première
  connexion.
* Santé de l'API : `docker compose exec web wget -qO- http://api:8080/actuator/health`

En production, placez `web` et `keycloak` derrière un reverse proxy TLS et renseignez
`SAYTU_PUBLIC_URL` / `SAYTU_KEYCLOAK_PUBLIC_URL` en `https://`.

LLM local optionnel (phase 7) : `docker compose --profile ai up -d`.

## Configuration utile

| Variable | Rôle |
|---|---|
| `SAYTU_MASTER_KEY` | clé de chiffrement des tokens (générée par `scripts/generate-secrets.sh`) ; à sauvegarder à part |
| `SAYTU_PREVIOUS_MASTER_KEYS` | anciennes clés pendant une rotation |
| `SAYTU_GIT_CA_BUNDLE_IN_CONTAINER` | certificat PEM d'une autorité interne, déposé dans `./data/ca/` |
| `SAYTU_LOCAL_REPOS_HOST_DIR` | répertoire de dépôts locaux, monté en lecture seule sur `/srv/git` |
| `SAYTU_JAVA_PROXY_OPTS` | proxy sortant vers github.com, gitlab.com… |
| `SAYTU_GIT_ALLOW_PLAIN_HTTP` | autoriser les forges en `http://` (réseau isolé uniquement) |

## Développement

```bash
# Backend : tests unitaires + intégration (Testcontainers, nécessite Docker)
mvn -f backend/pom.xml verify

# Schéma : applique les migrations sur un PostgreSQL jetable et vérifie les contraintes
scripts/verify-schema.sh

# Frontend
cd frontend && npm install && npm test && npm run build
```

Lancer l'API hors conteneur : démarrer `postgres` et `keycloak` via Compose en publiant le port
PostgreSQL, puis `mvn -f backend/pom.xml -pl saytu-app spring-boot:run` avec les variables `SAYTU_DB_*`.

## Structure

```
backend/saytu-core   domaine et ports, sans framework (empreintes, dédoublonnage, expurgation, chiffrement)
backend/saytu-git    connecteurs GitLab / GitHub / Bitbucket / local, JDK seul
backend/saytu-scan   moteur d'analyse, JDK seul : sandbox, clone sécurisé, adaptateurs Opengrep / Trivy / Gitleaks
backend/saytu-app    application Spring Boot (API, et worker avec SAYTU_WORKER_ENABLED=true)
scanners/          règles Opengrep (SAYTU, Aikido), configurations Gitleaks, Checkstyle, ESLint
frontend/          Angular 20
infra/             realm Keycloak
scripts/           secrets, vérification du schéma et du SQL, import de packs de règles
docs/              architecture, ADR, licences
```

## Licence

Apache-2.0 (voir [LICENSE](LICENSE)). Licences des composants : [docs/licenses.md](docs/licenses.md).
