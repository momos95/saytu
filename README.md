# AfriCodeShield

Plateforme **on-premise** et open source d'audit automatisé de la sécurité et de la qualité du
code, multi-organisations et multi-dépôts (GitLab, GitHub, Bitbucket, dépôts locaux).
Aucun abonnement, aucun service SaaS : le code analysé ne quitte jamais votre infrastructure.

> **État : phase 1 / 8** — architecture, modèle de données, structure du monorepo et socle
> Docker Compose. Aucun scan n'est encore exécutable. Détail : [docs/roadmap.md](docs/roadmap.md).

## Documentation

| Document | Contenu |
|---|---|
| [docs/architecture.md](docs/architecture.md) | vue de déploiement, modules, sécurité, flux, scoring, réseau |
| [docs/data-model.md](docs/data-model.md) | schéma PostgreSQL et règles de cycle de vie |
| [docs/adr/](docs/adr) | décisions d'architecture |
| [docs/licenses.md](docs/licenses.md) | licences des composants et des règles |
| [docs/roadmap.md](docs/roadmap.md) | phases et état d'avancement |

## Prérequis

* Linux x86_64, Docker Engine ≥ 24 avec Docker Compose v2, 4 vCPU / 8 Go RAM conseillés
* Pour développer : JDK 21, Maven 3.9, Node.js 22, PostgreSQL 16 (binaires) pour
  `scripts/verify-schema.sh`

## Démarrage (phase 1)

```bash
scripts/generate-secrets.sh          # crée .env (mode 600) avec des secrets aléatoires
docker compose up -d --build
docker compose ps                    # postgres, keycloak, api, web doivent être "healthy"
```

* Interface : <http://localhost:8080> (coquille de navigation ; les pages indiquent leur phase de livraison)
* Keycloak : <http://localhost:8180> — realm `africodeshield`, utilisateur `admin`, mot de passe
  temporaire dans `.env` (`ACS_INITIAL_ADMIN_PASSWORD`) ; changement et TOTP exigés à la première
  connexion.
* Santé de l'API : `docker compose exec web wget -qO- http://api:8080/actuator/health`

En production, placez `web` et `keycloak` derrière un reverse proxy TLS et renseignez
`ACS_PUBLIC_URL` / `ACS_KEYCLOAK_PUBLIC_URL` en `https://`.

LLM local optionnel (phase 7) : `docker compose --profile ai up -d`.

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
PostgreSQL, puis `mvn -f backend/pom.xml -pl acs-app spring-boot:run` avec les variables `ACS_DB_*`.

## Structure

```
backend/acs-core   domaine et ports, sans framework (empreintes, dédoublonnage, expurgation)
backend/acs-app    application Spring Boot (API ; worker en phase 4)
frontend/          Angular 20
infra/             realm Keycloak, initialisation PostgreSQL
scripts/           secrets, vérification du schéma
docs/              architecture, ADR, licences
```

## Licence

Apache-2.0 (voir [LICENSE](LICENSE)). Licences des composants : [docs/licenses.md](docs/licenses.md).
