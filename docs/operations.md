# Exploitation du moteur d'audit (phases 4-5)

## Services en jeu

| Service | Rôle pour un audit |
|---|---|
| `api` | enregistre la demande (`POST /api/v1/scans`) ; ne clone rien, n'exécute aucun scanner |
| `worker` | transforme la demande en jobs (un par dépôt × branche), les exécute, enregistre les résultats, met à jour la base Trivy |
| `postgres` | file d'attente (`scan_job`), résultats (`scanner_execution`, `finding`, `finding_occurrence`) |

Le worker n'expose aucun port. Il sort sur le réseau pour deux raisons seulement : cloner les dépôts
(vers vos plateformes Git) et télécharger la base de vulnérabilités Trivy (avis publics). Aucun code,
token ou résultat n'est envoyé à un service d'analyse externe.

## Suivre un audit

* Interface : page **Audits** (statut par branche et par scanner, durée, version des outils et des
  règles, raison de tout échec).
* Journaux : `docker compose logs -f worker` (une ligne par job : début, fin, nombre de résultats).

Statuts d'un scanner pour une branche :

| Statut | Sens | Effet sur les vulnérabilités déjà connues |
|---|---|---|
| `SUCCEEDED` | l'outil a tout analysé | celles qu'il ne retrouve plus passent à `RESOLVED` |
| `FAILED` | erreur, mémoire dépassée, ou analyse partielle (ex. Trivy sans base) | aucune n'est considérée corrigée |
| `TIMED_OUT` | délai dépassé, processus tués | aucune n'est considérée corrigée |
| `SKIPPED` | désactivé, ou non intégré (Dependency-Check) | aucune n'est considérée corrigée |
| `NOT_APPLICABLE` | rien à analyser : langage absent (« aucun fichier PHP ») | — |

Les statuts `ACCEPTED_RISK` et `FALSE_POSITIVE` posés par un humain ne sont jamais modifiés
automatiquement.

## Base de vulnérabilités Trivy

Sans cette base, Trivy ne vérifie **pas** les dépendances : l'exécution est marquée `FAILED`
(« dependencies were NOT checked ») et seuls les fichiers de configuration sont analysés.

### Installation connectée (par défaut)

`SAYTU_TRIVY_DB_AUTO_UPDATE=true` : au démarrage puis toutes les 12 h (`SAYTU_TRIVY_DB_UPDATE_INTERVAL`),
quand aucun job ne tourne, le worker télécharge la base (≈ 70 Mo compressés) dans le volume `trivy-db`.
Vérifier :
```bash
docker compose logs worker | grep -i "trivy vulnerability database"
docker compose exec worker ls -l /var/lib/saytu/trivy/db
```
Derrière un proxy : `SAYTU_HTTPS_PROXY=http://proxy:3128` dans `.env`. Miroir interne (registre OCI) :
`SAYTU_TRIVY_DB_REPOSITORY=registry.corp/aquasecurity/trivy-db:2`.

### Installation isolée (sans Internet)

1. Sur une machine connectée, avec la même version de Trivy (0.76.1) :
   ```bash
   trivy image --download-db-only --cache-dir ./trivy-cache
   tar -C ./trivy-cache -czf trivy-db.tgz db
   ```
2. Transférer `trivy-db.tgz`, puis sur le serveur SAYTU (`.env` : `SAYTU_TRIVY_DB_AUTO_UPDATE=false`) :
   ```bash
   docker compose cp trivy-db.tgz worker:/tmp/trivy-db.tgz
   docker compose exec worker tar -C /var/lib/saytu/trivy -xzf /tmp/trivy-db.tgz
   docker compose exec worker cat /var/lib/saytu/trivy/db/metadata.json
   ```
3. Répéter au moins chaque semaine : la date de la base (`UpdatedAt`) est enregistrée avec chaque
   exécution de Trivy et affichée dans la page Audits.

La base Java (`trivy-java-db`, analyse des `.jar` présents dans les dépôts) n'est pas téléchargée :
les archives `.jar/.war/.ear` sont ignorées ; les `pom.xml`, `gradle.lockfile` et lockfiles des autres
écosystèmes sont analysés.

## Règles Opengrep

Embarquées : pack SAYTU (24 règles, Apache-2.0) et pack Aikido (MIT). Packs complémentaires, à
installer par chaque site dans `data/rules/opengrep/` (monté en lecture seule dans le worker, pris
en compte au prochain audit, sans redémarrage) :
```bash
scripts/fetch-opengrep-rules.sh trailofbits                                  # AGPL-3.0
scripts/fetch-opengrep-rules.sh semgrep --accept-semgrep-rules-license       # usage interne uniquement
scripts/fetch-opengrep-rules.sh --remove semgrep
```
Site isolé : lancer le script sur une machine connectée et copier le dossier `data/rules/opengrep/<pack>`.
Les conditions de licence de chaque pack sont dans `scanners/opengrep/rules/README.md`.

Ce qui vient du dépôt analysé ne peut pas désactiver l'audit : `.semgrepignore`, commentaires
`nosemgrep`, `.gitleaks.toml`, `.gitleaksignore` et `gitleaks:allow` sont ignorés.

## Langages et outils de qualité

Après le clone, le worker détecte les langages de la branche (étiquettes affichées dans les pages
Audits et Organisations & dépôts) et ne lance que les outils utiles :

| Langage | Outil | Réglables (page « Scanners & branches ») |
|---|---|---|
| Java | Checkstyle, PMD | parallélisme PMD |
| TypeScript / JavaScript | ESLint | — |
| PHP | PHP_CodeSniffer | norme (PSR12 par défaut) |
| C / C++ | Cppcheck | parallélisme |
| SQL | SQLFluff | dialecte (`ansi` par défaut : choisir `postgres`, `mysql`, `tsql`… selon vos bases), parallélisme |
| C# | aucun | la qualité C# est comptée « non couverte » |

Les options sont des listes blanches validées par l'API ; elles sont passées aux outils comme
arguments séparés, jamais par un shell. Aucun outil ne lit la configuration du dépôt analysé
(`.eslintrc`, `phpcs.xml`, `.sqlfluff`, `checkstyle.xml`…) ni n'exécute son build.

## Scores

Calculés à la fin de chaque job réussi : sécurité, qualité et global sur 100, avec couverture et
fiabilité. Formule, exemples et modification : [scoring.md](scoring.md). Un score « — » signifie
que trop peu d'analyses ont réussi pour en donner un.

## Réglages

| Variable (`.env`) | Défaut | Effet |
|---|---|---|
| `SAYTU_WORKER_MAX_PARALLEL_JOBS` | 2 | branches analysées en même temps |
| `SAYTU_CHECKOUT_MAX_MB` | 2048 | taille maximale d'une branche clonée (au-delà : job en échec `TOO_LARGE`) |
| page « Scanners & branches » | — | délai, temps CPU et mémoire de chaque scanner ; activation ; options des outils |
| `SAYTU_PUBLIC_URL` | http://localhost:8080 | adresse de SAYTU dans les liens des alertes |
| `SAYTU_KEYCLOAK_ADMIN_CLIENT_SECRET` | vide | active la page Utilisateurs (écrit par `scripts/keycloak-admin-client`) |
| onglets « Planification », « Alertes », « IA locale » | — | voir [automation.md](automation.md) |

Le conteneur `worker` est limité à 4 CPU et 6 Go : (nombre de jobs parallèles) × (mémoire du plus
gros scanner) doit rester en dessous.

## Pannes et reprises

* Worker arrêté ou redémarré pendant un job : le job reste `RUNNING` jusqu'à l'expiration de son bail
  (5 min), puis repart en file (2 tentatives au total). Au redémarrage, le worker remet
  immédiatement en file les jobs qu'il détenait.
* Un même dépôt × branche n'est jamais en file deux fois : un second audit le signale dans ses notes
  de planification (« already queued or running »).
* Annulation (page Audits) : les jobs en attente sont annulés ; un job en cours s'arrête avant son
  scanner suivant.

| Erreur d'un job | Cause probable |
|---|---|
| `AUTHENTICATION_FAILED` | token expiré, ou sans droit de lecture du code (`read_repository` GitLab, `Contents: read` GitHub) |
| `TLS_ERROR` | certificat interne ou proxy d'inspection : le mettre dans `data/ca/`, puis `docker compose up -d --build worker` |
| `BRANCH_NOT_FOUND` | branche supprimée depuis la configuration |
| `TOO_LARGE` | augmenter `SAYTU_CHECKOUT_MAX_MB` |
| `BLOCKED_BY_POLICY` | URL de clone en `http://` (voir `SAYTU_GIT_ALLOW_PLAIN_HTTP`) ou redirection du serveur |
