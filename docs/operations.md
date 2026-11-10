# Exploitation (phases 4-8)

Sommaire : [contrôle après installation](#contrôle-après-installation-ou-mise-à-jour) ·
[sauvegarde](#sauvegarde-et-restauration) · [mise à jour](#mise-à-jour-de-saytu) ·
[installation isolée](#installation-isolée-sans-internet) · [SBOM et licences](#sbom-et-licences) ·
[audits](#services-en-jeu).

Les scripts sont des scripts bash : sous Linux, ou sous Windows dans Git Bash (fourni avec Git for Windows et
cmder) ou WSL. `offline-bundle.sh` et `sbom.sh` s'utilisent sur une machine Linux ou WSL.

## Contrôle après installation ou mise à jour

```bash
scripts/smoke-test.sh
```
Lecture seule : santé des cinq services, `keycloak-config`, page d'accueil et en-têtes de sécurité (CSP,
`nosniff`), refus des appels anonymes à l'API (401), actuator non exposé, découverte OIDC de Keycloak avec le
bon émetteur (détecte un autre programme sur le port de Keycloak), isolation des scanners, présence et âge de
la base Trivy. Code de sortie 0 si tout passe ; les « WARN » n'échouent pas.

## Sauvegarde et restauration

```bash
scripts/backup.sh --with-env            # -> backups/saytu-AAAAMMJJ-HHMMSS/
scripts/restore.sh backups/saytu-20261110-220000 --yes
```
* Contenu : base applicative (`saytu.dump` : connexions, jetons chiffrés, résultats, scores, réglages,
  journal d'audit), base Keycloak (`keycloak.dump` : utilisateurs, rôles, TOTP), `manifest.txt` (date,
  version du schéma, SHA-256), et avec `--with-env` une copie de `.env`.
* **`SAYTU_MASTER_KEY` est indispensable** pour relire les jetons Git d'une sauvegarde : conservez `.env` (ou
  au moins la clé) à part, hors du serveur. Sans elle, les connexions doivent être ressaisies.
* Non sauvegardés, car recréés : base Trivy, répertoires de travail, secret du client `saytu-admin-api`.
* La restauration arrête `web`, `worker`, `api` et `keycloak`, vérifie les sommes de contrôle, **remplace** les
  deux bases puis redémarre tout ; l'API applique ensuite les migrations plus récentes. Vérifiée sur
  PostgreSQL 16 (sauvegarde, effacement, restauration, propriétaire des tables Keycloak).
* Planification : par exemple une tâche cron quotidienne `0 1 * * * cd /opt/saytu && scripts/backup.sh`, avec
  rotation des anciens répertoires.

## Mise à jour de SAYTU

1. `scripts/backup.sh --with-env`
2. `git pull` (ou `git checkout <tag>`), puis renseigner `SAYTU_VERSION=<version>` dans `.env` pour étiqueter
   les images (`saytu/api:<version>`…) et pouvoir revenir à la précédente.
3. `docker compose up -d --build`
4. `scripts/smoke-test.sh`

Les migrations Flyway s'appliquent au démarrage de l'API ; les scores sont recalculés par le worker si la
formule a changé. Retour arrière : `SAYTU_VERSION` précédente et `scripts/restore.sh` de la sauvegarde de
l'étape 1 (une base migrée n'est pas lisible par une version plus ancienne).

Installation isolée : construire les images sur une machine connectée, puis
`scripts/offline-bundle.sh --images` et `scripts/offline-import.sh` (ci-dessous).

## SBOM et licences

```bash
scripts/sbom.sh            # images SAYTU ; --all : aussi postgres, keycloak, ollama ; --strict : échec si licence interdite
```
Résultat dans `sbom/<version>/` : un SBOM CycloneDX par image et pour les paquets npm de l'interface, et
l'inventaire des licences classées par Trivy. Produit avec le Trivy de l'image `worker`, **sans réseau**. Voir
[licenses.md](licenses.md) pour la lecture attendue.

## Services en jeu

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

Sur le serveur isolé, `.env` : `SAYTU_TRIVY_DB_AUTO_UPDATE=false`.

1. Sur une machine **connectée** (Linux ou WSL) disposant du dépôt SAYTU et de l'image `worker` construite
   (`docker compose build worker`), à la même version que le serveur :
   ```bash
   scripts/offline-bundle.sh                   # base Trivy + packs de règles de data/rules
   scripts/offline-bundle.sh --images          # + toutes les images (première installation, mise à jour)
   ```
   La base est téléchargée par le Trivy de l'image `worker` (même version que celle qui l'utilisera). Le
   paquet `saytu-offline-AAAAMMJJ.tar` contient un manifeste avec la SHA-256 de chaque fichier ; un fichier
   `.sha256` l'accompagne. Seules des données publiques sont téléchargées.
2. Transférer les deux fichiers, puis sur le serveur :
   ```bash
   scripts/offline-import.sh saytu-offline-20261110.tar
   ```
   Le script vérifie toutes les sommes de contrôle (rien n'est importé si un fichier est altéré), charge les
   images, remplace la base Trivy **atomiquement** (extraction à côté puis échange : un audit en cours ne voit
   jamais une base à moitié écrite), la rend lisible par les comptes de scanners et affiche sa date
   (`UpdatedAt`), puis installe les packs de règles.
3. Répéter au moins chaque semaine : la date de la base est enregistrée avec chaque exécution de Trivy et
   affichée dans la page Audits ; `scripts/smoke-test.sh` avertit au-delà de 7 jours.

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
