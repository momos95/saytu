# Scores, couverture et fiabilité (formule `v2`)

Implémentation : `saytu-core/.../scoring/ScoreCalculator.java` (testée par `ScoreCalculatorTest`).
Paramètres : `app_setting['scoring.formula']`, lisibles par `GET /api/v1/scores/formula` et
modifiables par un ADMIN (`PUT /api/v1/scores/formula`, journalisé). Chaque score enregistré
(`score_snapshot`) garde la version de la formule et le détail du calcul (`details`).

Principe directeur : **un scanner qui n'a pas tourné ne vaut jamais « aucun problème »**. Il fait
baisser la couverture ; sous un seuil, le score n'est pas calculé (affiché « — »), jamais 100.

## 1. Langages détectés

Après le clone, le worker compte les fichiers et octets de chaque langage (extension et nom de
fichier), en ignorant `node_modules`, `vendor`, `target`, `build`, `dist`, `.git`… et les fichiers
générés ou minifiés (`*.min.js`, `*.d.ts`, `*.generated.*`…). Un langage reçoit une étiquette dès qu'il
représente ≥ 1 % des octets de code ou ≥ 5 fichiers. Les étiquettes sont enregistrées avec le job
(`scan_job.languages`) et sur le dépôt (`source_repository.languages`).

## 2. Outil de qualité selon le langage

| Langage | Outil(s) | Réglages SAYTU |
|---|---|---|
| Java | Checkstyle 14.3.0 + PMD 7.28.0 | `scanners/checkstyle/saytu-checks.xml` ; jeu `rulesets/java/quickstart.xml` |
| TypeScript / JavaScript | ESLint 9.39.5 (+ typescript-eslint, eslint-plugin-security) | `scanners/eslint/eslint.config.mjs`, sans les configurations du dépôt |
| PHP | PHP_CodeSniffer 4.0.2 | norme PSR12 (réglable) |
| C / C++ | Cppcheck 2.13.0 | `--enable=warning,style,performance,portability`, sans compilation ni fichier de projet |
| SQL | SQLFluff 4.4.0 | dialecte `ansi` (réglable) |
| C# | **aucun outil libre intégré** | qualité « non couverte » : abaisse la couverture qualité |
| autres (Python, Go, Kotlin…) | aucun dans cette version | idem |

Un outil dont le langage est absent est enregistré `NOT_APPLICABLE` (« aucun fichier PHP ») et
n'intervient pas dans la couverture. Les annotations du dépôt qui désactiveraient l'analyse
(`// eslint-disable`, `phpcs:ignore`, `-- noqa`, `@SuppressWarnings("PMD")`, configurations locales)
sont ignorées ou signalées.

## 3. Score de sécurité (formule `v2`, depuis le 6 novembre 2026)

Constat sur de vrais dépôts avec la v1 (`100 × e^(−points/50)`) : dès une vingtaine de vulnérabilités
élevées, le score tombait à 0 pour presque tous les dépôts et ne permettait plus de les classer ; les
réglages Kubernetes pesaient autant qu'une injection SQL et une dépendance à 10 CVE comptait 10 fois.

Findings **OPEN** de type SECURITY, SECRET et DEPENDENCY de la branche, classés par **ce qu'il faut faire
pour les corriger** (`SecurityIssue`) :

| Catégorie | Reconnue par | Facteur |
|---|---|---|
| Code | SAST (Opengrep) sur du code applicatif | × 1 |
| Secret | type SECRET, ou CWE-798 / 259 / 321 / 522 / 312 ; **jamais sous « Élevée »** | × 1 |
| Dépendance | type DEPENDENCY | × 1 si une version corrigée existe, × 0,5 sinon |
| Configuration | Trivy (Kubernetes, Dockerfile, Terraform…) ou fichier de déploiement (`Dockerfile`, `*.tf`, `docker-compose.yml`, YAML sous `k8s/`, `deploy/`, `manifests/`, `helm/`…) | × 0,5 |

```
poids(finding)   = poids(sévérité) × facteur        CRITICAL 25 · HIGH 10 · MEDIUM 3 · LOW 1 · INFO 0
groupe           = même paquet et version | même règle (secret, configuration) | même scanner et règle (code)
points(groupe)   = Σ poids_n / n   (poids triés du plus fort au plus faible : 1er en entier, 2e moitié, 3e tiers…)
sécurité         = 100 / (1 + Σ points / 100)       plafonnée à 59 tant qu'un CRITICAL est ouvert
```

Exemples : 1 élevée → 91 ; 100 points → 50 ; 250 points → 29 ; 1 000 points → 9 ; le score n'atteint
jamais 0. Une règle trouvée 30 fois coûte 10 × H(30) ≈ 40 points au lieu de 300 ; un paquet avec 10 CVE
élevées ≈ 29 points. Un microservice proche de `ht-ms` (≈ 170 résultats dont 8 paquets vulnérables, 72
réglages Kubernetes, 20 alertes SAST, 8 secrets) obtient entre 20 et 40 (test `ScoringV2Test`).

### Sévérité des remarques PMD

Le jeu de règles `quickstart` de PMD donne la priorité 1 à des règles de nommage et de style. La sévérité
SAYTU dépend donc aussi de la catégorie de la règle : *Error Prone*, *Multithreading* et *Security*
peuvent être « Élevée » (priorités 1-2) ; *Best Practices*, *Design*, *Performance* au plus « Moyenne » ;
*Code Style* et *Documentation* au plus « Faible ». La migration V7 a abaissé les remarques déjà
enregistrées et demandé un recalcul des scores au démarrage du worker.

### Sévérité des secrets

Un secret présent dans Git est exposé à toute personne pouvant cloner : **Élevée** au minimum,
**Critique** quand son format identifie l'émetteur (clé privée, AWS, GCP, Azure, GitHub, GitLab,
Bitbucket, Stripe, Slack, OpenAI, Anthropic, npm, PyPI, Vault… liste `GitleaksAdapter.CRITICAL_PREFIXES`).
La migration V6 a appliqué cette règle aux secrets déjà enregistrés.

### Recalcul

* Mise à jour vers la v2 : le worker recalcule au démarrage le score de chaque branche auditée **à partir
  des résultats enregistrés** (aucun clonage, aucune nouvelle analyse) dès que la formule enregistrée
  diffère de celle des derniers scores.
* Triage (risque accepté, faux positif, réouverture) : le score de la branche est recalculé immédiatement.
* Changement de formule par un ADMIN : toutes les branches sont recalculées.

### Plan d'action

Le détail d'un dépôt liste, pour sa branche la plus faible, les **8 corrections au plus fort gain** : une
action par groupe (mettre à jour un paquet vers la plus haute version corrigée citée par les avis,
révoquer un secret, corriger une règle de configuration ou de code), avec le score de sécurité avant et
après (même formule, même couverture). Retirer le seul groupe critique lève aussi le plafond de 59.

### Formule `v1` (historique)

`100 × e^(−points/50)`, mêmes poids, sans catégories ni regroupement (`ScoringFormula.V1`). Les scores
calculés avec elle gardent `formula_version = v1` dans l'historique.

## 4. Score de qualité (relatif à la taille)

Findings **OPEN** de type QUALITY (Checkstyle, PMD, ESLint, PHPCS, Cppcheck, SQLFluff et règles
qualité d'Opengrep) :

```
points  = Σ poids(sévérité)           CRITICAL 10 · HIGH 5 · MEDIUM 2 · LOW 0,5 · INFO 0,1
KLOC    = max(1, octets de code / 35 / 1000)
qualité = 100 × e^(−(points / KLOC) / 50)
```

## 5. Couverture et fiabilité

* **Sécurité** : Opengrep 40 % + Trivy 35 % + Gitleaks 25 %, pour ceux qui ont réussi (`SUCCEEDED`).
  Trivy sans base de vulnérabilités est `FAILED` : il ne compte pas.
* **Qualité** : part des octets de code écrits dans un langage dont au moins un outil a réussi.
  Exemple : 80 % Java analysé + 20 % C# ⇒ 80 %.
* **Couverture affichée** = 0,6 × sécurité + 0,4 × qualité (sécurité seule s'il n'y a pas de code).

| Couverture | Fiabilité |
|---|---|
| ≥ 90 % | élevée |
| ≥ 70 % | moyenne |
| ≥ 40 % (minimum de la formule) | faible |
| < 40 % | insuffisante : le score de la dimension n'est **pas calculé** |

Le seuil s'applique à chaque dimension : une branche dont seul Gitleaks a réussi (25 %) n'a pas de
score de sécurité.

## 6. Score global et agrégations

* **Global** = 0,6 × sécurité + 0,4 × qualité ; si une seule dimension a un score, c'est celui-là
  (la fiabilité affichée le signale).
* **Dépôt** = sa branche la plus faible ; couverture = la plus basse de ses branches.
* **Organisation** et **global** = moyennes des dépôts pondérées par leur taille de code, sur les
  dépôts qui ont un score ; le détail indique combien de dépôts en ont un.

Les scores sont recalculés à la fin de chaque job réussi (pas pour un job annulé ou en échec) et à
chaque changement de formule à partir du prochain audit.

## 7. Modifier la formule

```bash
curl -X PUT https://saytu.example/api/v1/scores/formula -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{
    "version": "v2-site", "securityWeights": {"CRITICAL": 30, "HIGH": 10, "MEDIUM": 3, "LOW": 1, "INFO": 0},
    "securityScale": 100, "criticalCap": 59, "qualityWeights": {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 0.5, "INFO": 0.1},
    "qualityScale": 50, "bytesPerLine": 35, "securityShare": 0.6, "minCoverage": 40,
    "securityCurve": "HYPERBOLIC", "categoryFactors": {"CODE": 1, "SECRET": 1, "DEPENDENCY": 1, "CONFIGURATION": 0.5},
    "noFixFactor": 0.5, "diminishingReturns": true }'
```

Champs absents : valeur par défaut. Valeurs refusées : poids négatifs, échelles ≤ 0, part,
plafond ou couverture hors de [0, 1] / [0, 100]. Changer `version` à chaque modification permet de
distinguer les historiques. Toutes les branches auditées sont recalculées immédiatement.

## 8. Limites

* La taille en lignes est estimée à partir des octets (35 octets / ligne).
* Les règles des outils n'ont pas toutes la même sévérité « naturelle » : la correspondance
  sévérité-outil → sévérité SAYTU est dans chaque adaptateur (`saytu-scan/.../adapter`).
* La catégorie « configuration » d'un résultat Opengrep repose sur le chemin du fichier (Dockerfile,
  manifestes) : un YAML de déploiement rangé ailleurs compte comme du code (facteur 1).
* Le gain affiché par le plan d'action suppose que la correction ne fait pas apparaître d'autre problème.
