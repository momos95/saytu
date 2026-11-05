# Scores, couverture et fiabilité (formule `v1`)

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

## 3. Score de sécurité (absolu)

Findings **OPEN** de type SECURITY, SECRET et DEPENDENCY de la branche :

```
points   = Σ poids(sévérité)          CRITICAL 25 · HIGH 10 · MEDIUM 3 · LOW 1 · INFO 0
sécurité = 100 × e^(−points / 50)     plafonné à 59 tant qu'un CRITICAL est ouvert
```

Exemples : 1 HIGH → 82 ; 1 CRITICAL → 59 (plafond) ; 5 MEDIUM → 74 ; 3 HIGH + 10 MEDIUM → 30.
Le score est absolu : une vulnérabilité critique compte autant dans un petit dépôt que dans un gros.

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
    "version": "v1-site", "securityWeights": {"CRITICAL": 30, "HIGH": 10, "MEDIUM": 3, "LOW": 1, "INFO": 0},
    "securityScale": 50, "criticalCap": 59, "qualityWeights": {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 0.5, "INFO": 0.1},
    "qualityScale": 50, "bytesPerLine": 35, "securityShare": 0.6, "minCoverage": 40 }'
```

Champs absents : valeur par défaut. Valeurs refusées : poids négatifs, échelles ≤ 0, part,
plafond ou couverture hors de [0, 1] / [0, 100]. Changer `version` à chaque modification permet de
distinguer les historiques.

## 8. Limites

* La taille en lignes est estimée à partir des octets (35 octets / ligne).
* Les règles des outils n'ont pas toutes la même sévérité « naturelle » : la correspondance
  sévérité-outil → sévérité SAYTU est dans chaque adaptateur (`saytu-scan/.../adapter`).
* Pas de score de tendance dans cette version : l'historique des `score_snapshot` est conservé et
  sera affiché par le tableau de bord (phase 6).
