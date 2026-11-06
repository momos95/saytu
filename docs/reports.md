# Rapports, tableau de bord et triage (phase 6)

## Rapports

`GET /api/v1/reports/findings?format=pdf|html|json|sarif` avec les mêmes filtres que la liste des
vulnérabilités (`repositoryId`, `branch`, `severity`, `type`, `status`, `scanner`, `q`, listes répétables).
Sans `status`, le rapport porte sur les vulnérabilités **ouvertes**. Boutons « Rapport » : tableau de
bord (tout), page Vulnérabilités (filtres en cours), détail d'un dépôt.

| Format | Contenu | Usage |
|---|---|---|
| PDF | synthèse, scores (avec couverture et fiabilité), analyses prises en compte (commit, version de chaque outil et de ses règles, outils en échec ou non applicables), dépendances concernées, vulnérabilités détaillées | diffusion, archivage, impression A4 |
| HTML | même contenu ; une seule page sans script ni ressource externe (CSP `default-src 'none'`) | lecture hors ligne, impression navigateur |
| JSON | format `saytu-report/1` : mêmes sections, champs stables, `null` conservés | intégration, outillage interne |
| SARIF | SARIF 2.1.0 (OASIS) : un *run* par scanner, règles, niveaux (`error` = critique / élevée, `warning` = moyenne, `note` = faible / info), emplacement relatif à la racine du dépôt (`%SRCROOT%`), empreinte stable `partialFingerprints["saytu/v1"]`, triage humain exporté comme *suppression* acceptée avec sa justification ; les vulnérabilités corrigées ne sont pas exportées | IDE (VS Code SARIF Viewer…), forges qui importent du SARIF |

* PDF et HTML détaillent au plus 2 000 vulnérabilités (les plus graves d'abord) ; JSON et SARIF jusqu'à
  20 000. Les compteurs de synthèse portent toujours sur la totalité, et le rapport indique quand il
  est tronqué.
* Pour importer du SARIF dans une forge, générer un rapport **par dépôt et par branche** (les chemins
  sont relatifs au dépôt).
* Les preuves sont celles stockées en base, déjà expurgées des secrets. Rien n'est recalculé, rien ne
  sort du serveur : le rapport est produit par l'API et téléchargé par le navigateur.
* Chaque génération est tracée : table `report` (format, filtres, SHA-256, taille, auteur) et
  journal d'audit (`REPORT_GENERATED`). Le fichier lui-même n'est pas conservé.
* PDF produit sans bibliothèque externe (`saytu-core/report/PdfDocument`) : polices standard PDF
  (Helvetica, Courier) en WinAnsi ; les caractères hors Latin-1 (idéogrammes, emoji) apparaissent
  comme « ? » dans le PDF — ils sont intacts dans les formats HTML, JSON et SARIF.

## Tableau de bord

`GET /api/v1/dashboard` : dernier score global (couverture, fiabilité), compteurs (vulnérabilités
ouvertes, nouvelles et corrigées sur 7 jours, triées à la main, dépôts audités, dernier audit),
répartition des vulnérabilités ouvertes par criticité × type, évolution des scores sur 90 jours
(dernier score de chaque jour ; un jour sans score possible apparaît comme un trou, jamais comme 0
ou 100), nouvelles / corrigées par semaine sur 12 semaines, 10 dépôts prioritaires, 5 derniers audits.

Dépôts prioritaires : d'abord le nombre de vulnérabilités **critiques ouvertes**, puis le score global le
plus bas (les dépôts sans score viennent après), puis le nombre d'élevées.

## Détail d'un dépôt

`GET /api/v1/repositories/{id}/overview` : informations de la plateforme, langages, score du dépôt
(branche la plus faible), chaque branche avec son score et ses vulnérabilités ouvertes par criticité,
évolution, 10 règles les plus fréquentes, 20 derniers jobs. Bouton « Auditer ce dépôt » (AUDITOR, ADMIN).

## Corrections proposées

Le détail d'une vulnérabilité affiche, en plus de l'indication du scanner, une **correction proposée**
par le fournisseur déterministe `RuleBasedRemediationProvider` (`saytu-core/remediation`) — aucune IA,
aucun envoi externe, résultat reproductible :

| Cas | Contenu |
|---|---|
| Dépendance | version cible (la plus haute version corrigée citée par les avis), extrait prêt à l'emploi pour forcer la version même transitive (Maven `dependencyManagement`, Gradle `constraints`, npm `overrides`, pip, Composer, Go, NuGet, Cargo, Bundler), commande pour vérifier la version résolue ; sans version corrigée : remplacement, isolement ou risque accepté |
| Secret | révoquer d'abord, lire la valeur depuis l'environnement (exemple dans la syntaxe du fichier : YAML Spring, `.properties`, `.env`, Java, TypeScript, PHP, Python, C#), purge de l'historique si le dépôt est partagé, pre-commit gitleaks |
| Configuration | règle Kubernetes (KSV) ou Dockerfile (DS) expliquée, `securityContext` / Dockerfile durcis complets |
| Code | 24 familles de failles par CWE (injection SQL, XSS, commande, chemin, désérialisation, XXE, SSRF, redirection, cryptographie, aléa, TLS, CSRF, JWT, cookies, CORS, ReDoS, NoSQL, LDAP, pollution de prototype, contrôle d'accès, affectation de masse…) : explication, impact, étapes, exemple vulnérable et corrigé dans le langage du fichier (Java, TypeScript/JavaScript, PHP, Python, C#), tests à ajouter |
| Qualité | règles courantes de PMD, Checkstyle, ESLint expliquées, lien vers la documentation de la règle |

Quand aucune fiche ne correspond, la suggestion est marquée « générale ». Les liens renvoient à l'OWASP
Cheat Sheet Series et à MITRE CWE (référencés, non copiés). L'explication libre par une IA locale
(Ollama, optionnelle) reste prévue en phase 7.

## Triage

`PUT /api/v1/findings/{id}/status` (AUDITOR, ADMIN) avec `{"status": "...", "reason": "..."}` :

| Depuis | Vers | Règle |
|---|---|---|
| Ouverte | Risque accepté, Faux positif | justification obligatoire (2 000 caractères au plus) |
| Risque accepté, Faux positif | Ouverte | justification facultative |
| Corrigée | — | refusé : seul un audit corrige ou rouvre |

Un statut posé à la main n'est jamais modifié par un audit. Chaque changement est conservé dans
`finding_status_history` (affiché dans le détail) et dans le journal d'audit (`FINDING_STATUS_CHANGED`).
Le score de la branche est **recalculé immédiatement** après un triage : les vulnérabilités triées ne
comptent plus ; elles restent visibles avec le filtre de statut correspondant.
