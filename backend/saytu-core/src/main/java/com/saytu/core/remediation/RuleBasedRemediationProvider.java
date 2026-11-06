package com.saytu.core.remediation;

import com.saytu.core.domain.Severity;
import com.saytu.core.finding.NormalizedFinding;
import com.saytu.core.scoring.SecurityIssue;
import com.saytu.core.scoring.Versions;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Deterministic remediation guidance: always available, reproducible, offline. Chooses, in order, the
 * guidance of the dependency ecosystem, of the secret, of the deployment configuration (Kubernetes,
 * Dockerfile), of the code weakness (CWE) or of the quality tool, and adapts the example to the language
 * of the file. Never modifies code: the suggestion is shown to a human.
 */
public final class RuleBasedRemediationProvider implements RemediationProvider {

    public static final String ID = "rule-based";

    private static final String CS = "https://cheatsheetseries.owasp.org/cheatsheets/";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public boolean isGenerative() {
        return false;
    }

    @Override
    public Optional<Remediation> suggest(NormalizedFinding f, String codeContext) {
        String path = f.location() == null ? null : f.location().path();
        String lang = languageOf(path);
        SecurityIssue issue = SecurityIssue.of(f.type(), f.severity(), f.scanner().key(), f.ruleId(), path, f.cwes(),
                f.dependency() == null ? null : f.dependency().name(),
                f.dependency() == null ? null : f.dependency().installedVersion(),
                f.dependency() == null ? null : f.dependency().fixedVersion());
        Remediation r;
        if (issue == null) {
            r = quality(f, lang);
        } else {
            r = switch (issue.category()) {
                case DEPENDENCY -> dependency(f);
                case SECRET -> secret(f, lang, path);
                case CONFIGURATION -> configuration(f, path);
                case CODE -> code(f, lang);
            };
        }
        return Optional.of(r);
    }

    // ------------------------------------------------------------------ dependencies

    private Remediation dependency(NormalizedFinding f) {
        NormalizedFinding.Dependency d = f.dependency();
        String name = d == null ? f.ruleId() : d.name();
        String installed = d == null || d.installedVersion() == null ? "?" : d.installedVersion();
        Optional<String> fixed = d == null ? Optional.empty() : Versions.highest(java.util.Arrays.asList(d.fixedVersion()));
        String ecosystem = d == null || d.ecosystem() == null ? "" : d.ecosystem().toLowerCase(Locale.ROOT);
        String id = f.cve() != null ? f.cve() : f.ruleId();
        List<String> steps = new ArrayList<>();
        String example = "";
        String exampleLanguage = "text";
        if (fixed.isPresent()) {
            steps.add("Mettre à jour " + name + " de " + installed + " vers " + fixed.get()
                    + " ou plus (version la plus récente citée par l'avis).");
            steps.add("Si la dépendance est transitive, forcer la version dans le gestionnaire de dépendances "
                    + "(exemple ci-dessous) ou mettre à jour la dépendance directe qui l'apporte.");
            String[] ex = upgradeExample(ecosystem, name, fixed.get());
            exampleLanguage = ex[0];
            example = ex[1];
        } else {
            steps.add("Aucune version corrigée n'est publiée pour " + name + " " + installed
                    + " : vérifier si le code vulnérable est réellement utilisé (fonction, configuration concernée).");
            steps.add("Remplacer la bibliothèque par une alternative maintenue, ou isoler l'usage (validation stricte des "
                    + "entrées qui l'atteignent, désactivation de la fonctionnalité concernée).");
            steps.add("Si le risque est accepté en connaissance de cause, le déclarer (« risque accepté » avec justification) "
                    + "et suivre la publication d'un correctif.");
        }
        steps.add("Relancer les tests, puis un audit SAYTU de la branche pour confirmer que l'avis " + id + " a disparu.");
        List<String> tests = new ArrayList<>(List.of(
                "Vérifier la version réellement résolue : " + resolvedVersionCommand(ecosystem, name) + ".",
                "Lancer toute la suite de tests : une montée de version peut changer un comportement."));
        List<String> refs = new ArrayList<>();
        if (f.cve() != null) {
            refs.add("https://nvd.nist.gov/vuln/detail/" + f.cve());
        }
        refs.addAll(f.references());
        refs.add(CS + "Vulnerable_Dependency_Management_Cheat_Sheet.html");
        return new Remediation(ID, "Dépendance vulnérable" + (f.cve() == null ? "" : " (" + f.cve() + ")"),
                "La version " + installed + " de " + name + " est concernée par l'avis " + id
                        + (f.cvssScore() == null ? "" : " (CVSS " + f.cvssScore() + ")") + ". "
                        + (f.description().isBlank() ? "" : f.description()),
                impact(f.severity(), "le composant vulnérable est exécuté avec les droits de l'application ; "
                        + "l'exploitabilité dépend de l'usage qui en est fait."),
                steps, exampleLanguage, "", example, tests, refs, true);
    }

    /** {language, snippet} forcing {@code version} of {@code name} in the given ecosystem. */
    static String[] upgradeExample(String ecosystem, String name, String version) {
        switch (ecosystem) {
            case "pom", "maven", "jar" -> {
                String[] ga = name.split(":", 2);
                String group = ga.length == 2 ? ga[0] : name;
                String artifact = ga.length == 2 ? ga[1] : name;
                return new String[]{"xml", """
                        <!-- pom.xml : version imposée, y compris pour une dépendance transitive -->
                        <dependencyManagement>
                          <dependencies>
                            <dependency>
                              <groupId>%s</groupId>
                              <artifactId>%s</artifactId>
                              <version>%s</version>
                            </dependency>
                          </dependencies>
                        </dependencyManagement>""".formatted(group, artifact, version)};
            }
            case "gradle" -> {
                return new String[]{"groovy", """
                        // build.gradle(.kts)
                        dependencies {
                            constraints {
                                implementation("%s:%s") { because("correctif de sécurité") }
                            }
                        }""".formatted(name, version)};
            }
            case "npm", "yarn", "pnpm", "node-pkg" -> {
                return new String[]{"json", """
                        // dépendance directe : npm install %s@%s
                        // dépendance transitive : package.json (npm ≥ 8.3 ; yarn : "resolutions", pnpm : "pnpm.overrides")
                        {
                          "overrides": {
                            "%s": "%s"
                          }
                        }""".formatted(name, version, name, version)};
            }
            case "pip", "pipenv", "poetry", "python-pkg", "uv" -> {
                return new String[]{"text", """
                        # requirements.txt (ou pyproject.toml / Pipfile)
                        %s>=%s
                        # puis : pip install -U "%s>=%s" et régénérer le fichier de verrouillage""".formatted(name, version, name, version)};
            }
            case "composer" -> {
                return new String[]{"shell", "composer require \"%s:^%s\"\ncomposer update %s --with-dependencies"
                        .formatted(name, version, name)};
            }
            case "gomod", "gobinary" -> {
                String v = version.startsWith("v") ? version : "v" + version;
                return new String[]{"shell", "go get %s@%s\ngo mod tidy".formatted(name, v)};
            }
            case "nuget", "dotnet-core", "packages-props" -> {
                return new String[]{"xml", "<PackageReference Include=\"%s\" Version=\"%s\" />".formatted(name, version)};
            }
            case "cargo" -> {
                return new String[]{"shell", "cargo update -p %s --precise %s".formatted(name, version)};
            }
            case "bundler", "gemspec" -> {
                return new String[]{"ruby", "gem '%s', '>= %s'\n# puis : bundle update %s".formatted(name, version, name)};
            }
            default -> {
                return new String[]{"text", name + " >= " + version};
            }
        }
    }

    private static String resolvedVersionCommand(String ecosystem, String name) {
        return switch (ecosystem) {
            case "pom", "maven", "jar" -> "`mvn dependency:tree -Dincludes=" + name + "`";
            case "gradle" -> "`gradle dependencyInsight --dependency " + name.replaceAll(".*:", "") + "`";
            case "npm", "node-pkg" -> "`npm ls " + name + "`";
            case "yarn" -> "`yarn why " + name + "`";
            case "pnpm" -> "`pnpm why " + name + "`";
            case "pip", "pipenv", "poetry", "python-pkg", "uv" -> "`pip show " + name + "`";
            case "composer" -> "`composer show " + name + "`";
            case "gomod", "gobinary" -> "`go list -m " + name + "`";
            case "nuget", "dotnet-core", "packages-props" -> "`dotnet list package --include-transitive`";
            case "cargo" -> "`cargo tree -i " + name + "`";
            default -> "l'arbre des dépendances du projet";
        };
    }

    // ------------------------------------------------------------------ secrets

    private Remediation secret(NormalizedFinding f, String lang, String path) {
        List<String> steps = List.of(
                "Considérer le secret comme compromis : le révoquer ou le changer chez son émetteur EN PREMIER "
                        + "(il reste dans l'historique Git même après suppression du fichier).",
                "Retirer la valeur du code et la lire au démarrage depuis l'environnement ou un gestionnaire de secrets "
                        + "(Vault, secrets Kubernetes, variables du pipeline).",
                "Si le dépôt est partagé ou public, purger l'historique (`git filter-repo --replace-text`) et faire "
                        + "re-cloner les copies ; sinon, la révocation suffit.",
                "Vérifier les journaux d'accès du service concerné depuis la date du premier commit contenant le secret.",
                "Ajouter une vérification avant commit (gitleaks en pre-commit) pour éviter la récidive.");
        String[] ex = secretExample(lang, path);
        return new Remediation(ID, "Secret dans le dépôt",
                "Une valeur ressemblant à un secret (" + f.ruleId() + ") est écrite dans "
                        + (path == null ? "le dépôt" : path) + ". Toute personne pouvant cloner le dépôt, ou ayant "
                        + "accès à une copie, à une sauvegarde ou à un journal de CI, peut l'utiliser.",
                impact(f.severity(), "accès au service protégé par ce secret avec les droits qui lui sont associés."),
                steps, ex[0], ex[1], ex[2],
                List.of("Démarrer l'application sans la variable d'environnement : elle doit échouer clairement (pas de valeur par défaut).",
                        "Relancer un audit SAYTU : Gitleaks ne doit plus trouver le secret dans la version courante.",
                        "Tester l'ancien secret auprès du service : il doit être refusé."),
                List.of(CS + "Secrets_Management_Cheat_Sheet.html", "https://github.com/newren/git-filter-repo"), true);
    }

    /** {language, vulnerable, fixed}. */
    private static String[] secretExample(String lang, String path) {
        String file = path == null ? "" : path.toLowerCase(Locale.ROOT);
        if (file.endsWith(".yml") || file.endsWith(".yaml")) {
            return new String[]{"yaml", """
                    spring:
                      datasource:
                        password: Sup3rS3cret!""", """
                    spring:
                      datasource:
                        password: ${DB_PASSWORD}   # fourni par l'environnement / un secret Kubernetes"""};
        }
        if (file.endsWith(".properties")) {
            return new String[]{"properties", "api.key=AKIA…", "api.key=${API_KEY}"};
        }
        if (file.endsWith(".env") || file.contains("/.env")) {
            return new String[]{"shell", "API_KEY=sk_live_…   # fichier .env versionné",
                    "# .env retiré du dépôt et ajouté à .gitignore ; fournir .env.example sans valeur :\nAPI_KEY="};
        }
        return switch (lang) {
            case "java" -> new String[]{"java", "private static final String API_KEY = \"sk_live_…\";", """
                    private final String apiKey = Objects.requireNonNull(System.getenv("API_KEY"), "API_KEY manquante");
                    // Spring : @Value("${api.key}") avec api.key=${API_KEY}"""};
            case "typescript" -> new String[]{"typescript", "const apiKey = 'sk_live_…';", """
                    const apiKey = process.env.API_KEY;
                    if (!apiKey) throw new Error('API_KEY manquante');
                    // front-end : ne jamais embarquer de secret dans le code livré au navigateur ; passer par le serveur"""};
            case "php" -> new String[]{"php", "$apiKey = 'sk_live_…';",
                    "$apiKey = getenv('API_KEY') ?: throw new RuntimeException('API_KEY manquante');"};
            case "python" -> new String[]{"python", "API_KEY = \"sk_live_…\"", "API_KEY = os.environ[\"API_KEY\"]  # KeyError si absente"};
            case "csharp" -> new String[]{"csharp", "var apiKey = \"sk_live_…\";",
                    "var apiKey = builder.Configuration[\"ApiKey\"]  // user-secrets en dev, variable d'environnement en prod\n"
                            + "    ?? throw new InvalidOperationException(\"ApiKey manquante\");"};
            default -> new String[]{"text", "", "Lire la valeur depuis l'environnement ou un gestionnaire de secrets."};
        };
    }

    // ------------------------------------------------------------------ deployment configuration

    private static final Map<String, String> KUBERNETES_CHECKS = Map.ofEntries(
            Map.entry("KSV001", "Interdire l'élévation de privilèges : `allowPrivilegeEscalation: false`."),
            Map.entry("KSV003", "Retirer toutes les capacités Linux : `capabilities.drop: [\"ALL\"]`, puis n'ajouter que le nécessaire."),
            Map.entry("KSV011", "Définir une limite CPU (`resources.limits.cpu`)."),
            Map.entry("KSV012", "Exécuter le conteneur sans root : `runAsNonRoot: true`."),
            Map.entry("KSV014", "Système de fichiers racine en lecture seule : `readOnlyRootFilesystem: true` (monter des volumes pour /tmp)."),
            Map.entry("KSV015", "Définir une réservation CPU (`resources.requests.cpu`)."),
            Map.entry("KSV016", "Définir une réservation mémoire (`resources.requests.memory`)."),
            Map.entry("KSV017", "Ne pas lancer de conteneur privilégié (`privileged: false`)."),
            Map.entry("KSV018", "Définir une limite mémoire (`resources.limits.memory`)."),
            Map.entry("KSV020", "Utiliser un UID élevé : `runAsUser: 10001`."),
            Map.entry("KSV021", "Utiliser un GID élevé : `runAsGroup: 10001`."),
            Map.entry("KSV030", "Activer le profil seccomp par défaut : `seccompProfile.type: RuntimeDefault`."),
            Map.entry("KSV104", "Activer un profil seccomp : `seccompProfile.type: RuntimeDefault`."),
            Map.entry("KSV106", "Retirer toutes les capacités Linux : `capabilities.drop: [\"ALL\"]`."),
            Map.entry("KSV110", "Déployer dans un namespace dédié plutôt que `default`."),
            Map.entry("KSV116", "Exécuter le pod sans root (`runAsNonRoot: true` au niveau du pod)."),
            Map.entry("KSV117", "Ne pas écouter sur un port privilégié (< 1024) dans le conteneur."),
            Map.entry("KSV118", "Définir un `securityContext` explicite (le contexte par défaut laisse root et toutes les capacités)."),
            Map.entry("KSV125", "Utiliser des images d'un registre de confiance (registre interne).")) ;

    private static final Map<String, String> DOCKERFILE_CHECKS = Map.ofEntries(
            Map.entry("DS001", "Épingler l'image de base sur une version précise (et idéalement un digest), jamais `:latest`."),
            Map.entry("DS002", "Ajouter un utilisateur non root et basculer dessus avec `USER`."),
            Map.entry("DS005", "Utiliser `COPY` plutôt que `ADD` (pas de téléchargement ni d'extraction implicite)."),
            Map.entry("DS013", "Utiliser `WORKDIR` plutôt que `RUN cd …`."),
            Map.entry("DS017", "Grouper `apt-get update` et `apt-get install` dans la même instruction RUN."),
            Map.entry("DS026", "Ajouter une instruction `HEALTHCHECK`."),
            Map.entry("DS029", "Installer avec `apt-get install --no-install-recommends` et vider le cache apt."));

    private Remediation configuration(NormalizedFinding f, String path) {
        String rule = f.ruleId() == null ? "" : f.ruleId().toUpperCase(Locale.ROOT).replace("-", "").replace("AVD", "");
        String file = path == null ? "" : path.toLowerCase(Locale.ROOT);
        boolean dockerfile = file.matches("(.*/)?(dockerfile[^/]*|[^/]*\\.dockerfile|containerfile)") || rule.startsWith("DS");
        boolean kubernetes = rule.startsWith("KSV") || !dockerfile && (file.endsWith(".yml") || file.endsWith(".yaml"));
        List<String> steps = new ArrayList<>();
        String specific = KUBERNETES_CHECKS.getOrDefault(normalizeCheck(rule), DOCKERFILE_CHECKS.get(normalizeCheck(rule)));
        if (specific != null) {
            steps.add(specific);
        }
        if (f.recommendation() != null && !f.recommendation().isBlank()) {
            steps.add(f.recommendation());
        }
        String language;
        String fixed;
        List<String> refs = new ArrayList<>(f.references());
        if (dockerfile && !kubernetes) {
            steps.add("Construire l'image avec un utilisateur dédié, des versions épinglées et le minimum de paquets.");
            language = "dockerfile";
            fixed = """
                    FROM eclipse-temurin:21.0.5_11-jre-alpine
                    RUN addgroup -S -g 10001 app && adduser -S -u 10001 -G app app
                    WORKDIR /app
                    COPY --chown=app:app target/app.jar app.jar
                    USER 10001
                    HEALTHCHECK --interval=30s CMD wget -qO- http://localhost:8080/actuator/health || exit 1
                    ENTRYPOINT ["java", "-jar", "app.jar"]""";
            refs.add(CS + "Docker_Security_Cheat_Sheet.html");
        } else if (kubernetes) {
            steps.add("Appliquer un `securityContext` restrictif à chaque conteneur (exemple ci-dessous) et des ressources bornées.");
            steps.add("Imposer ces règles à l'échelle du cluster (Pod Security Admission, niveau `restricted`).");
            language = "yaml";
            fixed = """
                    spec:
                      securityContext:
                        runAsNonRoot: true
                        runAsUser: 10001
                        runAsGroup: 10001
                        seccompProfile: { type: RuntimeDefault }
                      containers:
                        - name: app
                          securityContext:
                            allowPrivilegeEscalation: false
                            readOnlyRootFilesystem: true
                            capabilities: { drop: ["ALL"] }
                          resources:
                            requests: { cpu: 100m, memory: 256Mi }
                            limits: { cpu: "1", memory: 512Mi }""";
            refs.add(CS + "Kubernetes_Security_Cheat_Sheet.html");
        } else {
            steps.add("Appliquer la recommandation de la règle à la ressource concernée et relancer l'audit.");
            language = "text";
            fixed = "";
            refs.add(CS + "Infrastructure_as_Code_Security_Cheat_Sheet.html");
        }
        return new Remediation(ID, "Configuration de déploiement",
                f.title() + (f.description().isBlank() || f.description().equals(f.title()) ? "" : " — " + f.description()),
                impact(f.severity(), "un conteneur compromis obtient plus de droits que nécessaire sur le nœud ou le cluster."),
                steps, language, "", fixed,
                List.of("Valider le manifeste corrigé (`kubectl apply --dry-run=server` ou `docker build`), puis vérifier que "
                                + "l'application démarre avec un système de fichiers en lecture seule et sans root.",
                        "Relancer l'audit SAYTU : la règle " + f.ruleId() + " ne doit plus apparaître."),
                refs, specific != null);
    }

    /** "KSV0118" / "KSV118" / "AVD-KSV-0118" → "KSV118"; "DS002" → "DS002". */
    static String normalizeCheck(String rule) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("(KSV|DS)0*(\\d+)").matcher(rule);
        if (!m.find()) {
            return rule;
        }
        String digits = m.group(2);
        return m.group(1) + "0".repeat(Math.max(0, 3 - digits.length())) + digits;
    }

    // ------------------------------------------------------------------ code weaknesses

    private Remediation code(NormalizedFinding f, String lang) {
        Optional<CodeWeaknesses.Entry> entry = CodeWeaknesses.forCwes(f.cwes());
        if (entry.isEmpty()) {
            List<String> steps = new ArrayList<>();
            if (f.recommendation() != null && !f.recommendation().isBlank()) {
                steps.add(f.recommendation());
            }
            steps.add("Lire la documentation de la règle " + f.ruleId() + " (références) et corriger chaque emplacement signalé.");
            steps.add("Valider et encoder toute donnée venant de l'extérieur au plus près de son usage.");
            List<String> refs = new ArrayList<>(f.references());
            f.cwes().forEach(c -> refs.add(cweUrl(c)));
            return new Remediation(ID, f.title(), f.description().isBlank() ? f.title() : f.description(),
                    impact(f.severity(), "dépend de l'endroit où le code est atteint et des données qu'il manipule."),
                    steps, lang, "", "", List.of("Écrire un test reproduisant le cas signalé, puis le faire passer avec la correction."),
                    refs, false);
        }
        CodeWeaknesses.Entry e = entry.get();
        Map.Entry<String, CodeWeaknesses.Example> ex = pickExample(e.examples(), lang);
        List<String> steps = new ArrayList<>(e.steps());
        if (f.recommendation() != null && !f.recommendation().isBlank()) {
            steps.add("Indication de la règle : " + f.recommendation());
        }
        List<String> refs = new ArrayList<>(e.references());
        f.cwes().forEach(c -> refs.add(cweUrl(c)));
        refs.addAll(f.references());
        return new Remediation(ID, e.topic(), e.explanation(), impact(f.severity(), e.impact()), steps,
                ex == null ? lang : ex.getKey(), ex == null ? "" : ex.getValue().vulnerable(),
                ex == null ? "" : ex.getValue().fixed(), e.tests(), refs, true);
    }

    /** Example in the file's language, else Java, else the first one. */
    private static Map.Entry<String, CodeWeaknesses.Example> pickExample(Map<String, CodeWeaknesses.Example> examples, String lang) {
        if (examples.containsKey(lang)) {
            return Map.entry(lang, examples.get(lang));
        }
        if (examples.containsKey("java")) {
            return Map.entry("java", examples.get("java"));
        }
        return examples.entrySet().stream().findFirst().orElse(null);
    }

    // ------------------------------------------------------------------ quality

    private static final Map<String, String[]> QUALITY_RULES = Map.ofEntries(
            Map.entry("SystemPrintln", new String[]{"Sortie console au lieu d'un journal",
                    "Remplacer `System.out/err.println` par le logger de l'application (niveau adapté, paramètres `{}`)."}),
            Map.entry("AvoidPrintStackTrace", new String[]{"Trace d'exception imprimée sur la console",
                    "Journaliser l'exception avec le logger (`log.error(\"…\", e)`) ou la propager."}),
            Map.entry("EmptyCatchBlock", new String[]{"Exception avalée",
                    "Traiter l'exception, la propager ou au minimum la journaliser avec la raison pour laquelle on l'ignore."}),
            Map.entry("AvoidCatchingGenericException", new String[]{"Capture d'exception trop large",
                    "Capturer les exceptions précises attendues ; laisser remonter les autres."}),
            Map.entry("UnusedPrivateField", new String[]{"Champ privé inutilisé", "Supprimer le champ (ou l'utiliser)."}),
            Map.entry("UnusedLocalVariable", new String[]{"Variable inutilisée", "Supprimer la variable."}),
            Map.entry("UnusedPrivateMethod", new String[]{"Méthode privée inutilisée", "Supprimer la méthode morte."}),
            Map.entry("ClassWithOnlyPrivateConstructorsShouldBeFinal", new String[]{"Classe utilitaire non finale",
                    "Déclarer la classe `final` : elle ne peut de toute façon pas être étendue."}),
            Map.entry("UseUtilityClass", new String[]{"Classe utilitaire instanciable",
                    "Rendre la classe `final` et ajouter un constructeur privé."}),
            Map.entry("MagicNumber", new String[]{"Nombre magique", "Nommer la valeur dans une constante explicite."}),
            Map.entry("LineLength", new String[]{"Ligne trop longue", "Découper l'expression ou extraire des variables."}),
            Map.entry("StringLiteralEquality", new String[]{"Comparaison de chaînes avec ==",
                    "Utiliser `equals()` (== compare les références, pas le contenu)."}),
            Map.entry("no-unused-vars", new String[]{"Variable inutilisée", "Supprimer la variable ou l'import inutilisé."}),
            Map.entry("@typescript-eslint/no-unused-vars", new String[]{"Variable inutilisée", "Supprimer la variable ou l'import inutilisé."}),
            Map.entry("@typescript-eslint/no-explicit-any", new String[]{"Type any",
                    "Remplacer `any` par un type précis ou `unknown` suivi d'une vérification."}),
            Map.entry("eqeqeq", new String[]{"Égalité faible", "Utiliser `===` et `!==`."}),
            Map.entry("no-console", new String[]{"Appel console", "Utiliser le logger de l'application ou supprimer l'appel."}),
            Map.entry("no-empty", new String[]{"Bloc vide", "Traiter le cas ou expliquer en commentaire pourquoi rien n'est fait."}));

    private Remediation quality(NormalizedFinding f, String lang) {
        String rule = f.ruleId() == null ? "" : f.ruleId().replaceFirst("^[a-z]+:", "");
        String[] known = QUALITY_RULES.get(rule);
        List<String> steps = new ArrayList<>();
        if (known != null) {
            steps.add(known[1]);
        }
        if (f.recommendation() != null && !f.recommendation().isBlank()) {
            steps.add(f.recommendation());
        }
        steps.add("Corriger tous les emplacements de la même règle en une fois (liste filtrée par règle), puis relancer l'audit.");
        steps.add("Si la règle ne convient pas à l'équipe, l'ajuster dans la configuration SAYTU plutôt que d'ignorer les résultats un par un.");
        List<String> refs = new ArrayList<>(f.references());
        qualityDoc(f.scanner().key(), rule).ifPresent(refs::add);
        return new Remediation(ID, known != null ? known[0] : "Qualité du code",
                f.description().isBlank() ? f.title() : f.description(),
                switch (f.severity()) {
                    case CRITICAL, HIGH -> "Défaut probable ou code fragile : risque de bogue en production et de maintenance coûteuse.";
                    case MEDIUM -> "Lisibilité et maintenabilité dégradées ; peut masquer des erreurs.";
                    default -> "Convention ou style : homogénéité du code et facilité de relecture.";
                },
                steps, lang, "", "",
                List.of("Les tests existants doivent rester verts : ces corrections ne doivent pas changer le comportement.",
                        "Si la correction touche une logique (exception, égalité), ajouter un test du cas concerné."),
                refs, known != null);
    }

    static Optional<String> qualityDoc(String scanner, String rule) {
        return switch (scanner) {
            case "eslint" -> {
                if (rule.startsWith("@typescript-eslint/")) {
                    yield Optional.of("https://typescript-eslint.io/rules/" + rule.substring("@typescript-eslint/".length()) + "/");
                }
                if (rule.startsWith("security/")) {
                    yield Optional.of("https://github.com/eslint-community/eslint-plugin-security/blob/main/docs/rules/"
                            + rule.substring("security/".length()) + ".md");
                }
                yield rule.matches("[a-z-]+") ? Optional.of("https://eslint.org/docs/latest/rules/" + rule) : Optional.empty();
            }
            case "checkstyle" -> Optional.of("https://checkstyle.org/checks.html");
            case "sqlfluff" -> Optional.of("https://docs.sqlfluff.com/en/stable/reference/rules.html");
            case "phpcs" -> Optional.of("https://www.php-fig.org/psr/psr-12/");
            case "cppcheck" -> Optional.of("https://cppcheck.sourceforge.io/manual.pdf");
            default -> Optional.empty();
        };
    }

    // ------------------------------------------------------------------ helpers

    private static String impact(Severity severity, String what) {
        String level = switch (severity) {
            case CRITICAL -> "Critique : exploitable facilement ou aux conséquences graves ; à traiter immédiatement. ";
            case HIGH -> "Élevé : à corriger en priorité. ";
            case MEDIUM -> "Moyen : à planifier. ";
            case LOW -> "Faible : à corriger lors d'une prochaine évolution. ";
            case INFO -> "Informatif. ";
        };
        return level + Character.toUpperCase(what.charAt(0)) + what.substring(1);
    }

    static String cweUrl(String cwe) {
        return cwe.startsWith("CWE-") ? "https://cwe.mitre.org/data/definitions/" + cwe.substring(4) + ".html" : cwe;
    }

    /** Language key of the examples, from the file name. */
    static String languageOf(String path) {
        if (path == null) {
            return "text";
        }
        String p = path.toLowerCase(Locale.ROOT);
        if (p.endsWith(".java") || p.endsWith(".kt") || p.endsWith(".groovy") || p.endsWith(".scala")) {
            return "java";
        }
        if (p.matches(".*\\.(ts|tsx|js|jsx|mjs|cjs|vue|svelte)$")) {
            return "typescript";
        }
        if (p.endsWith(".php")) {
            return "php";
        }
        if (p.endsWith(".py")) {
            return "python";
        }
        if (p.endsWith(".cs")) {
            return "csharp";
        }
        if (p.endsWith(".go")) {
            return "go";
        }
        if (p.matches(".*\\.(c|h|cc|cpp|cxx|hpp)$")) {
            return "c";
        }
        if (p.endsWith(".sql")) {
            return "sql";
        }
        if (p.endsWith(".yml") || p.endsWith(".yaml")) {
            return "yaml";
        }
        return "text";
    }
}
