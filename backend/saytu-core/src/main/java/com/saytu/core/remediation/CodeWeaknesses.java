package com.saytu.core.remediation;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Deterministic guidance for code weaknesses, keyed by CWE. Examples exist for the languages SAYTU
 * audits most (Java, TypeScript/JavaScript, PHP, Python, C#); the closest available one is shown.
 * Texts are written for SAYTU (Apache-2.0); links point to the OWASP Cheat Sheet Series (CC BY-SA 4.0)
 * and to MITRE CWE, which are referenced, not copied.
 */
final class CodeWeaknesses {

    private CodeWeaknesses() {
    }

    /** A vulnerable / fixed pair in one language. */
    record Example(String vulnerable, String fixed) {
    }

    record Entry(Set<String> cwes, String topic, String explanation, String impact, List<String> steps,
                 Map<String, Example> examples, List<String> tests, List<String> references) {
    }

    private static final String CS = "https://cheatsheetseries.owasp.org/cheatsheets/";

    static final List<Entry> ENTRIES = List.of(
            new Entry(Set.of("CWE-89", "CWE-564"), "Injection SQL",
                    "Une requête SQL est construite en concaténant une valeur venant de l'extérieur (paramètre HTTP, "
                            + "en-tête, fichier, message). Le moteur ne distingue plus le code SQL des données.",
                    "Lecture ou modification de toute la base, contournement de l'authentification, parfois exécution "
                            + "de commandes sur le serveur de base de données.",
                    List.of("Remplacer la concaténation par une requête paramétrée (paramètres liés `?` ou nommés).",
                            "Pour les noms de colonnes ou de tri dynamiques, choisir dans une liste blanche fermée.",
                            "Donner au compte applicatif les seuls droits nécessaires (pas de DDL, pas de superutilisateur).",
                            "Rechercher les autres concaténations du même motif dans le dépôt."),
                    examples(
                            "java", new Example("""
                                    String sql = "SELECT * FROM users WHERE email = '" + email + "'";
                                    ResultSet rs = connection.createStatement().executeQuery(sql);""", """
                                    PreparedStatement ps = connection.prepareStatement("SELECT * FROM users WHERE email = ?");
                                    ps.setString(1, email);
                                    ResultSet rs = ps.executeQuery();
                                    // Spring Data JPA : @Query("select u from User u where u.email = :email")"""),
                            "typescript", new Example("""
                                    const rows = await db.query(`SELECT * FROM users WHERE email = '${email}'`);""", """
                                    const rows = await db.query('SELECT * FROM users WHERE email = $1', [email]);
                                    // TypeORM : repo.findOneBy({ email }) ou createQueryBuilder().where('u.email = :email', { email })"""),
                            "php", new Example("""
                                    $rows = $pdo->query("SELECT * FROM users WHERE email = '$email'");""", """
                                    $stmt = $pdo->prepare('SELECT * FROM users WHERE email = :email');
                                    $stmt->execute(['email' => $email]);
                                    $rows = $stmt->fetchAll();"""),
                            "python", new Example("""
                                    cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")""", """
                                    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))"""),
                            "csharp", new Example("""
                                    var cmd = new SqlCommand("SELECT * FROM Users WHERE Email = '" + email + "'", conn);""", """
                                    var cmd = new SqlCommand("SELECT * FROM Users WHERE Email = @email", conn);
                                    cmd.Parameters.AddWithValue("@email", email);""")),
                    List.of("Test d'intégration envoyant `' OR '1'='1` et `'; DROP TABLE users; --` : la requête ne doit "
                                    + "renvoyer aucune ligne en trop et ne lever aucune erreur SQL.",
                            "Test vérifiant que les valeurs contenant des apostrophes (O'Brien) sont trouvées normalement."),
                    List.of(CS + "SQL_Injection_Prevention_Cheat_Sheet.html", CS + "Query_Parameterization_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-79", "CWE-80", "CWE-83"), "Cross-site scripting (XSS)",
                    "Une valeur contrôlable par un utilisateur est insérée dans une page sans encodage adapté au "
                            + "contexte (HTML, attribut, URL, JavaScript), ou via une API qui interprète du HTML.",
                    "Exécution de JavaScript dans le navigateur des autres utilisateurs : vol de session ou de jeton, "
                            + "actions à leur place, défiguration.",
                    List.of("Afficher les données comme du texte (interpolation du framework, `textContent`), jamais via `innerHTML`.",
                            "Ne contourner l'assainissement du framework (`bypassSecurityTrust…`, `dangerouslySetInnerHTML`, `v-html`) "
                                    + "que pour du HTML assaini par une bibliothèque dédiée (DOMPurify).",
                            "Côté serveur, encoder selon le contexte de sortie (OWASP Java Encoder, `htmlspecialchars`).",
                            "Ajouter une Content-Security-Policy sans `unsafe-inline` pour limiter l'impact."),
                    examples(
                            "typescript", new Example("""
                                    element.innerHTML = comment.text;
                                    // Angular : this.sanitizer.bypassSecurityTrustHtml(comment.text)""", """
                                    element.textContent = comment.text;
                                    // Angular : <p>{{ comment.text }}</p> (encodé automatiquement)
                                    // HTML voulu : [innerHTML]="DOMPurify.sanitize(comment.html)\""""),
                            "java", new Example("""
                                    out.println("<p>" + request.getParameter("name") + "</p>");""", """
                                    import org.owasp.encoder.Encode;
                                    out.println("<p>" + Encode.forHtml(request.getParameter("name")) + "</p>");
                                    // Thymeleaf : <p th:text="${name}"></p> (et non th:utext)"""),
                            "php", new Example("""
                                    echo "<p>" . $_GET['name'] . "</p>";""", """
                                    echo '<p>' . htmlspecialchars($_GET['name'], ENT_QUOTES | ENT_HTML5, 'UTF-8') . '</p>';""")),
                    List.of("Test de composant ou de vue avec la valeur `<img src=x onerror=alert(1)>` : le texte doit "
                                    + "apparaître tel quel, sans élément <img> créé dans le DOM.",
                            "Test vérifiant la présence de l'en-tête Content-Security-Policy sur les pages."),
                    List.of(CS + "Cross_Site_Scripting_Prevention_Cheat_Sheet.html", CS + "DOM_based_XSS_Prevention_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-78", "CWE-77", "CWE-88"), "Injection de commande système",
                    "Une commande du système est lancée à travers un shell avec une valeur venant de l'extérieur : "
                            + "les caractères `;`, `|`, `$( )` ou les options `--…` changent la commande exécutée.",
                    "Exécution de commandes arbitraires sur le serveur avec les droits de l'application.",
                    List.of("Éviter d'appeler un programme externe quand une bibliothèque fait le travail.",
                            "Sinon, lancer le programme directement (sans shell) avec une liste d'arguments séparés.",
                            "Valider la valeur par liste blanche (format strict) et la séparer des options par `--`.",
                            "Exécuter le processus avec un compte et des droits minimaux."),
                    examples(
                            "java", new Example("""
                                    Runtime.getRuntime().exec("convert " + fileName + " out.png");""", """
                                    if (!fileName.matches("[A-Za-z0-9._-]{1,100}")) throw new IllegalArgumentException("nom invalide");
                                    new ProcessBuilder("convert", "--", fileName, "out.png").start();"""),
                            "typescript", new Example("""
                                    exec(`convert ${fileName} out.png`);""", """
                                    import { execFile } from 'node:child_process';
                                    execFile('convert', ['--', fileName, 'out.png'], (err) => { /* … */ });"""),
                            "python", new Example("""
                                    os.system(f"convert {file_name} out.png")""", """
                                    subprocess.run(["convert", "--", file_name, "out.png"], check=True)  # shell=False par défaut"""),
                            "php", new Example("""
                                    system("convert " . $file . " out.png");""", """
                                    $process = new Symfony\\Component\\Process\\Process(['convert', '--', $file, 'out.png']);
                                    $process->mustRun();""")),
                    List.of("Test avec la valeur `a.png; touch /tmp/pwned` : la valeur est refusée ou traitée comme un nom "
                            + "de fichier, et aucun fichier /tmp/pwned n'est créé."),
                    List.of(CS + "OS_Command_Injection_Defense_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-22", "CWE-23", "CWE-36", "CWE-73"), "Traversée de répertoire",
                    "Un chemin de fichier est construit avec une valeur venant de l'extérieur ; `../` ou un chemin "
                            + "absolu permettent de sortir du répertoire prévu.",
                    "Lecture ou écriture de fichiers arbitraires (configuration, clés, code), parfois exécution de code.",
                    List.of("Ne jamais utiliser le nom fourni comme chemin : préférer un identifiant interne.",
                            "Sinon, normaliser le chemin complet puis vérifier qu'il reste sous le répertoire autorisé.",
                            "Refuser les noms contenant `/`, `\\`, `..` ou un octet nul."),
                    examples(
                            "java", new Example("""
                                    File f = new File(UPLOAD_DIR, request.getParameter("name"));""", """
                                    Path base = Path.of(UPLOAD_DIR).toRealPath();
                                    Path file = base.resolve(name).normalize();
                                    if (!file.startsWith(base)) throw new SecurityException("chemin refusé");"""),
                            "typescript", new Example("""
                                    res.sendFile(path.join(UPLOAD_DIR, req.params.name));""", """
                                    const base = path.resolve(UPLOAD_DIR);
                                    const file = path.resolve(base, req.params.name);
                                    if (!file.startsWith(base + path.sep)) return res.status(400).end();
                                    res.sendFile(file);"""),
                            "php", new Example("""
                                    readfile(UPLOAD_DIR . '/' . $_GET['name']);""", """
                                    $base = realpath(UPLOAD_DIR);
                                    $file = realpath($base . '/' . basename($_GET['name']));
                                    if ($file === false || !str_starts_with($file, $base . DIRECTORY_SEPARATOR)) { http_response_code(400); exit; }
                                    readfile($file);""")),
                    List.of("Tests avec `../../etc/passwd`, `..%2f..%2fetc%2fpasswd` et `/etc/passwd` : réponse 400 et aucun accès hors du répertoire."),
                    List.of(CS + "File_Upload_Cheat_Sheet.html", CS + "Input_Validation_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-94", "CWE-95", "CWE-96"), "Injection de code",
                    "Du texte venant de l'extérieur est évalué comme du code (`eval`, `new Function`, `ScriptEngine`, "
                            + "expressions SpEL/OGNL, templates côté serveur).",
                    "Exécution de code arbitraire dans l'application.",
                    List.of("Supprimer l'évaluation dynamique : parser les données (`JSON.parse`), table de correspondance pour les actions.",
                            "Si un langage d'expression est indispensable, utiliser un contexte restreint (SpEL `SimpleEvaluationContext`)."),
                    examples(
                            "typescript", new Example("""
                                    const config = eval('(' + body + ')');""", """
                                    const config = JSON.parse(body);"""),
                            "java", new Example("""
                                    Expression exp = parser.parseExpression(userInput);
                                    Object value = exp.getValue(new StandardEvaluationContext(root));""", """
                                    Expression exp = parser.parseExpression(userInput);
                                    Object value = exp.getValue(SimpleEvaluationContext.forReadOnlyDataBinding().build(), root);""")),
                    List.of("Test avec une charge utile `process.exit(1)` / `T(java.lang.Runtime).getRuntime()` : refusée, application intacte."),
                    List.of(CS + "Injection_Prevention_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-502"), "Désérialisation non sûre",
                    "Des données non fiables sont désérialisées avec un mécanisme capable d'instancier des classes "
                            + "arbitraires (sérialisation Java, `pickle`, `unserialize`, typage polymorphe Jackson, YAML complet).",
                    "Exécution de code à distance via des chaînes de « gadgets » présentes dans les dépendances.",
                    List.of("Échanger des données simples (JSON) vers des classes explicites, sans typage polymorphe global.",
                            "Si la sérialisation native est inévitable, filtrer les classes autorisées (`ObjectInputFilter`).",
                            "YAML : chargeur sûr (`SafeConstructor`, `yaml.safe_load`)."),
                    examples(
                            "java", new Example("""
                                    Object o = new ObjectInputStream(in).readObject();
                                    mapper.activateDefaultTyping(mapper.getPolymorphicTypeValidator());""", """
                                    Order order = mapper.readValue(in, Order.class);   // classe explicite, pas de default typing
                                    // sérialisation native : ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.acme.dto.*;!*"));"""),
                            "python", new Example("""
                                    data = pickle.loads(request.data)
                                    cfg = yaml.load(text)""", """
                                    data = json.loads(request.data)
                                    cfg = yaml.safe_load(text)"""),
                            "php", new Example("""
                                    $cart = unserialize($_COOKIE['cart']);""", """
                                    $cart = json_decode($_COOKIE['cart'], true, 16, JSON_THROW_ON_ERROR);""")),
                    List.of("Test envoyant un objet sérialisé d'une classe non attendue : rejet sans instanciation."),
                    List.of(CS + "Deserialization_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-611", "CWE-776"), "Entités externes XML (XXE)",
                    "Le parseur XML accepte les DTD et les entités externes : un document peut référencer des fichiers "
                            + "locaux ou des URL internes.",
                    "Lecture de fichiers du serveur, requêtes vers le réseau interne, déni de service (« billion laughs »).",
                    List.of("Désactiver les DTD (ou à défaut les entités externes) sur chaque parseur XML.",
                            "Python : utiliser `defusedxml`."),
                    examples(
                            "java", new Example("""
                                    DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();""", """
                                    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                                    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
                                    dbf.setXIncludeAware(false);
                                    dbf.setExpandEntityReferences(false);
                                    DocumentBuilder db = dbf.newDocumentBuilder();"""),
                            "python", new Example("""
                                    from xml.etree.ElementTree import fromstring""", """
                                    from defusedxml.ElementTree import fromstring""")),
                    List.of("Test avec un document déclarant `<!ENTITY x SYSTEM \"file:///etc/passwd\">` : refusé."),
                    List.of(CS + "XML_External_Entity_Prevention_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-918"), "Requête côté serveur forgée (SSRF)",
                    "Le serveur appelle une URL fournie ou influencée par l'utilisateur.",
                    "Accès au réseau interne et aux services de métadonnées du cloud (jetons d'accès), contournement de pare-feu.",
                    List.of("N'autoriser que des destinations connues (liste blanche de domaines et de schémas `https`).",
                            "Résoudre le nom et refuser les adresses privées, de boucle locale et de lien local (169.254.0.0/16).",
                            "Désactiver le suivi automatique des redirections ou revalider chaque saut."),
                    examples(
                            "java", new Example("""
                                    restTemplate.getForObject(request.getParameter("url"), String.class);""", """
                                    URI uri = URI.create(url);
                                    if (!"https".equals(uri.getScheme()) || !ALLOWED_HOSTS.contains(uri.getHost()))
                                        throw new IllegalArgumentException("destination refusée");
                                    restTemplate.getForObject(uri, String.class);"""),
                            "typescript", new Example("""
                                    const r = await fetch(req.query.url as string);""", """
                                    const u = new URL(String(req.query.url));
                                    if (u.protocol !== 'https:' || !ALLOWED_HOSTS.has(u.hostname)) return res.status(400).end();
                                    const r = await fetch(u, { redirect: 'error' });""")),
                    List.of("Tests avec `http://169.254.169.254/latest/meta-data/`, `http://localhost:8080/actuator` et un domaine non listé : refusés."),
                    List.of(CS + "Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-601"), "Redirection ouverte",
                    "L'application redirige vers une URL fournie en paramètre sans vérifier sa destination.",
                    "Hameçonnage crédible depuis votre domaine, vol de jetons transmis dans l'URL de retour.",
                    List.of("N'accepter que des chemins relatifs internes (commençant par un seul `/`) ou une liste blanche de domaines.",
                            "Sinon, rediriger vers une page par défaut."),
                    examples(
                            "java", new Example("""
                                    response.sendRedirect(request.getParameter("next"));""", """
                                    String next = request.getParameter("next");
                                    boolean internal = next != null && next.startsWith("/") && !next.startsWith("//") && !next.contains("\\\\");
                                    response.sendRedirect(internal ? next : "/");"""),
                            "typescript", new Example("""
                                    res.redirect(req.query.next as string);""", """
                                    const next = String(req.query.next ?? '/');
                                    res.redirect(next.startsWith('/') && !next.startsWith('//') ? next : '/');""")),
                    List.of("Tests avec `https://evil.example`, `//evil.example` et `/\\evil.example` : redirection vers `/`."),
                    List.of(CS + "Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-327", "CWE-328", "CWE-326", "CWE-916", "CWE-759", "CWE-760"), "Cryptographie faible",
                    "Un algorithme cassé ou inadapté est utilisé (MD5, SHA-1, DES, RC4, ECB, clé trop courte), ou des mots "
                            + "de passe sont hachés avec une fonction rapide.",
                    "Collisions ou déchiffrement des données ; mots de passe retrouvés en quelques heures après une fuite de la base.",
                    List.of("Intégrité / empreinte : SHA-256 ou plus.",
                            "Chiffrement : AES-GCM (ou ChaCha20-Poly1305) avec un nonce unique par message.",
                            "Mots de passe : Argon2id, scrypt ou bcrypt via la bibliothèque du framework, jamais un simple hachage.",
                            "Prévoir la migration des valeurs existantes (re-hachage à la prochaine connexion)."),
                    examples(
                            "java", new Example("""
                                    MessageDigest md = MessageDigest.getInstance("MD5");
                                    String hash = hex(md.digest(password.getBytes()));""", """
                                    // empreinte de données
                                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                                    // mots de passe (Spring Security)
                                    PasswordEncoder encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
                                    String stored = encoder.encode(password);"""),
                            "typescript", new Example("""
                                    const hash = crypto.createHash('md5').update(password).digest('hex');""", """
                                    import argon2 from 'argon2';
                                    const stored = await argon2.hash(password);              // mots de passe
                                    const digest = crypto.createHash('sha256').update(data).digest('hex');  // empreinte"""),
                            "python", new Example("""
                                    hashlib.md5(password.encode()).hexdigest()""", """
                                    from argon2 import PasswordHasher
                                    stored = PasswordHasher().hash(password)"""),
                            "php", new Example("""
                                    $hash = md5($password);""", """
                                    $hash = password_hash($password, PASSWORD_ARGON2ID);
                                    // vérification : password_verify($password, $hash)""")),
                    List.of("Test vérifiant que deux hachages du même mot de passe diffèrent (sel) et que la vérification réussit.",
                            "Test de migration : un ancien hachage est accepté une fois puis remplacé."),
                    List.of(CS + "Password_Storage_Cheat_Sheet.html", CS + "Cryptographic_Storage_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-330", "CWE-338", "CWE-331"), "Aléa prévisible",
                    "Un générateur pseudo-aléatoire non cryptographique (`Math.random`, `java.util.Random`, `random`) "
                            + "produit un jeton, un identifiant de session ou un code.",
                    "Jetons devinables : prise de compte, réinitialisation de mot de passe détournée.",
                    List.of("Utiliser le générateur cryptographique de la plateforme pour toute valeur de sécurité."),
                    examples(
                            "java", new Example("""
                                    String token = Long.toHexString(new Random().nextLong());""", """
                                    byte[] bytes = new byte[32];
                                    new SecureRandom().nextBytes(bytes);
                                    String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);"""),
                            "typescript", new Example("""
                                    const token = Math.random().toString(36).slice(2);""", """
                                    const token = crypto.randomBytes(32).toString('base64url');   // ou crypto.randomUUID()"""),
                            "python", new Example("""
                                    token = str(random.random())""", """
                                    token = secrets.token_urlsafe(32)""")),
                    List.of("Test vérifiant la longueur (≥ 128 bits d'entropie) et l'unicité sur un grand nombre de jetons."),
                    List.of(CS + "Cryptographic_Storage_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-295", "CWE-297"), "Validation TLS désactivée",
                    "Les certificats ou le nom d'hôte du serveur distant ne sont pas vérifiés (gestionnaire « trust all », "
                            + "`rejectUnauthorized: false`, `verify=False`).",
                    "Interception et modification des échanges (homme du milieu), vol des identifiants transmis.",
                    List.of("Supprimer le contournement ; garder la vérification par défaut.",
                            "Pour une autorité interne, ajouter son certificat au magasin de confiance au lieu de tout accepter."),
                    examples(
                            "typescript", new Example("""
                                    const agent = new https.Agent({ rejectUnauthorized: false });""", """
                                    const agent = new https.Agent({ ca: fs.readFileSync('/etc/ssl/certs/corp-ca.pem') });"""),
                            "java", new Example("""
                                    TrustManager[] trustAll = { new X509TrustManager() { /* méthodes vides */ } };""", """
                                    // ajouter l'autorité interne au truststore : keytool -importcert -alias corp-ca -file corp-ca.pem -keystore truststore.p12
                                    // puis -Djavax.net.ssl.trustStore=truststore.p12 ; ne pas remplacer le TrustManager"""),
                            "python", new Example("""
                                    requests.get(url, verify=False)""", """
                                    requests.get(url, verify="/etc/ssl/certs/corp-ca.pem")""")),
                    List.of("Test d'intégration contre un serveur au certificat auto-signé : la connexion doit échouer."),
                    List.of(CS + "Transport_Layer_Security_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-352"), "Falsification de requête (CSRF)",
                    "Une action modifiant des données est acceptée sur la seule foi du cookie de session, sans jeton anti-CSRF.",
                    "Un site tiers fait exécuter des actions au nom de l'utilisateur connecté.",
                    List.of("Laisser la protection CSRF du framework active pour les sessions par cookie.",
                            "Cookies de session `SameSite=Lax` ou `Strict`.",
                            "Une API purement « Bearer token » (sans cookie) n'en a pas besoin : vérifier que c'est bien le cas."),
                    examples(
                            "java", new Example("""
                                    http.csrf(csrf -> csrf.disable());""", """
                                    http.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
                                    // API stateless avec JWT en en-tête Authorization : csrf peut rester désactivé, sans cookie de session""")),
                    List.of("Test MockMvc : une requête POST sans jeton CSRF reçoit 403."),
                    List.of(CS + "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-117", "CWE-93"), "Injection dans les journaux",
                    "Une valeur externe est écrite telle quelle dans les journaux : des retours à la ligne créent de fausses entrées.",
                    "Journaux falsifiés, enquêtes faussées, injection dans les outils qui lisent les journaux.",
                    List.of("Journaliser en format structuré (JSON) ou remplacer CR/LF avant écriture.",
                            "Utiliser les paramètres du logger plutôt que la concaténation."),
                    examples(
                            "java", new Example("""
                                    log.info("Connexion de " + username);""", """
                                    log.info("Connexion de {}", username.replaceAll("[\\\\r\\\\n]", "_"));"""),
                            "typescript", new Example("""
                                    console.log('login ' + username);""", """
                                    logger.info({ event: 'login', username });   // journal structuré""")),
                    List.of("Test avec un nom contenant `\\n2026-01-01 INFO admin connecté` : une seule entrée produite."),
                    List.of(CS + "Logging_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-532", "CWE-200", "CWE-209", "CWE-215", "CWE-497"), "Exposition d'informations sensibles",
                    "Des données sensibles (secrets, données personnelles, traces techniques) sont journalisées ou renvoyées "
                            + "à l'utilisateur.",
                    "Fuite de données personnelles ou de détails techniques utiles à un attaquant.",
                    List.of("Renvoyer un message d'erreur générique avec un identifiant de corrélation ; garder le détail dans les journaux.",
                            "Ne jamais journaliser mots de passe, jetons, en-têtes Authorization ou données de carte.",
                            "Désactiver les pages d'erreur détaillées et les points de diagnostic en production."),
                    examples(
                            "java", new Example("""
                                    return ResponseEntity.status(500).body(e.toString());""", """
                                    String id = UUID.randomUUID().toString();
                                    log.error("Erreur {}", id, e);
                                    return ResponseEntity.status(500).body(Map.of("error", "Erreur interne", "id", id));""")),
                    List.of("Test vérifiant qu'une erreur interne ne renvoie ni trace de pile ni nom de classe."),
                    List.of(CS + "Error_Handling_Cheat_Sheet.html", CS + "Logging_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-347", "CWE-345"), "Signature JWT non vérifiée",
                    "Un jeton JWT est décodé sans vérifier sa signature, ou l'algorithme accepté est choisi par le jeton (`none`).",
                    "N'importe qui fabrique un jeton valide et usurpe un utilisateur ou un administrateur.",
                    List.of("Vérifier la signature avec une clé ou un JWKS connu et une liste fermée d'algorithmes.",
                            "Vérifier aussi `exp`, `iss` et `aud`."),
                    examples(
                            "typescript", new Example("""
                                    const claims = jwt.decode(token);""", """
                                    const claims = jwt.verify(token, publicKey, { algorithms: ['RS256'], issuer: ISSUER, audience: AUDIENCE });"""),
                            "java", new Example("""
                                    Claims c = Jwts.parser().unsecured().build().parseUnsecuredClaims(token).getPayload();""", """
                                    Claims c = Jwts.parser().verifyWith(publicKey).requireIssuer(ISSUER).build()
                                            .parseSignedClaims(token).getPayload();""")),
                    List.of("Tests avec un jeton `alg: none`, une signature modifiée et un jeton expiré : tous refusés (401)."),
                    List.of(CS + "JSON_Web_Token_for_Java_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-614", "CWE-1004", "CWE-1275"), "Cookie sans attributs de sécurité",
                    "Un cookie de session est émis sans `Secure`, `HttpOnly` ou `SameSite`.",
                    "Vol de session par JavaScript (XSS) ou sur une connexion non chiffrée ; CSRF facilité.",
                    List.of("Émettre les cookies de session avec `Secure; HttpOnly; SameSite=Lax` (ou `Strict`)."),
                    examples(
                            "typescript", new Example("""
                                    res.cookie('session', id);""", """
                                    res.cookie('session', id, { secure: true, httpOnly: true, sameSite: 'lax' });"""),
                            "java", new Example("""
                                    response.addCookie(new Cookie("session", id));""", """
                                    ResponseCookie c = ResponseCookie.from("session", id).secure(true).httpOnly(true).sameSite("Lax").path("/").build();
                                    response.addHeader(HttpHeaders.SET_COOKIE, c.toString());""")),
                    List.of("Test vérifiant les attributs de l'en-tête Set-Cookie."),
                    List.of(CS + "Session_Management_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-942", "CWE-346"), "CORS trop permissif",
                    "Le serveur autorise toutes les origines (ou reflète l'origine reçue), parfois avec les cookies.",
                    "Un site tiers lit les réponses de l'API au nom de l'utilisateur connecté.",
                    List.of("Lister explicitement les origines autorisées ; jamais `*` avec `allowCredentials`."),
                    examples(
                            "java", new Example("""
                                    config.addAllowedOriginPattern("*");
                                    config.setAllowCredentials(true);""", """
                                    config.setAllowedOrigins(List.of("https://app.example.org"));
                                    config.setAllowCredentials(true);"""),
                            "typescript", new Example("""
                                    app.use(cors({ origin: true, credentials: true }));""", """
                                    app.use(cors({ origin: ['https://app.example.org'], credentials: true }));""")),
                    List.of("Test avec `Origin: https://evil.example` : pas d'en-tête Access-Control-Allow-Origin en réponse."),
                    List.of(CS + "HTML5_Security_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-1333", "CWE-400", "CWE-730"), "Expression régulière vulnérable (ReDoS) ou consommation non bornée",
                    "Une expression régulière à quantificateurs imbriqués, ou un traitement sans limite de taille, s'applique à une entrée externe.",
                    "Un seul message bien choisi bloque un cœur processeur : déni de service.",
                    List.of("Simplifier l'expression (pas de `(a+)+`, `(.*)*`), borner la taille de l'entrée avant le traitement.",
                            "Limiter taille des requêtes, nombre d'éléments et temps de traitement."),
                    examples(
                            "typescript", new Example("""
                                    /^(\\w+\\s?)*$/.test(input);""", """
                                    if (input.length > 200) throw new Error('trop long');
                                    /^[\\w ]{1,200}$/.test(input);""")),
                    List.of("Test de performance : une entrée de 10 000 caractères pathologiques est traitée en moins de 100 ms."),
                    List.of(CS + "Input_Validation_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-943"), "Injection NoSQL",
                    "Un objet venant de la requête est passé tel quel à une requête MongoDB : des opérateurs `$ne`, `$gt`, "
                            + "`$where` changent sa logique.",
                    "Contournement de l'authentification, lecture de documents non autorisés.",
                    List.of("Forcer le type attendu (chaîne) avant la requête, ou valider le corps avec un schéma.",
                            "Refuser les clés commençant par `$` (option `sanitizeFilter` de Mongoose)."),
                    examples(
                            "typescript", new Example("""
                                    User.findOne({ email: req.body.email, password: req.body.password });""", """
                                    const email = String(req.body.email);
                                    const user = await User.findOne({ email });   // puis vérification du mot de passe haché
                                    mongoose.set('sanitizeFilter', true);""")),
                    List.of("Test avec `{\"email\": {\"$ne\": null}}` : aucune connexion."),
                    List.of(CS + "Injection_Prevention_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-90"), "Injection LDAP",
                    "Un filtre LDAP est construit par concaténation d'une valeur externe.",
                    "Contournement d'authentification, énumération de l'annuaire.",
                    List.of("Encoder la valeur pour les filtres LDAP, ou utiliser les filtres paramétrés de la bibliothèque."),
                    examples(
                            "java", new Example("""
                                    String filter = "(uid=" + user + ")";""", """
                                    LdapQuery q = LdapQueryBuilder.query().where("uid").is(user);   // Spring LDAP encode la valeur""")),
                    List.of("Test avec `*)(uid=*))(|(uid=*` : aucun résultat inattendu."),
                    List.of(CS + "LDAP_Injection_Prevention_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-1321"), "Pollution de prototype",
                    "Une fusion ou affectation récursive accepte des clés `__proto__`, `constructor` ou `prototype` venant de l'extérieur.",
                    "Modification du comportement de tous les objets : contournement de contrôles, parfois exécution de code.",
                    List.of("Refuser ces clés lors des fusions, ou utiliser `Object.create(null)` / `Map` pour les données externes.",
                            "Mettre à jour les bibliothèques de fusion (lodash ≥ 4.17.21)."),
                    examples(
                            "typescript", new Example("""
                                    function merge(t, s) { for (const k in s) t[k] = typeof s[k] === 'object' ? merge(t[k] ?? {}, s[k]) : s[k]; return t; }""", """
                                    const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);
                                    function merge(t, s) {
                                      for (const k of Object.keys(s)) {
                                        if (FORBIDDEN.has(k)) continue;
                                        t[k] = typeof s[k] === 'object' && s[k] !== null ? merge(t[k] ?? Object.create(null), s[k]) : s[k];
                                      }
                                      return t;
                                    }""")),
                    List.of("Test avec `{\"__proto__\": {\"isAdmin\": true}}` : `({}).isAdmin` reste indéfini."),
                    List.of(CS + "Prototype_Pollution_Prevention_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-862", "CWE-863", "CWE-285", "CWE-639", "CWE-284"), "Contrôle d'accès manquant",
                    "Une opération est accessible sans vérifier que l'utilisateur a le droit d'agir sur cette ressource précise.",
                    "Lecture ou modification des données d'autres utilisateurs (IDOR), élévation de privilèges.",
                    List.of("Vérifier côté serveur le rôle ET la propriété de la ressource à chaque requête.",
                            "Refuser par défaut ; ne jamais se fier à un champ caché ou à l'interface."),
                    examples(
                            "java", new Example("""
                                    @GetMapping("/invoices/{id}")
                                    Invoice get(@PathVariable UUID id) { return repo.findById(id).orElseThrow(); }""", """
                                    @GetMapping("/invoices/{id}")
                                    @PreAuthorize("hasRole('USER')")
                                    Invoice get(@PathVariable UUID id, @AuthenticationPrincipal Jwt jwt) {
                                        return repo.findByIdAndOwner(id, jwt.getSubject()).orElseThrow(NotFoundException::new);
                                    }""")),
                    List.of("Test : l'utilisateur A demande la ressource de l'utilisateur B → 404 ou 403.",
                            "Test : rôle insuffisant → 403."),
                    List.of(CS + "Authorization_Cheat_Sheet.html", CS + "Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html")),

            new Entry(Set.of("CWE-915"), "Affectation de masse",
                    "Le corps de la requête est lié directement à une entité : des champs non prévus (`role`, `isAdmin`) sont modifiables.",
                    "Élévation de privilèges, modification de champs protégés.",
                    List.of("Lier la requête à un DTO ne contenant que les champs modifiables, puis copier explicitement."),
                    examples(
                            "java", new Example("""
                                    @PutMapping("/users/{id}") void update(@RequestBody User user) { repo.save(user); }""", """
                                    record ProfileUpdate(@Size(max = 100) String displayName) {}
                                    @PutMapping("/users/{id}") void update(@PathVariable UUID id, @RequestBody @Valid ProfileUpdate u) {
                                        User user = repo.findById(id).orElseThrow();
                                        user.setDisplayName(u.displayName());
                                    }""")),
                    List.of("Test envoyant `role: ADMIN` dans le corps : le rôle reste inchangé."),
                    List.of(CS + "Mass_Assignment_Cheat_Sheet.html")));

    static Optional<Entry> forCwes(List<String> cwes) {
        if (cwes == null) {
            return Optional.empty();
        }
        for (String cwe : cwes) {
            for (Entry e : ENTRIES) {
                if (e.cwes().contains(cwe)) {
                    return Optional.of(e);
                }
            }
        }
        return Optional.empty();
    }

    private static Map<String, Example> examples(Object... pairs) {
        Map<String, Example> m = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            m.put((String) pairs[i], (Example) pairs[i + 1]);
        }
        return m;
    }
}
