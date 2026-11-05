package com.saytu.scan.lang;

import com.saytu.core.domain.Language;
import com.saytu.core.domain.LanguageProfile;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Detects the languages of a checkout from file names (extension, or full name for Dockerfile,
 * Jenkinsfile...), skipping dependencies, build outputs and generated files.
 * <p>
 * C/C++ headers ({@code .h}) are ambiguous: they count as C++ when the checkout has C++ sources and
 * no C source, as C otherwise. Contents are never read, so detection cannot be fooled into running
 * anything and stays fast on large trees.
 */
public final class LanguageDetector {

    private static final Map<String, Language> EXTENSIONS = new HashMap<>();
    private static final Map<String, Language> FILE_NAMES = new HashMap<>();

    static {
        map(Language.JAVA, "java");
        map(Language.KOTLIN, "kt", "kts");
        map(Language.SCALA, "scala", "sc");
        map(Language.GROOVY, "groovy", "gradle", "gvy");
        map(Language.TYPESCRIPT, "ts", "tsx", "mts", "cts");
        map(Language.JAVASCRIPT, "js", "jsx", "mjs", "cjs");
        map(Language.VUE, "vue");
        map(Language.SVELTE, "svelte");
        map(Language.PYTHON, "py", "pyi", "pyw");
        map(Language.GO, "go");
        map(Language.PHP, "php", "phtml", "php3", "php4", "php5", "php7", "php8", "phps");
        map(Language.C, "c");
        map(Language.CPP, "cpp", "cc", "cxx", "c++", "hpp", "hh", "hxx", "h++", "ipp", "inl", "tpp");
        map(Language.CSHARP, "cs", "csx", "cshtml", "razor");
        map(Language.SQL, "sql", "pks", "pkb", "pls", "plsql", "pck", "ddl");
        map(Language.RUBY, "rb", "rake", "gemspec");
        map(Language.RUST, "rs");
        map(Language.SWIFT, "swift");
        map(Language.DART, "dart");
        map(Language.OBJECTIVE_C, "m", "mm");
        map(Language.SHELL, "sh", "bash", "zsh", "ksh");
        map(Language.POWERSHELL, "ps1", "psm1", "psd1");
        map(Language.TERRAFORM, "tf", "tfvars", "hcl");
        map(Language.DOCKERFILE, "dockerfile");
        map(Language.HTML, "html", "htm", "xhtml");
        map(Language.CSS, "css", "scss", "sass", "less");
        FILE_NAMES.put("dockerfile", Language.DOCKERFILE);
        FILE_NAMES.put("containerfile", Language.DOCKERFILE);
        FILE_NAMES.put("jenkinsfile", Language.GROOVY);
        FILE_NAMES.put("gemfile", Language.RUBY);
        FILE_NAMES.put("rakefile", Language.RUBY);
    }

    private static void map(Language language, String... extensions) {
        for (String e : extensions) {
            EXTENSIONS.put(e, language);
        }
    }

    /** Language of one file name, or {@code null}. */
    public static Language languageOf(String fileName) {
        String n = fileName.toLowerCase(Locale.ROOT);
        Language byName = FILE_NAMES.get(n);
        if (byName != null) {
            return byName;
        }
        if (n.startsWith("dockerfile.") || n.startsWith("containerfile.")) {
            return Language.DOCKERFILE;
        }
        if (SourceFilters.isGenerated(n)) {
            return null;
        }
        int dot = n.lastIndexOf('.');
        if (dot <= 0 || dot == n.length() - 1) {
            return null;
        }
        return EXTENSIONS.get(n.substring(dot + 1));
    }

    public LanguageProfile detect(Path root) throws IOException {
        Map<Language, long[]> stats = new EnumMap<>(Language.class);
        long[] headers = new long[2];
        long[] analysed = new long[1];
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                if (!dir.equals(root) && SourceFilters.isExcludedDirectory(dir.getFileName().toString())) {
                    return FileVisitResult.SKIP_SUBTREE;
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (!attrs.isRegularFile()) {
                    return FileVisitResult.CONTINUE;
                }
                analysed[0]++;
                String name = file.getFileName().toString();
                if (name.toLowerCase(Locale.ROOT).endsWith(".h")) {
                    headers[0]++;
                    headers[1] += attrs.size();
                    return FileVisitResult.CONTINUE;
                }
                Language language = languageOf(name);
                if (language != null) {
                    long[] s = stats.computeIfAbsent(language, l -> new long[2]);
                    s[0]++;
                    s[1] += attrs.size();
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                return FileVisitResult.CONTINUE;
            }
        });
        if (headers[0] > 0) {
            Language owner = stats.containsKey(Language.CPP) && !stats.containsKey(Language.C)
                    ? Language.CPP
                    : stats.containsKey(Language.OBJECTIVE_C) && !stats.containsKey(Language.C) ? Language.OBJECTIVE_C
                    : Language.C;
            long[] s = stats.computeIfAbsent(owner, l -> new long[2]);
            s[0] += headers[0];
            s[1] += headers[1];
        }
        Map<Language, LanguageProfile.Stats> result = new EnumMap<>(Language.class);
        stats.forEach((l, s) -> result.put(l, new LanguageProfile.Stats(s[0], s[1])));
        return new LanguageProfile(result, analysed[0]);
    }
}
