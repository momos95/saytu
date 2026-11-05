package com.saytu.scan.lang;

import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Directories and files that are not the team's own source code (dependencies, build outputs,
 * generated or minified files). Shared by the language detection and the tools' exclusions so that
 * labels and findings describe the same files.
 */
public final class SourceFilters {

    public static final Set<String> EXCLUDED_DIRECTORIES = Set.of(
            ".git", "node_modules", "bower_components", "jspm_packages", "vendor", "third_party", "third-party",
            "dist", "build", "target", "out", "bin", "obj", ".gradle", ".mvn", ".idea", ".vscode",
            ".venv", "venv", "env", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
            ".next", ".nuxt", ".angular", ".svelte-kit", "coverage", ".terraform", "Pods", "DerivedData");

    /** Glob-style suffixes of generated files. */
    public static final List<String> GENERATED_SUFFIXES = List.of(
            ".min.js", ".min.css", ".bundle.js", ".chunk.js", ".map", ".pb.go", "_pb2.py", ".g.dart", ".freezed.dart",
            ".designer.cs", ".generated.cs", ".d.ts");

    private SourceFilters() {
    }

    public static boolean isExcludedDirectory(String name) {
        return EXCLUDED_DIRECTORIES.contains(name);
    }

    public static boolean isGenerated(String fileName) {
        String n = fileName.toLowerCase(Locale.ROOT);
        for (String suffix : GENERATED_SUFFIXES) {
            if (n.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }
}
