package com.saytu.scan.lang;

import com.saytu.core.domain.Language;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Files of given languages in a checkout, with the same exclusions as the language detection.
 * Tools receive this list (or the exclusion pattern) rather than walking the tree themselves, so
 * that dependencies and generated code never end up in the quality findings.
 */
public final class SourceFiles {

    private SourceFiles() {
    }

    /** Files of the given languages, sorted; at most {@code max} (0 = no limit). */
    public static List<Path> list(Path root, Set<Language> languages, int max) throws IOException {
        boolean headers = languages.contains(Language.C) || languages.contains(Language.CPP);
        List<Path> files = new ArrayList<>();
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
                String name = file.getFileName().toString();
                Language l = LanguageDetector.languageOf(name);
                boolean header = headers && name.toLowerCase(Locale.ROOT).endsWith(".h");
                if (header || (l != null && languages.contains(l))) {
                    files.add(file);
                    if (max > 0 && files.size() >= max) {
                        return FileVisitResult.TERMINATE;
                    }
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                return FileVisitResult.CONTINUE;
            }
        });
        files.sort(null);
        return files;
    }

    /** Writes one absolute path per line (tools' --file-list option). */
    public static Path writeList(List<Path> files, Path target) throws IOException {
        Files.writeString(target, files.stream().map(Path::toString).collect(Collectors.joining("\n", "", "\n")),
                StandardCharsets.UTF_8);
        return target;
    }

    /** Regular expression matching an excluded directory at the end of an absolute path. */
    public static String excludedDirectoryRegex() {
        return "[/\\\\](" + SourceFilters.EXCLUDED_DIRECTORIES.stream().sorted()
                .map(d -> d.replace(".", "\\.")).collect(Collectors.joining("|")) + ")$";
    }
}
