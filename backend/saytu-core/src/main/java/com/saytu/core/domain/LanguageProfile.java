package com.saytu.core.domain;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Languages found in a checkout, with file count and size per language.
 *
 * @param stats         per language (absent = no file)
 * @param analysedFiles regular files considered (excluded directories and generated files left out)
 */
public record LanguageProfile(Map<Language, Stats> stats, long analysedFiles) {

    /** A label is shown for a code language holding at least this share of the code bytes... */
    static final double LABEL_MIN_SHARE = 0.01;
    /** ...or at least this many files. */
    static final long LABEL_MIN_FILES = 5;

    public record Stats(long files, long bytes) {
        public Stats {
            if (files < 0 || bytes < 0) {
                throw new IllegalArgumentException("negative stats");
            }
        }
    }

    public LanguageProfile {
        Objects.requireNonNull(stats, "stats");
        EnumMap<Language, Stats> copy = new EnumMap<>(Language.class);
        stats.forEach((l, s) -> {
            if (s.files() > 0) {
                copy.put(l, s);
            }
        });
        stats = Collections.unmodifiableMap(copy);
    }

    public static LanguageProfile empty() {
        return new LanguageProfile(Map.of(), 0);
    }

    public boolean contains(Language language) {
        return stats.containsKey(language);
    }

    public boolean containsAny(Collection<Language> languages) {
        return languages.stream().anyMatch(this::contains);
    }

    /** Code and infrastructure languages worth a label, most present first. */
    public List<Language> labels() {
        long codeBytes = stats.entrySet().stream().filter(e -> e.getKey().kind() != Language.Kind.MARKUP)
                .mapToLong(e -> e.getValue().bytes()).sum();
        List<Language> labels = new ArrayList<>();
        stats.entrySet().stream()
                .filter(e -> e.getKey().kind() != Language.Kind.MARKUP)
                .filter(e -> e.getValue().files() >= LABEL_MIN_FILES
                        || (codeBytes > 0 && (double) e.getValue().bytes() / codeBytes >= LABEL_MIN_SHARE))
                .sorted(Comparator.comparingLong((Map.Entry<Language, Stats> e) -> e.getValue().bytes()).reversed()
                        .thenComparing(e -> e.getKey().ordinal()))
                .forEach(e -> labels.add(e.getKey()));
        return labels;
    }

    /** Share of the code bytes (0..1) held by a language. */
    public double share(Language language) {
        long codeBytes = stats.entrySet().stream().filter(e -> e.getKey().kind() != Language.Kind.MARKUP)
                .mapToLong(e -> e.getValue().bytes()).sum();
        Stats s = stats.get(language);
        return s == null || codeBytes == 0 ? 0 : (double) s.bytes() / codeBytes;
    }
}
