package com.saytu.core.domain;

import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

/**
 * Languages recognised in a checkout. {@link Kind#CODE} and {@link Kind#INFRASTRUCTURE} languages are
 * shown as labels and select the quality tools; {@link Kind#MARKUP} ones are counted but not shown.
 */
public enum Language {
    JAVA("java", "Java", Kind.CODE),
    KOTLIN("kotlin", "Kotlin", Kind.CODE),
    SCALA("scala", "Scala", Kind.CODE),
    GROOVY("groovy", "Groovy", Kind.CODE),
    TYPESCRIPT("typescript", "TypeScript", Kind.CODE),
    JAVASCRIPT("javascript", "JavaScript", Kind.CODE),
    VUE("vue", "Vue", Kind.CODE),
    SVELTE("svelte", "Svelte", Kind.CODE),
    PYTHON("python", "Python", Kind.CODE),
    GO("go", "Go", Kind.CODE),
    PHP("php", "PHP", Kind.CODE),
    C("c", "C", Kind.CODE),
    CPP("cpp", "C++", Kind.CODE),
    CSHARP("csharp", "C#", Kind.CODE),
    SQL("sql", "SQL", Kind.CODE),
    RUBY("ruby", "Ruby", Kind.CODE),
    RUST("rust", "Rust", Kind.CODE),
    SWIFT("swift", "Swift", Kind.CODE),
    DART("dart", "Dart", Kind.CODE),
    OBJECTIVE_C("objective-c", "Objective-C", Kind.CODE),
    SHELL("shell", "Shell", Kind.CODE),
    POWERSHELL("powershell", "PowerShell", Kind.CODE),
    DOCKERFILE("dockerfile", "Dockerfile", Kind.INFRASTRUCTURE),
    TERRAFORM("terraform", "Terraform", Kind.INFRASTRUCTURE),
    HTML("html", "HTML", Kind.MARKUP),
    CSS("css", "CSS", Kind.MARKUP);

    public enum Kind { CODE, INFRASTRUCTURE, MARKUP }

    private final String key;
    private final String label;
    private final Kind kind;

    Language(String key, String label, Kind kind) {
        this.key = key;
        this.label = label;
        this.kind = kind;
    }

    /** Stable identifier persisted in JSON columns. */
    public String key() {
        return key;
    }

    /** Display name. */
    public String label() {
        return label;
    }

    public Kind kind() {
        return kind;
    }

    public static Optional<Language> fromKey(String key) {
        if (key == null) {
            return Optional.empty();
        }
        String k = key.trim().toLowerCase(Locale.ROOT);
        return Arrays.stream(values()).filter(l -> l.key.equals(k)).findFirst();
    }
}
