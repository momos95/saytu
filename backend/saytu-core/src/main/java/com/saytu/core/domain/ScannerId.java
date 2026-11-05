package com.saytu.core.domain;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/** Identifiers of the integrated scanners and the finding types each one can produce. */
public enum ScannerId {
    OPENGREP("opengrep", EnumSet.of(FindingType.SECURITY, FindingType.QUALITY), true),
    TRIVY("trivy", EnumSet.of(FindingType.DEPENDENCY, FindingType.SECURITY), true),
    GITLEAKS("gitleaks", EnumSet.of(FindingType.SECRET), true),
    PMD("pmd", EnumSet.of(FindingType.QUALITY, FindingType.SECURITY), true),
    CHECKSTYLE("checkstyle", EnumSet.of(FindingType.QUALITY), true),
    DEPENDENCY_CHECK("dependency-check", EnumSet.of(FindingType.DEPENDENCY), false);

    private final String key;
    private final Set<FindingType> producedTypes;
    private final boolean enabledByDefault;

    ScannerId(String key, Set<FindingType> producedTypes, boolean enabledByDefault) {
        this.key = key;
        this.producedTypes = producedTypes;
        this.enabledByDefault = enabledByDefault;
    }

    /** Stable identifier persisted in the database (column {@code scanner_id}). */
    public String key() {
        return key;
    }

    public Set<FindingType> producedTypes() {
        return EnumSet.copyOf(producedTypes);
    }

    public boolean enabledByDefault() {
        return enabledByDefault;
    }

    public static Optional<ScannerId> fromKey(String key) {
        if (key == null) {
            return Optional.empty();
        }
        String normalized = key.trim().toLowerCase(Locale.ROOT);
        return Arrays.stream(values()).filter(s -> s.key.equals(normalized)).findFirst();
    }
}
