package com.saytu.core.scoring;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/** Version strings as published in advisories ("2.13.4.2", "v1.2.3", "4.1.94.Final"). */
public final class Versions {

    private Versions() {
    }

    /**
     * Highest of the fixed versions listed by the advisories of one package (each value may itself be a
     * comma-separated list): upgrading to it fixes every advisory that names a fix.
     */
    public static Optional<String> highest(Collection<String> fixedVersions) {
        String best = null;
        for (String value : fixedVersions) {
            if (value == null) {
                continue;
            }
            for (String v : value.split(",")) {
                String candidate = v.strip();
                if (!candidate.isEmpty() && (best == null || compare(candidate, best) > 0)) {
                    best = candidate;
                }
            }
        }
        return Optional.ofNullable(best);
    }

    /** Compares numeric parts numerically and other parts alphabetically; "1.10" > "1.9". */
    public static int compare(String a, String b) {
        List<String> x = parts(a);
        List<String> y = parts(b);
        for (int i = 0; i < Math.max(x.size(), y.size()); i++) {
            String p = i < x.size() ? x.get(i) : "0";
            String q = i < y.size() ? y.get(i) : "0";
            int c;
            if (p.chars().allMatch(Character::isDigit) && q.chars().allMatch(Character::isDigit)) {
                c = new java.math.BigInteger(p).compareTo(new java.math.BigInteger(q));
            } else {
                c = p.compareToIgnoreCase(q);
            }
            if (c != 0) {
                return c;
            }
        }
        return 0;
    }

    private static List<String> parts(String v) {
        List<String> parts = new ArrayList<>();
        String s = v.strip();
        if (s.startsWith("v") || s.startsWith("V")) {
            s = s.substring(1);
        }
        for (String p : s.split("[.\\-+_:]")) {
            if (!p.isEmpty()) {
                parts.add(p);
            }
        }
        return parts;
    }
}
