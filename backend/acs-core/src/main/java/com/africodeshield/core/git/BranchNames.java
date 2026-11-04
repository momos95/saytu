package com.africodeshield.core.git;

import java.util.List;
import java.util.Optional;

/**
 * Validation of branch names typed by users, following {@code git check-ref-format --branch} rules.
 * Branch names end up as arguments of git and as URL path segments: rejecting anything git itself
 * would refuse closes option-injection ({@code -x}) and path tricks ({@code ..}).
 */
public final class BranchNames {

    public static final int MAX_LENGTH = 255;
    /** Default candidates of the PRESET branch mode, kept when they exist in the repository. */
    public static final List<String> PRESET = List.of("main", "master", "develop");

    private BranchNames() {
    }

    /** @return the reason the name is invalid, or empty when it is a valid branch name */
    public static Optional<String> problem(String name) {
        if (name == null || name.isEmpty()) {
            return Optional.of("empty name");
        }
        if (name.length() > MAX_LENGTH) {
            return Optional.of("longer than " + MAX_LENGTH + " characters");
        }
        if (name.startsWith("-")) {
            return Optional.of("must not start with '-'");
        }
        if (name.equals("@") || name.equals("HEAD")) {
            return Optional.of("reserved name");
        }
        if (name.contains("..") || name.contains("@{") || name.contains("//")) {
            return Optional.of("must not contain '..', '@{' or '//'");
        }
        if (name.startsWith("/") || name.endsWith("/") || name.endsWith(".")) {
            return Optional.of("must not start with '/' nor end with '/' or '.'");
        }
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c < 0x20 || c == 0x7f || c == ' ' || c == '~' || c == '^' || c == ':' || c == '?' || c == '*'
                    || c == '[' || c == '\\') {
                return Optional.of("forbidden character '" + (c < 0x20 || c == 0x7f ? "\\u" + (int) c : String.valueOf(c)) + "'");
            }
        }
        for (String component : name.split("/")) {
            if (component.startsWith(".")) {
                return Optional.of("a path component must not start with '.'");
            }
            if (component.endsWith(".lock")) {
                return Optional.of("a path component must not end with '.lock'");
            }
        }
        return Optional.empty();
    }

    public static boolean isValid(String name) {
        return problem(name).isEmpty();
    }

    /** Validates and returns the name, or throws {@link IllegalArgumentException} with a readable reason. */
    public static String require(String name) {
        problem(name).ifPresent(p -> {
            throw new IllegalArgumentException("Invalid branch name '" + (name == null ? "" : name.replaceAll("\\p{Cntrl}", "?"))
                    + "': " + p);
        });
        return name;
    }
}
