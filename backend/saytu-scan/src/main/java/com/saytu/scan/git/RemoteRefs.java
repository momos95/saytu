package com.saytu.scan.git;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Branches and tags of a remote repository as listed by {@code git ls-remote --heads --tags}; annotated
 * tags are resolved to the commit they point to (the peeled {@code ^{}} line wins).
 */
public record RemoteRefs(Map<String, String> branches, Map<String, String> tags) {

    private static final Pattern LINE = Pattern.compile("^([0-9a-f]{40}|[0-9a-f]{64})\\t(refs/(heads|tags)/(.+))$");
    static final int MAX_REFS = 20_000;

    public RemoteRefs {
        branches = Collections.unmodifiableMap(new LinkedHashMap<>(branches));
        tags = Collections.unmodifiableMap(new LinkedHashMap<>(tags));
    }

    /** Parses ls-remote output; malformed lines are ignored, at most 20 000 refs are kept. */
    public static RemoteRefs parse(String output) {
        Map<String, String> branches = new LinkedHashMap<>();
        Map<String, String> tags = new LinkedHashMap<>();
        Map<String, String> peeled = new LinkedHashMap<>();
        int n = 0;
        for (String line : output.split("\n")) {
            var m = LINE.matcher(line.strip());
            if (!m.matches() || ++n > MAX_REFS) {
                continue;
            }
            String sha = m.group(1);
            String name = m.group(4);
            if ("heads".equals(m.group(3))) {
                branches.put(name, sha);
            } else if (name.endsWith("^{}")) {
                peeled.put(name.substring(0, name.length() - 3), sha);
            } else {
                tags.putIfAbsent(name, sha);
            }
        }
        peeled.forEach((name, sha) -> tags.put(name, sha));
        return new RemoteRefs(branches, tags);
    }
}
