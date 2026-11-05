package com.saytu.scan.adapter;

import com.saytu.core.finding.FindingFingerprint;
import com.saytu.git.json.JsonNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/** Helpers shared by the scanner adapters. */
final class AdapterSupport {

    /** Reports larger than this are refused rather than loaded in memory. */
    static final long MAX_REPORT_BYTES = 512L * 1024 * 1024;
    static final int MAX_EVIDENCE_CHARS = 2_000;
    static final int MAX_REFERENCES = 10;
    static final String SYSTEM_PATH = "/usr/local/bin:/usr/bin:/bin";

    private AdapterSupport() {
    }

    static JsonNode readJson(Path report) throws IOException {
        if (!Files.isRegularFile(report)) {
            throw new IOException("the tool produced no report");
        }
        long size = Files.size(report);
        if (size > MAX_REPORT_BYTES) {
            throw new IOException("report too large: " + size + " bytes");
        }
        try {
            return JsonNode.parse(Files.readString(report, StandardCharsets.UTF_8));
        } catch (JsonNode.JsonParseException e) {
            throw new IOException("unreadable report: " + e.getMessage(), e);
        }
    }

    /** Minimal environment for a tool: no inherited variable, private HOME and TMPDIR. */
    static Map<String, String> environment(Path workDir) {
        Map<String, String> env = new LinkedHashMap<>();
        env.put("PATH", SYSTEM_PATH);
        env.put("HOME", workDir.toString());
        env.put("TMPDIR", workDir.toString());
        env.put("XDG_CACHE_HOME", workDir.resolve(".cache").toString());
        env.put("LANG", "C.UTF-8");
        return env;
    }

    /**
     * Path of a reported file relative to the analysed tree, with '/' separators.
     * Returns {@code null} for paths outside the tree (never trusted).
     */
    static String relativePath(Path sourceDir, String reported) {
        if (reported == null || reported.isBlank()) {
            return null;
        }
        Path root = sourceDir.toAbsolutePath().normalize();
        Path p = Path.of(reported);
        Path absolute = (p.isAbsolute() ? p : root.resolve(p)).normalize();
        if (!absolute.startsWith(root) || absolute.equals(root)) {
            return null;
        }
        return root.relativize(absolute).toString().replace('\\', '/');
    }

    /** Context hash of a line of the analysed file, {@code null} when unavailable. */
    static String contextHash(Path sourceDir, String relativePath, Integer line) {
        String text = sourceLine(sourceDir, relativePath, line);
        return text == null ? null : FindingFingerprint.contextHash(text);
    }

    static String sourceLine(Path sourceDir, String relativePath, Integer line) {
        if (relativePath == null || line == null || line < 1) {
            return null;
        }
        Path file = sourceDir.resolve(relativePath).normalize();
        if (!file.startsWith(sourceDir.normalize()) || !Files.isRegularFile(file)) {
            return null;
        }
        try (Stream<String> lines = Files.lines(file, StandardCharsets.UTF_8)) {
            return lines.skip(line - 1L).findFirst().orElse(null);
        } catch (IOException | java.io.UncheckedIOException e) {
            return null; // binary or non-UTF-8 file: the fingerprint falls back to the line number
        }
    }

    static String truncate(String text, int max) {
        if (text == null) {
            return null;
        }
        String stripped = text.strip();
        return stripped.length() <= max ? stripped : stripped.substring(0, max - 1) + "…";
    }

    /** First sentence of a message, for titles. */
    static String firstSentence(String text, int max) {
        if (text == null || text.isBlank()) {
            return null;
        }
        String t = text.strip().replaceAll("\\s+", " ");
        int dot = t.indexOf(". ");
        if (dot > 20) {
            t = t.substring(0, dot + 1);
        }
        return truncate(t, max);
    }

    /** Accepts a JSON string or an array of strings. */
    static List<String> stringOrList(JsonNode node) {
        if (node.isArray()) {
            return node.textElements();
        }
        if (node.isTextual() && !node.asText().isBlank()) {
            return List.of(node.asText());
        }
        return List.of();
    }

    static List<String> urls(List<String> candidates) {
        List<String> out = new ArrayList<>();
        for (String c : candidates) {
            if (c != null && (c.startsWith("https://") || c.startsWith("http://")) && !out.contains(c)) {
                out.add(c);
                if (out.size() == MAX_REFERENCES) {
                    break;
                }
            }
        }
        return out;
    }

    static Integer positiveInt(JsonNode node) {
        long v = node.asLong(-1);
        return v >= 1 && v <= Integer.MAX_VALUE ? (int) v : null;
    }

    static String sha256Hex(String text) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Digest of a set of files (path + content), used as rule-pack version. */
    static String digestFiles(List<Path> roots, java.util.function.Predicate<Path> filter) throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        for (Path root : roots) {
            if (!Files.isDirectory(root)) {
                continue;
            }
            List<Path> files;
            try (Stream<Path> walk = Files.walk(root)) {
                files = walk.filter(Files::isRegularFile).filter(filter).sorted().toList();
            }
            for (Path f : files) {
                digest.update(root.relativize(f).toString().getBytes(StandardCharsets.UTF_8));
                digest.update(Files.readAllBytes(f));
            }
        }
        return HexFormat.of().formatHex(digest.digest()).substring(0, 12);
    }
}
