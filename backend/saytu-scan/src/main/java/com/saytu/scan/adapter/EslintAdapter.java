package com.saytu.scan.adapter;

import com.saytu.core.domain.FindingType;
import com.saytu.core.domain.Language;
import com.saytu.core.domain.ScannerId;
import com.saytu.core.domain.Severity;
import com.saytu.core.finding.NormalizedFinding;
import com.saytu.core.scan.CommandSpec;
import com.saytu.core.scan.ScanContext;
import com.saytu.core.scan.ScannerAdapter;
import com.saytu.git.json.JsonNode;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * ESLint (MIT) with typescript-eslint and eslint-plugin-security: JavaScript and TypeScript bugs,
 * bad practices and dangerous patterns. The configuration is SAYTU's
 * ({@code scanners/eslint/eslint.config.mjs}); the repository's configuration is never loaded and
 * {@code eslint-disable} comments are ignored.
 * <p>
 * ESLint only lints files under its working directory: it runs from the job directory, which holds
 * both the sources and this run's private directory, and lints the sources only.
 */
public final class EslintAdapter implements ScannerAdapter {

    private final Path node;
    private final Path home;

    /**
     * @param node node executable
     * @param home directory holding {@code eslint.config.mjs} and {@code node_modules}
     */
    public EslintAdapter(Path node, Path home) {
        this.node = Objects.requireNonNull(node, "node");
        this.home = Objects.requireNonNull(home, "home");
    }

    private Path cli() {
        return home.resolve("node_modules").resolve("eslint").resolve("bin").resolve("eslint.js");
    }

    private Path config() {
        return home.resolve("eslint.config.mjs");
    }

    @Override
    public ScannerId id() {
        return ScannerId.ESLINT;
    }

    @Override
    public Set<Language> languages() {
        return Set.of(Language.JAVASCRIPT, Language.TYPESCRIPT);
    }

    @Override
    public CommandSpec versionCommand(Path workDir) {
        return new CommandSpec(List.of(node.toString(), cli().toString(), "--version"), environment(workDir), workDir,
                workDir.resolve("version.txt"));
    }

    @Override
    public String parseVersion(String stdout) {
        return stdout == null ? null : stdout.strip().replaceFirst("^v", "");
    }

    @Override
    public boolean isApplicable(Path sourceDir) {
        return true;
    }

    @Override
    public Optional<String> rulesetVersion() {
        try {
            return Optional.of("eslint.config.mjs@" + AdapterSupport.sha256Hex(Files.readString(config())).substring(0, 12));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    private Map<String, String> environment(Path workDir) {
        Map<String, String> env = AdapterSupport.environment(workDir);
        env.put("NODE_OPTIONS", "--max-old-space-size=1536");
        return env;
    }

    @Override
    public CommandSpec buildCommand(ScanContext context) {
        Path work = context.workDir();
        Path source = context.sourceDir();
        Path parent = work.getParent();
        Path cwd = parent != null && source.normalize().startsWith(parent.normalize()) ? parent : work;
        Path report = work.resolve("eslint.json");
        long heapMb = Math.max(256, context.limits().memoryBytes() / (1024 * 1024) * 3 / 4);
        List<String> argv = new ArrayList<>(List.of(node.toString(), "--max-old-space-size=" + heapMb, cli().toString(),
                "--config", config().toString(),
                "--format", "json", "--output-file", report.toString(),
                "--no-inline-config", "--no-warn-ignored", "--no-error-on-unmatched-pattern",
                "--", source.toString()));
        Map<String, String> env = environment(work);
        env.remove("NODE_OPTIONS");
        return new CommandSpec(argv, env, cwd, report);
    }

    /** 0 = no problem, 1 = problems found, 2 = configuration or internal error. */
    @Override
    public boolean isSuccessfulExit(int exitCode) {
        return exitCode == 0 || exitCode == 1;
    }

    @Override
    public List<NormalizedFinding> parse(Path reportFile, ScanContext context) throws IOException {
        JsonNode root = AdapterSupport.readJson(reportFile);
        if (!root.isArray()) {
            throw new IOException("unexpected ESLint report");
        }
        List<NormalizedFinding> findings = new ArrayList<>();
        for (JsonNode file : root.elements()) {
            String path = AdapterSupport.relativePath(context.sourceDir(), file.get("filePath").asText());
            if (path == null) {
                continue;
            }
            for (JsonNode m : file.get("messages").elements()) {
                String rule = m.get("ruleId").asText();
                if (rule == null || rule.isBlank() || m.get("fatal").asBoolean(false)) {
                    continue; // parsing errors and ignore notices are not findings
                }
                Integer start = AdapterSupport.positiveInt(m.get("line"));
                Integer end = AdapterSupport.positiveInt(m.get("endLine"));
                String message = m.get("message").asText();
                boolean securityRule = rule.startsWith("security/");
                findings.add(new NormalizedFinding(ScannerId.ESLINT, "eslint:" + rule,
                        securityRule ? FindingType.SECURITY : FindingType.QUALITY,
                        severity(rule, (int) m.get("severity").asLong(1)),
                        AdapterSupport.firstSentence(message, 200), message + "\n\nRule: " + rule,
                        new NormalizedFinding.SourceLocation(path, start, end == null ? start : end),
                        List.of(), null, null, null, null,
                        AdapterSupport.truncate(AdapterSupport.sourceLine(context.sourceDir(), path, start), 500),
                        recommendation(rule), List.of(documentation(rule)),
                        AdapterSupport.contextHash(context.sourceDir(), path, start)));
            }
        }
        return findings;
    }

    static Severity severity(String rule, int eslintSeverity) {
        if (rule.startsWith("security/")) {
            return Severity.MEDIUM;
        }
        return eslintSeverity >= 2 ? Severity.LOW : Severity.INFO;
    }

    static String documentation(String rule) {
        if (rule.startsWith("@typescript-eslint/")) {
            return "https://typescript-eslint.io/rules/" + rule.substring("@typescript-eslint/".length());
        }
        if (rule.startsWith("security/")) {
            return "https://github.com/eslint-community/eslint-plugin-security/blob/main/docs/rules/"
                    + rule.substring("security/".length()) + ".md";
        }
        return "https://eslint.org/docs/latest/rules/" + rule;
    }

    static String recommendation(String rule) {
        return switch (rule) {
            case "no-unused-vars", "@typescript-eslint/no-unused-vars" -> "Remove the unused variable or import.";
            case "@typescript-eslint/no-explicit-any" -> "Replace any with a precise type, or unknown plus a type guard.";
            case "no-eval", "security/detect-eval-with-expression" -> "Remove eval; parse data with JSON.parse.";
            case "security/detect-child-process" -> "Use execFile/spawn with an argument array, never a shell command built from input.";
            case "security/detect-non-literal-fs-filename" -> "Validate the path against an allowed directory before using it.";
            case "security/detect-object-injection" -> "Check the key against an allow-list (or use a Map) before indexing the object.";
            default -> "See the rule documentation for the explanation and a compliant example.";
        };
    }
}
