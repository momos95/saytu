package com.saytu.scan.adapter;

import com.saytu.core.domain.FindingType;
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
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Opengrep (LGPL-2.1), multi-language SAST.
 * <p>
 * Rules come only from local directories: the packs shipped in the worker image and the optional packs
 * an administrator installs (see {@code scanners/opengrep/rules/README.md}); registry configurations
 * ({@code p/...}, URLs) are never used, so nothing is downloaded and no code leaves the machine.
 * Suppression mechanisms controlled by the analysed repository ({@code .semgrepignore},
 * {@code nosemgrep} comments) are ignored: an audit must not be switched off by the code it audits.
 * <p>
 * Settings ({@code scanner_config.settings}): {@code exclude} (comma-separated globs added to the
 * defaults), {@code jobs} (parallelism, default 2), {@code fileTimeoutSeconds} (per file and rule, default 30).
 */
public final class OpengrepAdapter implements ScannerAdapter {

    static final List<String> DEFAULT_EXCLUDES = List.of(
            "node_modules", "bower_components", "vendor", "third_party", "dist", "build", "target", "out",
            ".venv", "venv", "__pycache__", "*.min.js", "*.bundle.js", "*.map");

    private final Path executable;
    private final List<Path> ruleRoots;
    private final Path extractedRuntime;

    public OpengrepAdapter(Path executable, List<Path> ruleRoots) {
        this(executable, ruleRoots, null);
    }

    /**
     * @param executable       absolute path of the opengrep binary
     * @param ruleRoots        directories containing rule packs: each directory, and each sub-directory of a
     *                         directory that holds no YAML file directly, is passed as one {@code --config}
     * @param extractedRuntime cache directory where the self-extracting binary was unpacked once (read-only
     *                         in the worker image, ~250 MB); {@code null} extracts it in each run's directory
     */
    public OpengrepAdapter(Path executable, List<Path> ruleRoots, Path extractedRuntime) {
        this.executable = Objects.requireNonNull(executable, "executable");
        this.ruleRoots = List.copyOf(ruleRoots);
        this.extractedRuntime = extractedRuntime;
    }

    private Map<String, String> environment(Path workDir) {
        Map<String, String> env = AdapterSupport.environment(workDir);
        if (extractedRuntime != null) {
            env.put("XDG_CACHE_HOME", extractedRuntime.toString());
        }
        return env;
    }

    @Override
    public ScannerId id() {
        return ScannerId.OPENGREP;
    }

    @Override
    public CommandSpec versionCommand(Path workDir) {
        return new CommandSpec(List.of(executable.toString(), "--version"), environment(workDir),
                workDir, workDir.resolve("version.txt"));
    }

    @Override
    public String parseVersion(String stdout) {
        return stdout == null ? null : stdout.strip().lines().reduce((a, b) -> b).orElse(null);
    }

    @Override
    public boolean isApplicable(Path sourceDir) {
        return true;
    }

    /** Rule pack directories currently installed, in a stable order. */
    List<Path> packs() {
        List<Path> packs = new ArrayList<>();
        for (Path root : ruleRoots) {
            if (!Files.isDirectory(root)) {
                continue;
            }
            if (hasYamlDirectly(root)) {
                packs.add(root);
                continue;
            }
            try (Stream<Path> children = Files.list(root)) {
                children.filter(Files::isDirectory).sorted().forEach(packs::add);
            } catch (IOException e) {
                // unreadable optional directory: ignored, visible through the ruleset version
            }
        }
        return packs;
    }

    private static boolean hasYamlDirectly(Path dir) {
        try (Stream<Path> children = Files.list(dir)) {
            return children.anyMatch(p -> isYaml(p) && Files.isRegularFile(p));
        } catch (IOException e) {
            return false;
        }
    }

    private static boolean isYaml(Path p) {
        String n = p.getFileName().toString().toLowerCase(Locale.ROOT);
        return n.endsWith(".yaml") || n.endsWith(".yml");
    }

    @Override
    public Optional<String> rulesetVersion() {
        List<Path> packs = packs();
        if (packs.isEmpty()) {
            return Optional.empty();
        }
        try {
            String names = String.join("+", packs.stream().map(p -> p.getFileName().toString()).toList());
            return Optional.of(names + "@" + AdapterSupport.digestFiles(packs, OpengrepAdapter::isYaml));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    @Override
    public Optional<String> degradedReason() {
        return packs().isEmpty() ? Optional.of("no Opengrep rule pack installed") : Optional.empty();
    }

    @Override
    public CommandSpec buildCommand(ScanContext context) {
        Path report = context.workDir().resolve("opengrep.json");
        long maxMemoryMb = Math.max(256, context.limits().memoryBytes() / (1024 * 1024) * 3 / 4);
        List<String> argv = new ArrayList<>(List.of(
                executable.toString(), "scan",
                "--json", "--output=" + report,
                "--quiet",
                "--disable-version-check",
                "--no-rewrite-rule-ids",
                "--disable-nosem",
                "--x-ignore-semgrepignore-files",
                "--exclude-minified-files",
                "--max-target-bytes=" + 2_000_000,
                "--timeout=" + intSetting(context.settings(), "fileTimeoutSeconds", 30, 1, 600),
                "--max-memory=" + maxMemoryMb,
                "--jobs=" + intSetting(context.settings(), "jobs", 2, 1, 16)));
        List<String> excludes = new ArrayList<>(DEFAULT_EXCLUDES);
        String extra = context.settings().get("exclude");
        if (extra != null) {
            for (String e : extra.split(",")) {
                if (!e.isBlank() && !e.strip().startsWith("-")) {
                    excludes.add(e.strip());
                }
            }
        }
        for (String e : excludes) {
            argv.add("--exclude=" + e);
        }
        for (Path pack : packs()) {
            argv.add("--config=" + pack);
        }
        argv.add("--");
        argv.add(context.sourceDir().toString());
        return new CommandSpec(argv, environment(context.workDir()), context.workDir(), report);
    }

    /** 0 = scan completed (findings or not); other codes are errors (invalid rules, fatal error...). */
    @Override
    public boolean isSuccessfulExit(int exitCode) {
        return exitCode == 0;
    }

    @Override
    public List<NormalizedFinding> parse(Path reportFile, ScanContext context) throws IOException {
        JsonNode root = AdapterSupport.readJson(reportFile);
        if (!root.get("results").isArray()) {
            throw new IOException("unexpected Opengrep report: no results array");
        }
        List<NormalizedFinding> findings = new ArrayList<>();
        for (JsonNode r : root.get("results").elements()) {
            String ruleId = r.get("check_id").asText();
            String path = AdapterSupport.relativePath(context.sourceDir(), r.get("path").asText());
            if (ruleId == null || ruleId.isBlank() || path == null) {
                continue;
            }
            JsonNode extra = r.get("extra");
            JsonNode meta = extra.get("metadata");
            Integer start = AdapterSupport.positiveInt(r.get("start").get("line"));
            Integer end = AdapterSupport.positiveInt(r.get("end").get("line"));
            String message = extra.get("message").asText();
            String category = meta.get("category").asText();
            FindingType type = category == null || category.equalsIgnoreCase("security")
                    || meta.get("cwe").isArray() || meta.get("cwe").isTextual()
                    ? FindingType.SECURITY : FindingType.QUALITY;
            Severity severity = Severity.parseLenient(extra.get("severity").asText()).orElse(Severity.MEDIUM);

            List<String> refs = new ArrayList<>(AdapterSupport.stringOrList(meta.get("references")));
            meta.text("source").ifPresent(refs::add);
            String recommendation = meta.text("remediation")
                    .or(() -> meta.text("fix"))
                    .or(() -> extra.text("fix").map(f -> "Suggested replacement: " + f))
                    .orElse(null);

            findings.add(new NormalizedFinding(
                    ScannerId.OPENGREP, ruleId, type, severity,
                    AdapterSupport.firstSentence(message, 200),
                    message,
                    new NormalizedFinding.SourceLocation(path, start, end),
                    AdapterSupport.stringOrList(meta.get("cwe")),
                    null, null, null, null,
                    AdapterSupport.truncate(extra.get("lines").asText(), AdapterSupport.MAX_EVIDENCE_CHARS),
                    recommendation,
                    AdapterSupport.urls(refs),
                    AdapterSupport.contextHash(context.sourceDir(), path, start)));
        }
        return findings;
    }

    private static int intSetting(Map<String, String> settings, String key, int def, int min, int max) {
        String v = settings.get(key);
        if (v == null) {
            return def;
        }
        try {
            return Math.clamp(Integer.parseInt(v.strip()), min, max);
        } catch (NumberFormatException e) {
            return def;
        }
    }
}
