package com.saytu.scan.adapter;

import com.saytu.core.domain.FindingType;
import com.saytu.core.domain.ScannerId;
import com.saytu.core.domain.Severity;
import com.saytu.core.finding.NormalizedFinding;
import com.saytu.core.finding.SecretRedactor;
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
 * Gitleaks (MIT): secrets in the files of the checked-out branch.
 * <p>
 * The configuration is always the one shipped in the worker image ({@code --config}), never a
 * {@code .gitleaks.toml} or {@code .gitleaksignore} from the analysed repository, and inline
 * {@code gitleaks:allow} comments are ignored unless the {@code honorInlineAllow} setting is
 * {@code true}: the audited code cannot hide its own secrets.
 * <p>
 * The report holds the raw secrets: it stays in the job's private directory, deleted after the run.
 * Only a SHA-256 of each secret (stable fingerprint across line moves) and a masked excerpt leave
 * this adapter.
 */
public final class GitleaksAdapter implements ScannerAdapter {

    /** Rules whose matches are entropy-based guesses rather than a known token format. */
    private static final Set<String> GENERIC_RULES = Set.of("generic-api-key", "generic-secret");
    private static final Set<String> CRITICAL_RULES = Set.of("private-key");
    static final String RECOMMENDATION = "Consider the secret compromised: revoke or rotate it at its issuer first, "
            + "then remove it from the code (and from the Git history if the repository is shared) and load it "
            + "at run time from the environment or a secret manager.";

    private final Path executable;
    private final Path config;

    /**
     * @param executable absolute path of the gitleaks binary
     * @param config     gitleaks configuration shipped with SAYTU (default rules of the same version)
     */
    public GitleaksAdapter(Path executable, Path config) {
        this.executable = Objects.requireNonNull(executable, "executable");
        this.config = Objects.requireNonNull(config, "config");
    }

    @Override
    public ScannerId id() {
        return ScannerId.GITLEAKS;
    }

    @Override
    public CommandSpec versionCommand(Path workDir) {
        return new CommandSpec(List.of(executable.toString(), "version"), AdapterSupport.environment(workDir),
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

    @Override
    public Optional<String> rulesetVersion() {
        try {
            return Optional.of(config.getFileName() + "@" + AdapterSupport.sha256Hex(Files.readString(config)).substring(0, 12));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    @Override
    public Optional<String> degradedReason() {
        return Files.isRegularFile(config) ? Optional.empty() : Optional.of("gitleaks configuration missing: " + config);
    }

    @Override
    public CommandSpec buildCommand(ScanContext context) {
        Path report = context.workDir().resolve("gitleaks.json");
        Path emptyIgnoreDir = context.workDir().resolve("no-ignore");
        List<String> argv = new ArrayList<>(List.of(
                executable.toString(), "dir",
                "--no-banner", "--no-color", "--log-level", "warn",
                "--config", config.toString(),
                "--gitleaks-ignore-path", emptyIgnoreDir.toString(),
                "--report-format", "json", "--report-path", report.toString(),
                "--exit-code", "0",
                "--max-target-megabytes", "10"));
        if (!"true".equalsIgnoreCase(context.settings().getOrDefault("honorInlineAllow", "false"))) {
            argv.add("--ignore-gitleaks-allow");
        }
        argv.add(context.sourceDir().toString());
        Map<String, String> env = AdapterSupport.environment(context.workDir());
        env.put("GOMEMLIMIT", (context.limits().memoryBytes() / 10 * 8) + "B");
        try {
            Files.createDirectories(emptyIgnoreDir);
        } catch (IOException e) {
            throw new IllegalStateException("cannot prepare gitleaks working directory", e);
        }
        return new CommandSpec(argv, env, context.workDir(), report);
    }

    @Override
    public boolean isSuccessfulExit(int exitCode) {
        return exitCode == 0;
    }

    @Override
    public List<NormalizedFinding> parse(Path reportFile, ScanContext context) throws IOException {
        JsonNode root = AdapterSupport.readJson(reportFile);
        if (!root.isArray()) {
            throw new IOException("unexpected gitleaks report: not an array");
        }
        List<NormalizedFinding> findings = new ArrayList<>();
        for (JsonNode leak : root.elements()) {
            String ruleId = leak.get("RuleID").asText();
            String path = AdapterSupport.relativePath(context.sourceDir(), leak.get("File").asText());
            if (ruleId == null || ruleId.isBlank() || path == null) {
                continue;
            }
            String secret = leak.get("Secret").asText();
            Integer start = AdapterSupport.positiveInt(leak.get("StartLine"));
            Integer end = AdapterSupport.positiveInt(leak.get("EndLine"));
            String evidence = SecretRedactor.redact(
                    AdapterSupport.truncate(leak.get("Match").asText(), AdapterSupport.MAX_EVIDENCE_CHARS),
                    secret == null ? List.of() : List.of(secret));
            String contextHash = secret == null || secret.isEmpty() ? null : AdapterSupport.sha256Hex(ruleId + ":" + secret);
            Severity severity = CRITICAL_RULES.contains(ruleId) ? Severity.CRITICAL
                    : GENERIC_RULES.contains(ruleId) ? Severity.MEDIUM : Severity.HIGH;
            String description = leak.get("Description").asText();
            findings.add(new NormalizedFinding(
                    ScannerId.GITLEAKS, ruleId, FindingType.SECRET, severity,
                    AdapterSupport.firstSentence(description, 200),
                    description,
                    new NormalizedFinding.SourceLocation(path, start, end),
                    List.of("CWE-798"), null, null, null, null,
                    evidence, RECOMMENDATION,
                    List.of("https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"),
                    contextHash));
        }
        return findings;
    }
}
