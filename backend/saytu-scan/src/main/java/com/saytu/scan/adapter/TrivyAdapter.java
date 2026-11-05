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
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Trivy (Apache-2.0): vulnerable dependencies (lockfiles and manifests) and misconfigurations
 * (Dockerfile, Kubernetes, Terraform, Helm, CloudFormation...).
 * <p>
 * Runs fully offline: the vulnerability database is read from {@code cacheDir} (filled by the
 * worker's database update job, or copied by hand on an air-gapped site, see docs/operations.md),
 * {@code --offline-scan} forbids lookups to package registries, and the misconfiguration checks
 * embedded in the binary are used. Without the database, only configuration files are analysed and
 * the execution is reported as degraded: missing data never reads as "no vulnerability".
 */
public final class TrivyAdapter implements ScannerAdapter {

    private final Path executable;
    private final Path cacheDir;

    /**
     * @param executable absolute path of the trivy binary
     * @param cacheDir   Trivy cache directory holding {@code db/trivy.db} (and optionally {@code java-db/})
     */
    public TrivyAdapter(Path executable, Path cacheDir) {
        this.executable = Objects.requireNonNull(executable, "executable");
        this.cacheDir = Objects.requireNonNull(cacheDir, "cacheDir");
    }

    @Override
    public ScannerId id() {
        return ScannerId.TRIVY;
    }

    @Override
    public CommandSpec versionCommand(Path workDir) {
        return new CommandSpec(List.of(executable.toString(), "--version"), AdapterSupport.environment(workDir),
                workDir, workDir.resolve("version.txt"));
    }

    @Override
    public String parseVersion(String stdout) {
        if (stdout == null) {
            return null;
        }
        return stdout.lines().filter(l -> l.startsWith("Version:")).map(l -> l.substring(8).strip()).findFirst()
                .orElse(stdout.strip().lines().findFirst().orElse(null));
    }

    @Override
    public boolean isApplicable(Path sourceDir) {
        return true;
    }

    boolean hasVulnerabilityDb() {
        return Files.isRegularFile(cacheDir.resolve("db").resolve("trivy.db"));
    }

    boolean hasJavaDb() {
        return Files.isRegularFile(cacheDir.resolve("java-db").resolve("trivy-java.db"));
    }

    @Override
    public Optional<String> rulesetVersion() {
        Path metadata = cacheDir.resolve("db").resolve("metadata.json");
        if (!Files.isRegularFile(metadata)) {
            return Optional.empty();
        }
        try {
            JsonNode m = AdapterSupport.readJson(metadata);
            return Optional.of("trivy-db v" + m.get("Version").asText() + " " + m.get("UpdatedAt").asText());
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    @Override
    public Optional<String> degradedReason() {
        return hasVulnerabilityDb() ? Optional.empty()
                : Optional.of("Trivy vulnerability database missing: dependencies were NOT checked, only configuration files");
    }

    @Override
    public CommandSpec buildCommand(ScanContext context) {
        Path report = context.workDir().resolve("trivy.json");
        long seconds = Math.max(30, context.limits().timeout().toSeconds() - 15);
        List<String> argv = new ArrayList<>(List.of(
                executable.toString(), "fs",
                "--quiet", "--no-progress",
                "--format", "json", "--output", report.toString(),
                "--scanners", hasVulnerabilityDb() ? "vuln,misconfig" : "misconfig",
                "--cache-dir", cacheDir.toString(),
                "--cache-backend", "memory",
                "--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--skip-vex-repo-update",
                "--offline-scan", "--disable-telemetry", "--skip-version-check",
                "--timeout", seconds + "s",
                "--exit-code", "0"));
        if (!hasJavaDb()) {
            // archives need the Java index database; lockfiles and pom.xml do not
            argv.addAll(List.of("--skip-files", "**/*.jar,**/*.war,**/*.ear,**/*.par"));
        }
        argv.add(context.sourceDir().toString());
        Map<String, String> env = AdapterSupport.environment(context.workDir());
        env.put("GOMEMLIMIT", (context.limits().memoryBytes() / 10 * 8) + "B");
        return new CommandSpec(argv, env, context.workDir(), report);
    }

    @Override
    public boolean isSuccessfulExit(int exitCode) {
        return exitCode == 0;
    }

    @Override
    public List<NormalizedFinding> parse(Path reportFile, ScanContext context) throws IOException {
        JsonNode root = AdapterSupport.readJson(reportFile);
        if (!root.isObject() || root.get("SchemaVersion").isAbsent()) {
            throw new IOException("unexpected Trivy report");
        }
        List<NormalizedFinding> findings = new ArrayList<>();
        for (JsonNode result : root.get("Results").elements()) {
            String target = AdapterSupport.relativePath(context.sourceDir(), result.get("Target").asText());
            String ecosystem = result.get("Type").asText();
            for (JsonNode v : result.get("Vulnerabilities").elements()) {
                vulnerability(v, target, ecosystem).ifPresent(findings::add);
            }
            for (JsonNode m : result.get("Misconfigurations").elements()) {
                misconfiguration(m, target, context).ifPresent(findings::add);
            }
        }
        return findings;
    }

    private static Optional<NormalizedFinding> vulnerability(JsonNode v, String target, String ecosystem) {
        String id = v.get("VulnerabilityID").asText();
        String pkg = v.get("PkgName").asText();
        if (id == null || id.isBlank() || pkg == null || pkg.isBlank()) {
            return Optional.empty();
        }
        String installed = v.get("InstalledVersion").asText();
        String fixed = v.get("FixedVersion").asText();
        Severity severity = Severity.parseLenient(v.get("Severity").asText()).orElse(Severity.INFO);

        // CVSS from the source that set the severity, else NVD, else any source
        JsonNode cvss = v.get("CVSS");
        String source = v.get("SeveritySource").asText();
        JsonNode chosen = source != null && cvss.get(source).isObject() ? cvss.get(source) : cvss.get("nvd");
        if (!chosen.isObject() && cvss.isObject()) {
            for (String name : List.of("ghsa", "redhat", "nvd")) {
                if (cvss.get(name).isObject()) {
                    chosen = cvss.get(name);
                    break;
                }
            }
        }
        Double score = null;
        String vector = null;
        if (chosen.isObject()) {
            score = chosen.get("V40Score").asDouble() != null ? chosen.get("V40Score").asDouble() : chosen.get("V3Score").asDouble();
            vector = chosen.get("V40Score").asDouble() != null ? chosen.get("V40Vector").asText() : chosen.get("V3Vector").asText();
            if (score != null && (score < 0 || score > 10)) {
                score = null;
            }
        }

        Integer line = null;
        for (JsonNode loc : v.get("Locations").elements()) {
            line = AdapterSupport.positiveInt(loc.get("StartLine"));
            break;
        }
        String recommendation = fixed != null && !fixed.isBlank()
                ? "Upgrade " + pkg + " from " + installed + " to " + fixed + " or later, then regenerate the lockfile."
                : "No fixed version is published yet: check the advisory for a workaround, or replace or remove the dependency.";
        List<String> refs = new ArrayList<>();
        v.text("PrimaryURL").ifPresent(refs::add);
        refs.addAll(v.get("References").textElements());

        return Optional.of(new NormalizedFinding(
                ScannerId.TRIVY, id, FindingType.DEPENDENCY, severity,
                v.text("Title").orElse(id + " in " + pkg),
                v.get("Description").asText(),
                target == null ? null : new NormalizedFinding.SourceLocation(target, line, line),
                v.get("CweIDs").textElements(),
                id, score, vector,
                new NormalizedFinding.Dependency(ecosystem, pkg, installed, fixed),
                null, recommendation, AdapterSupport.urls(refs), null));
    }

    private static Optional<NormalizedFinding> misconfiguration(JsonNode m, String target, ScanContext context) {
        if (!"FAIL".equals(m.get("Status").asText())) {
            return Optional.empty();
        }
        String id = m.text("AVDID").or(() -> m.text("ID")).orElse(null);
        if (id == null || target == null) {
            return Optional.empty();
        }
        JsonNode cause = m.get("CauseMetadata");
        Integer start = AdapterSupport.positiveInt(cause.get("StartLine"));
        Integer end = AdapterSupport.positiveInt(cause.get("EndLine"));
        StringBuilder evidence = new StringBuilder();
        for (JsonNode line : cause.get("Code").get("Lines").elements()) {
            if (line.get("IsCause").asBoolean(false) && line.get("Content").asText() != null) {
                evidence.append(line.get("Content").asText()).append('\n');
            }
        }
        String message = m.get("Message").asText();
        String description = m.get("Description").asText();
        List<String> refs = new ArrayList<>();
        m.text("PrimaryURL").ifPresent(refs::add);
        refs.addAll(m.get("References").textElements());
        return Optional.of(new NormalizedFinding(
                ScannerId.TRIVY, id, FindingType.SECURITY,
                Severity.parseLenient(m.get("Severity").asText()).orElse(Severity.MEDIUM),
                m.text("Title").orElse(id),
                message == null ? description : message + (description == null ? "" : "\n\n" + description),
                new NormalizedFinding.SourceLocation(target, start, end),
                List.of(), null, null, null, null,
                AdapterSupport.truncate(evidence.toString(), AdapterSupport.MAX_EVIDENCE_CHARS),
                m.get("Resolution").asText(),
                AdapterSupport.urls(refs),
                AdapterSupport.contextHash(context.sourceDir(), target, start)));
    }
}
