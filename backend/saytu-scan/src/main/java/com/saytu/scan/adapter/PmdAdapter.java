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
import com.saytu.scan.lang.SourceFiles;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * PMD 7 (BSD-style licence): Java bugs, bad practices, design and performance problems, with PMD's
 * own "quickstart" rule set. Suppressions written in the audited code ({@code // NOPMD},
 * {@code @SuppressWarnings("PMD")}) do not hide anything: the NOPMD marker is replaced by an
 * unguessable one and suppressed violations are reported like the others.
 */
public final class PmdAdapter implements ScannerAdapter {

    static final String MAIN = "net.sourceforge.pmd.cli.PmdCli";
    static final String RULESET = "rulesets/java/quickstart.xml";
    static final int MAX_FILES = 50_000;

    private final Path java;
    private final Path classpath;

    public PmdAdapter(Path java, Path classpath) {
        this.java = Objects.requireNonNull(java, "java");
        this.classpath = Objects.requireNonNull(classpath, "classpath");
    }

    @Override
    public ScannerId id() {
        return ScannerId.PMD;
    }

    @Override
    public Set<Language> languages() {
        return Set.of(Language.JAVA);
    }

    @Override
    public CommandSpec versionCommand(Path workDir) {
        return new CommandSpec(List.of(java.toString(), "-cp", classpath.resolve("*").toString(), MAIN, "--version"),
                AdapterSupport.environment(workDir), workDir, workDir.resolve("version.txt"));
    }

    /** The version text is a banner followed by "PMD 7.28.0 (...)". */
    @Override
    public String parseVersion(String stdout) {
        if (stdout == null) {
            return null;
        }
        return stdout.lines().map(String::strip).filter(l -> l.startsWith("PMD ")).findFirst()
                .map(l -> l.substring(4).split("\\s+")[0]).orElse(null);
    }

    @Override
    public boolean isApplicable(Path sourceDir) {
        return true;
    }

    @Override
    public Optional<String> rulesetVersion() {
        return Optional.of(RULESET);
    }

    @Override
    public CommandSpec buildCommand(ScanContext context) {
        Path report = context.workDir().resolve("pmd.json");
        Path list;
        try {
            list = SourceFiles.writeList(SourceFiles.list(context.sourceDir(), Set.of(Language.JAVA), MAX_FILES),
                    context.workDir().resolve("pmd-files.txt"));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        String threads = String.valueOf(Math.clamp(AdapterSupport.intSetting(context.settings(), "threads", 2), 1, 8));
        List<String> argv = new ArrayList<>(JvmTool.command(java, classpath, MAIN, context));
        argv.addAll(List.of("check",
                "--rulesets", RULESET,
                "--format", "json", "--report-file", report.toString(),
                "--file-list", list.toString(),
                "--no-cache", "--no-progress", "--no-fail-on-violation", "--show-suppressed",
                "--suppress-marker", "SAYTU-" + context.scanJobId().toString().replace("-", ""),
                "--threads", threads));
        return new CommandSpec(argv, AdapterSupport.environment(context.workDir()), context.workDir(), report);
    }

    /** 0 = done; 4 / 5 = violations or recoverable errors (unparsable file) reported in the report. */
    @Override
    public boolean isSuccessfulExit(int exitCode) {
        return exitCode == 0 || exitCode == 4 || exitCode == 5;
    }

    @Override
    public List<NormalizedFinding> parse(Path reportFile, ScanContext context) throws IOException {
        JsonNode root = AdapterSupport.readJson(reportFile);
        if (!root.get("files").isArray()) {
            throw new IOException("unexpected PMD report");
        }
        if (root.get("configurationErrors").size() > 0) {
            throw new IOException("PMD configuration error: " + root.get("configurationErrors").elements().getFirst());
        }
        List<NormalizedFinding> findings = new ArrayList<>();
        for (String section : List.of("files", "suppressedViolations")) {
            for (JsonNode file : root.get(section).elements()) {
                String path = AdapterSupport.relativePath(context.sourceDir(), file.get("filename").asText());
                if (path == null) {
                    continue;
                }
                for (JsonNode v : file.get("violations").elements()) {
                    findings.add(finding(v, path, context, section.equals("suppressedViolations")));
                }
            }
        }
        return findings;
    }

    private static NormalizedFinding finding(JsonNode v, String path, ScanContext context, boolean suppressed) {
        String rule = v.get("rule").asText();
        String ruleset = v.get("ruleset").asText();
        Integer start = AdapterSupport.positiveInt(v.get("beginline"));
        Integer end = AdapterSupport.positiveInt(v.get("endline"));
        String description = v.get("description").asText();
        String text = suppressed ? description + " (suppressed in the code, reported anyway)" : description;
        FindingType type = "Security".equalsIgnoreCase(ruleset) ? FindingType.SECURITY : FindingType.QUALITY;
        List<String> refs = new ArrayList<>();
        v.text("externalInfoUrl").ifPresent(refs::add);
        return new NormalizedFinding(ScannerId.PMD, "pmd:" + rule, type, severity((int) v.get("priority").asLong(3)),
                AdapterSupport.firstSentence(description, 200), text + (ruleset == null ? "" : "\n\nPMD category: " + ruleset),
                new NormalizedFinding.SourceLocation(path, start, end), List.of(), null, null, null, null,
                AdapterSupport.truncate(AdapterSupport.sourceLine(context.sourceDir(), path, start), 500),
                "See the PMD rule " + rule + " for the explanation and a compliant example.",
                AdapterSupport.urls(refs), AdapterSupport.contextHash(context.sourceDir(), path, start));
    }

    /** PMD priority 1 (high) .. 5 (low). */
    static Severity severity(int priority) {
        return switch (priority) {
            case 1 -> Severity.HIGH;
            case 2 -> Severity.MEDIUM;
            case 3 -> Severity.LOW;
            default -> Severity.INFO;
        };
    }
}
