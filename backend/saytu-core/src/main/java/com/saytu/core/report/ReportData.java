package com.saytu.core.report;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeSet;

/**
 * Everything a report shows, already read from the database and already redacted (evidence is stored
 * redacted). Writers only format it: they never compute scores or decide what is a vulnerability.
 *
 * @param scope       human-readable filters ("Dépôt : acme/api", "Statut : OPEN")
 * @param totalFindings number of findings matching the filters (may exceed {@code findings.size()})
 */
public record ReportData(String title, Instant generatedAt, String generatedBy, String producerVersion,
                         List<String> scope, List<ScoreLine> scores, Map<String, Long> bySeverity,
                         List<ScanLine> scans, List<Finding> findings, long totalFindings) {

    public ReportData {
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(generatedAt, "generatedAt");
        generatedBy = generatedBy == null ? "?" : generatedBy;
        producerVersion = producerVersion == null ? "dev" : producerVersion;
        scope = List.copyOf(scope == null ? List.of() : scope);
        scores = List.copyOf(scores == null ? List.of() : scores);
        bySeverity = bySeverity == null ? Map.of() : java.util.Collections.unmodifiableMap(new LinkedHashMap<>(bySeverity));
        scans = List.copyOf(scans == null ? List.of() : scans);
        findings = List.copyOf(findings == null ? List.of() : findings);
    }

    /** True when the report lists fewer findings than match the filters. */
    public boolean truncated() {
        return totalFindings > findings.size();
    }

    /** A score line: global, an organisation, a repository or a branch. Null scores = coverage too low. */
    public record ScoreLine(String label, Double security, Double quality, Double global, double coverage,
                            String reliability, String formulaVersion, Instant computedAt) {
    }

    /** Latest finished analysis of a repository branch with what each tool did. */
    public record ScanLine(String repository, String branch, String commitSha, Instant finishedAt, String status,
                           List<String> languages, List<ToolRun> tools) {
        public ScanLine {
            languages = List.copyOf(languages == null ? List.of() : languages);
            tools = List.copyOf(tools == null ? List.of() : tools);
        }
    }

    public record ToolRun(String scanner, String status, String toolVersion, String rulesetVersion, int findings,
                          String message) {
    }

    public record Finding(String id, String fingerprint, String repository, String branch, String commitSha,
                          String type, String severity, String status, String scanner, List<String> scanners,
                          String ruleId, String title, String description, List<String> cwes, String cve,
                          BigDecimal cvss, String filePath, Integer startLine, Integer endLine,
                          String packageEcosystem, String packageName, String packageVersion, String fixedVersion,
                          String evidence, String recommendation, List<String> references, String statusReason,
                          Instant firstSeenAt, Instant lastSeenAt) {
        public Finding {
            scanners = List.copyOf(scanners == null ? List.of() : scanners);
            cwes = List.copyOf(cwes == null ? List.of() : cwes);
            references = List.copyOf(references == null ? List.of() : references);
        }

        /** "src/App.java:12-14", "pom.xml", or "" */
        public String location() {
            if (filePath == null || filePath.isEmpty()) {
                return "";
            }
            if (startLine == null) {
                return filePath;
            }
            return filePath + ":" + startLine + (endLine != null && endLine > startLine ? "-" + endLine : "");
        }
    }

    /** A vulnerable package version, across the findings that name it. */
    public record Dependency(String ecosystem, String name, String version, String fixedVersions, String worstSeverity,
                             List<String> cves, List<String> repositories, int findings) {
    }

    /** Packages named by the findings of the report, worst first. */
    public List<Dependency> dependencies() {
        Map<String, List<Finding>> byPackage = new LinkedHashMap<>();
        for (Finding f : findings) {
            if (f.packageName() != null && !f.packageName().isBlank()) {
                String key = Objects.toString(f.packageEcosystem(), "") + "\u0000" + f.packageName() + "\u0000"
                        + Objects.toString(f.packageVersion(), "");
                byPackage.computeIfAbsent(key, k -> new ArrayList<>()).add(f);
            }
        }
        List<Dependency> result = new ArrayList<>();
        for (List<Finding> group : byPackage.values()) {
            Finding first = group.getFirst();
            TreeSet<String> cves = new TreeSet<>();
            TreeSet<String> fixed = new TreeSet<>();
            TreeSet<String> repos = new TreeSet<>();
            String worst = first.severity();
            for (Finding f : group) {
                if (f.cve() != null) {
                    cves.add(f.cve());
                }
                if (f.fixedVersion() != null && !f.fixedVersion().isBlank()) {
                    fixed.add(f.fixedVersion());
                }
                repos.add(f.repository());
                if (severityRank(f.severity()) < severityRank(worst)) {
                    worst = f.severity();
                }
            }
            result.add(new Dependency(first.packageEcosystem(), first.packageName(), first.packageVersion(),
                    String.join(", ", fixed), worst, List.copyOf(cves), List.copyOf(repos), group.size()));
        }
        result.sort(Comparator.comparingInt((Dependency d) -> severityRank(d.worstSeverity()))
                .thenComparing(Dependency::name));
        return result;
    }

    /** CRITICAL 0 … INFO 4, unknown 5. */
    public static int severityRank(String severity) {
        return switch (severity == null ? "" : severity) {
            case "CRITICAL" -> 0;
            case "HIGH" -> 1;
            case "MEDIUM" -> 2;
            case "LOW" -> 3;
            case "INFO" -> 4;
            default -> 5;
        };
    }
}
