package com.saytu.core.report;

import com.saytu.core.report.ReportData.Finding;
import com.saytu.core.report.ReportData.ScanLine;
import com.saytu.core.report.ReportData.ToolRun;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * SARIF 2.1.0 (OASIS) export: one run per scanner, results located relative to the repository root
 * ({@code %SRCROOT%}). Human triage (accepted risk, false positive) becomes an external, accepted
 * suppression with its justification; resolved findings are not exported.
 */
public final class SarifReport {

    static final String SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
    static final Map<String, String> TOOL_NAMES = Map.ofEntries(
            Map.entry("opengrep", "Opengrep"), Map.entry("trivy", "Trivy"), Map.entry("gitleaks", "Gitleaks"),
            Map.entry("pmd", "PMD"), Map.entry("checkstyle", "Checkstyle"), Map.entry("eslint", "ESLint"),
            Map.entry("phpcs", "PHP_CodeSniffer"), Map.entry("cppcheck", "Cppcheck"), Map.entry("sqlfluff", "SQLFluff"),
            Map.entry("dependency-check", "OWASP Dependency-Check"));

    private SarifReport() {
    }

    public static String write(ReportData r) {
        Map<String, List<Finding>> byScanner = new TreeMap<>();
        for (Finding f : r.findings()) {
            if (!"RESOLVED".equals(f.status())) {
                byScanner.computeIfAbsent(f.scanner(), k -> new ArrayList<>()).add(f);
            }
        }
        JsonOut j = new JsonOut().beginObject().field("$schema", SCHEMA).field("version", "2.1.0");
        j.name("runs").beginArray();
        for (Map.Entry<String, List<Finding>> e : byScanner.entrySet()) {
            run(j, r, e.getKey(), e.getValue());
        }
        return j.endArray().endObject().toString();
    }

    private static void run(JsonOut j, ReportData r, String scanner, List<Finding> findings) {
        Map<String, Finding> rules = new LinkedHashMap<>();
        for (Finding f : findings) {
            rules.putIfAbsent(f.ruleId(), f);
        }
        List<String> ruleIds = new ArrayList<>(rules.keySet());
        j.beginObject();
        j.name("tool").beginObject().name("driver").beginObject()
                .field("name", TOOL_NAMES.getOrDefault(scanner, scanner))
                .optional("version", toolVersion(r, scanner))
                .field("informationUri", "https://github.com/momos95/saytu");
        j.name("rules").beginArray();
        for (Finding f : rules.values()) {
            j.beginObject().field("id", f.ruleId()).field("name", f.ruleId())
                    .name("shortDescription").beginObject().field("text", f.title()).endObject();
            String help = f.references().isEmpty() ? null : f.references().getFirst();
            if (help != null && help.startsWith("https://")) {
                j.field("helpUri", help);
            }
            j.name("defaultConfiguration").beginObject().field("level", level(f.severity())).endObject();
            List<String> tags = new ArrayList<>();
            tags.add(f.type().toLowerCase(java.util.Locale.ROOT));
            tags.addAll(f.cwes());
            j.name("properties").beginObject().field("tags", tags).endObject();
            j.endObject();
        }
        j.endArray().endObject().endObject();
        j.name("results").beginArray();
        for (Finding f : findings) {
            result(j, f, ruleIds.indexOf(f.ruleId()));
        }
        j.endArray();
        j.name("properties").beginObject().field("generatedBy", "SAYTU " + r.producerVersion())
                .field("generatedAt", r.generatedAt()).endObject();
        j.endObject();
    }

    private static void result(JsonOut j, Finding f, int ruleIndex) {
        j.beginObject().field("ruleId", f.ruleId()).field("ruleIndex", ruleIndex).field("level", level(f.severity()));
        String text = f.title();
        if (f.description() != null && !f.description().isBlank() && !f.description().equals(f.title())) {
            text = f.title() + "\n\n" + f.description();
        }
        j.name("message").beginObject().field("text", text).endObject();
        String uri = uri(f.filePath());
        if (uri != null) {
            j.name("locations").beginArray().beginObject().name("physicalLocation").beginObject()
                    .name("artifactLocation").beginObject().field("uri", uri).field("uriBaseId", "%SRCROOT%").endObject();
            if (f.startLine() != null) {
                j.name("region").beginObject().field("startLine", f.startLine());
                if (f.endLine() != null && f.endLine() >= f.startLine()) {
                    j.field("endLine", f.endLine());
                }
                j.endObject();
            }
            j.endObject().endObject().endArray();
        }
        if (f.fingerprint() != null) {
            j.name("partialFingerprints").beginObject().field("saytu/v1", f.fingerprint()).endObject();
        }
        if ("ACCEPTED_RISK".equals(f.status()) || "FALSE_POSITIVE".equals(f.status())) {
            j.name("suppressions").beginArray().beginObject().field("kind", "external").field("status", "accepted")
                    .field("justification", f.status() + (f.statusReason() == null ? "" : ": " + f.statusReason()))
                    .endObject().endArray();
        }
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("saytu/severity", f.severity());
        props.put("saytu/type", f.type());
        props.put("saytu/status", f.status());
        props.put("repository", f.repository());
        props.put("branch", f.branch());
        if (f.commitSha() != null) {
            props.put("commitSha", f.commitSha());
        }
        if (f.cve() != null) {
            props.put("cve", f.cve());
        }
        if (f.cvss() != null) {
            props.put("security-severity", f.cvss().toPlainString());
        }
        if (f.packageName() != null) {
            props.put("package", f.packageName() + (f.packageVersion() == null ? "" : "@" + f.packageVersion()));
        }
        if (f.fixedVersion() != null) {
            props.put("fixedVersion", f.fixedVersion());
        }
        if (f.scanners().size() > 1) {
            props.put("saytu/scanners", f.scanners());
        }
        j.field("properties", props);
        j.endObject();
    }

    /** CRITICAL/HIGH = error, MEDIUM = warning, LOW/INFO = note. */
    static String level(String severity) {
        return switch (severity == null ? "" : severity) {
            case "CRITICAL", "HIGH" -> "error";
            case "MEDIUM" -> "warning";
            default -> "note";
        };
    }

    /** Relative URI reference of a repository path (percent-encoded), or null if unusable. */
    static String uri(String path) {
        if (path == null || path.isBlank() || path.startsWith("/") || path.contains("\\") || path.matches("(?s)(.*/)?\\.\\.(/.*)?")) {
            return null;
        }
        try {
            return new URI(null, null, path, null).toASCIIString();
        } catch (URISyntaxException e) {
            return null;
        }
    }

    private static String toolVersion(ReportData r, String scanner) {
        String version = null;
        for (ScanLine s : r.scans()) {
            for (ToolRun t : s.tools()) {
                if (t.scanner().equals(scanner) && t.toolVersion() != null) {
                    if (version != null && !version.equals(t.toolVersion())) {
                        return null; // several versions in the report: none is "the" version
                    }
                    version = t.toolVersion();
                }
            }
        }
        return version;
    }
}
