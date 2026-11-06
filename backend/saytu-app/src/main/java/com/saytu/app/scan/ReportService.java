package com.saytu.app.scan;

import com.saytu.app.audit.AuditService;
import com.saytu.app.scan.ScoreService.ScoreView;
import com.saytu.app.web.ResourceNotFoundException;
import com.saytu.core.report.HtmlReport;
import com.saytu.core.report.JsonReport;
import com.saytu.core.report.PdfReport;
import com.saytu.core.report.ReportData;
import com.saytu.core.report.ReportData.Finding;
import com.saytu.core.report.ReportData.ScanLine;
import com.saytu.core.report.ReportData.ScoreLine;
import com.saytu.core.report.ReportData.ToolRun;
import com.saytu.core.report.SarifReport;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.info.BuildProperties;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Types;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Builds reports on demand from the stored results (nothing is re-analysed, nothing leaves the server).
 * Each generation is recorded in {@code report} (format, filters, hash, size) and in the audit trail.
 */
@Service
public class ReportService {

    /** Detailed findings per format; the summary counts always cover every matching finding. */
    static final int READABLE_LIMIT = 2_000;
    static final int EXPORT_LIMIT = 20_000;
    static final int MAX_SCANS = 500;
    static final int MAX_SCORE_LINES = 200;

    public enum Format {
        HTML("text/html;charset=UTF-8", "html"),
        PDF("application/pdf", "pdf"),
        JSON("application/json", "json"),
        SARIF("application/sarif+json", "sarif");

        public final String contentType;
        public final String extension;

        Format(String contentType, String extension) {
            this.contentType = contentType;
            this.extension = extension;
        }

        static Format parse(String value) {
            try {
                return valueOf(value == null ? "" : value.strip().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Unknown report format: " + value + " (html, pdf, json, sarif)");
            }
        }
    }

    public record Report(Format format, String fileName, byte[] content) {
    }

    private final NamedParameterJdbcTemplate jdbc;
    private final ScoreService scores;
    private final AuditService audit;
    private final ObjectProvider<BuildProperties> build;
    private final Clock clock;

    public ReportService(NamedParameterJdbcTemplate jdbc, ScoreService scores, AuditService audit,
                         ObjectProvider<BuildProperties> build, Clock clock) {
        this.jdbc = jdbc;
        this.scores = scores;
        this.audit = audit;
        this.build = build;
        this.clock = clock;
    }

    /** Statuses reported when the request names none: what still needs work. */
    static FindingQueryService.Filter withDefaultStatus(FindingQueryService.Filter f) {
        if (f.statuses() != null) {
            return f;
        }
        return new FindingQueryService.Filter(f.repositoryId(), f.branch(), f.severities(), f.types(), List.of("OPEN"),
                f.scanner(), f.text());
    }

    @Transactional
    public Report generate(String formatName, FindingQueryService.Filter requested) {
        Format format = Format.parse(formatName);
        FindingQueryService.Filter filter = withDefaultStatus(requested);
        String repositoryName = null;
        if (filter.repositoryId() != null) {
            List<String> names = jdbc.queryForList("SELECT full_name FROM source_repository WHERE id = :id",
                    new MapSqlParameterSource("id", filter.repositoryId()), String.class);
            if (names.isEmpty()) {
                throw new ResourceNotFoundException("Repository " + filter.repositoryId() + " not found");
            }
            repositoryName = names.getFirst();
        }
        MapSqlParameterSource p = FindingQueryService.filterParams(filter);
        Long total = jdbc.queryForObject(ScanSql.COUNT_FINDINGS, p, Long.class);
        Map<String, Long> bySeverity = new LinkedHashMap<>();
        for (String s : List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")) {
            bySeverity.put(s, 0L);
        }
        jdbc.query(ScanSql.FINDING_COUNTS_BY_SEVERITY, p, rs -> {
            bySeverity.put(rs.getString(1), rs.getLong(2));
        });
        p.addValue("limit", format == Format.HTML || format == Format.PDF ? READABLE_LIMIT : EXPORT_LIMIT);
        List<Finding> findings = jdbc.query(InsightSql.REPORT_FINDINGS, p, (rs, i) -> new Finding(
                JdbcRows.uuid(rs, "id").toString(), rs.getString("fingerprint"), rs.getString("repository_name"),
                rs.getString("branch"), rs.getString("commit_sha"), rs.getString("type"), rs.getString("severity"),
                rs.getString("status"), rs.getString("scanner_id"), JdbcRows.strings(rs, "scanners"),
                rs.getString("rule_id"), rs.getString("title"), rs.getString("description"),
                JdbcRows.strings(rs, "cwe_ids"), rs.getString("cve_id"), rs.getBigDecimal("cvss_score"),
                rs.getString("file_path"), JdbcRows.integer(rs, "start_line"), JdbcRows.integer(rs, "end_line"),
                rs.getString("package_ecosystem"), rs.getString("package_name"), rs.getString("package_version"),
                rs.getString("fixed_version"), rs.getString("evidence_redacted"), rs.getString("recommendation"),
                JdbcRows.strings(rs, "references_urls"), rs.getString("status_reason"),
                JdbcRows.instant(rs, "first_seen_at"), JdbcRows.instant(rs, "last_seen_at")));

        Instant now = clock.instant();
        String user = currentUser();
        String version = build.getIfAvailable() == null ? "dev" : build.getIfAvailable().getVersion();
        String title = repositoryName == null ? "Rapport d'audit SAYTU" : "Rapport d'audit — " + repositoryName;
        ReportData data = new ReportData(title, now, user, version, scope(filter, repositoryName),
                scoreLines(filter, repositoryName), bySeverity, scans(filter), findings, total == null ? 0 : total);

        byte[] content = switch (format) {
            case HTML -> HtmlReport.write(data).getBytes(StandardCharsets.UTF_8);
            case PDF -> PdfReport.write(data);
            case JSON -> JsonReport.write(data).getBytes(StandardCharsets.UTF_8);
            case SARIF -> SarifReport.write(data).getBytes(StandardCharsets.UTF_8);
        };
        Map<String, Object> filters = filterMap(filter);
        jdbc.update(InsightSql.INSERT_REPORT, new MapSqlParameterSource().addValue("format", format.name())
                .addValue("sha256", sha256(content)).addValue("size", (long) content.length)
                .addValue("filters", Json.write(filters)).addValue("user", user));
        Map<String, Object> details = new LinkedHashMap<>(filters);
        details.put("format", format.name());
        details.put("findings", findings.size());
        audit.record("REPORT_GENERATED", "report", format.name(), details);
        String slug = repositoryName == null ? "global" : repositoryName.replaceAll("[^A-Za-z0-9._-]+", "-");
        String fileName = "saytu-" + slug + "-" + DateTimeFormatter.ofPattern("yyyyMMdd-HHmm").withZone(ZoneOffset.UTC).format(now)
                + "." + format.extension;
        return new Report(format, fileName, content);
    }

    private List<ScoreLine> scoreLines(FindingQueryService.Filter filter, String repositoryName) {
        List<ScoreLine> lines = new ArrayList<>();
        ScoreService.Summary summary = scores.summary();
        if (filter.repositoryId() == null) {
            if (summary.global() != null) {
                lines.add(line("Global", summary.global()));
            }
            summary.repositories().stream().sorted(Comparator.comparing(ScoreService.RepositoryScore::repository))
                    .limit(MAX_SCORE_LINES).forEach(r -> lines.add(line(r.repository(), r.score())));
            return lines;
        }
        summary.repositories().stream().filter(r -> r.repositoryId().equals(filter.repositoryId())).findFirst()
                .ifPresent(r -> lines.add(line(repositoryName + " (branche la plus faible)", r.score())));
        jdbc.query(ScoreSql.LATEST_BRANCH_SNAPSHOTS, new MapSqlParameterSource("repositoryId", filter.repositoryId()), rs -> {
            String branch = rs.getString("branch");
            if (filter.branch() == null || filter.branch().equals(branch)) {
                lines.add(line(repositoryName + " · " + branch, ScoreService.view(rs)));
            }
        });
        return lines;
    }

    private static ScoreLine line(String label, ScoreView v) {
        return new ScoreLine(label, v.security(), v.quality(), v.global(), v.coverage(), v.reliability(),
                v.formulaVersion(), v.computedAt());
    }

    private List<ScanLine> scans(FindingQueryService.Filter filter) {
        MapSqlParameterSource p = new MapSqlParameterSource()
                .addValue("repositoryId", filter.repositoryId(), Types.OTHER)
                .addValue("branch", filter.branch(), Types.VARCHAR);
        record Job(UUID id, String repository, String branch, String commit, Instant finished, String status,
                   List<String> languages) {
        }
        List<Job> jobs = jdbc.query(InsightSql.REPORT_SCANS, p, (rs, i) -> new Job(JdbcRows.uuid(rs, "id"),
                rs.getString("full_name"), rs.getString("branch"), rs.getString("commit_sha"),
                JdbcRows.instant(rs, "finished_at"), rs.getString("status"),
                ScanService.languageLabels(rs.getString("languages"))));
        jobs = jobs.stream().sorted(Comparator.comparing(Job::repository).thenComparing(Job::branch)).limit(MAX_SCANS).toList();
        if (jobs.isEmpty()) {
            return List.of();
        }
        Map<UUID, List<ToolRun>> tools = new LinkedHashMap<>();
        jdbc.query(InsightSql.REPORT_EXECUTIONS, new MapSqlParameterSource()
                .addValue("jobIds", jobs.stream().map(Job::id).toArray(UUID[]::new), Types.ARRAY), rs -> {
            tools.computeIfAbsent(JdbcRows.uuid(rs, "scan_job_id"), k -> new ArrayList<>()).add(new ToolRun(
                    rs.getString("scanner_id"), rs.getString("status"), rs.getString("tool_version"),
                    rs.getString("ruleset_version"), rs.getInt("findings_count"), rs.getString("error_message")));
        });
        return jobs.stream().map(j -> new ScanLine(j.repository(), j.branch(), j.commit(), j.finished(), j.status(),
                j.languages(), tools.getOrDefault(j.id(), List.of()))).toList();
    }

    static List<String> scope(FindingQueryService.Filter f, String repositoryName) {
        List<String> scope = new ArrayList<>();
        scope.add(repositoryName == null ? "Tous les dépôts" : "Dépôt : " + repositoryName);
        if (f.branch() != null) {
            scope.add("Branche : " + f.branch());
        }
        if (f.statuses() != null) {
            scope.add("Statut : " + String.join(", ", f.statuses()));
        }
        if (f.severities() != null) {
            scope.add("Sévérité : " + String.join(", ", f.severities()));
        }
        if (f.types() != null) {
            scope.add("Type : " + String.join(", ", f.types()));
        }
        if (f.scanner() != null) {
            scope.add("Scanner : " + f.scanner());
        }
        if (f.text() != null) {
            scope.add("Recherche : « " + f.text() + " »");
        }
        return scope;
    }

    private static Map<String, Object> filterMap(FindingQueryService.Filter f) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (f.repositoryId() != null) {
            m.put("repositoryId", f.repositoryId().toString());
        }
        if (f.branch() != null) {
            m.put("branch", f.branch());
        }
        if (f.statuses() != null) {
            m.put("status", f.statuses());
        }
        if (f.severities() != null) {
            m.put("severity", f.severities());
        }
        if (f.types() != null) {
            m.put("type", f.types());
        }
        if (f.scanner() != null) {
            m.put("scanner", f.scanner());
        }
        if (f.text() != null) {
            m.put("q", f.text());
        }
        return m;
    }

    static String sha256(byte[] content) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String currentUser() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        return auth == null ? "system" : auth.getName();
    }
}
