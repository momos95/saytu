package com.saytu.app.scan;

import com.saytu.app.scan.ScanViews.FindingDetail;
import com.saytu.app.scan.ScanViews.FindingPage;
import com.saytu.app.scan.ScanViews.FindingView;
import com.saytu.app.scan.ScanViews.OccurrenceView;
import com.saytu.app.scan.ScanViews.PageView;
import com.saytu.app.scan.ScanViews.StatusChangeView;
import com.saytu.app.web.ResourceNotFoundException;
import com.saytu.core.domain.FindingStatus;
import com.saytu.core.domain.FindingType;
import com.saytu.core.domain.ScannerId;
import com.saytu.core.domain.Severity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/** Read side of findings (list with filters, detail with occurrences and triage history). */
@Service
public class FindingQueryService {

    static final int MAX_PAGE_SIZE = 200;

    private final NamedParameterJdbcTemplate jdbc;

    public FindingQueryService(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * @param filter all fields optional
     */
    public record Filter(UUID repositoryId, String branch, List<String> severities, List<String> types,
                         List<String> statuses, String scanner, String text) {
        public Filter {
            severities = normalize(severities, Severity.class);
            types = normalize(types, FindingType.class);
            statuses = normalize(statuses, FindingStatus.class);
            if (scanner != null && !scanner.isBlank()) {
                String requested = scanner;
                scanner = ScannerId.fromKey(requested).map(ScannerId::key)
                        .orElseThrow(() -> new IllegalArgumentException("Unknown scanner: " + requested));
            } else {
                scanner = null;
            }
            branch = branch == null || branch.isBlank() ? null : branch.strip();
            text = text == null || text.isBlank() ? null : text.strip();
            if (text != null && text.length() > 200) {
                throw new IllegalArgumentException("Search text too long");
            }
        }

        private static <E extends Enum<E>> List<String> normalize(List<String> values, Class<E> type) {
            if (values == null || values.isEmpty()) {
                return null;
            }
            return values.stream().filter(v -> v != null && !v.isBlank())
                    .map(v -> Enum.valueOf(type, v.strip().toUpperCase(Locale.ROOT)).name()).distinct().toList();
        }
    }

    @Transactional(readOnly = true)
    public FindingPage list(Filter filter, int page, int size) {
        int safeSize = Math.clamp(size, 1, MAX_PAGE_SIZE);
        int safePage = Math.max(page, 0);
        MapSqlParameterSource p = filterParams(filter);
        Long total = jdbc.queryForObject(ScanSql.COUNT_FINDINGS, p, Long.class);
        long count = total == null ? 0 : total;
        Map<String, Long> bySeverity = new LinkedHashMap<>();
        for (Severity s : Severity.values()) {
            bySeverity.put(s.name(), 0L);
        }
        jdbc.query(ScanSql.FINDING_COUNTS_BY_SEVERITY, p, rs -> {
            bySeverity.put(rs.getString(1), rs.getLong(2));
        });
        p.addValue("limit", safeSize).addValue("offset", (long) safePage * safeSize);
        List<FindingView> items = jdbc.query(ScanSql.LIST_FINDINGS, p, FINDING_MAPPER);
        return new FindingPage(new PageView<>(items, safePage, safeSize, count, (int) ((count + safeSize - 1) / safeSize)),
                bySeverity);
    }

    @Transactional(readOnly = true)
    public FindingDetail get(UUID findingId) {
        MapSqlParameterSource p = new MapSqlParameterSource("findingId", findingId);
        List<FindingDetail> found = jdbc.query(ScanSql.GET_FINDING, p, (rs, i) -> new FindingDetail(
                FINDING_MAPPER.mapRow(rs, i), rs.getString("description"), rs.getString("evidence_redacted"),
                rs.getString("recommendation"), JdbcRows.strings(rs, "references_urls"), rs.getString("cvss_vector"),
                rs.getString("package_ecosystem"), JdbcRows.instant(rs, "resolved_at"), rs.getString("status_reason"),
                rs.getString("status_changed_by"), JdbcRows.instant(rs, "status_changed_at"), List.of(), List.of()));
        if (found.isEmpty()) {
            throw new ResourceNotFoundException("Finding " + findingId + " not found");
        }
        List<OccurrenceView> occurrences = jdbc.query(ScanSql.FINDING_OCCURRENCES, p, (rs, i) -> new OccurrenceView(
                rs.getString("scanner_id"), rs.getString("rule_id"), rs.getString("reported_severity"),
                rs.getString("file_path"), JdbcRows.integer(rs, "start_line"), JdbcRows.instant(rs, "detected_at"),
                JdbcRows.uuid(rs, "scan_job_id")));
        List<StatusChangeView> history = jdbc.query(InsightSql.STATUS_HISTORY, p, (rs, i) -> new StatusChangeView(
                rs.getString("from_status"), rs.getString("to_status"), rs.getString("reason"), rs.getString("changed_by"),
                JdbcRows.instant(rs, "changed_at")));
        FindingDetail d = found.getFirst();
        return new FindingDetail(d.finding(), d.description(), d.evidence(), d.recommendation(), d.references(),
                d.cvssVector(), d.packageEcosystem(), d.resolvedAt(), d.statusReason(), d.statusChangedBy(),
                d.statusChangedAt(), occurrences, history);
    }

    static MapSqlParameterSource filterParams(Filter f) {
        MapSqlParameterSource p = new MapSqlParameterSource();
        p.addValue("repositoryId", f.repositoryId(), Types.OTHER);
        p.addValue("branch", f.branch(), Types.VARCHAR);
        p.addValue("severities", array(f.severities()), Types.ARRAY);
        p.addValue("types", array(f.types()), Types.ARRAY);
        p.addValue("statuses", array(f.statuses()), Types.ARRAY);
        p.addValue("scanner", f.scanner(), Types.VARCHAR);
        p.addValue("text", f.text() == null ? null : "%" + escapeLike(f.text()) + "%", Types.VARCHAR);
        return p;
    }

    private static String[] array(List<String> values) {
        return values == null ? null : values.toArray(String[]::new);
    }

    static String escapeLike(String text) {
        return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
    }

    static final RowMapper<FindingView> FINDING_MAPPER = FindingQueryService::mapFinding;

    private static FindingView mapFinding(ResultSet rs, int i) throws SQLException {
        return new FindingView(JdbcRows.uuid(rs, "id"), JdbcRows.uuid(rs, "repository_id"),
                rs.getString("repository_name"), rs.getString("branch"), rs.getString("type"), rs.getString("severity"),
                rs.getString("scanner_id"), rs.getString("rule_id"), rs.getString("title"), rs.getString("file_path"),
                JdbcRows.integer(rs, "start_line"), JdbcRows.integer(rs, "end_line"), JdbcRows.strings(rs, "cwe_ids"),
                rs.getString("cve_id"), rs.getBigDecimal("cvss_score"), rs.getString("package_name"),
                rs.getString("package_version"), rs.getString("fixed_version"), rs.getString("status"),
                JdbcRows.instant(rs, "first_seen_at"), JdbcRows.instant(rs, "last_seen_at"), rs.getString("commit_sha"),
                JdbcRows.strings(rs, "scanners"));
    }
}
