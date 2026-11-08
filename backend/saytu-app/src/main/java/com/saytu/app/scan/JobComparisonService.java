package com.saytu.app.scan;

import com.saytu.app.scan.ScanViews.FindingView;
import com.saytu.app.scan.ScoreService.ScoreView;
import com.saytu.app.web.ResourceNotFoundException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/**
 * Compares two analyses of the same repository (usually two audits of a branch, or two branches).
 * A finding only counts as "fixed" when every scanner that reported it succeeded in the newer analysis,
 * and as "introduced" when every scanner that reports it also succeeded in the older one; otherwise it is
 * listed as "not verifiable": a tool that did not run never proves an absence.
 */
@Service
public class JobComparisonService {

    static final int MAX_LISTED = 500;

    private final NamedParameterJdbcTemplate jdbc;

    public JobComparisonService(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public record JobRef(UUID id, UUID repositoryId, String repository, String branch, String status, String commitSha,
                         Instant finishedAt, ScoreView score) {
    }

    public record ScannerDiff(String scanner, String baseStatus, String headStatus, String baseVersion, String headVersion) {
    }

    public record Comparison(JobRef base, JobRef head, List<FindingView> introduced, List<FindingView> fixed,
                             List<FindingView> unverified, int persisting, int introducedTotal, int fixedTotal,
                             int unverifiedTotal, List<ScannerDiff> scanners) {
    }

    /** Pure classification (tested without a database). */
    record Classified(Set<UUID> introduced, Set<UUID> fixed, Set<UUID> unverified, int persisting) {
    }

    static Classified classify(Map<UUID, Set<String>> base, Map<UUID, Set<String>> head, Set<String> baseSucceeded,
                               Set<String> headSucceeded) {
        Set<UUID> introduced = new HashSet<>();
        Set<UUID> fixed = new HashSet<>();
        Set<UUID> unverified = new HashSet<>();
        int persisting = 0;
        for (var e : head.entrySet()) {
            if (base.containsKey(e.getKey())) {
                persisting++;
            } else if (baseSucceeded.containsAll(e.getValue())) {
                introduced.add(e.getKey());
            } else {
                unverified.add(e.getKey());
            }
        }
        for (var e : base.entrySet()) {
            if (!head.containsKey(e.getKey())) {
                (headSucceeded.containsAll(e.getValue()) ? fixed : unverified).add(e.getKey());
            }
        }
        return new Classified(introduced, fixed, unverified, persisting);
    }

    @Transactional(readOnly = true)
    public Comparison compare(UUID headJobId, UUID baseJobId) {
        JobRef head = job(headJobId);
        UUID baseId = baseJobId;
        if (baseId == null) {
            baseId = jdbc.queryForList(AutomationSql.PREVIOUS_JOB, new MapSqlParameterSource("jobId", headJobId), UUID.class)
                    .stream().findFirst().orElseThrow(() -> new IllegalArgumentException(
                            "Aucun audit terminé plus ancien sur cette branche : rien à comparer"));
        }
        if (baseId.equals(headJobId)) {
            throw new IllegalArgumentException("Choisissez deux analyses différentes");
        }
        JobRef base = job(baseId);
        if (!base.repositoryId().equals(head.repositoryId())) {
            throw new IllegalArgumentException("Les deux analyses doivent porter sur le même dépôt");
        }
        Map<String, String[]> baseExec = executions(base.id());
        Map<String, String[]> headExec = executions(head.id());
        Classified c = classify(seen(base.id()), seen(head.id()), succeeded(baseExec), succeeded(headExec));
        List<ScannerDiff> scanners = new ArrayList<>();
        for (String s : new TreeSet<>(union(baseExec.keySet(), headExec.keySet()))) {
            String[] b = baseExec.get(s);
            String[] h = headExec.get(s);
            scanners.add(new ScannerDiff(s, b == null ? null : b[0], h == null ? null : h[0], b == null ? null : b[1],
                    h == null ? null : h[1]));
        }
        return new Comparison(base, head, findings(c.introduced()), findings(c.fixed()), findings(c.unverified()),
                c.persisting(), c.introduced().size(), c.fixed().size(), c.unverified().size(), scanners);
    }

    private JobRef job(UUID id) {
        MapSqlParameterSource p = new MapSqlParameterSource("jobId", id);
        ScoreView score = jdbc.query(AutomationSql.JOB_SCORE, p, (rs, i) -> ScoreService.view(rs)).stream().findFirst().orElse(null);
        return jdbc.query(AutomationSql.COMPARE_JOB, p, (rs, i) -> new JobRef(JdbcRows.uuid(rs, "id"),
                        JdbcRows.uuid(rs, "repository_id"), rs.getString("full_name"), rs.getString("branch"), rs.getString("status"),
                        rs.getString("commit_sha"), JdbcRows.instant(rs, "finished_at"), score)).stream().findFirst()
                .orElseThrow(() -> new ResourceNotFoundException("Job " + id + " not found"));
    }

    private Map<String, String[]> executions(UUID jobId) {
        Map<String, String[]> m = new LinkedHashMap<>();
        jdbc.query(AutomationSql.COMPARE_EXECUTIONS, new MapSqlParameterSource("jobId", jobId), rs -> {
            m.put(rs.getString("scanner_id"), new String[]{rs.getString("status"), rs.getString("tool_version")});
        });
        return m;
    }

    private static Set<String> succeeded(Map<String, String[]> executions) {
        Set<String> s = new HashSet<>();
        executions.forEach((k, v) -> {
            if ("SUCCEEDED".equals(v[0])) {
                s.add(k);
            }
        });
        return s;
    }

    private Map<UUID, Set<String>> seen(UUID jobId) {
        Map<UUID, Set<String>> m = new HashMap<>();
        jdbc.query(AutomationSql.FINDINGS_SEEN_BY_JOB, new MapSqlParameterSource("jobId", jobId), rs -> {
            m.put(JdbcRows.uuid(rs, "finding_id"), new HashSet<>(JdbcRows.strings(rs, "scanners")));
        });
        return m;
    }

    private List<FindingView> findings(Collection<UUID> ids) {
        if (ids.isEmpty()) {
            return List.of();
        }
        UUID[] some = ids.stream().sorted().limit(MAX_LISTED).toArray(UUID[]::new);
        return jdbc.query(AutomationSql.FINDINGS_BY_IDS, new MapSqlParameterSource().addValue("ids", some, Types.ARRAY),
                FindingQueryService.FINDING_MAPPER);
    }

    private static Set<String> union(Set<String> a, Set<String> b) {
        Set<String> u = new HashSet<>(a);
        u.addAll(b);
        return u;
    }
}
