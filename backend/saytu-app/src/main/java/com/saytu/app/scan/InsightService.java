package com.saytu.app.scan;

import com.saytu.app.scan.ScanViews.ScanRunView;
import com.saytu.app.scan.ScoreService.ScoreView;
import com.saytu.app.web.ResourceNotFoundException;
import com.saytu.core.domain.FindingType;
import com.saytu.core.domain.Severity;
import com.saytu.core.scoring.ScoreCalculator;
import com.saytu.core.scoring.ScoringFormula;
import com.saytu.core.scoring.SecurityIssue;
import com.saytu.core.scoring.Versions;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;

/** Read models of the dashboard and of the repository detail page. */
@Service
public class InsightService {

    static final int TREND_DAYS = 90;
    static final int PRIORITY_LIMIT = 10;

    private final NamedParameterJdbcTemplate jdbc;
    private final ScoreService scores;
    private final ScanService scans;

    public InsightService(NamedParameterJdbcTemplate jdbc, ScoreService scores, ScanService scans) {
        this.jdbc = jdbc;
        this.scores = scores;
        this.scans = scans;
    }

    public record Counters(long auditedRepositories, long openFindings, long newLast7Days, long resolvedLast7Days,
                           long triaged, Instant lastAuditAt) {
    }

    public record TrendPoint(Instant day, Double security, Double quality, Double global, double coverage,
                             String reliability) {
    }

    public record FlowPoint(Instant week, long opened, long resolved) {
    }

    /** score is null when the repository has open findings but no score yet. */
    public record RepositoryPriority(UUID repositoryId, String repository, List<String> languages, long critical,
                                     long high, long securityFindings, long openFindings, ScoreView score) {
    }

    /**
     * @param openBySeverity severity → type → count, every severity and type present (zeros included)
     */
    public record Dashboard(ScoreView global, Counters counters, Map<String, Map<String, Long>> openBySeverity,
                            List<TrendPoint> trend, List<FlowPoint> weeklyFlow, List<RepositoryPriority> priorities,
                            List<ScanRunView> recentRuns) {
    }

    public record RepositoryInfo(UUID id, String fullName, String name, String webUrl, String defaultBranch,
                                 String visibility, boolean archived, boolean removed, List<String> languages,
                                 Instant languagesUpdatedAt, Instant lastActivityAt, UUID namespaceId, String namespace,
                                 String connectionName, String providerType) {
    }

    public record BranchOverview(String branch, ScoreView score, Map<String, Long> openBySeverity, long openFindings) {
    }

    public record RuleCount(String scanner, String ruleId, String title, String severity, long count) {
    }

    public record JobLine(UUID id, UUID runId, String branch, String status, String commitSha, Instant queuedAt,
                          Instant startedAt, Instant finishedAt, int findings, int newFindings, int resolvedFindings,
                          String errorMessage) {
    }

    /**
     * One fix and what it brings: every OPEN finding of the group disappears.
     *
     * @param kind          DEPENDENCY_UPGRADE, DEPENDENCY_WITHOUT_FIX, SECRET, CONFIGURATION, CODE
     * @param target        package and version, or rule id
     * @param fixedVersion  for an upgrade: highest fixed version named by the advisories
     * @param securityAfter security score of the branch once fixed (same formula, same coverage)
     * @param query         filters of the findings concerned (findings page)
     */
    public record ActionItem(String kind, String title, String target, String fixedVersion, String severity, int findings,
                             double securityBefore, double securityAfter, double gain, UUID exampleFindingId,
                             Map<String, String> query) {
    }

    /** Fixes ranked by security gain for one branch (the weakest one). */
    public record ActionPlan(String branch, String formulaVersion, Double securityScore, List<ActionItem> items) {
    }

    public record RepositoryOverview(RepositoryInfo repository, ScoreView score, List<BranchOverview> branches,
                                     Map<String, Map<String, Long>> openBySeverity, List<TrendPoint> trend,
                                     List<FlowPoint> weeklyFlow, List<RuleCount> topRules, List<JobLine> recentJobs,
                                     ActionPlan actionPlan) {
    }

    @Transactional(readOnly = true)
    public Dashboard dashboard() {
        MapSqlParameterSource none = new MapSqlParameterSource().addValue("repositoryId", null, Types.OTHER);
        Counters counters = jdbc.queryForObject(InsightSql.DASHBOARD_COUNTERS, new MapSqlParameterSource(), (rs, i) ->
                new Counters(rs.getLong("audited_repositories"), rs.getLong("open_findings"), rs.getLong("new_last_7_days"),
                        rs.getLong("resolved_last_7_days"), rs.getLong("triaged"), JdbcRows.instant(rs, "last_audit_at")));
        List<RepositoryPriority> priorities = jdbc.query(InsightSql.PRIORITY_REPOSITORIES,
                new MapSqlParameterSource("limit", PRIORITY_LIMIT), (rs, i) -> new RepositoryPriority(
                        JdbcRows.uuid(rs, "repository_id"), rs.getString("full_name"),
                        ScanService.languageLabels(rs.getString("languages")), rs.getLong("critical"), rs.getLong("high"),
                        rs.getLong("security_findings"), rs.getLong("open_findings"),
                        rs.getString("reliability") == null ? null : ScoreService.view(rs)));
        return new Dashboard(scores.summary().global(), counters, openBySeverity(none),
                trend("GLOBAL", null), flow(null), priorities, scans.list(0, 5).items());
    }

    @Transactional(readOnly = true)
    public RepositoryOverview repository(UUID repositoryId) {
        MapSqlParameterSource p = new MapSqlParameterSource("repositoryId", repositoryId);
        List<RepositoryInfo> info = jdbc.query(InsightSql.REPOSITORY_INFO, p, (rs, i) -> new RepositoryInfo(
                JdbcRows.uuid(rs, "id"), rs.getString("full_name"), rs.getString("name"), rs.getString("web_url"),
                rs.getString("default_branch"), rs.getString("visibility"), rs.getBoolean("archived"),
                rs.getTimestamp("removed_at") != null, ScanService.languageLabels(rs.getString("languages")),
                JdbcRows.instant(rs, "languages_updated_at"), JdbcRows.instant(rs, "last_activity_at"),
                JdbcRows.uuid(rs, "namespace_id"), rs.getString("namespace"), rs.getString("connection_name"),
                rs.getString("provider_type")));
        if (info.isEmpty()) {
            throw new ResourceNotFoundException("Repository " + repositoryId + " not found");
        }
        Map<String, ScoreView> branchScores = new LinkedHashMap<>();
        jdbc.query(ScoreSql.LATEST_BRANCH_SNAPSHOTS, p, rs -> {
            branchScores.put(rs.getString("branch"), ScoreService.view(rs));
        });
        Map<String, Map<String, Long>> openByBranch = new TreeMap<>();
        jdbc.query(InsightSql.OPEN_BY_BRANCH, p, rs -> {
            openByBranch.computeIfAbsent(rs.getString("branch"), b -> emptySeverityCounts())
                    .merge(rs.getString("severity"), rs.getLong("n"), Long::sum);
        });
        List<String> branchNames = new ArrayList<>(branchScores.keySet());
        openByBranch.keySet().stream().filter(b -> !branchScores.containsKey(b)).forEach(branchNames::add);
        branchNames.sort(String::compareTo);
        List<BranchOverview> branches = branchNames.stream().map(b -> {
            Map<String, Long> open = openByBranch.getOrDefault(b, emptySeverityCounts());
            return new BranchOverview(b, branchScores.get(b), open, open.values().stream().mapToLong(Long::longValue).sum());
        }).toList();
        List<TrendPoint> trend = trend("REPOSITORY", repositoryId);
        List<RuleCount> rules = jdbc.query(InsightSql.TOP_RULES, p, (rs, i) -> new RuleCount(rs.getString("scanner_id"),
                rs.getString("rule_id"), rs.getString("title"), Severity.values()[rs.getInt("severity_rank")].name(),
                rs.getLong("n")));
        List<JobLine> jobs = jdbc.query(InsightSql.RECENT_JOBS, p, (rs, i) -> new JobLine(JdbcRows.uuid(rs, "id"),
                JdbcRows.uuid(rs, "scan_run_id"), rs.getString("branch"), rs.getString("status"), rs.getString("commit_sha"),
                JdbcRows.instant(rs, "queued_at"), JdbcRows.instant(rs, "started_at"), JdbcRows.instant(rs, "finished_at"),
                rs.getInt("findings_count"), rs.getInt("new_findings"), rs.getInt("resolved_findings"),
                rs.getString("error_message")));
        ScoreView latest = scores.summary().repositories().stream().filter(r -> r.repositoryId().equals(repositoryId))
                .map(ScoreService.RepositoryScore::score).findFirst().orElse(null);
        return new RepositoryOverview(info.getFirst(), latest, branches, openBySeverity(p), trend, flow(repositoryId),
                rules, jobs, actionPlan(repositoryId, branches, info.getFirst().defaultBranch()));
    }

    static final int ACTION_LIMIT = 8;

    /** Branch the plan is made for: lowest security score, else the default branch, else the first. */
    static String planBranch(List<BranchOverview> branches, String defaultBranch) {
        return branches.stream()
                .filter(b -> b.score() != null && b.score().security() != null)
                .min(java.util.Comparator.comparingDouble((BranchOverview b) -> b.score().security()).thenComparing(BranchOverview::branch))
                .map(BranchOverview::branch)
                .or(() -> branches.stream().map(BranchOverview::branch).filter(b -> b.equals(defaultBranch)).findFirst())
                .or(() -> branches.stream().map(BranchOverview::branch).findFirst())
                .orElse(null);
    }

    private ActionPlan actionPlan(UUID repositoryId, List<BranchOverview> branches, String defaultBranch) {
        String branch = planBranch(branches, defaultBranch);
        ScoringFormula formula = scores.formula();
        if (branch == null) {
            return new ActionPlan(null, formula.version(), null, List.of());
        }
        List<ScoreService.OpenSecurityFinding> open = scores.securityIssues(repositoryId, branch);
        return plan(new ScoreCalculator(formula), repositoryId, branch, open);
    }

    /** Pure part of the action plan (tested without a database). */
    static ActionPlan plan(ScoreCalculator calc, UUID repositoryId, String branch, List<ScoreService.OpenSecurityFinding> open) {
        List<SecurityIssue> issues = open.stream().map(ScoreService.OpenSecurityFinding::issue).toList();
        List<ScoreCalculator.GroupImpact> groups = calc.groups(issues);
        double total = groups.stream().mapToDouble(ScoreCalculator.GroupImpact::points).sum();
        double before = calc.securityScore(total, groups.stream().anyMatch(ScoreCalculator.GroupImpact::critical));
        List<ActionItem> items = new ArrayList<>();
        for (ScoreCalculator.GroupImpact g : groups.stream().limit(ACTION_LIMIT).toList()) {
            List<ScoreService.OpenSecurityFinding> members = open.stream().filter(f -> f.issue().group().equals(g.group())).toList();
            ScoreService.OpenSecurityFinding first = members.stream()
                    .min(java.util.Comparator.comparingInt((ScoreService.OpenSecurityFinding f) -> f.issue().severity().ordinal()))
                    .orElseThrow();
            double after = calc.securityScoreWithout(groups, g.group());
            Map<String, String> query = new LinkedHashMap<>();
            query.put("repositoryId", repositoryId.toString());
            query.put("branch", branch);
            query.put("status", "OPEN");
            String kind;
            String title;
            String target;
            String fixed = null;
            int n = members.size();
            switch (g.category()) {
                case DEPENDENCY -> {
                    target = first.packageName() == null ? first.ruleId()
                            : first.packageName() + (first.packageVersion() == null ? "" : " " + first.packageVersion());
                    fixed = Versions.highest(members.stream().map(ScoreService.OpenSecurityFinding::fixedVersion).toList()).orElse(null);
                    kind = fixed == null ? "DEPENDENCY_WITHOUT_FIX" : "DEPENDENCY_UPGRADE";
                    title = fixed == null
                            ? "Remplacer ou isoler " + target + " (aucune version corrigée publiée)"
                            : "Mettre à jour " + target + " vers " + fixed + " ou plus";
                    query.put("q", first.packageName() == null ? first.ruleId() : first.packageName());
                }
                case SECRET -> {
                    kind = "SECRET";
                    target = first.ruleId();
                    title = "Révoquer puis retirer " + (n > 1 ? n + " secrets « " : "le secret « ") + first.title() + " »";
                    query.put("q", first.ruleId());
                }
                case CONFIGURATION -> {
                    kind = "CONFIGURATION";
                    target = first.ruleId();
                    title = "Corriger la configuration : " + first.title() + (n > 1 ? " (" + n + " emplacements)" : "");
                    query.put("q", first.ruleId());
                }
                default -> {
                    kind = "CODE";
                    target = first.ruleId();
                    title = "Corriger dans le code : " + first.title() + (n > 1 ? " (" + n + " emplacements)" : "");
                    query.put("q", first.ruleId());
                }
            }
            items.add(new ActionItem(kind, title, target, fixed, first.issue().severity().name(), n, before, after,
                    ScoreCalculator.round(after - before), first.id(), query));
        }
        return new ActionPlan(branch, calc.formula().version(), before, items);
    }

    private Map<String, Map<String, Long>> openBySeverity(MapSqlParameterSource p) {
        Map<String, Map<String, Long>> result = new LinkedHashMap<>();
        for (Severity s : Severity.values()) {
            Map<String, Long> byType = new LinkedHashMap<>();
            for (FindingType t : FindingType.values()) {
                byType.put(t.name(), 0L);
            }
            result.put(s.name(), byType);
        }
        jdbc.query(InsightSql.OPEN_BY_SEVERITY_TYPE, p, rs -> {
            result.get(rs.getString("severity")).put(rs.getString("type"), rs.getLong("n"));
        });
        return result;
    }

    private List<TrendPoint> trend(String scopeType, UUID repositoryId) {
        MapSqlParameterSource p = new MapSqlParameterSource().addValue("scopeType", scopeType)
                .addValue("repositoryId", repositoryId, Types.OTHER).addValue("days", TREND_DAYS);
        return jdbc.query(InsightSql.SCORE_TREND, p, (rs, i) -> trendPoint(rs));
    }

    private static TrendPoint trendPoint(ResultSet rs) throws SQLException {
        ScoreView v = ScoreService.view(rs);
        return new TrendPoint(JdbcRows.instant(rs, "day"), v.security(), v.quality(), v.global(), v.coverage(),
                v.reliability());
    }

    private List<FlowPoint> flow(UUID repositoryId) {
        return jdbc.query(InsightSql.WEEKLY_FLOW, new MapSqlParameterSource().addValue("repositoryId", repositoryId, Types.OTHER),
                (rs, i) -> new FlowPoint(JdbcRows.instant(rs, "week"), rs.getLong("opened"), rs.getLong("resolved")));
    }

    private static Map<String, Long> emptySeverityCounts() {
        Map<String, Long> m = new LinkedHashMap<>();
        for (Severity s : Severity.values()) {
            m.put(s.name(), 0L);
        }
        return m;
    }
}
