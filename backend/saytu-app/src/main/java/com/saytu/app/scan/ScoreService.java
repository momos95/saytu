package com.saytu.app.scan;

import com.saytu.app.audit.AuditService;
import com.saytu.core.domain.FindingType;
import com.saytu.core.domain.Language;
import com.saytu.core.domain.LanguageProfile;
import com.saytu.core.domain.ScannerExecutionStatus;
import com.saytu.core.domain.ScannerId;
import com.saytu.core.domain.Severity;
import com.saytu.core.scoring.BranchScoreInput;
import com.saytu.core.scoring.Reliability;
import com.saytu.core.scoring.Score;
import com.saytu.core.scoring.ScoreCalculator;
import com.saytu.core.scoring.ScoringFormula;
import com.saytu.core.scoring.SecurityIssue;
import com.saytu.git.json.JsonNode;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Computes and stores score snapshots (branch, repository, organisation, global) after each job, and
 * serves the latest ones. Formula: docs/scoring.md, parameters in {@code app_setting['scoring.formula']}.
 */
@Service
public class ScoreService {

    private final NamedParameterJdbcTemplate jdbc;
    private final AuditService audit;

    public ScoreService(NamedParameterJdbcTemplate jdbc, AuditService audit) {
        this.jdbc = jdbc;
        this.audit = audit;
    }

    /** A stored score. */
    public record ScoreView(Double security, Double quality, Double global, double coverage, String reliability,
                            String formulaVersion, Map<String, Object> details, Instant computedAt) {
    }

    public record RepositoryScore(UUID repositoryId, UUID namespaceId, String repository, ScoreView score) {
    }

    public record NamespaceScore(UUID namespaceId, String namespace, ScoreView score) {
    }

    public record Summary(ScoreView global, List<NamespaceScore> namespaces, List<RepositoryScore> repositories,
                          ScoringFormula formula) {
    }

    // ------------------------------------------------------------------ formula

    @Transactional(readOnly = true)
    public ScoringFormula formula() {
        List<String> rows = jdbc.query(ScoreSql.FORMULA, new MapSqlParameterSource(), (rs, i) -> rs.getString(1));
        return rows.isEmpty() ? ScoringFormula.DEFAULT : parseFormula(rows.getFirst());
    }

    @Transactional
    public ScoringFormula updateFormula(ScoringFormula formula) {
        jdbc.update(ScoreSql.UPDATE_FORMULA, new MapSqlParameterSource()
                .addValue("value", formulaJson(formula))
                .addValue("updatedBy", currentUser()));
        audit.record("SCORING_FORMULA_UPDATED", "app_setting", "scoring.formula", Map.of("version", formula.version()));
        rescore(null, null);
        return formula;
    }

    static ScoringFormula parseFormula(String json) {
        ScoringFormula d = ScoringFormula.DEFAULT;
        JsonNode n = JsonNode.parse(json);
        Map<SecurityIssue.Category, Double> factors = new EnumMap<>(SecurityIssue.Category.class);
        for (SecurityIssue.Category c : SecurityIssue.Category.values()) {
            factors.put(c, number(n.get("categoryFactors").get(c.name()), d.categoryFactors().get(c)));
        }
        Optional<String> curve = n.text("securityCurve");
        return new ScoringFormula(
                n.text("version").orElse(d.version()),
                weights(n.get("securityWeights"), d.securityWeights()),
                number(n.get("securityScale"), d.securityScale()),
                number(n.get("criticalCap"), d.criticalCap()),
                weights(n.get("qualityWeights"), d.qualityWeights()),
                number(n.get("qualityScale"), d.qualityScale()),
                number(n.get("bytesPerLine"), d.bytesPerLine()),
                number(n.get("securityShare"), d.securityShare()),
                number(n.get("minCoverage"), d.minCoverage()),
                curve.map(c -> ScoringFormula.SecurityCurve.valueOf(c.toUpperCase(java.util.Locale.ROOT))).orElse(d.securityCurve()),
                factors,
                number(n.get("noFixFactor"), d.noFixFactor()),
                n.get("diminishingReturns").asBoolean(d.diminishingReturns()));
    }

    private static Map<Severity, Double> weights(JsonNode node, Map<Severity, Double> defaults) {
        Map<Severity, Double> w = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) {
            w.put(s, number(node.get(s.name()), defaults.get(s)));
        }
        return w;
    }

    private static double number(JsonNode node, double def) {
        Double v = node.asDouble();
        return v == null ? def : v;
    }

    static String formulaJson(ScoringFormula f) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("version", f.version());
        m.put("securityWeights", byName(f.securityWeights()));
        m.put("securityScale", f.securityScale());
        m.put("criticalCap", f.criticalCap());
        m.put("qualityWeights", byName(f.qualityWeights()));
        m.put("qualityScale", f.qualityScale());
        m.put("bytesPerLine", f.bytesPerLine());
        m.put("securityShare", f.securityShare());
        m.put("minCoverage", f.minCoverage());
        m.put("securityCurve", f.securityCurve().name());
        Map<String, Object> factors = new LinkedHashMap<>();
        for (SecurityIssue.Category c : SecurityIssue.Category.values()) {
            factors.put(c.name(), f.categoryFactors().get(c));
        }
        m.put("categoryFactors", factors);
        m.put("noFixFactor", f.noFixFactor());
        m.put("diminishingReturns", f.diminishingReturns());
        return Json.write(m);
    }

    private static Map<String, Object> byName(Map<Severity, Double> w) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (Severity s : Severity.values()) {
            m.put(s.name(), w.get(s));
        }
        return m;
    }

    // ------------------------------------------------------------------ computation (worker, inside the result transaction)

    /**
     * Stores the branch score of a finished job, then refreshes the repository, organisation and global
     * scores. Called by {@link ResultWriter} in the same transaction as the findings.
     */
    @Transactional
    public Score recordJob(UUID jobId, UUID repositoryId, String branch, LanguageProfile languages,
                           Map<ScannerId, ScannerExecutionStatus> executions) {
        ScoreCalculator calc = new ScoreCalculator(formula());
        Map<Severity, Long> quality = new EnumMap<>(Severity.class);
        jdbc.query(ScoreSql.OPEN_COUNTS, new MapSqlParameterSource().addValue("repositoryId", repositoryId)
                .addValue("branch", branch), rs -> {
            if (FindingType.QUALITY.name().equals(rs.getString("type"))) {
                quality.merge(Severity.valueOf(rs.getString("severity")), rs.getLong("n"), Long::sum);
            }
        });
        List<SecurityIssue> issues = securityIssues(repositoryId, branch).stream().map(OpenSecurityFinding::issue).toList();
        Score score = calc.branch(BranchScoreInput.of(issues, quality, languages, executions));
        Map<String, Object> details = new LinkedHashMap<>(score.details());
        details.put("codeBytes", codeBytes(languages));
        insert("BRANCH", null, repositoryId, branch, jobId, score, calc.formula(), details);
        refreshAggregates(calc, repositoryId);
        return score;
    }

    /** An OPEN security finding with its formula v2 classification (also used by the action plan). */
    public record OpenSecurityFinding(UUID id, String type, String severity, String scanner, String ruleId, String title,
                                      String filePath, String packageName, String packageVersion, String fixedVersion,
                                      SecurityIssue issue) {
    }

    @Transactional(readOnly = true)
    public List<OpenSecurityFinding> securityIssues(UUID repositoryId, String branch) {
        return jdbc.query(ScoreSql.SECURITY_ISSUES, new MapSqlParameterSource().addValue("repositoryId", repositoryId)
                .addValue("branch", branch), (rs, i) -> {
            FindingType type = FindingType.valueOf(rs.getString("type"));
            Severity severity = Severity.valueOf(rs.getString("severity"));
            SecurityIssue issue = SecurityIssue.of(type, severity, rs.getString("scanner_id"), rs.getString("rule_id"),
                    rs.getString("file_path"), JdbcRows.strings(rs, "cwe_ids"), rs.getString("package_name"),
                    rs.getString("package_version"), rs.getString("fixed_version"));
            return new OpenSecurityFinding(JdbcRows.uuid(rs, "id"), type.name(), severity.name(), rs.getString("scanner_id"),
                    rs.getString("rule_id"), rs.getString("title"), rs.getString("file_path"), rs.getString("package_name"),
                    rs.getString("package_version"), rs.getString("fixed_version"), issue);
        });
    }

    /**
     * Recomputes branch scores from the stored results (no new analysis): after a triage, a formula change
     * or an upgrade. Uses the latest finished job of each branch for coverage and languages.
     *
     * @return number of branches rescored
     */
    @Transactional
    public int rescore(UUID repositoryId, String branch) {
        record Latest(UUID jobId, UUID repositoryId, String branch, String languages) {
        }
        List<Latest> jobs = jdbc.query(ScoreSql.LATEST_FINISHED_JOBS, new MapSqlParameterSource()
                        .addValue("repositoryId", repositoryId, Types.OTHER).addValue("branch", branch, Types.VARCHAR),
                (rs, i) -> new Latest(JdbcRows.uuid(rs, "id"), JdbcRows.uuid(rs, "repository_id"), rs.getString("branch"),
                        rs.getString("languages")));
        for (Latest j : jobs) {
            Map<ScannerId, ScannerExecutionStatus> executions = new EnumMap<>(ScannerId.class);
            jdbc.query(ScoreSql.JOB_EXECUTIONS, new MapSqlParameterSource("jobId", j.jobId()), rs -> {
                String status = rs.getString("status");
                ScannerId.fromKey(rs.getString("scanner_id")).ifPresent(id ->
                        executions.put(id, ScannerExecutionStatus.valueOf(status)));
            });
            recordJob(j.jobId(), j.repositoryId(), j.branch(), ScanService.languageProfile(j.languages()), executions);
        }
        return jobs.size();
    }

    /** Removes and returns the pending rescore request left by a migration, if any. */
    @Transactional
    public Optional<String> consumeRescoreRequest() {
        return jdbc.query(ScoreSql.CONSUME_RESCORE_REQUEST, new MapSqlParameterSource(), (rs, i) -> rs.getString(1))
                .stream().findFirst();
    }

    /** Version of the formula of the latest branch score, if any. */
    @Transactional(readOnly = true)
    public Optional<String> latestFormulaVersion() {
        return jdbc.query(ScoreSql.LATEST_BRANCH_FORMULA, new MapSqlParameterSource(), (rs, i) -> rs.getString(1))
                .stream().findFirst();
    }

    private void refreshAggregates(ScoreCalculator calc, UUID repositoryId) {
        // repository: weakest of its recent branches; weight = largest code size among them
        List<Score> branches = new ArrayList<>();
        long[] weight = new long[1];
        jdbc.query(ScoreSql.LATEST_BRANCH_SNAPSHOTS, new MapSqlParameterSource("repositoryId", repositoryId), rs -> {
            ScoreView v = view(rs);
            branches.add(toScore(v));
            weight[0] = Math.max(weight[0], longDetail(v.details(), "codeBytes"));
        });
        Score repository = calc.weakest(branches);
        if (repository == null) {
            return;
        }
        Map<String, Object> repoDetails = new LinkedHashMap<>(repository.details());
        repoDetails.put("codeBytes", weight[0]);
        insert("REPOSITORY", null, repositoryId, null, null, repository, calc.formula(), repoDetails);

        List<UUID> namespaces = jdbc.query(ScoreSql.REPOSITORY_NAMESPACE,
                new MapSqlParameterSource("repositoryId", repositoryId), (rs, i) -> JdbcRows.uuid(rs, "namespace_id"));
        UUID namespaceId = namespaces.isEmpty() ? null : namespaces.getFirst();
        if (namespaceId != null) {
            Score ns = calc.weightedAverage(repositories(namespaceId));
            if (ns != null) {
                insert("NAMESPACE", namespaceId, null, null, null, ns, calc.formula(), ns.details());
            }
        }
        Score global = calc.weightedAverage(repositories(null));
        if (global != null) {
            insert("GLOBAL", null, null, null, null, global, calc.formula(), global.details());
        }
    }

    private List<ScoreCalculator.Weighted> repositories(UUID namespaceId) {
        return jdbc.query(ScoreSql.LATEST_REPOSITORY_SNAPSHOTS,
                new MapSqlParameterSource().addValue("namespaceId", namespaceId, Types.OTHER), (rs, i) -> {
                    ScoreView v = view(rs);
                    return new ScoreCalculator.Weighted(toScore(v), longDetail(v.details(), "codeBytes"));
                });
    }

    private void insert(String scope, UUID namespaceId, UUID repositoryId, String branch, UUID jobId, Score s,
                        ScoringFormula formula, Map<String, Object> details) {
        jdbc.update(ScoreSql.INSERT_SNAPSHOT, new MapSqlParameterSource()
                .addValue("scopeType", scope)
                .addValue("namespaceId", namespaceId, Types.OTHER)
                .addValue("repositoryId", repositoryId, Types.OTHER)
                .addValue("branch", branch, Types.VARCHAR)
                .addValue("scanJobId", jobId, Types.OTHER)
                .addValue("security", decimal(s.security()), Types.NUMERIC)
                .addValue("quality", decimal(s.quality()), Types.NUMERIC)
                .addValue("global", decimal(s.global()), Types.NUMERIC)
                .addValue("coverage", decimal(s.coverage()), Types.NUMERIC)
                .addValue("reliability", s.reliability().name())
                .addValue("formulaVersion", formula.version())
                .addValue("details", Json.write(details)));
    }

    // ------------------------------------------------------------------ reading

    @Transactional(readOnly = true)
    public Summary summary() {
        List<ScoreView> global = jdbc.query(ScoreSql.LATEST_GLOBAL_SNAPSHOT, new MapSqlParameterSource(), (rs, i) -> view(rs));
        List<NamespaceScore> namespaces = jdbc.query(ScoreSql.LATEST_NAMESPACE_SNAPSHOTS, new MapSqlParameterSource(),
                (rs, i) -> new NamespaceScore(JdbcRows.uuid(rs, "namespace_id"), rs.getString("full_path"), view(rs)));
        List<RepositoryScore> repositories = jdbc.query(ScoreSql.LATEST_REPOSITORY_SNAPSHOTS,
                new MapSqlParameterSource().addValue("namespaceId", null, Types.OTHER),
                (rs, i) -> new RepositoryScore(JdbcRows.uuid(rs, "repository_id"), JdbcRows.uuid(rs, "namespace_id"),
                        rs.getString("full_name"), view(rs)));
        return new Summary(global.isEmpty() ? null : global.getFirst(), namespaces, repositories, formula());
    }

    /** Branch score of each job of a run. */
    @Transactional(readOnly = true)
    public Map<UUID, ScoreView> runJobScores(UUID runId) {
        Map<UUID, ScoreView> scores = new LinkedHashMap<>();
        jdbc.query(ScoreSql.RUN_JOB_SCORES, new MapSqlParameterSource("runId", runId),
                rs -> {
                    scores.put(JdbcRows.uuid(rs, "scan_job_id"), view(rs));
                });
        return scores;
    }

    static ScoreView view(ResultSet rs) throws SQLException {
        return new ScoreView(dbl(rs, "security_score"), dbl(rs, "quality_score"), dbl(rs, "global_score"),
                rs.getBigDecimal("coverage_percent").doubleValue(), rs.getString("reliability"),
                rs.getString("formula_version"), Json.read(rs.getString("details")), JdbcRows.instant(rs, "computed_at"));
    }

    private static Score toScore(ScoreView v) {
        return new Score(v.security(), v.quality(), v.global(), v.coverage(), Reliability.valueOf(v.reliability()),
                v.details());
    }

    private static Double dbl(ResultSet rs, String column) throws SQLException {
        BigDecimal d = rs.getBigDecimal(column);
        return d == null ? null : d.doubleValue();
    }

    private static BigDecimal decimal(Double v) {
        return v == null ? null : BigDecimal.valueOf(v).setScale(2, RoundingMode.HALF_UP);
    }

    private static long longDetail(Map<String, Object> details, String key) {
        Object v = details.get(key);
        return v instanceof Number n ? n.longValue() : 0;
    }

    static long codeBytes(LanguageProfile languages) {
        return languages.stats().entrySet().stream().filter(e -> e.getKey().kind() == Language.Kind.CODE)
                .mapToLong(e -> e.getValue().bytes()).sum();
    }

    private static String currentUser() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        return auth == null ? "system" : auth.getName();
    }
}
