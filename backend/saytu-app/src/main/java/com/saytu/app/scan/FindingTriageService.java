package com.saytu.app.scan;

import com.saytu.app.audit.AuditService;
import com.saytu.app.scan.ScanViews.FindingDetail;
import com.saytu.app.web.ResourceNotFoundException;
import com.saytu.core.domain.FindingStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Types;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Human triage of a finding. Allowed: OPEN → ACCEPTED_RISK / FALSE_POSITIVE (reason required) and back to
 * OPEN; the branch score is recomputed at once. RESOLVED is decided by the scanners only (a fixed issue that comes back is reopened by the next
 * scan); a triaged finding is never changed by a scan. Every change is kept in finding_status_history
 * and in the audit trail.
 */
@Service
public class FindingTriageService {

    static final int MAX_REASON = 2000;

    private final NamedParameterJdbcTemplate jdbc;
    private final FindingQueryService queries;
    private final AuditService audit;
    private final ScoreService scores;

    public FindingTriageService(NamedParameterJdbcTemplate jdbc, FindingQueryService queries, AuditService audit,
                                ScoreService scores) {
        this.jdbc = jdbc;
        this.queries = queries;
        this.audit = audit;
        this.scores = scores;
    }

    public record StatusChange(String status, String reason) {
    }

    /** Validated target status and reason; throws IllegalArgumentException with a user-facing message. */
    static Map.Entry<FindingStatus, String> validate(StatusChange change) {
        if (change == null || change.status() == null || change.status().isBlank()) {
            throw new IllegalArgumentException("Le statut est obligatoire");
        }
        FindingStatus target;
        try {
            target = FindingStatus.valueOf(change.status().strip().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Statut inconnu : " + change.status());
        }
        if (target == FindingStatus.RESOLVED) {
            throw new IllegalArgumentException("« Corrigée » est déterminé par les scanners, pas à la main");
        }
        String reason = change.reason() == null ? "" : change.reason().strip();
        if (reason.length() > MAX_REASON) {
            throw new IllegalArgumentException("Justification trop longue (" + MAX_REASON + " caractères au plus)");
        }
        if (target != FindingStatus.OPEN && reason.isEmpty()) {
            throw new IllegalArgumentException("Une justification est obligatoire pour accepter un risque ou déclarer un faux positif");
        }
        return Map.entry(target, reason);
    }

    @Transactional
    public FindingDetail changeStatus(UUID findingId, StatusChange change) {
        Map.Entry<FindingStatus, String> valid = validate(change);
        FindingStatus target = valid.getKey();
        String reason = valid.getValue().isEmpty() ? null : valid.getValue();
        MapSqlParameterSource p = new MapSqlParameterSource("findingId", findingId);
        record Current(String status, UUID repositoryId, String branch) {
        }
        List<Current> current = jdbc.query(InsightSql.LOCK_FINDING, p, (rs, i) -> new Current(rs.getString("status"),
                JdbcRows.uuid(rs, "repository_id"), rs.getString("branch")));
        if (current.isEmpty()) {
            throw new ResourceNotFoundException("Finding " + findingId + " not found");
        }
        FindingStatus from = FindingStatus.valueOf(current.getFirst().status());
        if (from == FindingStatus.RESOLVED) {
            throw new IllegalArgumentException("Cette vulnérabilité est corrigée : elle sera rouverte automatiquement si un audit la retrouve");
        }
        if (from == target) {
            return queries.get(findingId);
        }
        String user = currentUser();
        p.addValue("status", target.name()).addValue("reason", reason, Types.VARCHAR).addValue("user", user)
                .addValue("fromStatus", from.name()).addValue("toStatus", target.name());
        jdbc.update(InsightSql.UPDATE_FINDING_STATUS, p);
        jdbc.update(InsightSql.INSERT_STATUS_HISTORY, p);
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("from", from.name());
        details.put("to", target.name());
        if (reason != null) {
            details.put("reason", reason);
        }
        audit.record("FINDING_STATUS_CHANGED", "finding", findingId.toString(), details);
        // the score follows the triage at once (accepted risks and false positives no longer count)
        scores.rescore(current.getFirst().repositoryId(), current.getFirst().branch());
        return queries.get(findingId);
    }

    private static String currentUser() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        return auth == null ? "system" : auth.getName();
    }
}
