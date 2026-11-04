package com.saytu.app.audit;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Clock;
import java.util.Map;

/**
 * Records security-relevant actions. Callers must never put secrets in {@code details}: only
 * identifiers, names and outcomes.
 */
@Service
public class AuditService {

    /** Actions recorded by phase 2. */
    public static final String CONNECTION_CREATED = "GIT_CONNECTION_CREATED";
    public static final String CONNECTION_UPDATED = "GIT_CONNECTION_UPDATED";
    public static final String CONNECTION_DELETED = "GIT_CONNECTION_DELETED";
    public static final String CONNECTION_TESTED = "GIT_CONNECTION_TESTED";
    public static final String CONNECTION_TOKEN_CHANGED = "GIT_CONNECTION_TOKEN_CHANGED";

    private final AuditEventRepository repository;
    private final Clock clock;

    public AuditService(AuditEventRepository repository, Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    /** Joins the caller's transaction: the audit row is committed or rolled back with the action. */
    @Transactional(propagation = Propagation.MANDATORY)
    public void record(String action, String targetType, String targetId, Map<String, Object> details) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String subject = "system";
        String username = null;
        if (auth != null) {
            if (auth.getPrincipal() instanceof Jwt jwt) {
                subject = jwt.getSubject() != null ? jwt.getSubject() : auth.getName();
                username = jwt.getClaimAsString("preferred_username");
            } else {
                subject = auth.getName();
            }
        }
        repository.save(new AuditEventEntity(clock.instant(), subject, username, action, targetType, targetId,
                details, clientIp()));
    }

    private static String clientIp() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
            HttpServletRequest request = attributes.getRequest();
            // X-Forwarded-For is already applied by server.forward-headers-strategy=framework
            return request.getRemoteAddr();
        }
        return null;
    }
}
