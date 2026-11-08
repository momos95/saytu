package com.saytu.app.scan;

import com.saytu.app.audit.AuditService;
import com.saytu.app.vault.TokenVault;
import com.saytu.app.web.ResourceNotFoundException;
import com.saytu.core.security.SensitiveValue;
import com.saytu.core.security.TokenCipher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.Types;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Webhook endpoints (ADMIN), the outbox written when a job finishes, and the HTTP delivery itself.
 * Signing secrets are encrypted like Git tokens; URLs are masked in every view because many services
 * put their token in the path.
 */
@Service
public class WebhookService {

    private static final Logger log = LoggerFactory.getLogger(WebhookService.class);
    static final String OWNER_TABLE = "webhook_endpoint";

    private final NamedParameterJdbcTemplate jdbc;
    private final TokenVault vault;
    private final AuditService audit;
    private final String publicUrl;
    private final HttpClient http;

    public WebhookService(NamedParameterJdbcTemplate jdbc, TokenVault vault, AuditService audit,
                          @Value("${saytu.public-url:http://localhost:8080}") String publicUrl) {
        this.jdbc = jdbc;
        this.vault = vault;
        this.audit = audit;
        this.publicUrl = publicUrl;
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER).proxy(ProxySelector.getDefault()).build();
    }

    /**
     * @param secret null = keep the current secret, "" = remove it
     */
    public record WebhookRequest(String name, String url, String format, String minSeverity, List<String> events,
                                 Boolean enabled, String secret) {
    }

    public record WebhookView(UUID id, String name, String url, String format, String minSeverity, List<String> events,
                              boolean enabled, boolean hasSecret, String lastStatus, Instant lastDeliveredAt,
                              String createdBy, Instant createdAt) {
    }

    public record DeliveryView(UUID id, String event, String status, int attempts, Integer httpStatus, String error,
                               Instant createdAt, Instant deliveredAt, Instant nextAttemptAt) {
    }

    public record TestResult(boolean delivered, Integer httpStatus, String message) {
    }

    record Valid(String name, String url, String format, String minSeverity, List<String> events, boolean enabled) {
    }

    static Valid validate(WebhookRequest r) {
        if (r == null) {
            throw new IllegalArgumentException("Requête vide");
        }
        String name = r.name() == null ? "" : r.name().strip();
        if (name.isEmpty() || name.length() > 120) {
            throw new IllegalArgumentException("Nom obligatoire (120 caractères au plus)");
        }
        String format = r.format() == null ? "GENERIC" : r.format().strip().toUpperCase(Locale.ROOT);
        if (!format.equals("GENERIC") && !format.equals("SLACK")) {
            throw new IllegalArgumentException("Format inconnu : " + r.format() + " (GENERIC ou SLACK)");
        }
        String min = r.minSeverity() == null ? "CRITICAL" : r.minSeverity().strip().toUpperCase(Locale.ROOT);
        if (!WebhookMessages.SEVERITIES.contains(min)) {
            throw new IllegalArgumentException("Sévérité inconnue : " + r.minSeverity());
        }
        Set<String> events = new LinkedHashSet<>();
        for (String e : r.events() == null || r.events().isEmpty() ? List.of("NEW_FINDINGS") : r.events()) {
            String ev = e == null ? "" : e.strip().toUpperCase(Locale.ROOT);
            if (!WebhookMessages.EVENTS.contains(ev)) {
                throw new IllegalArgumentException("Événement inconnu : " + e);
            }
            events.add(ev);
        }
        if (r.secret() != null && r.secret().length() > 256) {
            throw new IllegalArgumentException("Secret trop long (256 caractères au plus)");
        }
        return new Valid(name, WebhookMessages.checkUrl(r.url()), format, min, List.copyOf(events), r.enabled() == null || r.enabled());
    }

    @Transactional(readOnly = true)
    public List<WebhookView> list() {
        return jdbc.query(AutomationSql.LIST_WEBHOOKS, new MapSqlParameterSource(), (rs, i) -> view(rs));
    }

    @Transactional(readOnly = true)
    public WebhookView get(UUID id) {
        return jdbc.query(AutomationSql.GET_WEBHOOK, new MapSqlParameterSource("id", id), (rs, i) -> view(rs)).stream()
                .findFirst().orElseThrow(() -> new ResourceNotFoundException("Webhook " + id + " not found"));
    }

    @Transactional
    public WebhookView create(WebhookRequest request) {
        Valid v = validate(request);
        UUID id = UUID.randomUUID();
        MapSqlParameterSource p = params(id, v).addValue("user", currentUser());
        addSecret(p, id, request.secret());
        jdbc.update(AutomationSql.INSERT_WEBHOOK, p);
        audit.record("WEBHOOK_CREATED", OWNER_TABLE, id.toString(), Map.of("name", v.name(), "url", WebhookMessages.maskUrl(v.url())));
        return get(id);
    }

    @Transactional
    public WebhookView update(UUID id, WebhookRequest request) {
        get(id);
        if (request != null && (request.url() == null || request.url().isBlank())) {
            // the UI only shows a masked URL: an empty URL keeps the stored one
            request = new WebhookRequest(request.name(), urlOf(id), request.format(), request.minSeverity(), request.events(),
                    request.enabled(), request.secret());
        }
        Valid v = validate(request);
        jdbc.update(AutomationSql.UPDATE_WEBHOOK, params(id, v));
        if (request.secret() != null) {
            MapSqlParameterSource p = new MapSqlParameterSource("id", id);
            addSecret(p, id, request.secret());
            jdbc.update(AutomationSql.UPDATE_WEBHOOK_SECRET, p);
        }
        audit.record("WEBHOOK_UPDATED", OWNER_TABLE, id.toString(), Map.of("name", v.name(), "enabled", v.enabled()));
        return get(id);
    }

    @Transactional
    public void delete(UUID id) {
        WebhookView w = get(id);
        jdbc.update(AutomationSql.DELETE_WEBHOOK, new MapSqlParameterSource("id", id));
        audit.record("WEBHOOK_DELETED", OWNER_TABLE, id.toString(), Map.of("name", w.name()));
    }

    @Transactional(readOnly = true)
    public List<DeliveryView> deliveries(UUID id) {
        get(id);
        return jdbc.query(AutomationSql.LIST_DELIVERIES, new MapSqlParameterSource("id", id), (rs, i) -> new DeliveryView(
                JdbcRows.uuid(rs, "id"), rs.getString("event_type"), rs.getString("status"), rs.getInt("attempts"),
                JdbcRows.integer(rs, "last_http_status"), rs.getString("last_error"), JdbcRows.instant(rs, "created_at"),
                JdbcRows.instant(rs, "delivered_at"), JdbcRows.instant(rs, "next_attempt_at")));
    }

    /** Sends a test message now (not through the outbox) and reports the HTTP result. */
    public TestResult test(UUID id) {
        WebhookView w = get(id);
        Endpoint e = endpoint(id);
        Map<String, Object> payload = WebhookMessages.render(w.format(), WebhookMessages.testPayload(publicUrl));
        Attempt a = send(e.url(), "TEST", UUID.randomUUID(), Json.write(payload), e.secret());
        audit.record("WEBHOOK_TESTED", OWNER_TABLE, id.toString(), Map.of("delivered", a.ok()));
        return new TestResult(a.ok(), a.httpStatus(), a.ok() ? "Message reçu par le service (HTTP " + a.httpStatus() + ")" : a.error());
    }

    // ------------------------------------------------------------------ outbox (called by the worker)

    /**
     * Writes the deliveries of a finished job (called right after the job's commit); never throws.
     * REQUIRES_NEW: in afterCommit the committed transaction's resources are still bound (Spring docs).
     */
    @Transactional(propagation = org.springframework.transaction.annotation.Propagation.REQUIRES_NEW)
    public void jobFinished(UUID jobId) {
        try {
            List<WebhookMessages.JobContext> ctx = jdbc.query(AutomationSql.JOB_CONTEXT, new MapSqlParameterSource("jobId", jobId),
                    (rs, i) -> new WebhookMessages.JobContext(jobId.toString(), String.valueOf(JdbcRows.uuid(rs, "scan_run_id")),
                            String.valueOf(JdbcRows.uuid(rs, "repository_id")), rs.getString("full_name"), rs.getString("branch"),
                            rs.getString("status"), rs.getString("commit_sha"), rs.getInt("findings_count"),
                            rs.getInt("new_findings"), rs.getInt("resolved_findings")));
            if (ctx.isEmpty()) {
                return;
            }
            WebhookMessages.JobContext job = ctx.getFirst();
            List<WebhookMessages.NewFinding> fresh = null;
            for (Map<String, Object> endpoint : jdbc.queryForList(AutomationSql.SUBSCRIBED_WEBHOOKS,
                    new MapSqlParameterSource("event", "NEW_FINDINGS"))) {
                if (fresh == null) {
                    fresh = jdbc.query(AutomationSql.NEW_FINDINGS_OF_JOB, new MapSqlParameterSource("jobId", jobId),
                            (rs, i) -> new WebhookMessages.NewFinding(String.valueOf(JdbcRows.uuid(rs, "id")), rs.getString("severity"),
                                    rs.getString("type"), rs.getString("scanner_id"), rs.getString("rule_id"), rs.getString("title"),
                                    rs.getString("file_path"), JdbcRows.integer(rs, "start_line"), rs.getString("cve_id"),
                                    rs.getString("package_name"), rs.getString("package_version")));
                }
                String min = String.valueOf(endpoint.get("min_severity"));
                if (fresh.stream().anyMatch(f -> WebhookMessages.atLeast(f.severity(), min))) {
                    enqueue(endpoint, "NEW_FINDINGS", WebhookMessages.newFindingsPayload(job, fresh, publicUrl, min));
                }
            }
            for (Map<String, Object> endpoint : jdbc.queryForList(AutomationSql.SUBSCRIBED_WEBHOOKS,
                    new MapSqlParameterSource("event", "SCAN_COMPLETED"))) {
                enqueue(endpoint, "SCAN_COMPLETED", WebhookMessages.scanCompletedPayload(job, publicUrl));
            }
        } catch (RuntimeException e) {
            log.warn("Webhook notifications of job {} not queued: {}", jobId, e.getMessage());
        }
    }

    private void enqueue(Map<String, Object> endpoint, String event, Map<String, Object> payload) {
        jdbc.queryForObject(AutomationSql.ENQUEUE_DELIVERY, new MapSqlParameterSource()
                .addValue("endpointId", endpoint.get("id")).addValue("event", event)
                .addValue("payload", Json.write(WebhookMessages.render(String.valueOf(endpoint.get("format")), payload))), UUID.class);
    }

    // ------------------------------------------------------------------ delivery

    record Attempt(boolean ok, Integer httpStatus, String error) {
    }

    record Endpoint(String url, String secret) {
    }

    Attempt send(String url, String event, UUID deliveryId, String body, String secret) {
        long timestamp = Instant.now().getEpochSecond();
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(15))
                .header("Content-Type", "application/json; charset=utf-8")
                .header("User-Agent", "SAYTU-Webhook/1")
                .header("X-Saytu-Event", event)
                .header("X-Saytu-Delivery", deliveryId.toString())
                .header("X-Saytu-Timestamp", Long.toString(timestamp))
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        if (secret != null && !secret.isEmpty()) {
            request.header("X-Saytu-Signature", WebhookMessages.signature(secret, timestamp, body));
        }
        try {
            HttpResponse<Void> response = http.send(request.build(), HttpResponse.BodyHandlers.discarding());
            int status = response.statusCode();
            return status >= 200 && status < 300 ? new Attempt(true, status, null)
                    : new Attempt(false, status, "Réponse HTTP " + status + " de " + WebhookMessages.maskUrl(url));
        } catch (IOException e) {
            return new Attempt(false, null, "Échec de connexion à " + WebhookMessages.maskUrl(url) + " : " + e.getClass().getSimpleName());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Attempt(false, null, "Interrompu");
        }
    }

    Endpoint endpoint(UUID id) {
        return jdbc.query(AutomationSql.WEBHOOK_SECRET, new MapSqlParameterSource("id", id), (rs, i) -> {
            byte[] cipher = rs.getBytes("secret_ciphertext");
            String secret = cipher == null ? null : decrypt(id, cipher, rs.getString("secret_key_id"));
            return new Endpoint(null, secret);
        }).stream().findFirst().map(e -> new Endpoint(urlOf(id), e.secret()))
                .orElseThrow(() -> new ResourceNotFoundException("Webhook " + id + " not found"));
    }

    private String urlOf(UUID id) {
        return jdbc.queryForObject("SELECT url FROM webhook_endpoint WHERE id = :id", new MapSqlParameterSource("id", id), String.class);
    }

    String decrypt(UUID endpointId, byte[] cipher, String keyId) {
        try (SensitiveValue v = vault.decrypt(cipher, keyId, TokenVault.owner(OWNER_TABLE, endpointId))) {
            return v.reveal();
        }
    }

    private void addSecret(MapSqlParameterSource p, UUID id, String secret) {
        if (secret == null || secret.isEmpty()) {
            p.addValue("secretCiphertext", null, Types.BINARY).addValue("secretKeyId", null, Types.VARCHAR);
            return;
        }
        try (SensitiveValue value = SensitiveValue.of(secret)) {
            TokenCipher.Encrypted e = vault.encrypt(value, TokenVault.owner(OWNER_TABLE, id));
            p.addValue("secretCiphertext", e.ciphertext(), Types.BINARY).addValue("secretKeyId", e.keyId());
        }
    }

    private static MapSqlParameterSource params(UUID id, Valid v) {
        return new MapSqlParameterSource().addValue("id", id).addValue("name", v.name()).addValue("url", v.url())
                .addValue("format", v.format()).addValue("minSeverity", v.minSeverity())
                .addValue("events", v.events().toArray(String[]::new), Types.ARRAY).addValue("enabled", v.enabled());
    }

    private static WebhookView view(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new WebhookView(JdbcRows.uuid(rs, "id"), rs.getString("name"), WebhookMessages.maskUrl(rs.getString("url")),
                rs.getString("format"), rs.getString("min_severity"), JdbcRows.strings(rs, "events"), rs.getBoolean("enabled"),
                rs.getBoolean("has_secret"), rs.getString("last_status"), JdbcRows.instant(rs, "last_delivered_at"),
                rs.getString("created_by"), JdbcRows.instant(rs, "created_at"));
    }

    private static String currentUser() {
        var auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        return auth == null ? "system" : auth.getName();
    }
}
