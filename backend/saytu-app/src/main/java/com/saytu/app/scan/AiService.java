package com.saytu.app.scan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.saytu.app.audit.AuditService;
import com.saytu.app.web.ServiceUnavailableException;
import com.saytu.core.remediation.RemediationProvider;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Settings of the optional local AI and generated explanations (cached per finding and model). */
@Service
public class AiService {

    static final String SETTING = "ai.ollama";

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper json;
    private final FindingQueryService findings;
    private final AuditService audit;

    public AiService(NamedParameterJdbcTemplate jdbc, ObjectMapper json, FindingQueryService findings, AuditService audit) {
        this.jdbc = jdbc;
        this.json = json;
        this.findings = findings;
        this.audit = audit;
    }

    public record Explanation(RemediationProvider.Remediation content, String providerId, Instant createdAt) {
    }

    public record TestResult(boolean reachable, boolean modelAvailable, List<String> models, String message) {
    }

    @Transactional(readOnly = true)
    public AiSettings settings() {
        List<String> raw = jdbc.queryForList(AutomationSql.GET_SETTING, new MapSqlParameterSource("key", SETTING), String.class);
        if (raw.isEmpty()) {
            return AiSettings.DEFAULT;
        }
        try {
            JsonNode n = json.readTree(raw.getFirst());
            AiSettings d = AiSettings.DEFAULT;
            return new AiSettings(n.path("enabled").asBoolean(d.enabled()), n.path("baseUrl").asText(d.baseUrl()),
                    n.path("model").asText(d.model()), n.path("timeoutSeconds").asInt(d.timeoutSeconds()));
        } catch (IOException e) {
            return AiSettings.DEFAULT;
        }
    }

    @Transactional
    public AiSettings update(AiSettings requested) {
        AiSettings s = requested.validated();
        try {
            jdbc.update(AutomationSql.PUT_SETTING, new MapSqlParameterSource().addValue("key", SETTING)
                    .addValue("value", json.writeValueAsString(s)).addValue("user", currentUser()));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        audit.record("AI_SETTINGS_UPDATED", "app_setting", SETTING, Map.of("enabled", s.enabled(), "model", s.model()));
        return s;
    }

    /** Checks that Ollama answers and has the model (GET /api/tags). */
    public TestResult test() {
        AiSettings s = settings().validated();
        try {
            HttpResponse<String> r = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build().send(
                    HttpRequest.newBuilder(URI.create(s.baseUrl() + "/api/tags")).timeout(Duration.ofSeconds(10)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) {
                return new TestResult(false, false, List.of(), "Ollama a répondu HTTP " + r.statusCode());
            }
            List<String> models = new ArrayList<>();
            json.readTree(r.body()).path("models").forEach(m -> models.add(m.path("name").asText()));
            boolean available = models.stream().anyMatch(m -> m.equals(s.model()) || m.equals(s.model() + ":latest"));
            return new TestResult(true, available, models, available ? "Ollama répond et le modèle est installé"
                    : "Ollama répond mais le modèle n'est pas installé : docker compose exec ollama ollama pull " + s.model());
        } catch (IOException e) {
            return new TestResult(false, false, List.of(), "Ollama injoignable à " + s.baseUrl()
                    + " : démarrer le profil ai (docker compose --profile ai up -d)");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new TestResult(false, false, List.of(), "Interrompu");
        }
    }

    @Transactional(readOnly = true)
    public Explanation cached(UUID findingId) {
        findings.get(findingId);
        return jdbc.query(AutomationSql.GET_REMEDIATION, new MapSqlParameterSource("findingId", findingId), (rs, i) -> {
            try {
                return new Explanation(json.readValue(rs.getString("content"), RemediationProvider.Remediation.class),
                        rs.getString("provider_id"), JdbcRows.instant(rs, "created_at"));
            } catch (IOException e) {
                return null;
            }
        }).stream().filter(java.util.Objects::nonNull).findFirst().orElse(null);
    }

    /** Generates (or regenerates) the explanation; not transactional while waiting for the model. */
    public Explanation generate(UUID findingId) {
        AiSettings s = settings();
        if (!s.enabled()) {
            throw new ServiceUnavailableException("IA locale désactivée : l'activer dans Utilisateurs & paramètres");
        }
        ScanViews.FindingDetail detail = findings.get(findingId);
        OllamaRemediationProvider provider = new OllamaRemediationProvider(json, s.validated());
        RemediationProvider.Remediation r = provider.explain(detail);
        try {
            jdbc.update(AutomationSql.SAVE_REMEDIATION, new MapSqlParameterSource().addValue("findingId", findingId)
                    .addValue("providerId", provider.providerId()).addValue("content", json.writeValueAsString(r)));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        audit.record("AI_EXPLANATION_GENERATED", "finding", findingId.toString(), Map.of("model", s.model()));
        return new Explanation(r, provider.providerId(), Instant.now());
    }

    private static String currentUser() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        return auth == null ? "system" : auth.getName();
    }
}
