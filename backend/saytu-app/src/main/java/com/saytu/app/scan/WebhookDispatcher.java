package com.saytu.app.scan;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Types;
import java.util.List;
import java.util.UUID;

/** Sends pending webhook deliveries (worker only), with retries: 1 min, 5 min, 30 min, 2 h, 6 h. */
@Component
@ConditionalOnProperty(prefix = "saytu.scan.worker", name = "enabled", havingValue = "true")
public class WebhookDispatcher {

    private static final Logger log = LoggerFactory.getLogger(WebhookDispatcher.class);

    private final NamedParameterJdbcTemplate jdbc;
    private final WebhookService webhooks;

    public WebhookDispatcher(NamedParameterJdbcTemplate jdbc, WebhookService webhooks) {
        this.jdbc = jdbc;
        this.webhooks = webhooks;
    }

    record Pending(UUID id, UUID endpointId, String event, String payload, int attempts, String url, byte[] cipher,
                   String keyId) {
    }

    @Scheduled(fixedDelayString = "${saytu.webhooks.poll-interval:PT15S}", initialDelayString = "PT30S")
    @Transactional
    public void deliver() {
        List<Pending> due = jdbc.query(AutomationSql.CLAIM_DELIVERIES, new MapSqlParameterSource(), (rs, i) -> new Pending(
                JdbcRows.uuid(rs, "id"), JdbcRows.uuid(rs, "endpoint_id"), rs.getString("event_type"), rs.getString("payload"),
                rs.getInt("attempts"), rs.getString("url"), rs.getBytes("secret_ciphertext"), rs.getString("secret_key_id")));
        for (Pending d : due) {
            String secret = d.cipher() == null ? null : webhooks.decrypt(d.endpointId(), d.cipher(), d.keyId());
            WebhookService.Attempt a = webhooks.send(d.url(), d.event(), d.id(), d.payload(), secret);
            if (a.ok()) {
                jdbc.update(AutomationSql.DELIVERY_SUCCEEDED, new MapSqlParameterSource("id", d.id())
                        .addValue("httpStatus", a.httpStatus()));
            } else {
                int attempts = d.attempts() + 1;
                jdbc.update(AutomationSql.DELIVERY_FAILED, new MapSqlParameterSource("id", d.id())
                        .addValue("httpStatus", a.httpStatus(), Types.INTEGER)
                        .addValue("error", a.error() == null ? null : a.error().substring(0, Math.min(1000, a.error().length())))
                        .addValue("maxAttempts", WebhookMessages.MAX_ATTEMPTS)
                        .addValue("retryInSeconds", WebhookMessages.retryDelay(attempts)));
                log.info("Webhook delivery {} failed (attempt {}): {}", d.id(), attempts, a.error());
            }
        }
    }
}
