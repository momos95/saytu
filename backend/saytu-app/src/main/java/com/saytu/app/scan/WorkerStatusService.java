package com.saytu.app.scan;

import com.saytu.scan.sandbox.ScannerIsolation;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Isolation of the scanners as reported by the worker at startup ({@code app_setting['worker.isolation']}),
 * read by the API for the "Scanners & branches" page: the API process never runs scanners itself.
 */
@Service
public class WorkerStatusService {

    static final String KEY = "worker.isolation";

    /**
     * @param separateUser scanners run under a dedicated account per job (not the worker's)
     * @param network      "blocked", or "open: reason"
     * @param detail       why the scanners are not isolated, null when they are
     */
    public record Isolation(boolean separateUser, String network, String detail, String workerId, Instant reportedAt) {
        public boolean networkBlocked() {
            return "blocked".equals(network);
        }
    }

    private final NamedParameterJdbcTemplate jdbc;

    public WorkerStatusService(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** Called by the worker when it starts. */
    public void publish(String workerId, ScannerIsolation isolation) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("separateUser", isolation.enabled());
        value.put("network", isolation.networkStatus());
        value.put("detail", isolation.disabledReason().orElse(null));
        value.put("workerId", workerId);
        value.put("reportedAt", Instant.now().toString());
        jdbc.update(AutomationSql.PUT_SETTING, new MapSqlParameterSource().addValue("key", KEY)
                .addValue("value", Json.write(value)).addValue("user", "worker"));
    }

    /** Latest report, or null before the first worker start. */
    public Isolation isolation() {
        List<String> rows = jdbc.queryForList(AutomationSql.GET_SETTING, new MapSqlParameterSource("key", KEY), String.class);
        if (rows.isEmpty()) {
            return null;
        }
        return parse(rows.getFirst());
    }

    static Isolation parse(String json) {
        Map<String, Object> m = Json.read(json);
        Object at = m.get("reportedAt");
        return new Isolation(Boolean.TRUE.equals(m.get("separateUser")), (String) m.get("network"),
                (String) m.get("detail"), (String) m.get("workerId"), at == null ? null : Instant.parse(at.toString()));
    }
}
