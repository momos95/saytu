package com.saytu.app.scan;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Pure part of the webhooks: payloads, Slack-compatible text, HMAC signature, retry delays, URL checks.
 * Payloads carry titles and locations only: never evidence, code or secrets.
 */
final class WebhookMessages {

    static final int MAX_FINDINGS = 20;
    static final int MAX_ATTEMPTS = 6;
    private static final long[] RETRY_SECONDS = {60, 300, 1800, 7200, 21600};
    static final List<String> SEVERITIES = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO");
    static final List<String> EVENTS = List.of("NEW_FINDINGS", "SCAN_COMPLETED");
    private static final Map<String, String> LABELS = Map.of("CRITICAL", "Critique", "HIGH", "Élevée", "MEDIUM", "Moyenne",
            "LOW", "Faible", "INFO", "Info");

    private WebhookMessages() {
    }

    record NewFinding(String id, String severity, String type, String scanner, String ruleId, String title, String filePath,
                      Integer startLine, String cve, String packageName, String packageVersion) {
        String location() {
            return filePath == null ? "" : filePath + (startLine == null ? "" : ":" + startLine);
        }
    }

    record JobContext(String jobId, String runId, String repositoryId, String repository, String branch, String status,
                      String commitSha, int findings, int newFindings, int resolvedFindings) {
    }

    /** True when {@code severity} is at least {@code minimum} (CRITICAL is the highest). */
    static boolean atLeast(String severity, String minimum) {
        return SEVERITIES.indexOf(severity) <= SEVERITIES.indexOf(minimum) && SEVERITIES.contains(severity);
    }

    static Map<String, Object> newFindingsPayload(JobContext job, List<NewFinding> findings, String publicUrl, String minimum) {
        List<NewFinding> kept = findings.stream().filter(f -> atLeast(f.severity(), minimum)).toList();
        Map<String, Long> counts = new LinkedHashMap<>();
        for (String s : SEVERITIES) {
            long n = kept.stream().filter(f -> f.severity().equals(s)).count();
            if (n > 0) {
                counts.put(s, n);
            }
        }
        List<Map<String, Object>> items = new ArrayList<>();
        for (NewFinding f : kept.stream().limit(MAX_FINDINGS).toList()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", f.id());
            m.put("severity", f.severity());
            m.put("type", f.type());
            m.put("scanner", f.scanner());
            m.put("ruleId", f.ruleId());
            m.put("title", f.title());
            m.put("location", f.location());
            m.put("cve", f.cve());
            m.put("package", f.packageName() == null ? null : f.packageName() + (f.packageVersion() == null ? "" : "@" + f.packageVersion()));
            m.put("url", base(publicUrl) + "/findings/" + f.id());
            items.add(m);
        }
        Map<String, Object> p = header("NEW_FINDINGS", job, publicUrl);
        p.put("minSeverity", minimum);
        p.put("counts", counts);
        p.put("total", kept.size());
        p.put("truncated", kept.size() > MAX_FINDINGS);
        p.put("findings", items);
        return p;
    }

    static Map<String, Object> scanCompletedPayload(JobContext job, String publicUrl) {
        Map<String, Object> p = header("SCAN_COMPLETED", job, publicUrl);
        p.put("status", job.status());
        p.put("findings", job.findings());
        p.put("newFindings", job.newFindings());
        p.put("resolvedFindings", job.resolvedFindings());
        return p;
    }

    static Map<String, Object> testPayload(String publicUrl) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("event", "TEST");
        p.put("source", "SAYTU");
        p.put("message", "Test de notification SAYTU : la configuration du webhook fonctionne.");
        p.put("url", base(publicUrl));
        return p;
    }

    private static Map<String, Object> header(String event, JobContext job, String publicUrl) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("event", event);
        p.put("source", "SAYTU");
        p.put("repository", job.repository());
        p.put("branch", job.branch());
        p.put("commitSha", job.commitSha());
        p.put("jobId", job.jobId());
        p.put("runId", job.runId());
        p.put("url", base(publicUrl) + "/repositories/" + job.repositoryId());
        return p;
    }

    /** Body actually sent: the generic JSON, or {"text": …} understood by Slack, Mattermost and Rocket.Chat. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> render(String format, Map<String, Object> payload) {
        if (!"SLACK".equals(format)) {
            return payload;
        }
        StringBuilder t = new StringBuilder();
        String event = String.valueOf(payload.get("event"));
        switch (event) {
            case "NEW_FINDINGS" -> {
                t.append("🚨 SAYTU — ").append(payload.get("total")).append(" nouvelle(s) vulnérabilité(s) sur ")
                        .append(payload.get("repository")).append(" (").append(payload.get("branch")).append(")\n");
                for (Map<String, Object> f : (List<Map<String, Object>>) payload.get("findings")) {
                    t.append("• [").append(LABELS.getOrDefault(String.valueOf(f.get("severity")), String.valueOf(f.get("severity"))))
                            .append("] ").append(f.get("title"));
                    Object location = f.get("location");
                    if (location != null && !location.toString().isEmpty()) {
                        t.append(" — ").append(location);
                    }
                    t.append('\n');
                }
                if (Boolean.TRUE.equals(payload.get("truncated"))) {
                    t.append("… et d'autres dans SAYTU\n");
                }
            }
            case "SCAN_COMPLETED" -> t.append("SAYTU — audit terminé sur ").append(payload.get("repository")).append(" (")
                    .append(payload.get("branch")).append(") : ").append(payload.get("status")).append(", ")
                    .append(payload.get("newFindings")).append(" nouvelle(s), ").append(payload.get("resolvedFindings"))
                    .append(" corrigée(s)\n");
            default -> t.append(payload.getOrDefault("message", "SAYTU")).append('\n');
        }
        t.append(payload.get("url"));
        return Map.of("text", t.toString());
    }

    /** "sha256=<hex>" of HMAC-SHA256(secret, timestamp + "." + body). */
    static String signature(String secret, long timestamp, String body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return "sha256=" + HexFormat.of().formatHex(mac.doFinal((timestamp + "." + body).getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Seconds before the next attempt after {@code attempts} failures. */
    static long retryDelay(int attempts) {
        return RETRY_SECONDS[Math.min(Math.max(attempts, 1), RETRY_SECONDS.length) - 1];
    }

    /** Validated URL: http(s), a host, no user info, 2048 characters at most. */
    static String checkUrl(String url) {
        String u = url == null ? "" : url.strip();
        URI uri;
        try {
            uri = URI.create(u);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("URL invalide");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (u.length() > 2048 || !(scheme.equals("https") || scheme.equals("http")) || uri.getHost() == null) {
            throw new IllegalArgumentException("URL invalide : http(s)://hôte/chemin attendu");
        }
        if (uri.getRawUserInfo() != null) {
            throw new IllegalArgumentException("Pas d'identifiants dans l'URL : utilisez le secret de signature");
        }
        return u;
    }

    /** URL shown in the UI and logs: scheme, host and port only (paths often hold a token, e.g. Slack). */
    static String maskUrl(String url) {
        try {
            URI uri = URI.create(url);
            return uri.getScheme() + "://" + uri.getHost() + (uri.getPort() > 0 ? ":" + uri.getPort() : "")
                    + (uri.getRawPath() == null || uri.getRawPath().isEmpty() || uri.getRawPath().equals("/") ? "" : "/…");
        } catch (IllegalArgumentException e) {
            return "(URL invalide)";
        }
    }

    private static String base(String publicUrl) {
        String b = publicUrl == null ? "" : publicUrl.strip();
        return b.endsWith("/") ? b.substring(0, b.length() - 1) : b;
    }
}
