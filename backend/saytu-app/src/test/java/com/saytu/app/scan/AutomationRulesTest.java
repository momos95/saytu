package com.saytu.app.scan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;

class AutomationRulesTest {

    private static final WebhookMessages.JobContext JOB = new WebhookMessages.JobContext("j1", "r1", "repo-1", "acme/api", "main",
            "SUCCEEDED", "abc", 10, 3, 1);

    private static WebhookMessages.NewFinding f(String id, String severity, String title) {
        return new WebhookMessages.NewFinding(id, severity, "SECURITY", "opengrep", "rule", title, "src/A.java", 12, null, null, null);
    }

    @Test
    void newFindingsPayloadKeepsOnlyTheMinimumSeverityAndNoEvidence() {
        Map<String, Object> p = WebhookMessages.newFindingsPayload(JOB,
                List.of(f("1", "CRITICAL", "SQLi"), f("2", "HIGH", "XSS"), f("3", "LOW", "Style")), "https://saytu.example/", "HIGH");
        assertEquals("NEW_FINDINGS", p.get("event"));
        assertEquals(2, p.get("total"));
        assertEquals(Map.of("CRITICAL", 1L, "HIGH", 1L), p.get("counts"));
        assertEquals("https://saytu.example/repositories/repo-1", p.get("url"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) p.get("findings");
        assertEquals("https://saytu.example/findings/1", items.getFirst().get("url"));
        assertEquals("src/A.java:12", items.getFirst().get("location"));
        assertFalse(Json.write(p).contains("evidence"));
        assertTrue(WebhookMessages.atLeast("CRITICAL", "HIGH"));
        assertFalse(WebhookMessages.atLeast("MEDIUM", "HIGH"));
        assertFalse(WebhookMessages.atLeast("BOGUS", "INFO"));
    }

    @Test
    void slackFormatIsASingleTextField() {
        Map<String, Object> p = WebhookMessages.newFindingsPayload(JOB, List.of(f("1", "CRITICAL", "SQLi")), "https://s.example", "CRITICAL");
        Map<String, Object> slack = WebhookMessages.render("SLACK", p);
        assertEquals(Set.of("text"), slack.keySet());
        String text = (String) slack.get("text");
        assertTrue(text.contains("1 nouvelle(s) vulnérabilité(s) sur acme/api (main)"));
        assertTrue(text.contains("• [Critique] SQLi — src/A.java:12"));
        assertTrue(text.endsWith("https://s.example/repositories/repo-1"));
        assertEquals(p, WebhookMessages.render("GENERIC", p));
    }

    @Test
    void signatureRetriesAndUrls() {
        // HMAC-SHA256("key", "1700000000.{}") computed with: printf '%s' '1700000000.{}' | openssl dgst -sha256 -hmac key
        assertEquals("sha256=9d713ed406bb7076d4123f0dc2c39d2df5c654ed4b0cd56b52c8b4c940bd63ae", WebhookMessages.signature("key", 1_700_000_000L, "{}"));
        assertTrue(WebhookMessages.signature("key", 1_700_000_000L, "{}").matches("sha256=[0-9a-f]{64}"));
        assertEquals(WebhookMessages.signature("k", 1, "a"), WebhookMessages.signature("k", 1, "a"));
        assertFalse(WebhookMessages.signature("k", 1, "a").equals(WebhookMessages.signature("k", 2, "a")));
        assertEquals(60, WebhookMessages.retryDelay(1));
        assertEquals(21600, WebhookMessages.retryDelay(9));
        assertEquals("https://hooks.slack.com/…", WebhookMessages.maskUrl("https://hooks.slack.com/services/T0/B0/secret"));
        assertEquals("http://chat.local:8065", WebhookMessages.maskUrl("http://chat.local:8065"));
        assertThrows(IllegalArgumentException.class, () -> WebhookMessages.checkUrl("ftp://x"));
        assertThrows(IllegalArgumentException.class, () -> WebhookMessages.checkUrl("https://user:pass@x/h"));
        assertThrows(IllegalArgumentException.class, () -> WebhookMessages.checkUrl("javascript:alert(1)"));
        assertEquals("https://x.example/h", WebhookMessages.checkUrl(" https://x.example/h "));
    }

    @Test
    void webhookRequestValidation() {
        var ok = WebhookService.validate(new WebhookService.WebhookRequest("Équipe", "https://x.example/h", "slack", "high",
                List.of("new_findings", "SCAN_COMPLETED"), null, null));
        assertEquals("SLACK", ok.format());
        assertEquals("HIGH", ok.minSeverity());
        assertEquals(List.of("NEW_FINDINGS", "SCAN_COMPLETED"), ok.events());
        assertTrue(ok.enabled());
        assertEquals(List.of("NEW_FINDINGS"), WebhookService.validate(new WebhookService.WebhookRequest("a", "https://x.example",
                null, null, null, false, null)).events());
        assertThrows(IllegalArgumentException.class, () -> WebhookService.validate(new WebhookService.WebhookRequest("a",
                "https://x.example", "TEAMS", null, null, null, null)));
        assertThrows(IllegalArgumentException.class, () -> WebhookService.validate(new WebhookService.WebhookRequest("a",
                "https://x.example", null, null, List.of("DELETE_ALL"), null, null)));
        assertThrows(IllegalArgumentException.class, () -> WebhookService.validate(new WebhookService.WebhookRequest(" ",
                "https://x.example", null, null, null, null, null)));
    }

    @Test
    void comparisonNeverCountsAFailedScannerAsAFix() {
        UUID a = UUID.randomUUID(); // seen in both
        UUID b = UUID.randomUUID(); // gone, trivy succeeded in head → fixed
        UUID c = UUID.randomUUID(); // gone, gitleaks failed in head → not verifiable
        UUID d = UUID.randomUUID(); // new, opengrep succeeded in base → introduced
        UUID e = UUID.randomUUID(); // new, pmd did not run in base → not verifiable
        var base = Map.of(a, Set.of("opengrep"), b, Set.of("trivy"), c, Set.of("gitleaks"));
        var head = Map.of(a, Set.of("opengrep"), d, Set.of("opengrep"), e, Set.of("pmd"));
        var r = JobComparisonService.classify(base, head, Set.of("opengrep", "trivy", "gitleaks"), Set.of("opengrep", "trivy", "pmd"));
        assertEquals(1, r.persisting());
        assertEquals(Set.of(d), r.introduced());
        assertEquals(Set.of(b), r.fixed());
        assertEquals(Set.of(c, e), r.unverified());
    }

    @Test
    void scheduledScopeAndAiSettings() {
        assertNull(ScheduleTrigger.repositoryScope(Set.of()));
        UUID id = UUID.fromString("00000000-0000-0000-0000-000000000001");
        assertEquals("{\"repositoryIds\":[\"00000000-0000-0000-0000-000000000001\"]}", ScheduleTrigger.repositoryScope(Set.of(id)));
        AiSettings s = new AiSettings(true, " http://ollama:11434/ ", "qwen2.5-coder:7b", 120).validated();
        assertEquals("http://ollama:11434", s.baseUrl());
        assertThrows(IllegalArgumentException.class, () -> new AiSettings(true, "file:///etc", "m", 120).validated());
        assertThrows(IllegalArgumentException.class, () -> new AiSettings(true, "http://o:1", "m; rm -rf", 120).validated());
        assertThrows(IllegalArgumentException.class, () -> new AiSettings(true, "http://o:1", "m", 5).validated());
        assertFalse(AiSettings.DEFAULT.enabled());
    }
}
