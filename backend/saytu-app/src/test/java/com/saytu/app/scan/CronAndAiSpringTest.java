package com.saytu.app.scan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.saytu.app.web.ServiceUnavailableException;
import com.saytu.core.remediation.RemediationProvider;

import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;

/** Needs Spring's CronExpression and Jackson: runs with Maven (docker compose build). */
class CronAndAiSpringTest {

    @Test
    void cronExpressionsAreNormalizedAndBounded() {
        assertEquals("0 0 2 * * 1-5", CronSchedules.normalize(" 0 2 * * 1-5 "));
        assertEquals("0 30 6 * * MON", CronSchedules.normalize("0 30 6 * * MON"));
        assertEquals("@daily", CronSchedules.normalize("@DAILY"));
        assertThrows(IllegalArgumentException.class, () -> CronSchedules.normalize("tous les jours"));
        assertThrows(IllegalArgumentException.class, () -> CronSchedules.normalize(""));
        Instant now = Instant.parse("2026-11-08T00:00:00Z");
        assertThrows(IllegalArgumentException.class,
                () -> CronSchedules.checkInterval(CronSchedules.normalize("* * * * *"), ZoneId.of("UTC"), now));
        CronSchedules.checkInterval("0 0 2 * * *", ZoneId.of("UTC"), now);
        assertEquals(Instant.parse("2026-11-08T01:00:00Z"),
                CronSchedules.next("0 0 2 * * *", ZoneId.of("Europe/Paris"), now).orElseThrow(), "2 h à Paris = 1 h UTC en hiver");
        assertThrows(IllegalArgumentException.class, () -> CronSchedules.zone("Mars/Olympus"));
    }

    @Test
    void scheduleRequestsAreValidated() {
        Instant now = Instant.parse("2026-11-08T00:00:00Z");
        var v = ScheduleService.validate(new ScheduleService.ScheduleRequest("Nuit", "0 2 * * *", "Europe/Paris", null, null,
                null, null), now);
        assertEquals("ALL_SELECTED", v.scope());
        assertEquals("0 0 2 * * *", v.cron());
        assertTrue(v.enabled());
        assertThrows(IllegalArgumentException.class, () -> ScheduleService.validate(new ScheduleService.ScheduleRequest("x",
                "0 2 * * *", "UTC", "REPOSITORIES", true, List.of(), null), now));
        UUID repo = UUID.randomUUID();
        assertEquals(List.of(repo), ScheduleService.validate(new ScheduleService.ScheduleRequest("x", "0 2 * * *", "UTC",
                "repositories", true, List.of(repo, repo), null), now).targets());
        assertThrows(IllegalArgumentException.class, () -> ScheduleService.validate(new ScheduleService.ScheduleRequest("x",
                "0 2 * * *", "UTC", "EVERYTHING", true, null, null), now));
    }

    @Test
    void ollamaAnswersAreParsedDefensively() {
        ObjectMapper json = new ObjectMapper();
        RemediationProvider.Remediation r = OllamaRemediationProvider.parse(json,
                "{\"explanation\":\"Injection SQL.\",\"impact\":\"Fuite.\",\"fix\":\"1. Requête préparée\\n- Liste blanche\","
                        + "\"codeExample\":\"ps.setString(1, email);\",\"tests\":[\"Test avec ' OR 1=1\"]}", "ollama:m");
        assertEquals("Injection SQL.", r.explanation());
        assertEquals(List.of("Requête préparée", "Liste blanche"), r.steps());
        assertEquals(List.of("Test avec ' OR 1=1"), r.suggestedTests());
        assertEquals("ps.setString(1, email);", r.fixedCodeExample());
        assertEquals("ollama:m", r.providerId());
        assertEquals("pas du JSON", OllamaRemediationProvider.parse(json, "pas du JSON", "ollama:m").explanation());
        assertThrows(ServiceUnavailableException.class, () -> OllamaRemediationProvider.parse(json, "{}", "ollama:m"));
    }
}
