package com.saytu.app.scan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.saytu.core.domain.FindingStatus;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;

class TriageAndReportRulesTest {

    private static FindingTriageService.StatusChange change(String status, String reason) {
        return new FindingTriageService.StatusChange(status, reason);
    }

    @Test
    void triageNeedsAReasonExceptToReopen() {
        assertEquals(FindingStatus.ACCEPTED_RISK, FindingTriageService.validate(change("accepted_risk", " contrôle compensatoire ")).getKey());
        assertEquals("contrôle compensatoire", FindingTriageService.validate(change("ACCEPTED_RISK", " contrôle compensatoire ")).getValue());
        assertEquals(FindingStatus.OPEN, FindingTriageService.validate(change("OPEN", null)).getKey());
        assertThrows(IllegalArgumentException.class, () -> FindingTriageService.validate(change("FALSE_POSITIVE", "  ")));
        assertThrows(IllegalArgumentException.class, () -> FindingTriageService.validate(change("RESOLVED", "fixed")));
        assertThrows(IllegalArgumentException.class, () -> FindingTriageService.validate(change("WONTFIX", "x")));
        assertThrows(IllegalArgumentException.class, () -> FindingTriageService.validate(change(null, "x")));
        assertThrows(IllegalArgumentException.class, () -> FindingTriageService.validate(change("FALSE_POSITIVE", "x".repeat(2001))));
    }

    @Test
    void reportsDefaultToOpenFindingsAndDescribeTheirScope() {
        FindingQueryService.Filter none = new FindingQueryService.Filter(null, null, null, null, null, null, null);
        assertEquals(List.of("OPEN"), ReportService.withDefaultStatus(none).statuses());
        FindingQueryService.Filter triaged = new FindingQueryService.Filter(UUID.randomUUID(), "main", List.of("high"),
                null, List.of("false_positive"), "pmd", "sql");
        assertEquals(List.of("FALSE_POSITIVE"), ReportService.withDefaultStatus(triaged).statuses());
        assertEquals(List.of("Dépôt : acme/api", "Branche : main", "Statut : FALSE_POSITIVE", "Sévérité : HIGH",
                "Scanner : pmd", "Recherche : « sql »"), ReportService.scope(triaged, "acme/api"));
        assertEquals(List.of("Tous les dépôts"), ReportService.scope(none, null));
    }

    @Test
    void reportFormats() {
        assertEquals(ReportService.Format.SARIF, ReportService.Format.parse(" sarif "));
        assertEquals("application/pdf", ReportService.Format.parse("PDF").contentType);
        assertThrows(IllegalArgumentException.class, () -> ReportService.Format.parse("docx"));
        assertThrows(IllegalArgumentException.class, () -> ReportService.Format.parse(null));
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                ReportService.sha256("abc".getBytes(StandardCharsets.US_ASCII)));
    }
}
