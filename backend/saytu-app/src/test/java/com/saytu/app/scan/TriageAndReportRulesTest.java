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

    private static ScoreService.OpenSecurityFinding open(String type, String severity, String scanner, String rule, String path,
                                                         String pkg, String version, String fixed) {
        com.saytu.core.scoring.SecurityIssue issue = com.saytu.core.scoring.SecurityIssue.of(
                com.saytu.core.domain.FindingType.valueOf(type), com.saytu.core.domain.Severity.valueOf(severity),
                scanner, rule, path, List.of(), pkg, version, fixed);
        return new ScoreService.OpenSecurityFinding(UUID.randomUUID(), type, severity, scanner, rule, "Titre " + rule, path,
                pkg, version, fixed, issue);
    }

    @Test
    void actionPlanRanksFixesBySecurityGain() {
        var calc = new com.saytu.core.scoring.ScoreCalculator(com.saytu.core.scoring.ScoringFormula.DEFAULT);
        UUID repo = UUID.randomUUID();
        List<ScoreService.OpenSecurityFinding> open = List.of(
                open("DEPENDENCY", "CRITICAL", "trivy", "CVE-2021-44228", "pom.xml", "org.apache.logging.log4j:log4j-core", "2.14.1", "2.15.0"),
                open("DEPENDENCY", "HIGH", "trivy", "CVE-2021-45046", "pom.xml", "org.apache.logging.log4j:log4j-core", "2.14.1", "2.12.2, 2.16.0"),
                open("SECRET", "HIGH", "gitleaks", "generic-api-key", "a.yml", null, null, null),
                open("SECURITY", "MEDIUM", "trivy", "KSV-0118", "deploy/app.yaml", null, null, null));
        InsightService.ActionPlan plan = InsightService.plan(calc, repo, "main", open);
        assertEquals("main", plan.branch());
        assertEquals(3, plan.items().size());
        InsightService.ActionItem first = plan.items().getFirst();
        assertEquals("DEPENDENCY_UPGRADE", first.kind());
        assertEquals("2.16.0", first.fixedVersion(), "highest fixed version among the advisories");
        assertEquals(2, first.findings());
        assertEquals(59.0, first.securityBefore(), "critical cap");
        assertEquals(true, first.gain() > 30, "fixing the only critical lifts the cap: " + first.gain());
        assertEquals("org.apache.logging.log4j:log4j-core", first.query().get("q"));
        assertEquals("SECRET", plan.items().get(1).kind());
        assertEquals("CONFIGURATION", plan.items().get(2).kind());
    }

    @Test
    void planBranchIsTheWeakestScoredBranch() {
        assertEquals(null, InsightService.planBranch(List.of(), "main"));
        var noScore = new InsightService.BranchOverview("develop", null, java.util.Map.of(), 3);
        var main = new InsightService.BranchOverview("main", null, java.util.Map.of(), 1);
        assertEquals("main", InsightService.planBranch(List.of(noScore, main), "main"));
    }

    @Test
    void storedV2FormulaIsReadBack() {
        var f = ScoreService.parseFormula("{\"version\": \"v2\", \"securityCurve\": \"hyperbolic\", "
                + "\"categoryFactors\": {\"CONFIGURATION\": 0.25}, \"diminishingReturns\": false}");
        assertEquals(com.saytu.core.scoring.ScoringFormula.SecurityCurve.HYPERBOLIC, f.securityCurve());
        assertEquals(0.25, f.categoryFactors().get(com.saytu.core.scoring.SecurityIssue.Category.CONFIGURATION));
        assertEquals(1.0, f.categoryFactors().get(com.saytu.core.scoring.SecurityIssue.Category.CODE));
        assertEquals(false, f.diminishingReturns());
        assertEquals(f, ScoreService.parseFormula(ScoreService.formulaJson(f)));
    }
}
