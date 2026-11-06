package com.saytu.core.scoring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.saytu.core.domain.FindingType;
import com.saytu.core.domain.Language;
import com.saytu.core.domain.LanguageProfile;
import com.saytu.core.domain.ScannerExecutionStatus;
import com.saytu.core.domain.ScannerId;
import com.saytu.core.domain.Severity;
import com.saytu.core.scoring.SecurityIssue.Category;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class ScoringV2Test {

    private final ScoreCalculator calc = new ScoreCalculator(ScoringFormula.DEFAULT);

    static final Map<ScannerId, ScannerExecutionStatus> ALL_OK = Map.of(
            ScannerId.OPENGREP, ScannerExecutionStatus.SUCCEEDED, ScannerId.TRIVY, ScannerExecutionStatus.SUCCEEDED,
            ScannerId.GITLEAKS, ScannerExecutionStatus.SUCCEEDED, ScannerId.CHECKSTYLE, ScannerExecutionStatus.SUCCEEDED,
            ScannerId.PMD, ScannerExecutionStatus.SUCCEEDED);

    static LanguageProfile java() {
        return new LanguageProfile(Map.of(Language.JAVA, new LanguageProfile.Stats(300, 1_500_000)), 300);
    }

    static SecurityIssue dep(Severity s, String pkg, boolean fix) {
        return SecurityIssue.of(FindingType.DEPENDENCY, s, "trivy", "CVE-x", "pom.xml", List.of(), pkg, "1.0", fix ? "1.1" : null);
    }

    static SecurityIssue code(Severity s, String rule) {
        return SecurityIssue.of(FindingType.SECURITY, s, "opengrep", rule, "src/main/java/A.java", List.of("CWE-89"), null, null, null);
    }

    static SecurityIssue config(Severity s, String rule) {
        return SecurityIssue.of(FindingType.SECURITY, s, "trivy", rule, "deploy/app.yaml", List.of(), null, null, null);
    }

    @Test
    void classifiesFindingsByTheFixTheyNeed() {
        assertEquals(Category.CODE, code(Severity.HIGH, "sqli").category());
        assertEquals(Category.CONFIGURATION, config(Severity.HIGH, "KSV-0118").category());
        assertEquals(Category.CONFIGURATION, SecurityIssue.of(FindingType.SECURITY, Severity.HIGH, "opengrep",
                "missing-user-entrypoint", "deployment/Dockerfile", List.of("CWE-269"), null, null, null).category());
        assertEquals(Category.CONFIGURATION, SecurityIssue.of(FindingType.SECURITY, Severity.HIGH, "opengrep",
                "x", "ms-a/deployment/manifests/deployment_dev.yml", List.of(), null, null, null).category());
        SecurityIssue secretByCwe = SecurityIssue.of(FindingType.SECURITY, Severity.MEDIUM, "opengrep",
                "detected-generic-secret", "src/main/resources/application-ppd.yml", List.of("CWE-798"), null, null, null);
        assertEquals(Category.SECRET, secretByCwe.category());
        assertEquals(Severity.HIGH, secretByCwe.severity(), "a committed secret is never below HIGH");
        assertEquals("dependency:com.fasterxml:jackson@1.0", dep(Severity.HIGH, "com.fasterxml:Jackson", true).group());
        assertNull(SecurityIssue.of(FindingType.QUALITY, Severity.HIGH, "pmd", "r", "A.java", List.of(), null, null, null));
    }

    @Test
    void repeatedFindingsOfOneGroupCountLessAndLess() {
        List<SecurityIssue> sameRule = new ArrayList<>();
        for (int i = 0; i < 30; i++) {
            sameRule.add(code(Severity.HIGH, "same"));
        }
        ScoreCalculator.GroupImpact g = calc.groups(sameRule).getFirst();
        assertEquals(30, g.findings());
        assertEquals(39.95, ScoreCalculator.round(g.points()), "10 × H(30), not 300");
        // a package with 10 CVEs is one upgrade
        List<SecurityIssue> onePackage = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            onePackage.add(dep(Severity.HIGH, "jackson", true));
        }
        assertEquals(1, calc.groups(onePackage).size());
    }

    @Test
    void configurationAndUnfixableDependenciesWeighLess() {
        assertEquals(10.0, calc.groups(List.of(code(Severity.HIGH, "a"))).getFirst().points());
        assertEquals(5.0, calc.groups(List.of(config(Severity.HIGH, "a"))).getFirst().points());
        assertEquals(10.0, calc.groups(List.of(dep(Severity.HIGH, "p", true))).getFirst().points());
        assertEquals(5.0, calc.groups(List.of(dep(Severity.HIGH, "p", false))).getFirst().points());
    }

    @Test
    void theScoreDecreasesSmoothlyAndNeverHitsZero() {
        assertEquals(100.0, calc.securityScore(0, false));
        assertEquals(90.91, calc.securityScore(10, false));
        assertEquals(50.0, calc.securityScore(100, false));
        assertEquals(28.57, calc.securityScore(250, false));
        assertEquals(9.09, calc.securityScore(1000, false));
        assertTrue(calc.securityScore(100_000, false) > 0);
        assertEquals(59.0, calc.securityScore(10, true), "critical cap kept");
    }

    /** Close to the ht-ms audit of 6 Nov 2026 (171 results): v1 gave 0, v2 must still rank it. */
    @Test
    void aRealisticMicroserviceLandsBetween20And40() {
        List<SecurityIssue> issues = new ArrayList<>();
        String[] packages = {"jackson-databind", "spring-web", "snakeyaml", "netty-codec", "tomcat-embed", "logback", "guava", "commons-text"};
        for (String p : packages) {
            for (int i = 0; i < 3; i++) {
                issues.add(dep(Severity.HIGH, p, true));
            }
            for (int i = 0; i < 4; i++) {
                issues.add(dep(Severity.MEDIUM, p, true));
            }
        }
        for (int r = 0; r < 12; r++) {
            for (int i = 0; i < 6; i++) {
                issues.add(config(r < 4 ? Severity.HIGH : Severity.MEDIUM, "KSV-" + r));
            }
        }
        for (int r = 0; r < 10; r++) {
            for (int i = 0; i < 2; i++) {
                issues.add(code(r < 2 ? Severity.HIGH : Severity.MEDIUM, "rule-" + r));
            }
        }
        for (int i = 0; i < 8; i++) {
            issues.add(SecurityIssue.of(FindingType.SECRET, Severity.MEDIUM, "gitleaks", "generic-api-key", "a.yml",
                    List.of(), null, null, null));
        }
        Map<Severity, Long> quality = new EnumMap<>(Severity.class);
        Score s = calc.branch(BranchScoreInput.of(issues, quality, java(), ALL_OK));
        assertTrue(issues.size() > 150);
        assertTrue(s.security() >= 20 && s.security() <= 40, "security " + s.security() + " points " + s.details().get("securityPoints"));
        System.out.println("realistic microservice: security " + s.security() + ", points " + s.details().get("securityPointsByCategory"));
        assertEquals(100.0, s.coverage());

        // fixing the heaviest group raises the score (action plan)
        List<ScoreCalculator.GroupImpact> groups = calc.groups(issues);
        assertTrue(calc.securityScoreWithout(groups, groups.getFirst().group()) > s.security());
    }

    @Test
    void criticalCapIsLiftedWhenTheOnlyCriticalGroupIsFixed() {
        List<SecurityIssue> issues = List.of(dep(Severity.CRITICAL, "log4j-core", true), code(Severity.LOW, "x"));
        List<ScoreCalculator.GroupImpact> groups = calc.groups(issues);
        assertEquals("dependency:log4j-core@1.0", groups.getFirst().group());
        assertEquals(59.0, calc.securityScore(26, true));
        assertEquals(99.01, calc.securityScoreWithout(groups, groups.getFirst().group()));
    }

    @Test
    void v1IsReproducedWithCountsOnly() {
        ScoreCalculator v1 = new ScoreCalculator(ScoringFormula.V1);
        Map<Severity, Long> sec = new EnumMap<>(Map.of(Severity.HIGH, 1L));
        Score s = v1.branch(new BranchScoreInput(sec, Map.of(), java(), ALL_OK));
        assertEquals(81.87, s.security());
    }
}
