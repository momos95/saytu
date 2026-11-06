package com.saytu.core.remediation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.saytu.core.domain.FindingType;
import com.saytu.core.domain.ScannerId;
import com.saytu.core.domain.Severity;
import com.saytu.core.finding.NormalizedFinding;
import com.saytu.core.remediation.RemediationProvider.Remediation;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

class RuleBasedRemediationProviderTest {

    private final RuleBasedRemediationProvider provider = new RuleBasedRemediationProvider();

    private static NormalizedFinding finding(ScannerId scanner, String rule, FindingType type, Severity severity, String path,
                                             List<String> cwes, NormalizedFinding.Dependency dep, String recommendation) {
        return new NormalizedFinding(scanner, rule, type, severity, "Titre", "", path == null ? null
                : new NormalizedFinding.SourceLocation(path, 12, 12), cwes, dep == null ? null : "CVE-2022-42003", null, null,
                dep, null, recommendation, List.of(), null);
    }

    private Remediation suggest(NormalizedFinding f) {
        return provider.suggest(f, "").orElseThrow();
    }

    @Test
    void sqlInjectionGetsAnExampleInTheLanguageOfTheFile() {
        Remediation php = suggest(finding(ScannerId.OPENGREP, "php.sqli", FindingType.SECURITY, Severity.HIGH,
                "app/User.php", List.of("CWE-89"), null, null));
        assertEquals("Injection SQL", php.topic());
        assertEquals("php", php.exampleLanguage());
        assertTrue(php.fixedCodeExample().contains("prepare("));
        assertTrue(php.vulnerableExample().contains("query("));
        assertTrue(php.specific());
        assertTrue(php.impact().startsWith("Élevé"));
        assertTrue(php.references().contains("https://cwe.mitre.org/data/definitions/89.html"));
        Remediation go = suggest(finding(ScannerId.OPENGREP, "go.sqli", FindingType.SECURITY, Severity.HIGH,
                "main.go", List.of("CWE-89"), null, null));
        assertEquals("java", go.exampleLanguage(), "no Go example: the Java one is shown");
    }

    @Test
    void mavenDependencyUpgradeUsesTheHighestFixedVersionAndDependencyManagement() {
        Remediation r = suggest(finding(ScannerId.TRIVY, "CVE-2022-42003", FindingType.DEPENDENCY, Severity.HIGH, "pom.xml",
                List.of(), new NormalizedFinding.Dependency("pom", "com.fasterxml.jackson.core:jackson-databind", "2.9.10",
                        "2.12.7.1, 2.13.4.2"), null));
        assertEquals("xml", r.exampleLanguage());
        assertTrue(r.fixedCodeExample().contains("<artifactId>jackson-databind</artifactId>"));
        assertTrue(r.fixedCodeExample().contains("<version>2.13.4.2</version>"));
        assertTrue(r.steps().getFirst().contains("vers 2.13.4.2"));
        assertTrue(r.suggestedTests().getFirst().contains("mvn dependency:tree -Dincludes=com.fasterxml.jackson.core:jackson-databind"));
        assertTrue(r.references().contains("https://nvd.nist.gov/vuln/detail/CVE-2022-42003"));
    }

    @Test
    void dependencyWithoutFixSuggestsMitigation() {
        Remediation r = suggest(finding(ScannerId.TRIVY, "CVE-1", FindingType.DEPENDENCY, Severity.MEDIUM, "package-lock.json",
                List.of(), new NormalizedFinding.Dependency("npm", "left-pad", "1.0.0", null), null));
        assertTrue(r.steps().getFirst().contains("Aucune version corrigée"));
        assertEquals("", r.fixedCodeExample());
        assertEquals("json", RuleBasedRemediationProvider.upgradeExample("npm", "lodash", "4.17.21")[0]);
        assertTrue(RuleBasedRemediationProvider.upgradeExample("gomod", "golang.org/x/net", "0.17.0")[1].contains("@v0.17.0"));
    }

    @Test
    void secretsAreRevokedFirstAndLoadedFromTheEnvironment() {
        Remediation r = suggest(finding(ScannerId.GITLEAKS, "generic-api-key", FindingType.SECRET, Severity.HIGH,
                "ms-membres/src/main/resources/application-ppd.yml", List.of(), null, null));
        assertTrue(r.steps().getFirst().contains("révoquer"));
        assertEquals("yaml", r.exampleLanguage());
        assertTrue(r.fixedCodeExample().contains("${DB_PASSWORD}"));
        Remediation byCwe = suggest(finding(ScannerId.OPENGREP, "detected-generic-secret", FindingType.SECURITY, Severity.HIGH,
                "src/Config.java", List.of("CWE-798"), null, null));
        assertEquals("Secret dans le dépôt", byCwe.topic());
        assertTrue(byCwe.fixedCodeExample().contains("System.getenv"));
    }

    @Test
    void kubernetesAndDockerfileFindingsGetASecureManifest() {
        Remediation k8s = suggest(finding(ScannerId.TRIVY, "KSV-0118", FindingType.SECURITY, Severity.HIGH,
                "deployment/manifests/deployment_dev.yml", List.of(), null, "Set securityContext"));
        assertEquals("yaml", k8s.exampleLanguage());
        assertTrue(k8s.steps().getFirst().contains("securityContext"));
        assertTrue(k8s.fixedCodeExample().contains("runAsNonRoot: true"));
        assertTrue(k8s.specific());
        Remediation docker = suggest(finding(ScannerId.OPENGREP, "missing-user-entrypoint", FindingType.SECURITY, Severity.HIGH,
                "deployment/Dockerfile", List.of("CWE-269"), null, null));
        assertEquals("dockerfile", docker.exampleLanguage());
        assertTrue(docker.fixedCodeExample().contains("USER 10001"));
        assertEquals("KSV118", RuleBasedRemediationProvider.normalizeCheck("AVDKSV0118"));
        assertEquals("DS002", RuleBasedRemediationProvider.normalizeCheck("DS002"));
    }

    @Test
    void qualityFindingsLinkToTheRuleDocumentation() {
        Remediation r = suggest(finding(ScannerId.PMD, "pmd:ClassWithOnlyPrivateConstructorsShouldBeFinal", FindingType.QUALITY,
                Severity.LOW, "src/A.java", List.of(), null, null));
        assertTrue(r.steps().getFirst().contains("final"));
        assertTrue(r.specific());
        Remediation eslint = suggest(finding(ScannerId.ESLINT, "eslint:@typescript-eslint/no-explicit-any", FindingType.QUALITY,
                Severity.MEDIUM, "src/app.ts", List.of(), null, null));
        assertTrue(eslint.references().contains("https://typescript-eslint.io/rules/no-explicit-any/"));
        Remediation unknown = suggest(finding(ScannerId.SQLFLUFF, "sqlfluff:LT01", FindingType.QUALITY, Severity.LOW,
                "db/a.sql", List.of(), null, null));
        assertFalse(unknown.specific());
        assertTrue(unknown.references().contains("https://docs.sqlfluff.com/en/stable/reference/rules.html"));
    }

    @Test
    void everyCweEntryHasExamplesTestsAndOnlyHttpsReferences() {
        Set<String> seen = new HashSet<>();
        for (CodeWeaknesses.Entry e : CodeWeaknesses.ENTRIES) {
            for (String cwe : e.cwes()) {
                assertTrue(seen.add(cwe), "CWE listed twice: " + cwe);
                assertTrue(cwe.matches("CWE-\\d+"));
            }
            assertFalse(e.examples().isEmpty(), e.topic());
            assertFalse(e.tests().isEmpty(), e.topic());
            e.references().forEach(r -> assertTrue(r.startsWith("https://"), r));
            e.examples().values().forEach(x -> assertFalse(x.fixed().isBlank(), e.topic()));
        }
        assertTrue(CodeWeaknesses.ENTRIES.size() >= 20);
    }

    @Test
    void unknownCodeRuleFallsBackToGenericGuidance() {
        Remediation r = suggest(finding(ScannerId.OPENGREP, "custom.rule", FindingType.SECURITY, Severity.MEDIUM,
                "src/a.ts", List.of("CWE-1"), null, "Use the safe API."));
        assertFalse(r.specific());
        assertEquals("Use the safe API.", r.steps().getFirst());
        assertFalse(provider.isGenerative());
        assertEquals("rule-based", provider.id());
    }
}
