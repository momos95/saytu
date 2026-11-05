package com.saytu.scan.adapter;

import com.saytu.core.domain.FindingType;
import com.saytu.core.domain.ScannerId;
import com.saytu.core.domain.Severity;
import com.saytu.core.finding.NormalizedFinding;
import com.saytu.core.scan.ResourceLimits;
import com.saytu.core.scan.ScanContext;
import com.saytu.scan.TestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Parsing of reports recorded from real tool runs (see src/test/resources/reports/README.md). */
class AdapterParsingTest {

    private Path work;

    @BeforeEach
    void setUp() throws IOException {
        work = TestSupport.tempDir("adapter").resolve("work");
        Files.createDirectories(work);
    }

    @AfterEach
    void tearDown() {
        TestSupport.delete(work.getParent());
    }

    private static Path resource(String name) throws URISyntaxException {
        return Path.of(AdapterParsingTest.class.getResource("/" + name).toURI());
    }

    /** Separate empty source tree, for tests that do not read sources. */
    private Path src() throws IOException {
        return Files.createDirectories(work.getParent().resolve("empty-src"));
    }

    private ScanContext context(Path sourceDir) {
        return new ScanContext(UUID.randomUUID(), sourceDir, work, "0123456789abcdef0123456789abcdef01234567",
                ResourceLimits.DEFAULT, Map.of());
    }

    @Test
    void opengrepReport() throws Exception {
        Path app = resource("fixtures/vulnerable-app");
        OpengrepAdapter adapter = new OpengrepAdapter(Path.of("/opt/tools/opengrep"), List.of());
        List<NormalizedFinding> findings = adapter.parse(resource("reports/opengrep-1.33.1.json"), context(app));

        assertEquals(3, findings.size());
        NormalizedFinding sqli = findings.stream()
                .filter(f -> f.ruleId().equals("saytu.java.sql-injection-concatenation")).findFirst().orElseThrow();
        assertEquals(ScannerId.OPENGREP, sqli.scanner());
        assertEquals(FindingType.SECURITY, sqli.type());
        assertEquals(Severity.HIGH, sqli.severity());
        assertEquals(List.of("CWE-89"), sqli.cwes());
        assertEquals("src/main/java/demo/UserRepository.java", sqli.location().path());
        assertEquals(19, (int) sqli.location().startLine());
        assertTrue(sqli.evidence().contains("executeQuery"));
        assertTrue(sqli.recommendation().contains("PreparedStatement"));
        assertNotNull(sqli.contextHash(), "context hash computed from the source line");
        assertFalse(sqli.references().isEmpty());

        NormalizedFinding hash = findings.stream().filter(f -> f.ruleId().equals("saytu.java.weak-hash")).findFirst().orElseThrow();
        assertEquals(Severity.MEDIUM, hash.severity());
        assertEquals(List.of("CWE-328"), hash.cwes());
    }

    @Test
    void opengrepFingerprintSurvivesLineShifts() throws Exception {
        Path app = resource("fixtures/vulnerable-app");
        Path shifted = work.getParent().resolve("shifted");
        Path file = shifted.resolve("src/main/java/demo/UserRepository.java");
        Files.createDirectories(file.getParent());
        Files.writeString(file, "\n\n\n" + Files.readString(app.resolve("src/main/java/demo/UserRepository.java")));
        String report = Files.readString(resource("reports/opengrep-1.33.1.json"))
                .replace("\"line\": 19", "\"line\": 22").replace("\"line\":19", "\"line\":22");
        Path shiftedReport = work.resolve("shifted.json");
        Files.writeString(shiftedReport, report);

        OpengrepAdapter adapter = new OpengrepAdapter(Path.of("/opt/tools/opengrep"), List.of());
        String original = adapter.parse(resource("reports/opengrep-1.33.1.json"), context(app)).stream()
                .filter(f -> f.ruleId().endsWith("sql-injection-concatenation")).findFirst().orElseThrow().fingerprint();
        String moved = adapter.parse(shiftedReport, context(shifted)).stream()
                .filter(f -> f.ruleId().endsWith("sql-injection-concatenation")).findFirst().orElseThrow().fingerprint();
        assertEquals(original, moved);
    }

    @Test
    void trivyVulnerabilities() throws Exception {
        TrivyAdapter adapter = new TrivyAdapter(Path.of("/opt/tools/trivy"), work);
        List<NormalizedFinding> npm = adapter.parse(resource("reports/trivy-npm.json.golden"), context(src()));
        NormalizedFinding jquery = npm.stream().filter(f -> f.ruleId().equals("CVE-2019-11358")).findFirst().orElseThrow();
        assertEquals(FindingType.DEPENDENCY, jquery.type());
        assertEquals(Severity.MEDIUM, jquery.severity());
        assertEquals("CVE-2019-11358", jquery.cve());
        assertEquals("npm", jquery.dependency().ecosystem());
        assertEquals("jquery", jquery.dependency().name());
        assertEquals("3.3.9", jquery.dependency().installedVersion());
        assertEquals("3.4.0", jquery.dependency().fixedVersion());
        assertEquals(61, Math.round(jquery.cvssScore() * 10));
        assertTrue(jquery.cvssVector().startsWith("CVSS:3.1/"));
        assertEquals(List.of("CWE-79"), jquery.cwes());
        assertEquals("package-lock.json", jquery.location().path());
        assertTrue(jquery.recommendation().contains("3.4.0"));
        assertTrue(jquery.references().size() <= 10);

        List<NormalizedFinding> pom = adapter.parse(resource("reports/trivy-pom.json.golden"), context(src()));
        assertFalse(pom.isEmpty());
        assertTrue(pom.stream().allMatch(f -> f.dependency().name().contains(":")), "maven group:artifact names");
    }

    @Test
    void trivyMisconfigurations() throws Exception {
        Path app = resource("fixtures/vulnerable-app");
        TrivyAdapter adapter = new TrivyAdapter(Path.of("/opt/tools/trivy"), work);
        List<NormalizedFinding> findings = adapter.parse(resource("reports/trivy-misconfig-0.76.1.json"), context(app));
        assertEquals(4, findings.size());
        NormalizedFinding latest = findings.stream().filter(f -> f.ruleId().equals("DS-0001")).findFirst().orElseThrow();
        assertEquals(FindingType.SECURITY, latest.type());
        assertEquals("Dockerfile", latest.location().path());
        assertEquals(1, (int) latest.location().startLine());
        assertEquals("FROM ubuntu:latest", latest.evidence());
        assertNotNull(latest.recommendation());
        assertFalse(latest.evidence().contains("\u001b"), "no terminal colour codes");
    }

    @Test
    void trivyWithoutDatabaseIsDegraded() throws IOException {
        TrivyAdapter adapter = new TrivyAdapter(Path.of("/opt/tools/trivy"), work.resolve("empty-cache"));
        assertTrue(adapter.degradedReason().isPresent());
        var spec = adapter.buildCommand(context(src()));
        int i = spec.argv().indexOf("--scanners");
        assertEquals("misconfig", spec.argv().get(i + 1), "without DB only configuration checks run");
        assertTrue(spec.argv().contains("--offline-scan"));
        assertTrue(spec.argv().contains("--skip-db-update"));
    }

    @Test
    void gitleaksReportIsRedactedAndHashed() throws Exception {
        Path src = work.getParent().resolve("src");
        String token = TestSupport.fakeGithubToken();
        TestSupport.write(src, Map.of("config/app.env", "GITHUB_TOKEN=" + token + "\n"));
        // shape of a gitleaks 8.30 JSON report (fields as emitted by the tool)
        String report = """
                [{"RuleID":"github-pat","Description":"Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure.",
                  "StartLine":1,"EndLine":1,"StartColumn":1,"EndColumn":53,"Match":"GITHUB_TOKEN=%s","Secret":"%s",
                  "File":"%s","SymlinkFile":"","Commit":"","Entropy":4.9,"Author":"","Email":"","Date":"","Message":"","Tags":[],
                  "Fingerprint":"%s:github-pat:1"}]
                """.formatted(token, token, src.resolve("config/app.env"), src.resolve("config/app.env"));
        Path file = work.resolve("gitleaks.json");
        Files.writeString(file, report);
        GitleaksAdapter adapter = new GitleaksAdapter(Path.of("/opt/tools/gitleaks"), Path.of("/opt/rules/gitleaks.toml"));
        NormalizedFinding f = adapter.parse(file, context(src)).getFirst();
        assertEquals(FindingType.SECRET, f.type());
        assertEquals(Severity.HIGH, f.severity());
        assertEquals("config/app.env", f.location().path());
        assertFalse(f.evidence().contains(token), "secret must be masked: " + f.evidence());
        assertFalse(f.toString().contains(token));
        assertNotNull(f.contextHash());
        assertFalse(f.contextHash().contains(token));
        assertEquals(List.of("CWE-798"), f.cwes());
    }

    @Test
    void pathsOutsideTheSourceTreeAreDropped() throws Exception {
        String report = """
                {"version":"1.33.1","results":[{"check_id":"r","path":"/etc/passwd","start":{"line":1},"end":{"line":1},
                "extra":{"message":"m","severity":"ERROR","metadata":{},"lines":"x"}},
                {"check_id":"r","path":"../../outside.java","start":{"line":1},"end":{"line":1},
                "extra":{"message":"m","severity":"ERROR","metadata":{},"lines":"x"}}],"errors":[],"paths":{"scanned":[]}}
                """;
        Path file = work.resolve("og.json");
        Files.writeString(file, report);
        Path src = work.getParent().resolve("src");
        Files.createDirectories(src);
        assertTrue(new OpengrepAdapter(Path.of("/x/opengrep"), List.of()).parse(file, context(src)).isEmpty());
    }

    @Test
    void missingOrBrokenReportsAreErrorsNotEmptyResults() throws Exception {
        OpengrepAdapter adapter = new OpengrepAdapter(Path.of("/x/opengrep"), List.of());
        assertThrows(IOException.class, () -> adapter.parse(work.resolve("absent.json"), context(src())));
        Path broken = work.resolve("broken.json");
        Files.writeString(broken, "{\"results\": [");
        assertThrows(IOException.class, () -> adapter.parse(broken, context(src())));
    }

    @Test
    void opengrepCommandUsesOnlyLocalRulesAndIgnoresRepositorySuppressions() throws Exception {
        Path rules = work.resolve("rules");
        TestSupport.write(rules, Map.of("saytu/java.yaml", "rules: []\n", "extra/semgrep/a.yaml", "rules: []\n"));
        OpengrepAdapter adapter = new OpengrepAdapter(Path.of("/opt/tools/opengrep"), List.of(rules.resolve("saytu"), rules.resolve("extra")));
        var spec = adapter.buildCommand(context(src()));
        assertTrue(spec.argv().contains("--config=" + rules.resolve("saytu")));
        assertTrue(spec.argv().contains("--config=" + rules.resolve("extra/semgrep")));
        assertTrue(spec.argv().contains("--disable-nosem"));
        assertTrue(spec.argv().contains("--x-ignore-semgrepignore-files"));
        assertTrue(spec.argv().stream().noneMatch(a -> a.startsWith("--config=p/") || a.contains("http")));
        assertTrue(adapter.rulesetVersion().orElseThrow().startsWith("saytu+semgrep@"));
        assertNull(spec.environment().get("SEMGREP_APP_TOKEN"));
    }
}
