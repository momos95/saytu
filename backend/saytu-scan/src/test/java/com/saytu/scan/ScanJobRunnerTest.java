package com.saytu.scan;

import com.saytu.core.domain.FindingType;
import com.saytu.core.domain.ScanStatus;
import com.saytu.core.domain.ScannerExecutionStatus;
import com.saytu.core.domain.ScannerId;
import com.saytu.core.finding.FindingDeduplicator;
import com.saytu.core.finding.NormalizedFinding;
import com.saytu.core.scan.ResourceLimits;
import com.saytu.scan.adapter.GitleaksAdapter;
import com.saytu.scan.adapter.OpengrepAdapter;
import com.saytu.scan.adapter.TrivyAdapter;
import com.saytu.scan.git.CheckoutRequest;
import com.saytu.scan.git.GitCheckout;
import com.saytu.scan.sandbox.ProcessSandbox;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * End-to-end job with the real git, Opengrep, Trivy and Gitleaks binaries (skipped when
 * SAYTU_TOOLS_DIR is not set): no tool output is simulated.
 */
class ScanJobRunnerTest {

    private static final ResourceLimits LIMITS = new ResourceLimits(Duration.ofMinutes(3), 300,
            2L * 1024 * 1024 * 1024, 256L * 1024 * 1024, 4096);

    private Path tmp;
    private Path reposRoot;
    private Path workRoot;
    private Path trivyCache;

    @BeforeEach
    void setUp() throws Exception {
        assumeTrue(TestSupport.tool("opengrep") != null && TestSupport.tool("trivy") != null
                && TestSupport.tool("gitleaks") != null, "SAYTU_TOOLS_DIR with opengrep, trivy and gitleaks not set");
        assumeTrue(Files.isExecutable(TestSupport.GIT), "git not installed");
        assumeTrue(TestSupport.repositoryRoot() != null, "repository root (scanners/) not found");
        tmp = TestSupport.tempDir("e2e");
        reposRoot = tmp.resolve("repos");
        workRoot = tmp.resolve("work");
        trivyCache = tmp.resolve("trivy-cache-without-db");
        Files.createDirectories(reposRoot);
        Files.createDirectories(trivyCache);
    }

    @AfterEach
    void tearDown() {
        if (tmp != null) {
            TestSupport.delete(tmp);
        }
    }

    private Path vulnerableRepo() throws Exception {
        Path fixture = Path.of(ScanJobRunnerTest.class.getResource("/fixtures/vulnerable-app").toURI());
        Map<String, String> files = new HashMap<>();
        try (Stream<Path> walk = Files.walk(fixture)) {
            for (Path f : walk.filter(Files::isRegularFile).toList()) {
                files.put(fixture.relativize(f).toString(), Files.readString(f));
            }
        }
        files.put("config/app.env", "GITHUB_TOKEN=" + TestSupport.fakeGithubToken() + "\n");
        files.put("deploy/aws.properties", "aws.accessKeyId=" + TestSupport.fakeAwsKeyId() + "\n");
        // suppression files planted by the repository must not hide anything
        files.put(".gitleaks.toml", "[allowlist]\npaths = ['''.*''']\n");
        files.put(".semgrepignore", "*\n");
        return TestSupport.repo(reposRoot, "vulnerable-app", files);
    }

    private ScanJobRunner runner() {
        ProcessSandbox sandbox = ProcessSandbox.detect(false);
        GitCheckout checkout = new GitCheckout(sandbox, new GitCheckout.Settings(TestSupport.GIT, LIMITS,
                100L * 1024 * 1024, 100_000, null, false, reposRoot, Map.of()));
        return new ScanJobRunner(sandbox, checkout, workRoot);
    }

    private List<ScannerPlan> plans(ResourceLimits limits) {
        Path root = TestSupport.repositoryRoot();
        return List.of(
                new ScannerPlan(new OpengrepAdapter(TestSupport.tool("opengrep"),
                        List.of(root.resolve("scanners/opengrep/rules")), TestSupport.opengrepRuntime()), true, limits, Map.of()),
                new ScannerPlan(new TrivyAdapter(TestSupport.tool("trivy"), trivyCache), true, limits, Map.of()),
                new ScannerPlan(new GitleaksAdapter(TestSupport.tool("gitleaks"),
                        root.resolve("scanners/gitleaks/gitleaks.toml")), true, limits, Map.of()));
    }

    @Test
    void fullJobWithRealTools() throws Exception {
        Path repo = vulnerableRepo();
        String head = TestSupport.git(repo, "rev-parse", "HEAD");
        UUID jobId = UUID.randomUUID();

        JobOutcome outcome = runner().run(jobId, new CheckoutRequest(repo.toUri(), "main", null, true), plans(LIMITS), () -> false);

        assertNull(outcome.error());
        assertEquals(head, outcome.commitSha());
        Map<ScannerId, ScannerOutcome> byScanner = new HashMap<>();
        outcome.scanners().forEach(s -> byScanner.put(s.scanner(), s));

        ScannerOutcome opengrep = byScanner.get(ScannerId.OPENGREP);
        assertEquals(ScannerExecutionStatus.SUCCEEDED, opengrep.status(), String.valueOf(opengrep.errorMessage()));
        assertNotNull(opengrep.toolVersion());
        assertTrue(opengrep.rulesetVersion().startsWith("aikido+saytu@"), opengrep.rulesetVersion());
        assertTrue(opengrep.findings().stream().anyMatch(f -> f.ruleId().equals("saytu.java.sql-injection-concatenation")),
                "SQL injection detected despite .semgrepignore");

        ScannerOutcome gitleaks = byScanner.get(ScannerId.GITLEAKS);
        assertEquals(ScannerExecutionStatus.SUCCEEDED, gitleaks.status(), String.valueOf(gitleaks.errorMessage()));
        List<NormalizedFinding> secrets = gitleaks.findings();
        assertTrue(secrets.stream().anyMatch(f -> f.location().path().equals("config/app.env")),
                "secret found despite the repository's .gitleaks.toml: " + secrets);
        for (NormalizedFinding s : secrets) {
            assertEquals(FindingType.SECRET, s.type());
            assertFalse(s.evidence().contains(TestSupport.fakeGithubToken()), "raw secret in evidence");
            assertFalse(s.evidence().contains(TestSupport.fakeAwsKeyId()), "raw secret in evidence");
        }

        ScannerOutcome trivy = byScanner.get(ScannerId.TRIVY);
        assertEquals(ScannerExecutionStatus.FAILED, trivy.status(), "no vulnerability DB: must not read as success");
        assertTrue(trivy.errorMessage().contains("database"));
        assertTrue(trivy.findings().stream().anyMatch(f -> f.ruleId().equals("DS-0001")),
                "misconfigurations are still reported: " + trivy.findings());

        assertEquals(ScanStatus.PARTIAL, outcome.status());
        assertFalse(Files.exists(workRoot.resolve("job-" + jobId)), "sources and reports deleted");

        List<NormalizedFinding> all = outcome.scanners().stream().flatMap(s -> s.findings().stream()).toList();
        assertFalse(FindingDeduplicator.deduplicate(all).isEmpty());
    }

    @Test
    void timeoutAndDisabledScannersAreRecordedAsSuch() throws Exception {
        Path repo = vulnerableRepo();
        ResourceLimits tiny = new ResourceLimits(Duration.ofMillis(50), 10, 2L * 1024 * 1024 * 1024, 64L * 1024 * 1024, 1024);
        List<ScannerPlan> plans = List.of(
                new ScannerPlan(plans(LIMITS).get(0).adapter(), true, tiny, Map.of()),
                new ScannerPlan(plans(LIMITS).get(2).adapter(), false, LIMITS, Map.of()));
        JobOutcome outcome = runner().run(UUID.randomUUID(), new CheckoutRequest(repo.toUri(), "main", null, true), plans, () -> false);
        assertEquals(ScannerExecutionStatus.TIMED_OUT, outcome.scanners().get(0).status());
        assertTrue(outcome.scanners().get(0).findings().isEmpty());
        assertEquals(ScannerExecutionStatus.SKIPPED, outcome.scanners().get(1).status());
        assertEquals(ScanStatus.FAILED, outcome.status());
    }

    @Test
    void checkoutFailureFailsTheJob() throws Exception {
        Path repo = vulnerableRepo();
        JobOutcome outcome = runner().run(UUID.randomUUID(), new CheckoutRequest(repo.toUri(), "missing-branch", null, true),
                plans(LIMITS), () -> false);
        assertEquals(ScanStatus.FAILED, outcome.status());
        assertTrue(outcome.error().startsWith("BRANCH_NOT_FOUND"));
        assertTrue(outcome.scanners().isEmpty());
    }
}
