package com.saytu.scan;

import com.saytu.core.domain.Language;
import com.saytu.core.domain.ScannerExecutionStatus;
import com.saytu.core.domain.ScannerId;
import com.saytu.core.finding.NormalizedFinding;
import com.saytu.core.scan.ResourceLimits;
import com.saytu.core.scan.ScannerAdapter;
import com.saytu.scan.adapter.CheckstyleAdapter;
import com.saytu.scan.adapter.CppcheckAdapter;
import com.saytu.scan.adapter.EslintAdapter;
import com.saytu.scan.adapter.PhpcsAdapter;
import com.saytu.scan.adapter.PmdAdapter;
import com.saytu.scan.adapter.SqlfluffAdapter;
import com.saytu.scan.git.CheckoutRequest;
import com.saytu.scan.git.GitCheckout;
import com.saytu.scan.sandbox.ProcessSandbox;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Quality tools run for real on a generated multi-language repository. Each tool is tested when it
 * is installed (all of them in the worker image build); absent tools are skipped, never simulated.
 */
class QualityToolsTest {

    private static final ResourceLimits LIMITS = new ResourceLimits(Duration.ofMinutes(5), 600,
            2L * 1024 * 1024 * 1024, 256L * 1024 * 1024, 4096);

    private Path tmp;
    private Path reposRoot;

    @BeforeEach
    void setUp() throws Exception {
        assumeTrue(Files.isExecutable(TestSupport.GIT), "git not installed");
        tmp = TestSupport.tempDir("quality-e2e");
        reposRoot = tmp.resolve("repos");
        Files.createDirectories(reposRoot);
    }

    @AfterEach
    void tearDown() {
        if (tmp != null) {
            TestSupport.delete(tmp);
        }
    }

    /** Available quality adapters, keyed by scanner. */
    static Map<ScannerId, ScannerAdapter> installed() {
        Map<ScannerId, ScannerAdapter> tools = new HashMap<>();
        Path root = TestSupport.repositoryRoot();
        Path java = TestSupport.java();
        Path checkstyle = TestSupport.toolPath("checkstyle");
        if (java != null && checkstyle != null && root != null) {
            tools.put(ScannerId.CHECKSTYLE, new CheckstyleAdapter(java, checkstyle, root.resolve("scanners/checkstyle/saytu-checks.xml")));
        }
        Path pmd = TestSupport.toolPath("pmd");
        if (java != null && pmd != null) {
            tools.put(ScannerId.PMD, new PmdAdapter(java, pmd));
        }
        Path php = TestSupport.executable("/usr/bin/php", "/usr/local/bin/php");
        Path phpcs = TestSupport.toolPath("phpcs/bin/phpcs");
        if (php != null && phpcs != null) {
            tools.put(ScannerId.PHPCS, new PhpcsAdapter(php, phpcs));
        }
        Path cppcheck = TestSupport.toolPath("cppcheck");
        if (cppcheck == null) {
            cppcheck = TestSupport.executable("/usr/bin/cppcheck");
        }
        if (cppcheck != null && Files.isRegularFile(cppcheck)) {
            tools.put(ScannerId.CPPCHECK, new CppcheckAdapter(cppcheck));
        }
        Path sqlfluff = TestSupport.toolPath("sqlfluff/bin/sqlfluff");
        if (sqlfluff != null) {
            tools.put(ScannerId.SQLFLUFF, new SqlfluffAdapter(sqlfluff));
        }
        Path node = TestSupport.toolPath("node/bin/node");
        Path eslint = TestSupport.toolPath("eslint");
        if (node != null && eslint != null) {
            tools.put(ScannerId.ESLINT, new EslintAdapter(node, eslint));
        }
        return tools;
    }

    private Path repository(Map<String, String> extra) throws Exception {
        Path fixture = Path.of(QualityToolsTest.class.getResource("/fixtures/quality-app").toURI());
        Map<String, String> files = new HashMap<>();
        try (Stream<Path> walk = Files.walk(fixture)) {
            for (Path f : walk.filter(Files::isRegularFile).toList()) {
                files.put(fixture.relativize(f).toString(), Files.readString(f));
            }
        }
        files.putAll(extra);
        // repository-controlled configuration that must be ignored
        files.put("eslint.config.js", "throw new Error('repository config executed');\n");
        files.put("sql/.sqlfluff", "[sqlfluff]\ntemplater = python\n");
        files.put("php/phpcs.xml", "<?xml version=\"1.0\"?><ruleset name=\"none\"><exclude-pattern>*</exclude-pattern></ruleset>\n");
        return TestSupport.repo(reposRoot, "quality-app-" + UUID.randomUUID(), files);
    }

    private JobOutcome run(Path repo, List<ScannerAdapter> adapters) throws Exception {
        ProcessSandbox sandbox = ProcessSandbox.detect(false);
        GitCheckout checkout = new GitCheckout(sandbox, new GitCheckout.Settings(TestSupport.GIT, LIMITS,
                100L * 1024 * 1024, 100_000, null, false, reposRoot, Map.of()));
        List<ScannerPlan> plans = new ArrayList<>();
        adapters.forEach(a -> plans.add(new ScannerPlan(a, true, LIMITS, Map.of())));
        return new ScanJobRunner(sandbox, checkout, tmp.resolve("work"))
                .run(UUID.randomUUID(), new CheckoutRequest(repo.toUri(), "main", null, true), plans, () -> false);
    }

    @Test
    void everyInstalledQualityToolRunsOnItsLanguage() throws Exception {
        Map<ScannerId, ScannerAdapter> tools = installed();
        assumeTrue(!tools.isEmpty(), "no quality tool installed (set SAYTU_TOOLS_DIR)");
        JobOutcome outcome = run(repository(Map.of()), List.copyOf(tools.values()));
        assertTrue(outcome.languages().labels().containsAll(List.of(Language.JAVA, Language.TYPESCRIPT, Language.PHP,
                Language.C, Language.SQL)), "labels: " + outcome.languages().labels());

        Map<ScannerId, String> expectedRule = Map.of(
                ScannerId.CHECKSTYLE, "checkstyle:StringLiteralEquality",
                ScannerId.PMD, "pmd:UseEqualsToCompareStrings",
                ScannerId.PHPCS, "phpcs:Squiz.Classes.ValidClassName.NotPascalCase",
                ScannerId.CPPCHECK, "cppcheck:arrayIndexOutOfBounds",
                ScannerId.SQLFLUFF, "sqlfluff:LT09",
                ScannerId.ESLINT, "eslint:@typescript-eslint/no-explicit-any");
        for (ScannerOutcome s : outcome.scanners()) {
            assertEquals(ScannerExecutionStatus.SUCCEEDED, s.status(), s.scanner() + ": " + s.errorMessage());
            List<String> rules = s.findings().stream().map(NormalizedFinding::ruleId).toList();
            assertTrue(rules.contains(expectedRule.get(s.scanner())), s.scanner() + " found " + rules);
            assertTrue(s.findings().stream().allMatch(f -> f.location() != null && !f.location().path().startsWith("/")));
        }
    }

    @Test
    void toolsAreNotRunWithoutTheirLanguage() throws Exception {
        Map<ScannerId, ScannerAdapter> tools = installed();
        assumeTrue(!tools.isEmpty(), "no quality tool installed (set SAYTU_TOOLS_DIR)");
        Path repo = TestSupport.repo(reposRoot, "python-only", Map.of("app.py", "print('hello')\n"));
        JobOutcome outcome = run(repo, List.copyOf(tools.values()));
        for (ScannerOutcome s : outcome.scanners()) {
            assertEquals(ScannerExecutionStatus.NOT_APPLICABLE, s.status(), s.scanner().key());
            assertTrue(s.errorMessage().startsWith("no "), s.errorMessage());
        }
        assertEquals(List.of(Language.PYTHON), outcome.languages().labels());
    }
}
