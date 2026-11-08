package com.saytu.scan.adapter;

import com.saytu.core.domain.FindingType;
import com.saytu.core.domain.Language;
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
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Parsing of the quality tools' reports (see src/test/resources/reports/README.md). */
class QualityAdapterParsingTest {

    private Path work;

    @BeforeEach
    void setUp() throws IOException {
        work = TestSupport.tempDir("quality");
    }

    @AfterEach
    void tearDown() {
        TestSupport.delete(work);
    }

    private static Path resource(String name) throws URISyntaxException {
        return Path.of(QualityAdapterParsingTest.class.getResource("/" + name).toURI());
    }

    private ScanContext context(Path sourceDir, Map<String, String> settings) {
        return new ScanContext(UUID.randomUUID(), sourceDir, work, "0123456789abcdef0123456789abcdef01234567",
                ResourceLimits.DEFAULT, settings);
    }

    private static NormalizedFinding byRule(List<NormalizedFinding> findings, String rule) {
        return findings.stream().filter(f -> f.ruleId().equals(rule)).findFirst()
                .orElseThrow(() -> new AssertionError(rule + " not in " + findings.stream().map(NormalizedFinding::ruleId).toList()));
    }

    @Test
    void phpcsRealReport() throws Exception {
        Path src = resource("fixtures/quality-app/php");
        List<NormalizedFinding> f = new PhpcsAdapter(Path.of("/usr/bin/php"), Path.of("/opt/phpcs/bin/phpcs"))
                .parse(resource("reports/phpcs-4.0.2.json"), context(src, Map.of()));
        assertEquals(10, f.size());
        NormalizedFinding name = byRule(f, "phpcs:Squiz.Classes.ValidClassName.NotPascalCase");
        assertEquals("app/user.php", name.location().path());
        assertEquals(2, (int) name.location().startLine());
        assertEquals(FindingType.QUALITY, name.type());
        assertEquals(Severity.LOW, name.severity());
        assertTrue(name.evidence().contains("class user_repository"));
        assertTrue(byRule(f, "phpcs:PSR12.Files.FileHeader.SpacingAfterTagBlock").recommendation().contains("phpcbf"));
    }

    @Test
    void cppcheckRealReport() throws Exception {
        Path src = resource("fixtures/quality-app/c");
        List<NormalizedFinding> f = new CppcheckAdapter(Path.of("/usr/bin/cppcheck"))
                .parse(resource("reports/cppcheck-2.13.0.xml"), context(src, Map.of()));
        assertEquals(5, f.size());
        NormalizedFinding oob = byRule(f, "cppcheck:arrayIndexOutOfBounds");
        assertEquals(FindingType.SECURITY, oob.type(), "out-of-bounds write is a memory safety weakness");
        assertEquals(Severity.HIGH, oob.severity());
        assertEquals(List.of("CWE-788"), oob.cwes());
        assertEquals("native/buffer.c", oob.location().path());
        assertEquals(13, (int) oob.location().startLine());
        assertEquals(FindingType.SECURITY, byRule(f, "cppcheck:memleak").type());
        NormalizedFinding unused = byRule(f, "cppcheck:unusedVariable");
        assertEquals(FindingType.QUALITY, unused.type());
        assertEquals(Severity.LOW, unused.severity());
    }

    @Test
    void sqlfluffRealReport() throws Exception {
        Path src = resource("fixtures/quality-app/sql");
        List<NormalizedFinding> f = new SqlfluffAdapter(Path.of("/opt/sqlfluff/bin/sqlfluff"))
                .parse(resource("reports/sqlfluff-4.4.0.json"), context(src, Map.of()));
        assertFalse(f.isEmpty());
        assertTrue(f.stream().noneMatch(x -> x.ruleId().equals("sqlfluff:PRS")), "parse errors are not findings");
        assertEquals(Severity.INFO, byRule(f, "sqlfluff:LT09").severity());
        assertEquals(Severity.LOW, byRule(f, "sqlfluff:AM04").severity());
        assertTrue(f.stream().allMatch(x -> x.location().path().startsWith("db/")));
    }

    @Test
    void checkstyleReport() throws Exception {
        Path src = resource("fixtures/quality-app/java");
        List<NormalizedFinding> f = new CheckstyleAdapter(Path.of("/usr/bin/java"), Path.of("/opt/checkstyle"),
                Path.of("/opt/rules/checkstyle/saytu-checks.xml")).parse(resource("reports/checkstyle-format.xml"), context(src, Map.of()));
        assertEquals(4, f.size(), "file outside the sources ignored");
        NormalizedFinding eq = byRule(f, "checkstyle:StringLiteralEquality");
        assertEquals(Severity.MEDIUM, eq.severity());
        assertEquals("src/main/java/demo/Order.java", eq.location().path());
        assertTrue(eq.evidence().contains("status == \"PAID\""));
        assertEquals(Severity.INFO, byRule(f, "checkstyle:AvoidStarImport").severity());
        assertEquals("EqualsHashCode", CheckstyleAdapter.checkName("com.puppycrawl.tools.checkstyle.checks.coding.EqualsHashCodeCheck"));
    }

    @Test
    void pmdReportIncludesSuppressedViolations() throws Exception {
        Path src = resource("fixtures/quality-app/java");
        List<NormalizedFinding> f = new PmdAdapter(Path.of("/usr/bin/java"), Path.of("/opt/pmd"))
                .parse(resource("reports/pmd-format.json"), context(src, Map.of()));
        assertEquals(3, f.size());
        NormalizedFinding suppressed = byRule(f, "pmd:UseEqualsToCompareStrings");
        assertEquals(Severity.HIGH, suppressed.severity());
        assertTrue(suppressed.description().contains("suppressed in the code"));
        assertEquals(Severity.MEDIUM, byRule(f, "pmd:EmptyCatchBlock").severity(), "Error Prone, priority 3");
        assertEquals(Severity.LOW, PmdAdapter.severity(1, "Code Style"), "naming rules are not defects");
        assertEquals(Severity.INFO, PmdAdapter.severity(4, "Documentation"));
        assertEquals(Severity.MEDIUM, PmdAdapter.severity(1, "Design"));
        assertEquals(Severity.HIGH, PmdAdapter.severity(2, "Multithreading"));
        assertEquals(Severity.MEDIUM, PmdAdapter.severity(1, null));
        assertTrue(byRule(f, "pmd:EmptyCatchBlock").references().getFirst().startsWith("https://docs.pmd-code.org/"));
        assertEquals("7.28.0", new PmdAdapter(Path.of("/j"), Path.of("/p")).parseVersion(" ___ banner\n PMD 7.28.0 (abc, 2026-09-25)\nJava version: 21"));
    }

    @Test
    void eslintReport() throws Exception {
        Path src = resource("fixtures/quality-app");
        List<NormalizedFinding> f = new EslintAdapter(Path.of("/usr/bin/node"), Path.of("/opt/eslint"))
                .parse(resource("reports/eslint-format.json"), context(src, Map.of()));
        assertEquals(3, f.size(), "fatal parsing errors are not findings");
        NormalizedFinding fs = byRule(f, "eslint:security/detect-non-literal-fs-filename");
        assertEquals(FindingType.SECURITY, fs.type());
        assertEquals(Severity.MEDIUM, fs.severity());
        assertEquals(Severity.LOW, byRule(f, "eslint:@typescript-eslint/no-explicit-any").severity());
        assertTrue(byRule(f, "eslint:@typescript-eslint/no-explicit-any").references().getFirst()
                .equals("https://typescript-eslint.io/rules/no-explicit-any"));
    }

    @Test
    void commandsNeverLoadRepositoryConfiguration() throws Exception {
        Path src = Files.createDirectories(work.resolveSibling(work.getFileName() + "-src"));
        try {
            TestSupport.write(src, Map.of("a.php", "<?php\n", "b.sql", "select 1;\n", "c.c", "int x;\n", "A.java", "class A {}\n"));
            ScanContext ctx = context(src, Map.of("dialect", "postgres; rm -rf /", "standard", "../../evil"));
            List<String> sql = new SqlfluffAdapter(Path.of("/opt/sqlfluff/bin/sqlfluff")).buildCommand(ctx).argv();
            assertTrue(sql.containsAll(List.of("--ignore-local-config", "--disable-noqa", "--disregard-sqlfluffignores")));
            assertEquals("raw", sql.get(sql.indexOf("--templater") + 1), "no Jinja / Python templating");
            assertEquals("ansi", sql.get(sql.indexOf("--dialect") + 1), "invalid dialect setting falls back");
            List<String> php = new PhpcsAdapter(Path.of("/usr/bin/php"), Path.of("/opt/phpcs/bin/phpcs")).buildCommand(ctx).argv();
            assertTrue(php.contains("--standard=PSR12") && php.contains("--ignore-annotations"));
            List<String> pmd = new PmdAdapter(Path.of("/usr/bin/java"), Path.of("/opt/pmd")).buildCommand(ctx).argv();
            assertTrue(pmd.contains("--show-suppressed"));
            assertTrue(pmd.get(pmd.indexOf("--suppress-marker") + 1).startsWith("SAYTU-"));
            assertTrue(Files.readString(work.resolve("pmd-files.txt")).contains("A.java"));
            List<String> eslint = new EslintAdapter(Path.of("/usr/bin/node"), Path.of("/opt/eslint")).buildCommand(ctx).argv();
            assertTrue(eslint.contains("--no-inline-config"));
            assertEquals("/opt/eslint/eslint.config.mjs", eslint.get(eslint.indexOf("--config") + 1));
            assertEquals(Set.of(Language.C, Language.CPP), new CppcheckAdapter(Path.of("/usr/bin/cppcheck")).languages());
            List<String> cpp = new CppcheckAdapter(Path.of("/usr/bin/cppcheck")).buildCommand(ctx).argv();
            assertTrue(cpp.stream().noneMatch(a -> a.startsWith("--project") || a.equals("--inline-suppr")));
        } finally {
            TestSupport.delete(src);
        }
    }

    @Test
    void brokenReportsAreErrors() throws Exception {
        Path bad = work.resolve("bad.xml");
        Files.writeString(bad, "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><checkstyle>&e;</checkstyle>");
        Path src = resource("fixtures/quality-app/c");
        assertThrows(IOException.class, () -> new CheckstyleAdapter(Path.of("/j"), Path.of("/c"), Path.of("/x.xml"))
                .parse(bad, context(src, Map.of())), "DOCTYPE refused (XXE)");
        assertThrows(IOException.class, () -> new CppcheckAdapter(Path.of("/c")).parse(work.resolve("none.xml"), context(src, Map.of())));
        assertNotNull(CppcheckAdapter.severity("error"));
    }
}
