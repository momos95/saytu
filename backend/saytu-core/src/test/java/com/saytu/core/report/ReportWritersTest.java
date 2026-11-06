package com.saytu.core.report;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.saytu.core.report.ReportData.Finding;
import com.saytu.core.report.ReportData.ScanLine;
import com.saytu.core.report.ReportData.ScoreLine;
import com.saytu.core.report.ReportData.ToolRun;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

class ReportWritersTest {

    static final Instant NOW = Instant.parse("2026-11-06T09:30:00Z");

    static Finding finding(String id, String severity, String type, String status, String scanner, String rule, String path) {
        return new Finding(id, "a".repeat(63) + id.charAt(id.length() - 1), "acme/api", "main", "70df3256aa11",
                type, severity, status, scanner, List.of(scanner), rule, "Titre <script>alert(1)</script> (é)",
                "Description détaillée avec des accents : à, è, ç, œ — et des (parenthèses) \\ antislash.",
                List.of("CWE-89"), null, null, path, 12, 14, null, null, null, null,
                "password = \"****\"", "Utiliser des requêtes préparées.", List.of("https://cwe.mitre.org/data/definitions/89.html"),
                "FALSE_POSITIVE".equals(status) ? "code de test" : null, NOW.minusSeconds(86_400), NOW);
    }

    static Finding dependency(String id, String severity, String cve, String fixed) {
        return new Finding(id, "b".repeat(63) + id.charAt(id.length() - 1), "acme/api", "main", null, "DEPENDENCY", severity,
                "OPEN", "trivy", List.of("trivy"), cve, "Vulnérabilité de jackson-databind", "", List.of(), cve,
                new BigDecimal("8.1"), "pom.xml", null, null, "maven", "com.fasterxml.jackson.core:jackson-databind",
                "2.9.10", fixed, null, null, List.of(), null, NOW, NOW);
    }

    static ReportData sample(int extraFindings) {
        List<Finding> findings = new ArrayList<>(List.of(
                finding("f1", "HIGH", "SECURITY", "OPEN", "opengrep", "java.sqli", "src/main/java/App Main.java"),
                finding("f2", "MEDIUM", "QUALITY", "FALSE_POSITIVE", "pmd", "UnusedPrivateField", "src/Test.java"),
                finding("f3", "LOW", "QUALITY", "RESOLVED", "checkstyle", "LineLength", "src/Old.java"),
                dependency("d1", "CRITICAL", "CVE-2020-36518", "2.12.6.1"),
                dependency("d2", "HIGH", "CVE-2022-42003", "2.13.4.2")));
        for (int i = 0; i < extraFindings; i++) {
            findings.add(finding("x" + i, "INFO", "QUALITY", "OPEN", "checkstyle", "MagicNumber",
                    "src/very/long/path/" + "segment/".repeat(20) + "File" + i + ".java"));
        }
        Map<String, Long> bySeverity = new LinkedHashMap<>(Map.of("CRITICAL", 1L, "HIGH", 2L, "MEDIUM", 1L, "LOW", 1L,
                "INFO", (long) extraFindings));
        return new ReportData("Rapport d'audit — acme/api", NOW, "awa", "0.1.0",
                List.of("Dépôt : acme/api", "Statut : ouvertes"),
                List.of(new ScoreLine("Global", 59.0, 81.2, 67.88, 100, "HIGH", "v1", NOW),
                        new ScoreLine("acme/api · main", null, 81.2, 81.2, 35, "INSUFFICIENT", "v1", NOW)),
                bySeverity,
                List.of(new ScanLine("acme/api", "main", "70df3256aa11", NOW, "SUCCEEDED", List.of("Java", "SQL"),
                        List.of(new ToolRun("opengrep", "SUCCEEDED", "1.33.1", "saytu 1.0", 1, null),
                                new ToolRun("trivy", "FAILED", "0.76.1", null, 0, "database missing"),
                                new ToolRun("phpcs", "NOT_APPLICABLE", null, null, 0, "no PHP file")))),
                findings, findings.size() + 7);
    }

    @Test
    void jsonKeepsEveryFieldAndEscapesMarkup() {
        String json = JsonReport.write(sample(0));
        assertTrue(json.startsWith("{\"format\":\"saytu-report/1\""));
        assertTrue(json.contains("\"truncated\":true"));
        assertTrue(json.contains("\"totalFindings\":12"));
        assertTrue(json.contains("\"cvss\":8.1"));
        assertTrue(json.contains("\"security\":null"));
        assertTrue(json.contains("\\u003cscript\\u003e"), "markup escaped");
        assertFalse(json.contains("<script>"));
        assertTrue(json.contains("\"fixedVersions\":\"2.12.6.1, 2.13.4.2\""));
        assertTrue(json.contains("\"evidence\":\"password = \\\"****\\\"\""));
    }

    @Test
    void sarifHasOneRunPerScannerWithLevelsLocationsAndSuppressions() {
        String sarif = SarifReport.write(sample(0));
        assertTrue(sarif.contains("\"version\":\"2.1.0\""));
        assertEquals(3, count(sarif, "\"driver\":"), "opengrep, pmd, trivy (resolved checkstyle finding excluded)");
        assertFalse(sarif.contains("LineLength"));
        assertTrue(sarif.contains("\"uri\":\"src/main/java/App%20Main.java\""));
        assertTrue(sarif.contains("\"startLine\":12,\"endLine\":14"));
        assertTrue(sarif.contains("\"suppressions\":[{\"kind\":\"external\",\"status\":\"accepted\",\"justification\":\"FALSE_POSITIVE: code de test\"}]"));
        assertTrue(sarif.contains("\"security-severity\":\"8.1\""));
        assertTrue(sarif.contains("\"name\":\"Opengrep\",\"version\":\"1.33.1\""));
        assertTrue(sarif.contains("\"level\":\"error\""));
        assertTrue(sarif.contains("\"level\":\"warning\""));
        assertEquals("error", SarifReport.level("CRITICAL"));
        assertEquals("note", SarifReport.level("INFO"));
        assertNull(SarifReport.uri("../etc/passwd"));
        assertNull(SarifReport.uri("/abs/path"));
        assertNull(SarifReport.uri("a/../b"));
        assertEquals("a..b/c.txt", SarifReport.uri("a..b/c.txt"));
        assertEquals("d%C3%A9p%C3%B4t/x.java", SarifReport.uri("dépôt/x.java"));
    }

    @Test
    void htmlIsSelfContainedAndEscaped() {
        String html = HtmlReport.write(sample(0));
        assertTrue(html.contains("default-src 'none'"));
        assertFalse(html.contains("<script"), "no script, user content escaped");
        assertTrue(html.contains("Titre &lt;script&gt;alert(1)&lt;/script&gt; (é)"));
        assertTrue(html.contains("Faux positif (code de test)"));
        assertTrue(html.contains("<td class=\"score none\">—</td>"));
        assertTrue(html.contains("Trivy 0.76.1 : échec"));
        assertTrue(html.contains("PHP_CodeSniffer  : rien à analyser"));
        assertTrue(html.contains("les 5 plus graves sont détaillées"));
        assertFalse(html.contains("src=\"http"));
    }

    @Test
    void dependenciesAreGroupedWorstFirst() {
        List<ReportData.Dependency> deps = sample(0).dependencies();
        assertEquals(1, deps.size(), "same package and version");
        assertEquals("CRITICAL", deps.getFirst().worstSeverity());
        assertEquals(List.of("CVE-2020-36518", "CVE-2022-42003"), deps.getFirst().cves());
        assertEquals("2.12.6.1, 2.13.4.2", deps.getFirst().fixedVersions());
        assertEquals(2, deps.getFirst().findings());
    }

    @Test
    void pdfIsWellFormedWithValidCrossReferences() throws IOException {
        byte[] pdf = PdfReport.write(sample(120));
        String raw = new String(pdf, StandardCharsets.ISO_8859_1);
        assertTrue(raw.startsWith("%PDF-1.4\n"));
        assertTrue(raw.endsWith("%%EOF\n"));
        Matcher startxref = Pattern.compile("startxref\n(\\d+)\n%%EOF\n$").matcher(raw);
        assertTrue(startxref.find());
        int xref = Integer.parseInt(startxref.group(1));
        assertTrue(raw.startsWith("xref\n", xref), "startxref points at the xref table");
        Matcher entries = Pattern.compile("(\\d{10}) 00000 n \n").matcher(raw.substring(xref));
        int object = 1;
        while (entries.find()) {
            int offset = Integer.parseInt(entries.group(1));
            assertTrue(raw.startsWith(object + " 0 obj\n", offset), "offset of object " + object);
            object++;
        }
        int pages = count(raw, "/Type /Page ");
        assertTrue(pages >= 3, "120 findings need several pages, got " + pages);
        assertTrue(raw.contains("/Count " + pages + " "));
        assertFalse(raw.contains("<script>"), "content streams are compressed, nothing in clear text");
        String out = System.getenv("SAYTU_REPORT_SAMPLES");
        if (out != null) {
            Path dir = Path.of(out);
            Files.createDirectories(dir);
            Files.write(dir.resolve("sample.pdf"), pdf);
            Files.writeString(dir.resolve("sample.html"), HtmlReport.write(sample(3)));
            Files.writeString(dir.resolve("sample.json"), JsonReport.write(sample(3)));
            Files.writeString(dir.resolve("sample.sarif"), SarifReport.write(sample(3)));
        }
    }

    @Test
    void pdfTextEncodingAndWrapping() {
        byte[] b = PdfDocument.encode("é€…—’中\u0001");
        assertEquals(0xe9, b[0] & 0xff);
        assertEquals(0x80, b[1] & 0xff);
        assertEquals(0x85, b[2] & 0xff);
        assertEquals(0x97, b[3] & 0xff);
        assertEquals(0x92, b[4] & 0xff);
        assertEquals('?', b[5]);
        assertEquals(' ', b[6]);
        String longText = "mot ".repeat(200) + "x".repeat(400);
        for (PdfDocument.Font font : PdfDocument.Font.values()) {
            for (String line : PdfDocument.wrap(longText, font, 9, 300)) {
                assertTrue(PdfDocument.width(line, font, 9) <= 300, font + ": " + line);
            }
        }
        assertEquals(List.of("a", "", "b"), PdfDocument.wrap("a\n\nb", PdfDocument.Font.REGULAR, 9, 300));
    }

    private static int count(String text, String part) {
        int n = 0;
        for (int i = text.indexOf(part); i >= 0; i = text.indexOf(part, i + 1)) {
            n++;
        }
        return n;
    }
}
