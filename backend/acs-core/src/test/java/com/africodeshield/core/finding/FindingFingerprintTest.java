package com.africodeshield.core.finding;

import com.africodeshield.core.domain.FindingType;
import com.africodeshield.core.domain.ScannerId;
import com.africodeshield.core.domain.Severity;
import com.africodeshield.core.finding.NormalizedFinding.Dependency;
import com.africodeshield.core.finding.NormalizedFinding.SourceLocation;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FindingFingerprintTest {

    static NormalizedFinding code(ScannerId scanner, String rule, FindingType type, String path, int line,
                                  List<String> cwes, String contextHash) {
        return new NormalizedFinding(scanner, rule, type, Severity.HIGH, "t", "d",
                new SourceLocation(path, line, line), cwes, null, null, null, null,
                "evidence", "fix it", List.of(), contextHash);
    }

    static NormalizedFinding dep(ScannerId scanner, String path, String cve) {
        return new NormalizedFinding(scanner, cve, FindingType.DEPENDENCY, Severity.CRITICAL, cve, "",
                new SourceLocation(path, null, null), List.of(), cve, 9.8, null,
                new Dependency("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "2.17.1"),
                null, null, List.of(), null);
    }

    @Test
    void fingerprintIsSha256Hex() {
        String fp = code(ScannerId.OPENGREP, "r", FindingType.SECURITY, "a.java", 3, List.of(), "abc").fingerprint();
        assertEquals(64, fp.length());
        assertTrue(fp.matches("[0-9a-f]{64}"));
    }

    @Test
    void sameCweSameLineContentFromTwoScannersIsDeduplicated() {
        String ctx = FindingFingerprint.contextHash("stmt.executeQuery(\"select * from t where id=\" + id);");
        var opengrep = code(ScannerId.OPENGREP, "java.lang.security.audit.formatted-sql-string",
                FindingType.SECURITY, "src/Dao.java", 42, List.of("CWE-89: SQL Injection"), ctx);
        var pmd = code(ScannerId.PMD, "category/java/security.xml/SqlInjection",
                FindingType.SECURITY, "./src/Dao.java", 42, List.of("89"), ctx);
        assertEquals(opengrep.fingerprint(), pmd.fingerprint());
    }

    @Test
    void lineShiftDoesNotChangeFingerprintWhenContextIsTheSame() {
        String ctx = FindingFingerprint.contextHash("  password = \"x\";");
        var before = code(ScannerId.OPENGREP, "r", FindingType.SECURITY, "A.java", 10, List.of(), ctx);
        var after = code(ScannerId.OPENGREP, "r", FindingType.SECURITY, "A.java", 25, List.of(), ctx);
        assertEquals(before.fingerprint(), after.fingerprint());
    }

    @Test
    void contextHashIgnoresIndentationAndInnerWhitespace() {
        assertEquals(FindingFingerprint.contextHash("a  =   b;"), FindingFingerprint.contextHash("\t a = b;  "));
        assertNotEquals(FindingFingerprint.contextHash("a = b;"), FindingFingerprint.contextHash("a = c;"));
    }

    @Test
    void differentFilesProduceDifferentFingerprints() {
        var a = code(ScannerId.OPENGREP, "r", FindingType.SECURITY, "A.java", 1, List.of(), "h");
        var b = code(ScannerId.OPENGREP, "r", FindingType.SECURITY, "B.java", 1, List.of(), "h");
        assertNotEquals(a.fingerprint(), b.fingerprint());
    }

    @Test
    void qualityFindingsUseScannerAndRuleNotCwe() {
        var checkstyle = code(ScannerId.CHECKSTYLE, "LineLength", FindingType.QUALITY, "A.java", 1, List.of(), "h");
        var pmd = code(ScannerId.PMD, "LineLength", FindingType.QUALITY, "A.java", 1, List.of(), "h");
        assertNotEquals(checkstyle.fingerprint(), pmd.fingerprint());
    }

    @Test
    void dependencyFingerprintIgnoresManifestPathAndScanner() {
        var trivy = dep(ScannerId.TRIVY, "pom.xml", "CVE-2021-44228");
        var odc = dep(ScannerId.DEPENDENCY_CHECK, "lib/log4j-core-2.14.1.jar", "cve-2021-44228");
        assertEquals(trivy.fingerprint(), odc.fingerprint());
        assertNotEquals(trivy.fingerprint(), dep(ScannerId.TRIVY, "pom.xml", "CVE-2021-45046").fingerprint());
    }

    @Test
    void pathNormalisation() {
        assertEquals("src/main/A.java", FindingFingerprint.normalizePath(".\\src\\\\main/A.java"));
        assertEquals("src/A.java", FindingFingerprint.normalizePath("/./src/A.java"));
    }

    @Test
    void cweNormalisation() {
        assertEquals("CWE-79", NormalizedFinding.Cwe.normalize("CWE-79: Improper Neutralization"));
        assertEquals("CWE-79", NormalizedFinding.Cwe.normalize("cwe_079"));
        assertEquals("CWE-89", NormalizedFinding.Cwe.normalize("89"));
        assertEquals(null, NormalizedFinding.Cwe.normalize("not a cwe"));
    }

    @Test
    void dependencyFindingRequiresDependency() {
        assertThrows(IllegalArgumentException.class, () -> new NormalizedFinding(ScannerId.TRIVY, "CVE-1",
                FindingType.DEPENDENCY, Severity.LOW, null, null, null, null, "CVE-1", null, null, null,
                null, null, null, null));
    }

    @Test
    void evidenceIsAlwaysRedactedByConstructor() {
        var f = code(ScannerId.OPENGREP, "r", FindingType.SECURITY, "A.java", 1, List.of(), "h");
        var withSecret = new NormalizedFinding(f.scanner(), f.ruleId(), f.type(), f.severity(), f.title(),
                f.description(), f.location(), f.cwes(), null, null, null, null,
                "String key = \"AKIAIOSFODNN7EXAMPLE\";", null, null, null);
        assertTrue(withSecret.evidence().contains(SecretRedactor.REDACTED));
        assertTrue(!withSecret.evidence().contains("AKIAIOSFODNN7EXAMPLE"));
    }
}
