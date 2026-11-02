package com.africodeshield.core.finding;

import com.africodeshield.core.domain.FindingType;
import com.africodeshield.core.domain.ScannerId;
import com.africodeshield.core.domain.Severity;
import com.africodeshield.core.finding.NormalizedFinding.SourceLocation;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FindingDeduplicatorTest {

    private static NormalizedFinding f(ScannerId scanner, Severity severity, String cwe, String recommendation,
                                       Double cvss, String ref) {
        return new NormalizedFinding(scanner, scanner.key() + "-rule", FindingType.SECURITY, severity, "SQLi", "",
                new SourceLocation("Dao.java", 7, 7), cwe == null ? List.of("CWE-89") : List.of("CWE-89", cwe),
                null, cvss, null, null, "query", recommendation, List.of(ref), "ctx");
    }

    @Test
    void mergesSameIssueKeepingMostSevereAndUnionOfMetadata() {
        var low = f(ScannerId.PMD, Severity.MEDIUM, "CWE-20", "Use PreparedStatement", 5.0, "https://pmd");
        var high = f(ScannerId.OPENGREP, Severity.HIGH, null, null, null, "https://opengrep");

        List<FindingDeduplicator.Merged> merged = FindingDeduplicator.deduplicate(List.of(low, high));

        assertEquals(1, merged.size());
        var m = merged.getFirst();
        assertEquals(Severity.HIGH, m.finding().severity());
        assertEquals(ScannerId.OPENGREP, m.finding().scanner());
        assertEquals("Use PreparedStatement", m.finding().recommendation());
        assertEquals(5.0, m.finding().cvssScore());
        assertTrue(m.finding().cwes().containsAll(List.of("CWE-89", "CWE-20")));
        assertEquals(2, m.finding().references().size());
        assertEquals(2, m.sources().size());
        assertEquals(m.fingerprint(), m.finding().fingerprint());
    }

    @Test
    void keepsDistinctIssuesSeparateAndInOrder() {
        var a = f(ScannerId.OPENGREP, Severity.HIGH, null, null, null, "r");
        var b = new NormalizedFinding(ScannerId.OPENGREP, "other", FindingType.SECURITY, Severity.LOW, "x", "",
                new SourceLocation("Other.java", 1, 1), List.of(), null, null, null, null, null, null, null, "c2");
        var merged = FindingDeduplicator.deduplicate(List.of(a, b));
        assertEquals(2, merged.size());
        assertEquals("Dao.java", merged.get(0).finding().location().path());
        assertEquals("Other.java", merged.get(1).finding().location().path());
    }

    @Test
    void emptyInputGivesEmptyOutput() {
        assertTrue(FindingDeduplicator.deduplicate(List.of()).isEmpty());
    }
}
