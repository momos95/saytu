package com.saytu.core.finding;

import com.saytu.core.domain.FindingStatus;
import com.saytu.core.domain.FindingType;
import com.saytu.core.domain.ScannerExecutionStatus;
import com.saytu.core.domain.ScannerId;
import com.saytu.core.domain.Severity;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DomainEnumsTest {

    @Test
    void cvssMappingFollowsFirstScale() {
        assertEquals(Severity.CRITICAL, Severity.fromCvss(9.0));
        assertEquals(Severity.HIGH, Severity.fromCvss(8.9));
        assertEquals(Severity.HIGH, Severity.fromCvss(7.0));
        assertEquals(Severity.MEDIUM, Severity.fromCvss(4.0));
        assertEquals(Severity.LOW, Severity.fromCvss(0.1));
        assertEquals(Severity.INFO, Severity.fromCvss(0.0));
        assertThrows(IllegalArgumentException.class, () -> Severity.fromCvss(10.1));
    }

    @Test
    void lenientSeverityParsing() {
        assertEquals(Optional.of(Severity.HIGH), Severity.parseLenient("error"));
        assertEquals(Optional.of(Severity.MEDIUM), Severity.parseLenient(" Warning "));
        assertEquals(Optional.of(Severity.INFO), Severity.parseLenient("UNKNOWN"));
        assertEquals(Optional.empty(), Severity.parseLenient("bogus"));
        assertEquals(Optional.empty(), Severity.parseLenient(null));
    }

    @Test
    void severityOrdering() {
        assertTrue(Severity.CRITICAL.isAtLeast(Severity.HIGH));
        assertTrue(Severity.HIGH.isAtLeast(Severity.HIGH));
        assertFalse(Severity.LOW.isAtLeast(Severity.MEDIUM));
    }

    @Test
    void manualStatusTransitions() {
        assertTrue(FindingStatus.OPEN.canTransitionManuallyTo(FindingStatus.FALSE_POSITIVE));
        assertTrue(FindingStatus.ACCEPTED_RISK.canTransitionManuallyTo(FindingStatus.OPEN));
        assertFalse(FindingStatus.RESOLVED.canTransitionManuallyTo(FindingStatus.OPEN));
        assertFalse(FindingStatus.OPEN.canTransitionManuallyTo(FindingStatus.RESOLVED));
        assertFalse(FindingStatus.OPEN.canTransitionManuallyTo(FindingStatus.OPEN));
        assertTrue(FindingStatus.FALSE_POSITIVE.isTriaged());
        assertTrue(FindingStatus.OPEN.countsInScore());
        assertFalse(FindingStatus.ACCEPTED_RISK.countsInScore());
    }

    @Test
    void onlySucceededExecutionsProveCoverage() {
        for (ScannerExecutionStatus s : ScannerExecutionStatus.values()) {
            assertEquals(s == ScannerExecutionStatus.SUCCEEDED, s.provesCoverage(), s.name());
        }
        assertFalse(ScannerExecutionStatus.NOT_APPLICABLE.countsInCoverageDenominator());
        assertTrue(ScannerExecutionStatus.TIMED_OUT.countsInCoverageDenominator());
        assertTrue(ScannerExecutionStatus.SKIPPED.countsInCoverageDenominator());
    }

    @Test
    void scannerKeys() {
        assertEquals(Optional.of(ScannerId.DEPENDENCY_CHECK), ScannerId.fromKey("Dependency-Check"));
        assertEquals(Optional.empty(), ScannerId.fromKey("sonar"));
        assertFalse(ScannerId.DEPENDENCY_CHECK.enabledByDefault());
        assertTrue(ScannerId.GITLEAKS.producedTypes().contains(FindingType.SECRET));
        assertFalse(FindingType.QUALITY.affectsSecurityScore());
    }
}
