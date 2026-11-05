package com.saytu.scan;

import com.saytu.core.domain.ScannerExecutionStatus;
import com.saytu.core.domain.ScannerId;
import com.saytu.core.finding.NormalizedFinding;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Result of one scanner on one job, persisted as a {@code scanner_execution} row.
 *
 * @param findings normalised findings; may be non-empty for a FAILED degraded run (kept, not trusted as complete)
 */
public record ScannerOutcome(ScannerId scanner, ScannerExecutionStatus status, String toolVersion, String rulesetVersion,
                             Integer exitCode, Duration duration, Instant startedAt, Instant finishedAt,
                             String errorMessage, List<NormalizedFinding> findings) {

    public ScannerOutcome {
        findings = findings == null ? List.of() : List.copyOf(findings);
        if (errorMessage != null && errorMessage.length() > 2000) {
            errorMessage = errorMessage.substring(0, 1999) + "…";
        }
    }

    static ScannerOutcome notRun(ScannerId scanner, ScannerExecutionStatus status, String reason) {
        Instant now = Instant.now();
        return new ScannerOutcome(scanner, status, null, null, null, Duration.ZERO, now, now, reason, List.of());
    }
}
