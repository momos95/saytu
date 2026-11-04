package com.saytu.core.domain;

/**
 * Outcome of one scanner on one scan job.
 * <p>
 * Only {@link #SUCCEEDED} proves the absence of findings for the scanner's scope. Every other
 * value means "unknown" and must reduce score coverage, never be read as "no vulnerability".
 */
public enum ScannerExecutionStatus {
    SUCCEEDED,
    FAILED,
    TIMED_OUT,
    /** Disabled by configuration. */
    SKIPPED,
    /** Nothing to analyse (e.g. PMD on a repository without Java sources). */
    NOT_APPLICABLE;

    public boolean provesCoverage() {
        return this == SUCCEEDED;
    }

    /** NOT_APPLICABLE does not reduce coverage: there was nothing in scope. */
    public boolean countsInCoverageDenominator() {
        return this != NOT_APPLICABLE;
    }
}
