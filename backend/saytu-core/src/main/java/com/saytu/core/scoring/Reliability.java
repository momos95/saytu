package com.saytu.core.scoring;

/** How much a score can be trusted, from the coverage of the analyses that actually ran. */
public enum Reliability {
    /** coverage of at least 90 % */
    HIGH,
    /** at least 70 % */
    MEDIUM,
    /** at least the formula's minimum coverage */
    LOW,
    /** below: no score is published */
    INSUFFICIENT;

    public static Reliability of(double coveragePercent, double minCoverage) {
        if (coveragePercent >= 90) {
            return HIGH;
        }
        if (coveragePercent >= 70) {
            return MEDIUM;
        }
        return coveragePercent >= minCoverage ? LOW : INSUFFICIENT;
    }
}
