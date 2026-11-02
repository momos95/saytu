package com.africodeshield.core.domain;

import java.util.EnumSet;
import java.util.Set;

/**
 * Lifecycle of a finding.
 * <ul>
 *   <li>OPEN: detected in the latest scan of the branch.</li>
 *   <li>RESOLVED: no longer detected by a scan in which the producing scanner actually ran.</li>
 *   <li>ACCEPTED_RISK / FALSE_POSITIVE: human triage decisions, kept across scans.</li>
 * </ul>
 */
public enum FindingStatus {
    OPEN,
    RESOLVED,
    ACCEPTED_RISK,
    FALSE_POSITIVE;

    /** Statuses set by a human. They must never be overwritten automatically. */
    public static final Set<FindingStatus> TRIAGED = EnumSet.of(ACCEPTED_RISK, FALSE_POSITIVE);

    public boolean isTriaged() {
        return TRIAGED.contains(this);
    }

    /** Whether the finding still counts against scores. */
    public boolean countsInScore() {
        return this == OPEN;
    }

    /** Allowed manual transitions (automatic OPEN/RESOLVED transitions are handled by the engine). */
    public boolean canTransitionManuallyTo(FindingStatus target) {
        if (target == null || target == this) {
            return false;
        }
        return switch (this) {
            case OPEN -> target == ACCEPTED_RISK || target == FALSE_POSITIVE;
            case ACCEPTED_RISK, FALSE_POSITIVE -> target == OPEN;
            case RESOLVED -> false;
        };
    }
}
