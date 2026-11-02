package com.africodeshield.core.domain;

/** Nature of a finding. Drives which score (security or quality) it impacts. */
public enum FindingType {
    SECURITY,
    QUALITY,
    SECRET,
    DEPENDENCY;

    /** {@code true} when the finding contributes to the security score. */
    public boolean affectsSecurityScore() {
        return this != QUALITY;
    }
}
