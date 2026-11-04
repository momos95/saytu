package com.saytu.core.domain;

/** Status of a scan run (a user/cron request) or of a scan job (one repository branch). */
public enum ScanStatus {
    QUEUED,
    RUNNING,
    /** Every applicable scanner succeeded. */
    SUCCEEDED,
    /** At least one scanner failed or timed out: results exist but coverage is reduced. */
    PARTIAL,
    FAILED,
    CANCELLED;

    public boolean isTerminal() {
        return this == SUCCEEDED || this == PARTIAL || this == FAILED || this == CANCELLED;
    }
}
