package com.saytu.scan;

import com.saytu.core.domain.LanguageProfile;
import com.saytu.core.domain.ScanStatus;
import com.saytu.core.domain.ScannerExecutionStatus;

import java.util.List;

/**
 * Result of a job (one repository branch).
 *
 * @param commitSha analysed commit, {@code null} when the checkout failed
 * @param languages languages of the checkout (empty when the checkout failed)
 * @param error     checkout error, {@code null} when the checkout succeeded
 */
public record JobOutcome(String commitSha, long checkoutBytes, long checkoutFiles, LanguageProfile languages,
                         List<ScannerOutcome> scanners, String error) {

    public JobOutcome {
        scanners = scanners == null ? List.of() : List.copyOf(scanners);
        languages = languages == null ? LanguageProfile.empty() : languages;
    }

    /** Same outcome with other scanner results (e.g. scanners not integrated, added by the worker). */
    public JobOutcome withScanners(List<ScannerOutcome> other) {
        return new JobOutcome(commitSha, checkoutBytes, checkoutFiles, languages, other, error);
    }

    /**
     * SUCCEEDED when every scanner that should have run succeeded (or had nothing to analyse),
     * PARTIAL when at least one failed or timed out but another produced results, FAILED otherwise.
     */
    public ScanStatus status() {
        if (error != null) {
            return ScanStatus.FAILED;
        }
        boolean anySucceeded = false;
        boolean anyFailed = false;
        for (ScannerOutcome s : scanners) {
            switch (s.status()) {
                case SUCCEEDED -> anySucceeded = true;
                case FAILED, TIMED_OUT -> anyFailed = true;
                case SKIPPED, NOT_APPLICABLE -> { }
            }
        }
        if (!anyFailed) {
            return anySucceeded || scanners.stream().allMatch(s -> s.status() != ScannerExecutionStatus.SKIPPED)
                    ? ScanStatus.SUCCEEDED : ScanStatus.FAILED;
        }
        return anySucceeded ? ScanStatus.PARTIAL : ScanStatus.FAILED;
    }
}
