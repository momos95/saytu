package com.saytu.app.scan;

import com.saytu.core.remediation.RemediationProvider;

import jakarta.validation.constraints.Size;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** DTOs of the scan and finding endpoints. */
public final class ScanViews {

    private ScanViews() {
    }

    /**
     * Scan request: either every current scan target, or a list of repositories (which must be targets).
     */
    public record ScanRequest(@Size(max = 5000) List<UUID> repositoryIds, boolean allTargets) {
        public ScanRequest {
            repositoryIds = repositoryIds == null ? List.of() : List.copyOf(repositoryIds);
        }
    }

    public record ScanCreated(UUID id) {
    }

    public record PageView<T>(List<T> items, int page, int size, long totalElements, int totalPages) {
    }

    /**
     * @param planned         the worker has turned the request into jobs
     * @param finishedJobs    jobs no longer queued or running
     * @param problemJobs     jobs FAILED or PARTIAL (some scanner did not complete)
     */
    public record ScanRunView(UUID id, String triggerType, String requestedBy, String status, int totalJobs,
                              long finishedJobs, long problemJobs, long newFindings, Instant createdAt,
                              Instant startedAt, Instant finishedAt, boolean planned, boolean cancelRequested,
                              String errorMessage, String scope) {
    }

    public record ScannerExecutionView(String scanner, String status, String toolVersion, String rulesetVersion,
                                       Long durationMs, int findingsCount, String errorMessage) {
    }

    public record ScanJobView(UUID id, UUID repositoryId, String repositoryName, String branch, String commitSha,
                              String status, int attempt, Instant queuedAt, Instant startedAt, Instant finishedAt,
                              String errorMessage, Long checkoutBytes, int findingsCount, int newFindings,
                              int resolvedFindings, List<ScannerExecutionView> scanners, List<String> languages,
                              ScoreService.ScoreView score) {
    }

    /** Repository of the scope that produced no job, and why. */
    public record PlanningNote(UUID repositoryId, String repository, String note) {
    }

    public record ScanRunDetail(ScanRunView run, List<ScanJobView> jobs, List<PlanningNote> planningNotes) {
    }

    public record FindingView(UUID id, UUID repositoryId, String repositoryName, String branch, String type,
                              String severity, String scanner, String ruleId, String title, String filePath,
                              Integer startLine, Integer endLine, List<String> cwes, String cve, BigDecimal cvssScore,
                              String packageName, String packageVersion, String fixedVersion, String status,
                              Instant firstSeenAt, Instant lastSeenAt, String commitSha, List<String> scanners) {
    }

    public record OccurrenceView(String scanner, String ruleId, String severity, String filePath, Integer startLine,
                                 Instant detectedAt, UUID scanJobId) {
    }

    public record FindingDetail(FindingView finding, String description, String evidence, String recommendation,
                                List<String> references, String cvssVector, String packageEcosystem, Instant resolvedAt,
                                String statusReason, String statusChangedBy, Instant statusChangedAt,
                                List<OccurrenceView> occurrences, List<StatusChangeView> history,
                                RemediationProvider.Remediation suggestion) {
    }

    /** One manual status change (triage), oldest first. */
    public record StatusChangeView(String fromStatus, String toStatus, String reason, String changedBy, Instant changedAt) {
    }

    /** Page of findings plus the count per severity for the same filters. */
    public record FindingPage(PageView<FindingView> page, Map<String, Long> bySeverity) {
    }
}
