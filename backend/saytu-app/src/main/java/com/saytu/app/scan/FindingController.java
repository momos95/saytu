package com.saytu.app.scan;

import com.saytu.app.scan.ScanViews.FindingDetail;
import com.saytu.app.scan.ScanViews.FindingPage;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/** Findings, readable by every role. Triage (accepted risk, false positive) comes with phase 6. */
@RestController
@RequestMapping("/api/v1/findings")
@Tag(name = "Findings")
public class FindingController {

    private final FindingQueryService findings;
    private final FindingTriageService triage;

    public FindingController(FindingQueryService findings, FindingTriageService triage) {
        this.findings = findings;
        this.triage = triage;
    }

    @GetMapping
    @Operation(summary = "Findings, most severe first, with optional filters")
    public FindingPage list(@RequestParam(required = false) UUID repositoryId,
                            @RequestParam(required = false) String branch,
                            @RequestParam(required = false) List<String> severity,
                            @RequestParam(required = false) List<String> type,
                            @RequestParam(required = false) List<String> status,
                            @RequestParam(required = false) String scanner,
                            @RequestParam(required = false) String q,
                            @RequestParam(defaultValue = "0") int page,
                            @RequestParam(defaultValue = "50") int size) {
        return findings.list(new FindingQueryService.Filter(repositoryId, branch, severity, type, status, scanner, q),
                page, size);
    }

    @GetMapping("/{id}")
    @Operation(summary = "One finding with its evidence (secrets masked), recommendation and occurrences")
    public FindingDetail get(@PathVariable UUID id) {
        return findings.get(id);
    }

    @PutMapping("/{id}/status")
    @PreAuthorize("hasAnyRole('AUDITOR', 'ADMIN')")
    @Operation(summary = "Triage: accept the risk, declare a false positive (reason required) or reopen")
    public FindingDetail changeStatus(@PathVariable UUID id, @RequestBody FindingTriageService.StatusChange change) {
        return triage.changeStatus(id, change);
    }
}
