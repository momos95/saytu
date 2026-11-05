package com.saytu.app.scan;

import com.saytu.app.scan.ScanViews.PageView;
import com.saytu.app.scan.ScanViews.ScanCreated;
import com.saytu.app.scan.ScanViews.ScanRequest;
import com.saytu.app.scan.ScanViews.ScanRunDetail;
import com.saytu.app.scan.ScanViews.ScanRunView;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/** Audits: launch (AUDITOR, ADMIN), history and progress (every role), cancellation. */
@RestController
@RequestMapping("/api/v1/scans")
@Tag(name = "Scans")
public class ScanController {

    private final ScanService scans;

    public ScanController(ScanService scans) {
        this.scans = scans;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.ACCEPTED)
    @PreAuthorize("hasAnyRole('AUDITOR', 'ADMIN')")
    @Operation(summary = "Request an audit of every selected repository, or of a list of repositories")
    public ScanCreated request(@Valid @RequestBody ScanRequest request) {
        return scans.request(request);
    }

    @GetMapping
    @Operation(summary = "Audit history, newest first")
    public PageView<ScanRunView> list(@RequestParam(defaultValue = "0") int page,
                                      @RequestParam(defaultValue = "20") int size) {
        return scans.list(page, size);
    }

    @GetMapping("/{id}")
    @Operation(summary = "An audit with its jobs (repository x branch) and scanner executions")
    public ScanRunDetail get(@PathVariable UUID id) {
        return scans.get(id);
    }

    @PostMapping("/{id}/cancel")
    @PreAuthorize("hasAnyRole('AUDITOR', 'ADMIN')")
    @Operation(summary = "Cancel an audit: queued jobs are dropped, running jobs stop before their next scanner")
    public ScanRunDetail cancel(@PathVariable UUID id) {
        return scans.cancel(id);
    }
}
