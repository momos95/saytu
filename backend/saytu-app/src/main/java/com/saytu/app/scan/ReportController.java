package com.saytu.app.scan;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/reports")
@Tag(name = "Reports")
public class ReportController {

    private final ReportService reports;

    public ReportController(ReportService reports) {
        this.reports = reports;
    }

    @GetMapping("/findings")
    @Operation(summary = "Report of the findings matching the filters (status OPEN when none): html, pdf, json or sarif")
    public ResponseEntity<byte[]> findings(@RequestParam String format,
                                           @RequestParam(required = false) UUID repositoryId,
                                           @RequestParam(required = false) String branch,
                                           @RequestParam(required = false) List<String> severity,
                                           @RequestParam(required = false) List<String> type,
                                           @RequestParam(required = false) List<String> status,
                                           @RequestParam(required = false) String scanner,
                                           @RequestParam(required = false) String q) {
        ReportService.Report report = reports.generate(format,
                new FindingQueryService.Filter(repositoryId, branch, severity, type, status, scanner, q));
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(report.format().contentType))
                // the file name is ASCII by construction (see ReportService), so no RFC 5987 encoding is needed
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment()
                        .filename(report.fileName()).build().toString())
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header("X-Content-Type-Options", "nosniff")
                .body(report.content());
    }
}
