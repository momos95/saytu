package com.saytu.app.scan;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** How the scanners are confined on the worker (every role). */
@RestController
@RequestMapping("/api/v1/system")
@Tag(name = "System")
public class WorkerStatusController {

    private final WorkerStatusService status;

    public WorkerStatusController(WorkerStatusService status) {
        this.status = status;
    }

    @GetMapping("/worker")
    @Operation(summary = "Scanner isolation reported by the worker (dedicated account, network), 204 before its first start")
    public ResponseEntity<WorkerStatusService.Isolation> worker() {
        WorkerStatusService.Isolation isolation = status.isolation();
        return isolation == null ? ResponseEntity.noContent().build() : ResponseEntity.ok(isolation);
    }
}
