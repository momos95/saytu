package com.saytu.app.scan;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/jobs")
@Tag(name = "Scans")
public class JobComparisonController {

    private final JobComparisonService comparisons;

    public JobComparisonController(JobComparisonService comparisons) {
        this.comparisons = comparisons;
    }

    @GetMapping("/{jobId}/compare")
    @Operation(summary = "Findings introduced, fixed and not verifiable between two analyses of a repository "
            + "(default: the previous finished analysis of the same branch)")
    public JobComparisonService.Comparison compare(@PathVariable UUID jobId, @RequestParam(required = false) UUID with) {
        return comparisons.compare(jobId, with);
    }
}
