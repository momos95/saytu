package com.saytu.app.scan;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1")
@Tag(name = "Dashboard")
public class InsightController {

    private final InsightService insights;

    public InsightController(InsightService insights) {
        this.insights = insights;
    }

    @GetMapping("/dashboard")
    @Operation(summary = "Global score, open findings by severity and type, trends, priority repositories, recent audits")
    public InsightService.Dashboard dashboard() {
        return insights.dashboard();
    }

    @GetMapping("/repositories/{repositoryId}/overview")
    @Operation(summary = "Repository detail: scores per branch, trend, open findings, frequent rules, recent jobs")
    public InsightService.RepositoryOverview repository(@PathVariable UUID repositoryId) {
        return insights.repository(repositoryId);
    }
}
