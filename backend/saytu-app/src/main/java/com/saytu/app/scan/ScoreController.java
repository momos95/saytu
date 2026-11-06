package com.saytu.app.scan;

import com.saytu.core.domain.Severity;
import com.saytu.core.scoring.ScoringFormula;
import com.saytu.core.scoring.SecurityIssue;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** Scores (every role) and the scoring formula (changed by ADMIN only). */
@RestController
@RequestMapping("/api/v1/scores")
@Tag(name = "Scores")
public class ScoreController {

    private final ScoreService scores;

    public ScoreController(ScoreService scores) {
        this.scores = scores;
    }

    @GetMapping
    @Operation(summary = "Latest global, organisation and repository scores, with the formula in use")
    public ScoreService.Summary summary() {
        return scores.summary();
    }

    @GetMapping("/formula")
    @Operation(summary = "Scoring formula parameters (docs/scoring.md)")
    public ScoringFormula formula() {
        return scores.formula();
    }

    /**
     * New formula parameters. Every audited branch is rescored immediately from the stored results (older
     * snapshots keep the version they were computed with). Fields added in v2 default to the v2 values.
     */
    public record FormulaUpdate(String version, Map<Severity, Double> securityWeights, double securityScale,
                                double criticalCap, Map<Severity, Double> qualityWeights, double qualityScale,
                                double bytesPerLine, double securityShare, double minCoverage,
                                ScoringFormula.SecurityCurve securityCurve,
                                Map<SecurityIssue.Category, Double> categoryFactors, Double noFixFactor,
                                Boolean diminishingReturns) {
    }

    @PutMapping("/formula")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Change the scoring formula (ADMIN)")
    public ScoringFormula updateFormula(@RequestBody FormulaUpdate u) {
        if (u.version() == null || !u.version().matches("^[A-Za-z0-9._-]{1,32}$")) {
            throw new IllegalArgumentException("version: 1 to 32 letters, digits, dots, dashes or underscores");
        }
        ScoringFormula d = ScoringFormula.DEFAULT;
        return scores.updateFormula(new ScoringFormula(u.version(), u.securityWeights(), u.securityScale(),
                u.criticalCap(), u.qualityWeights(), u.qualityScale(), u.bytesPerLine(), u.securityShare(), u.minCoverage(),
                u.securityCurve() == null ? d.securityCurve() : u.securityCurve(),
                u.categoryFactors() == null ? d.categoryFactors() : u.categoryFactors(),
                u.noFixFactor() == null ? d.noFixFactor() : u.noFixFactor(),
                u.diminishingReturns() == null ? d.diminishingReturns() : u.diminishingReturns()));
    }
}
