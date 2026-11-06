package com.saytu.core.scoring;

import java.util.ArrayList;
import java.util.List;

import com.saytu.core.domain.LanguageProfile;
import com.saytu.core.domain.ScannerExecutionStatus;
import com.saytu.core.domain.ScannerId;
import com.saytu.core.domain.Severity;

import java.util.EnumMap;
import java.util.Map;

/**
 * What the score of one branch is computed from: its OPEN findings (triaged ones excluded) and how
 * the scanners of its latest job ended.
 *
 * @param security   OPEN SECURITY, SECRET and DEPENDENCY findings per severity
 * @param quality    OPEN QUALITY findings per severity
 * @param languages  languages of the latest checkout
 * @param executions status of each scanner in the latest job (absent = not run)
 * @param securityIssues the same security findings, classified (category, group) for formula v2
 */
public record BranchScoreInput(Map<Severity, Long> security, Map<Severity, Long> quality, LanguageProfile languages,
                               Map<ScannerId, ScannerExecutionStatus> executions, List<SecurityIssue> securityIssues) {

    /** Counts only (v1 callers, tests): each finding is its own group of code issues. */
    public BranchScoreInput(Map<Severity, Long> security, Map<Severity, Long> quality, LanguageProfile languages,
                            Map<ScannerId, ScannerExecutionStatus> executions) {
        this(security, quality, languages, executions, null);
    }

    /** Classified security issues; the per-severity counts are derived from them. */
    public static BranchScoreInput of(List<SecurityIssue> issues, Map<Severity, Long> quality, LanguageProfile languages,
                                      Map<ScannerId, ScannerExecutionStatus> executions) {
        Map<Severity, Long> counts = new EnumMap<>(Severity.class);
        for (SecurityIssue i : issues) {
            counts.merge(i.severity(), 1L, Long::sum);
        }
        return new BranchScoreInput(counts, quality, languages, executions, issues);
    }

    public BranchScoreInput {
        security = copy(security);
        if (securityIssues == null) {
            List<SecurityIssue> derived = new ArrayList<>();
            int n = 0;
            for (Severity s : Severity.values()) {
                for (long i = 0; i < security.get(s); i++) {
                    derived.add(new SecurityIssue(s, SecurityIssue.Category.CODE, "finding:" + n++, false));
                }
            }
            securityIssues = List.copyOf(derived);
        } else {
            securityIssues = List.copyOf(securityIssues);
        }
        quality = copy(quality);
        languages = languages == null ? LanguageProfile.empty() : languages;
        executions = executions == null || executions.isEmpty() ? Map.of() : Map.copyOf(new EnumMap<>(executions));
    }

    private static Map<Severity, Long> copy(Map<Severity, Long> counts) {
        Map<Severity, Long> c = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) {
            long v = counts == null || counts.get(s) == null ? 0 : counts.get(s);
            c.put(s, Math.max(0, v));
        }
        return Map.copyOf(c);
    }

    boolean succeeded(ScannerId id) {
        return executions.get(id) == ScannerExecutionStatus.SUCCEEDED;
    }
}
