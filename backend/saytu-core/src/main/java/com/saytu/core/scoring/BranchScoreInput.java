package com.saytu.core.scoring;

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
 */
public record BranchScoreInput(Map<Severity, Long> security, Map<Severity, Long> quality, LanguageProfile languages,
                               Map<ScannerId, ScannerExecutionStatus> executions) {

    public BranchScoreInput {
        security = copy(security);
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
