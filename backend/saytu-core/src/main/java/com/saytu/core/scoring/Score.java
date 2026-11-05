package com.saytu.core.scoring;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Score of a branch, repository, organisation or the whole installation.
 *
 * @param security        0..100, {@code null} when the security analyses' coverage is too low
 * @param quality         0..100, {@code null} when too low or when there is no code to judge
 * @param global          weighted combination of the available scores, {@code null} when none
 * @param coverage        0..100, share of the expected analyses that succeeded
 * @param reliability     derived from the coverage
 * @param details         inputs and intermediate values, stored with the snapshot for transparency
 */
public record Score(Double security, Double quality, Double global, double coverage, Reliability reliability,
                   Map<String, Object> details) {

    public Score {
        details = details == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(details));
    }
}
