package com.saytu.core.remediation;

import com.saytu.core.finding.NormalizedFinding;

import java.util.List;
import java.util.Optional;

/**
 * Produces remediation guidance for a finding. Implementations (later phases):
 * <ul>
 *   <li>{@code RuleBasedRemediationProvider}: deterministic, from scanner rule metadata — always on;</li>
 *   <li>{@code OllamaRemediationProvider}: optional, local LLM via Ollama — never a remote API.</li>
 * </ul>
 * Guidance is advisory only: the MVP never modifies analysed repositories.
 */
public interface RemediationProvider {

    /** Stable id stored with the generated remediation ({@code rule-based}, {@code ollama:<model>}). */
    String id();

    /** {@code true} for providers whose output is not reproducible (LLMs); the UI labels them. */
    boolean isGenerative();

    /**
     * @param finding     finding with redacted evidence (the only code ever sent to a provider)
     * @param codeContext redacted surrounding lines, may be empty
     */
    Optional<Remediation> suggest(NormalizedFinding finding, String codeContext);

    /**
     * @param explanation      what the weakness is
     * @param impact           what an attacker / maintainer is exposed to
     * @param recommendation   how to fix it
     * @param fixedCodeExample example of corrected code, may be empty
     * @param suggestedTests   tests proving the fix
     * @param references       links to rule docs / advisories
     */
    record Remediation(String providerId, String explanation, String impact, String recommendation,
                       String fixedCodeExample, List<String> suggestedTests, List<String> references) {
        public Remediation {
            suggestedTests = suggestedTests == null ? List.of() : List.copyOf(suggestedTests);
            references = references == null ? List.of() : List.copyOf(references);
        }
    }
}
