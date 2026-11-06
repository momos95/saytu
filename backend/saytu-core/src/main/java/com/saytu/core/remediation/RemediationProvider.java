package com.saytu.core.remediation;

import com.saytu.core.finding.NormalizedFinding;

import java.util.List;
import java.util.Optional;

/**
 * Produces remediation guidance for a finding. Implementations:
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
     * @param topic            short name of the weakness ("Injection SQL")
     * @param explanation      what the weakness is
     * @param impact           what an attacker / maintainer is exposed to
     * @param steps            how to fix it, in order
     * @param exampleLanguage  language of the examples (java, typescript, php, python, csharp, yaml, xml…)
     * @param vulnerableExample typical vulnerable code, may be empty
     * @param fixedCodeExample example of corrected code, may be empty
     * @param suggestedTests   tests proving the fix
     * @param references       links to rule docs / advisories / cheat sheets
     * @param specific         false when only the generic guidance of the category applies
     */
    record Remediation(String providerId, String topic, String explanation, String impact, List<String> steps,
                       String exampleLanguage, String vulnerableExample, String fixedCodeExample,
                       List<String> suggestedTests, List<String> references, boolean specific) {
        public Remediation {
            steps = steps == null ? List.of() : List.copyOf(steps);
            suggestedTests = suggestedTests == null ? List.of() : List.copyOf(suggestedTests);
            references = references == null ? List.of() : references.stream().distinct().toList();
            vulnerableExample = vulnerableExample == null ? "" : vulnerableExample;
            fixedCodeExample = fixedCodeExample == null ? "" : fixedCodeExample;
        }
    }
}
