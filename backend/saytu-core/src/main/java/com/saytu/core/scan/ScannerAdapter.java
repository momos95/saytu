package com.saytu.core.scan;

import com.saytu.core.domain.Language;
import com.saytu.core.domain.ScannerId;
import com.saytu.core.finding.NormalizedFinding;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Port implemented once per analysis tool (Opengrep, Trivy, Gitleaks, PMD, Checkstyle,
 * OWASP Dependency-Check).
 * <p>
 * An adapter never starts a process itself: it describes the command ({@link #buildCommand}) and
 * parses the report ({@link #parse}). Execution, isolation, limits and timeouts belong to the
 * worker's sandbox, so every tool gets the same guarantees. Adapters must:
 * <ul>
 *   <li>run tools in offline mode (no telemetry, no database update, no remote lookups);</li>
 *   <li>never invoke a build tool or a script from the analysed repository;</li>
 *   <li>redact secret values before returning findings.</li>
 * </ul>
 */
public interface ScannerAdapter {

    ScannerId id();

    /** Version of the tool binary, captured once at worker start-up (e.g. {@code trivy --version}). */
    CommandSpec versionCommand(Path workDir);

    /** Parses the output of {@link #versionCommand}. */
    String parseVersion(String stdout);

    /**
     * Whether the tool has anything to analyse in the checkout (e.g. PMD needs {@code *.java} files).
     * A non-applicable scanner is recorded as {@code NOT_APPLICABLE}, which does not reduce coverage.
     */
    boolean isApplicable(Path sourceDir) throws IOException;

    CommandSpec buildCommand(ScanContext context);

    /**
     * Exit codes meaning "the tool ran correctly" (several tools exit non-zero when they find issues,
     * e.g. Gitleaks exits 1 when leaks are found).
     */
    boolean isSuccessfulExit(int exitCode);

    /** Parses the report written at {@link CommandSpec#reportFile()} into normalised findings. */
    List<NormalizedFinding> parse(Path reportFile, ScanContext context) throws IOException;

    /**
     * Languages this tool analyses. When none of them is present in the checkout the scanner is not
     * run and recorded as NOT_APPLICABLE. Empty set = every checkout (multi-language tools).
     */
    default Set<Language> languages() {
        return Set.of();
    }

    /**
     * Version of the rules or vulnerability database the next run will use (e.g. rule pack digest,
     * Trivy DB build date), recorded with each execution for reproducibility. Empty when unknown.
     */
    default Optional<String> rulesetVersion() {
        return Optional.empty();
    }

    /**
     * Reason why the next run can only cover part of the tool's scope (e.g. Trivy without its
     * vulnerability database still checks configuration files). When present, the run still happens
     * and its findings are kept, but the execution is recorded as {@code FAILED} with this reason, so
     * the missing part never reads as "no vulnerability".
     */
    default Optional<String> degradedReason() {
        return Optional.empty();
    }
}
