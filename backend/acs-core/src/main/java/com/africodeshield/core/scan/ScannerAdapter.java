package com.africodeshield.core.scan;

import com.africodeshield.core.domain.ScannerId;
import com.africodeshield.core.finding.NormalizedFinding;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

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
}
