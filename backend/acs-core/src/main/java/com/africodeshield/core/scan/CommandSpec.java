package com.africodeshield.core.scan;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A scanner invocation, built by a {@link ScannerAdapter} and executed by the worker's sandbox.
 * <p>
 * Safety invariants enforced at construction:
 * <ul>
 *   <li>argv form only (no shell), so repository-controlled file names cannot inject commands;</li>
 *   <li>the environment starts empty; only variables listed here are passed, and names that look
 *       like credentials are rejected so Git tokens can never reach a scanner process;</li>
 *   <li>the executable must be an absolute path inside the worker image.</li>
 * </ul>
 *
 * @param argv        executable (absolute path) followed by arguments
 * @param environment complete environment of the child process
 * @param workingDir  per-job temporary directory
 * @param reportFile  file the tool writes its machine-readable output to
 */
public record CommandSpec(List<String> argv, Map<String, String> environment, Path workingDir, Path reportFile) {

    private static final Pattern FORBIDDEN_ENV = Pattern.compile(
            "(?i).*(TOKEN|PASSWORD|PASSWD|SECRET|CREDENTIAL|PRIVATE_KEY|ASKPASS|_AUTH).*");

    /** Variables that tools legitimately read but that match the pattern above. */
    private static final Set<String> ALLOWED_EXCEPTIONS = Set.of();

    public CommandSpec {
        Objects.requireNonNull(argv, "argv");
        Objects.requireNonNull(workingDir, "workingDir");
        Objects.requireNonNull(reportFile, "reportFile");
        if (argv.isEmpty() || !argv.getFirst().startsWith("/")) {
            throw new IllegalArgumentException("argv[0] must be an absolute executable path");
        }
        if (argv.stream().anyMatch(Objects::isNull)) {
            throw new IllegalArgumentException("argv must not contain null");
        }
        environment = environment == null ? Map.of() : Map.copyOf(environment);
        for (String name : environment.keySet()) {
            if (FORBIDDEN_ENV.matcher(name).matches() && !ALLOWED_EXCEPTIONS.contains(name)) {
                throw new IllegalArgumentException("Environment variable not allowed for scanner processes: " + name);
            }
        }
        argv = List.copyOf(argv);
        if (!reportFile.normalize().startsWith(workingDir.normalize())) {
            throw new IllegalArgumentException("reportFile must be inside workingDir");
        }
    }
}
