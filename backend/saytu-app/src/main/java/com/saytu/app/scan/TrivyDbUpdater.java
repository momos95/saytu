package com.saytu.app.scan;

import com.saytu.core.scan.CommandSpec;
import com.saytu.core.scan.ResourceLimits;
import com.saytu.scan.sandbox.ProcessSandbox;
import com.saytu.scan.sandbox.SandboxResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Downloads and refreshes the Trivy vulnerability database (public advisories only: nothing about the
 * analysed code is sent). Disabled on air-gapped sites, where the database is copied by hand
 * (docs/operations.md). Runs only while no job is executing.
 */
public class TrivyDbUpdater {

    private static final Logger log = LoggerFactory.getLogger(TrivyDbUpdater.class);
    private static final List<String> PROXY_VARIABLES = List.of("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
            "NO_PROXY", "no_proxy", "SSL_CERT_FILE");
    private static final ResourceLimits LIMITS = new ResourceLimits(Duration.ofMinutes(20), 1200,
            2L * 1024 * 1024 * 1024, 4L * 1024 * 1024 * 1024, 1024);

    private final ProcessSandbox sandbox;
    private final ScanProperties.Tools tools;
    private final Path workRoot;
    private final Clock clock;
    private Instant lastAttempt = Instant.EPOCH;

    public TrivyDbUpdater(ProcessSandbox sandbox, ScanProperties.Tools tools, Path workRoot, Clock clock) {
        this.sandbox = sandbox;
        this.tools = tools;
        this.workRoot = workRoot;
        this.clock = clock;
    }

    /** Refreshes the database when auto-update is on and the interval elapsed (or it is missing). */
    public synchronized void updateIfDue() {
        if (!tools.trivyDbAutoUpdate()) {
            return;
        }
        Instant now = clock.instant();
        boolean missing = !Files.isRegularFile(tools.trivyCacheDir().resolve("db").resolve("trivy.db"));
        Duration wait = missing ? Duration.ofMinutes(15) : tools.trivyDbUpdateInterval();
        if (Duration.between(lastAttempt, now).compareTo(wait) < 0) {
            return;
        }
        lastAttempt = now;
        Path dir = workRoot.resolve("trivy-db-update");
        try {
            Files.createDirectories(dir);
            Files.createDirectories(tools.trivyCacheDir());
            List<String> argv = new ArrayList<>(List.of(tools.trivy().toString(), "image", "--download-db-only",
                    "--cache-dir", tools.trivyCacheDir().toString(), "--quiet", "--no-progress",
                    "--disable-telemetry", "--skip-version-check"));
            if (tools.trivyDbRepository() != null) {
                argv.addAll(List.of("--db-repository", tools.trivyDbRepository()));
            }
            Map<String, String> env = new LinkedHashMap<>();
            env.put("PATH", "/usr/local/bin:/usr/bin:/bin");
            env.put("HOME", dir.toString());
            env.put("TMPDIR", dir.toString());
            for (String name : PROXY_VARIABLES) {
                String value = System.getenv(name);
                if (value != null && !value.isBlank()) {
                    env.put(name, value);
                }
            }
            SandboxResult r = sandbox.run(new CommandSpec(argv, env, dir, dir.resolve("unused")), LIMITS);
            if (r.completed() && r.exitCode() == 0) {
                log.info("Trivy vulnerability database updated");
                // read by the scanner accounts (ScannerIsolation); Trivy creates its directories private
                com.saytu.scan.sandbox.ScannerIsolation.makeReadable(tools.trivyCacheDir());
            } else {
                log.warn("Trivy vulnerability database update failed (dependency checks stay degraded): {}",
                        r.timedOut() ? "timeout" : r.diagnostic(500));
            }
        } catch (IOException e) {
            log.warn("Trivy vulnerability database update failed: {}", e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
