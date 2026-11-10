package com.saytu.scan;

import com.saytu.core.domain.Language;
import com.saytu.core.domain.LanguageProfile;
import com.saytu.core.domain.ScannerExecutionStatus;
import com.saytu.core.domain.ScannerId;
import com.saytu.core.finding.NormalizedFinding;
import com.saytu.core.scan.CommandSpec;
import com.saytu.core.scan.ResourceLimits;
import com.saytu.core.scan.ScanContext;
import com.saytu.core.scan.ScannerAdapter;
import com.saytu.scan.git.CheckoutException;
import com.saytu.scan.git.CheckoutRequest;
import com.saytu.scan.git.RemoteRefs;
import com.saytu.scan.git.CheckoutResult;
import com.saytu.scan.git.GitCheckout;
import com.saytu.scan.lang.LanguageDetector;
import com.saytu.scan.sandbox.ProcessSandbox;
import com.saytu.scan.sandbox.ScannerIsolation;
import com.saytu.scan.sandbox.SandboxResult;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BooleanSupplier;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Executes one job: checkout, every planned scanner, cleanup.
 * <p>
 * Never invents a result: a scanner that did not run to completion is recorded as FAILED or
 * TIMED_OUT with the reason, and its findings are only kept when the tool itself reported them.
 * The job directory (sources, reports with raw secrets) is always deleted, whatever happens.
 */
public final class ScanJobRunner {

    private static final Logger LOG = Logger.getLogger(ScanJobRunner.class.getName());
    /** Self-extracting tools (Opengrep) may unpack ~250 MB on first start. */
    private static final ResourceLimits VERSION_LIMITS = new ResourceLimits(Duration.ofSeconds(60), 60,
            1024L * 1024 * 1024, 512L * 1024 * 1024, 256);

    private final ProcessSandbox sandbox;
    private final GitCheckout checkout;
    private final Path workRoot;
    private final ScannerIsolation isolation;
    private final Map<ScannerId, String> toolVersions = new ConcurrentHashMap<>();

    /** @param workRoot directory under which each job gets a private sub-directory */
    public ScanJobRunner(ProcessSandbox sandbox, GitCheckout checkout, Path workRoot) {
        this(sandbox, checkout, workRoot, ScannerIsolation.disabled("not configured"));
    }

    /** @param isolation runs the scanners of each job under a dedicated account when enabled */
    public ScanJobRunner(ProcessSandbox sandbox, GitCheckout checkout, Path workRoot, ScannerIsolation isolation) {
        this.sandbox = Objects.requireNonNull(sandbox, "sandbox");
        this.checkout = Objects.requireNonNull(checkout, "checkout");
        this.workRoot = Objects.requireNonNull(workRoot, "workRoot");
        this.isolation = Objects.requireNonNull(isolation, "isolation");
        try {
            isolation.prepareWorkRoot(workRoot);
        } catch (IOException e) {
            throw new IllegalStateException("cannot prepare the work directory " + workRoot, e);
        }
    }

    /**
     * @param cancelled polled between steps; when it returns {@code true} the job stops and the
     *                  remaining scanners are not run
     */
    public JobOutcome run(UUID jobId, CheckoutRequest request, List<ScannerPlan> plans, BooleanSupplier cancelled)
            throws InterruptedException {
        Path jobDir = workRoot.resolve("job-" + jobId);
        ScannerIsolation.Identity identity = null;
        try {
            GitCheckout.deleteRecursively(jobDir); // left over by a crashed attempt of the same job
            createPrivateDir(jobDir);
            identity = isolation.acquire();
            CheckoutResult source;
            try {
                source = checkout.checkout(request, jobDir);
            } catch (CheckoutException e) {
                return new JobOutcome(null, 0, 0, null, List.of(), e.kind() + ": " + e.getMessage());
            }
            // branch / tag hygiene (Git flow): a failure here never fails the audit
            RemoteRefs refs = null;
            String refsError = null;
            try {
                Path refsDir = jobDir.resolve("refs");
                createPrivateDir(refsDir);
                refs = checkout.listRefs(request, refsDir);
            } catch (CheckoutException e) {
                refsError = e.kind() + ": " + e.getMessage();
            }
            LanguageProfile languages = new LanguageDetector().detect(source.sourceDir());
            isolation.shareWithJob(jobDir, identity); // after the trusted steps: refs/ stays private
            List<ScannerOutcome> outcomes = new ArrayList<>();
            for (ScannerPlan plan : plans) {
                if (cancelled.getAsBoolean()) {
                    outcomes.add(ScannerOutcome.notRun(plan.adapter().id(), ScannerExecutionStatus.SKIPPED, "job cancelled"));
                    continue;
                }
                outcomes.add(runScanner(jobId, jobDir, source, languages, plan, identity));
            }
            return new JobOutcome(source.commitSha(), source.totalBytes(), source.fileCount(), languages, outcomes, null,
                    refs, refsError);
        } catch (IOException e) {
            return new JobOutcome(null, 0, 0, null, List.of(), "FAILED: cannot prepare the job directory");
        } finally {
            isolation.release(identity);
            try {
                GitCheckout.deleteRecursively(jobDir);
            } catch (IOException e) {
                LOG.log(Level.WARNING, "could not delete job directory " + jobDir, e);
            }
        }
    }

    private ScannerOutcome runScanner(UUID jobId, Path jobDir, CheckoutResult source, LanguageProfile languages,
                                      ScannerPlan plan, ScannerIsolation.Identity identity) throws InterruptedException {
        ScannerAdapter adapter = plan.adapter();
        ScannerId id = adapter.id();
        if (!plan.enabled()) {
            return ScannerOutcome.notRun(id, ScannerExecutionStatus.SKIPPED, "disabled in the scanner settings");
        }
        if (!adapter.languages().isEmpty() && !languages.containsAny(adapter.languages())) {
            String names = adapter.languages().stream().sorted().map(Language::label)
                    .reduce((a, b) -> a + " / " + b).orElse("");
            return ScannerOutcome.notRun(id, ScannerExecutionStatus.NOT_APPLICABLE, "no " + names + " file");
        }
        try {
            if (!adapter.isApplicable(source.sourceDir())) {
                return ScannerOutcome.notRun(id, ScannerExecutionStatus.NOT_APPLICABLE, null);
            }
        } catch (IOException e) {
            return ScannerOutcome.notRun(id, ScannerExecutionStatus.FAILED, "cannot inspect the sources: " + e.getMessage());
        }
        Path workDir = jobDir.resolve("scanner-" + id.key());
        String toolVersion = toolVersion(adapter, jobDir, identity);
        String ruleset = adapter.rulesetVersion().orElse(null);
        String degraded = adapter.degradedReason().orElse(null);
        Instant started = Instant.now();
        try {
            createPrivateDir(workDir);
            isolation.handOver(workDir, identity);
            ScanContext context = new ScanContext(jobId, source.sourceDir(), workDir, source.commitSha(),
                    plan.limits(), plan.settings());
            CommandSpec command = adapter.buildCommand(context);
            SandboxResult result = sandbox.run(command, plan.limits(), isolation, identity);
            isolation.reap(identity); // kills what the tool left behind (daemons, double forks)
            Instant finished = Instant.now();
            if (result.timedOut()) {
                return new ScannerOutcome(id, ScannerExecutionStatus.TIMED_OUT, toolVersion, ruleset, null,
                        result.duration(), started, finished,
                        "timed out after " + plan.limits().timeout().toSeconds() + " s", List.of());
            }
            if (result.memoryExceeded()) {
                return new ScannerOutcome(id, ScannerExecutionStatus.FAILED, toolVersion, ruleset, null,
                        result.duration(), started, finished,
                        "memory limit exceeded (" + plan.limits().memoryBytes() / (1024 * 1024) + " MB)", List.of());
            }
            if (!adapter.isSuccessfulExit(result.exitCode())) {
                return new ScannerOutcome(id, ScannerExecutionStatus.FAILED, toolVersion, ruleset, result.exitCode(),
                        result.duration(), started, finished,
                        "exit code " + result.exitCode() + ": " + result.diagnostic(1500), List.of());
            }
            List<NormalizedFinding> findings = adapter.parse(command.reportFile(), context);
            ScannerExecutionStatus status = degraded == null ? ScannerExecutionStatus.SUCCEEDED : ScannerExecutionStatus.FAILED;
            return new ScannerOutcome(id, status, toolVersion, ruleset, result.exitCode(), result.duration(), started,
                    finished, degraded, findings);
        } catch (IOException | RuntimeException e) {
            LOG.log(Level.WARNING, "scanner " + id.key() + " failed on job " + jobId, e);
            Instant finished = Instant.now();
            return new ScannerOutcome(id, ScannerExecutionStatus.FAILED, toolVersion, ruleset, null,
                    Duration.between(started, finished), started, finished,
                    "could not run or read the tool: " + e.getMessage(), List.of());
        }
    }

    /** Tool version, asked once per worker process. */
    String toolVersion(ScannerAdapter adapter, Path jobDir) throws InterruptedException {
        return toolVersion(adapter, jobDir, null);
    }

    private String toolVersion(ScannerAdapter adapter, Path jobDir, ScannerIsolation.Identity identity)
            throws InterruptedException {
        String cached = toolVersions.get(adapter.id());
        if (cached != null) {
            return cached;
        }
        Path dir = jobDir.resolve("version-" + adapter.id().key());
        try {
            createPrivateDir(dir);
            isolation.handOver(dir, identity);
            SandboxResult r = sandbox.run(adapter.versionCommand(dir), VERSION_LIMITS, isolation, identity);
            if (r.completed() && r.exitCode() == 0) {
                String version = adapter.parseVersion(r.stdoutTail());
                if (version != null && !version.isBlank()) {
                    String v = version.length() > 120 ? version.substring(0, 120) : version;
                    toolVersions.put(adapter.id(), v);
                    return v;
                }
            }
        } catch (IOException | RuntimeException e) {
            LOG.log(Level.FINE, "version of " + adapter.id().key() + " unavailable", e);
        }
        return null;
    }

    private static void createPrivateDir(Path dir) throws IOException {
        Files.createDirectories(dir.getParent());
        try {
            Files.createDirectory(dir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        } catch (UnsupportedOperationException e) {
            Files.createDirectory(dir);
        }
    }
}
