package com.saytu.app.scan;

import com.saytu.app.scan.JobQueue.ClaimedJob;
import com.saytu.app.scanner.ScannerConfigService;
import com.saytu.app.scanner.ScannerConfigService.RuntimeConfig;
import com.saytu.app.source.ScanSourceService;
import com.saytu.app.source.ScanSourceService.CloneSource;
import com.saytu.core.domain.GitProviderType;
import com.saytu.core.domain.ScanStatus;
import com.saytu.core.domain.ScannerExecutionStatus;
import com.saytu.core.domain.ScannerId;
import com.saytu.core.scan.ScannerAdapter;
import com.saytu.scan.JobOutcome;
import com.saytu.scan.ScanJobRunner;
import com.saytu.scan.ScannerOutcome;
import com.saytu.scan.ScannerPlan;
import com.saytu.scan.git.CheckoutRequest;
import com.saytu.scan.git.GitCredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Consumes the job queue: plans pending runs, claims jobs up to {@code maxParallelJobs}, runs them
 * with {@link ScanJobRunner} while renewing their lease, and stores the results.
 */
public class ScanWorker {

    private static final Logger log = LoggerFactory.getLogger(ScanWorker.class);

    private final ScanProperties.Worker settings;
    private final String workerId;
    private final JobQueue queue;
    private final ScanPlanner planner;
    private final ResultWriter writer;
    private final ScanJobRunner runner;
    private final ScanSourceService sources;
    private final ScannerConfigService scannerConfigs;
    private final Map<ScannerId, ScannerAdapter> adapters;
    private final TrivyDbUpdater trivyDb;
    private final ExecutorService pool;
    private final ScheduledExecutorService leases;
    private final Semaphore slots;
    private final AtomicInteger running = new AtomicInteger();

    public ScanWorker(ScanProperties.Worker settings, String workerId, JobQueue queue, ScanPlanner planner,
                      ResultWriter writer, ScanJobRunner runner, ScanSourceService sources,
                      ScannerConfigService scannerConfigs, Map<ScannerId, ScannerAdapter> adapters, TrivyDbUpdater trivyDb) {
        this.settings = settings;
        this.workerId = workerId;
        this.queue = queue;
        this.planner = planner;
        this.writer = writer;
        this.runner = runner;
        this.sources = sources;
        this.scannerConfigs = scannerConfigs;
        this.adapters = Map.copyOf(adapters);
        this.trivyDb = trivyDb;
        this.slots = new Semaphore(settings.maxParallelJobs());
        AtomicInteger n = new AtomicInteger();
        this.pool = Executors.newFixedThreadPool(settings.maxParallelJobs(), r -> {
            Thread t = new Thread(r, "saytu-scan-" + n.incrementAndGet());
            t.setDaemon(true);
            return t;
        });
        this.leases = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "saytu-scan-lease");
            t.setDaemon(true);
            return t;
        });
    }

    /** Jobs this worker held before a restart go back to the queue. */
    public void start() {
        int requeued = queue.requeueAbandoned(workerId);
        log.info("Scan worker '{}' started: {} parallel job(s), {} job(s) re-queued", workerId,
                settings.maxParallelJobs(), requeued);
    }

    public void stop() {
        pool.shutdownNow();
        leases.shutdownNow();
    }

    @Scheduled(fixedDelayString = "${saytu.scan.worker.poll-interval:PT5S}", initialDelayString = "PT10S")
    public void poll() {
        try {
            queue.requeueAbandoned(null);
            if (running.get() == 0) {
                trivyDb.updateIfDue();
            }
            for (int i = 0; i < 10 && planner.planNext(); i++) {
                // plan the backlog, a few runs per tick
            }
            while (slots.tryAcquire()) {
                Optional<ClaimedJob> job = queue.claim(workerId, settings.lease());
                if (job.isEmpty()) {
                    slots.release();
                    break;
                }
                running.incrementAndGet();
                pool.submit(() -> {
                    try {
                        execute(job.get());
                    } finally {
                        running.decrementAndGet();
                        slots.release();
                    }
                });
            }
        } catch (RuntimeException e) {
            log.error("Scan worker poll failed", e);
        }
    }

    void execute(ClaimedJob job) {
        Duration lease = settings.lease();
        long period = Math.max(10, lease.toSeconds() / 3);
        ScheduledFuture<?> renewal = leases.scheduleAtFixedRate(() -> {
            try {
                if (!queue.renewLease(job.id(), workerId, lease)) {
                    log.warn("Lease of job {} lost", job.id());
                }
            } catch (RuntimeException e) {
                log.warn("Lease renewal of job {} failed: {}", job.id(), e.getMessage());
            }
        }, period, period, TimeUnit.SECONDS);
        try {
            if (queue.isCancelRequested(job.runId())) {
                writer.fail(job, ScanStatus.CANCELLED, "scan cancelled");
                return;
            }
            List<ScannerPlan> plans = new ArrayList<>();
            List<ScannerOutcome> notIntegrated = new ArrayList<>();
            for (RuntimeConfig c : scannerConfigs.runtimeConfigs()) {
                Optional<ScannerId> id = ScannerId.fromKey(c.scannerId());
                if (id.isEmpty()) {
                    continue;
                }
                ScannerAdapter adapter = adapters.get(id.get());
                if (adapter == null) {
                    if (c.enabled()) {
                        Instant now = Instant.now();
                        notIntegrated.add(new ScannerOutcome(id.get(), ScannerExecutionStatus.SKIPPED, null, null, null,
                                Duration.ZERO, now, now, "not integrated in this version", List.of()));
                    }
                    continue;
                }
                plans.add(new ScannerPlan(adapter, c.enabled(), c.limits(), c.settings()));
            }
            log.info("Job {}: {} @ {} (attempt {})", job.id(), job.repositoryId(), job.branch(), job.attempt());
            JobOutcome outcome;
            try (CloneSource source = sources.openCloneSource(job.repositoryId())) {
                GitCredentials credentials = source.token() == null || source.token().isBlank()
                        || source.providerType() == GitProviderType.LOCAL
                        ? null : GitCredentials.forProvider(source.providerType(), source.username(), source.token());
                CheckoutRequest request = new CheckoutRequest(source.cloneUrl(), job.branch(), credentials, true);
                outcome = runner.run(job.id(), request, plans, () -> queue.isCancelRequested(job.runId()));
            }
            if (!notIntegrated.isEmpty()) {
                List<ScannerOutcome> all = new ArrayList<>(outcome.scanners());
                all.addAll(notIntegrated);
                outcome = outcome.withScanners(all);
            }
            ScanStatus status = outcome.status();
            boolean cancelled = outcome.scanners().stream().anyMatch(s -> "job cancelled".equals(s.errorMessage()));
            if (cancelled) {
                status = ScanStatus.CANCELLED;
            }
            ResultWriter.Summary summary = writer.write(job, outcome, status);
            log.info("Job {} finished: {} ({} findings, {} new, {} resolved)", job.id(), status, summary.findings(),
                    summary.newFindings(), summary.resolved());
        } catch (InterruptedException e) {
            // worker shutting down: the lease expires and the job is retried
            Thread.currentThread().interrupt();
            log.warn("Job {} interrupted by shutdown", job.id());
        } catch (RuntimeException e) {
            log.error("Job {} failed", job.id(), e);
            try {
                writer.fail(job, ScanStatus.FAILED, "internal error: " + e.getMessage());
            } catch (RuntimeException e2) {
                log.error("Could not record the failure of job {}", job.id(), e2);
            }
        } finally {
            renewal.cancel(false);
        }
    }
}
