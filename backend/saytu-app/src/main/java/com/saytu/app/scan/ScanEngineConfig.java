package com.saytu.app.scan;

import com.saytu.app.git.GitProperties;
import com.saytu.app.scanner.ScannerConfigService;
import com.saytu.app.source.ScanSourceService;
import com.saytu.core.domain.ScannerId;
import com.saytu.core.scan.ResourceLimits;
import com.saytu.core.scan.ScannerAdapter;
import com.saytu.scan.ScanJobRunner;
import com.saytu.scan.adapter.CheckstyleAdapter;
import com.saytu.scan.adapter.CppcheckAdapter;
import com.saytu.scan.adapter.EslintAdapter;
import com.saytu.scan.adapter.GitleaksAdapter;
import com.saytu.scan.adapter.OpengrepAdapter;
import com.saytu.scan.adapter.PhpcsAdapter;
import com.saytu.scan.adapter.PmdAdapter;
import com.saytu.scan.adapter.SqlfluffAdapter;
import com.saytu.scan.adapter.TrivyAdapter;
import com.saytu.scan.git.GitCheckout;
import com.saytu.scan.sandbox.ProcessSandbox;
import com.saytu.scan.sandbox.ScannerIsolation;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Scan worker wiring, active only with {@code saytu.scan.worker.enabled=true} (the {@code worker}
 * service of Docker Compose). The API process never runs scanners.
 */
@Configuration
@EnableScheduling
@ConditionalOnProperty(prefix = "saytu.scan.worker", name = "enabled", havingValue = "true")
public class ScanEngineConfig {

    private static final List<String> PROXY_VARIABLES = List.of("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
            "NO_PROXY", "no_proxy");

    @Bean
    ProcessSandbox processSandbox() {
        return ProcessSandbox.detect(true);
    }

    @Bean
    GitCheckout gitCheckout(ProcessSandbox sandbox, ScanProperties properties, GitProperties git) {
        ScanProperties.Checkout c = properties.checkout();
        ResourceLimits limits = new ResourceLimits(c.timeout(), c.timeout().toSeconds() * 2,
                1024L * 1024 * 1024, (long) c.maxMb() * 1024 * 1024 * 2, 4096);
        Map<String, String> proxy = new LinkedHashMap<>();
        for (String name : PROXY_VARIABLES) {
            String value = System.getenv(name);
            if (value != null && !value.isBlank()) {
                proxy.put(name, value);
            }
        }
        return new GitCheckout(sandbox, new GitCheckout.Settings(properties.tools().git(), limits,
                (long) c.maxMb() * 1024 * 1024, c.maxFiles(), git.caBundle(), git.allowPlainHttp(), git.localReposRoot(),
                proxy));
    }

    /**
     * Scanners of each job under a dedicated account (worker running as root with reduced capabilities);
     * mode AUTO falls back to the worker account with a warning, REQUIRED refuses to start.
     */
    @Bean
    ScannerIsolation scannerIsolation(ScanProperties properties,
                                      @Value("${saytu.scan.isolation.mode:AUTO}") String mode,
                                      @Value("${saytu.scan.isolation.base-id:20000}") int baseId) {
        ScannerIsolation isolation = ScannerIsolation.detect(ScannerIsolation.Mode.valueOf(mode.strip().toUpperCase(java.util.Locale.ROOT)),
                baseId, Math.max(1, properties.worker().maxParallelJobs()));
        if (isolation.enabled()) {
            // the Trivy database is public data: readable by the scanner accounts, writable by the worker only
            ScannerIsolation.makeReadable(properties.tools().trivyCacheDir());
        }
        return isolation;
    }

    @Bean
    ScanJobRunner scanJobRunner(ProcessSandbox sandbox, GitCheckout checkout, ScanProperties properties,
                                ScannerIsolation isolation) {
        Path workDir = properties.worker().workDir();
        try {
            Files.createDirectories(workDir);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot create the scan work directory " + workDir, e);
        }
        return new ScanJobRunner(sandbox, checkout, workDir, isolation);
    }

    /** Integrated scanners (OWASP Dependency-Check is not integrated: see docs/licenses.md). */
    public record ScannerAdapters(Map<ScannerId, ScannerAdapter> byId) {
        public ScannerAdapters {
            byId = Map.copyOf(byId);
        }
    }

    @Bean
    ScannerAdapters scannerAdapters(ScanProperties properties) {
        ScanProperties.Tools t = properties.tools();
        Map<ScannerId, ScannerAdapter> adapters = new EnumMap<>(ScannerId.class);
        adapters.put(ScannerId.OPENGREP, new OpengrepAdapter(t.opengrep(), t.opengrepRules(), t.opengrepRuntime()));
        adapters.put(ScannerId.TRIVY, new TrivyAdapter(t.trivy(), t.trivyCacheDir()));
        adapters.put(ScannerId.GITLEAKS, new GitleaksAdapter(t.gitleaks(), t.gitleaksConfig()));
        // quality tools, each run only when its language is present
        Path home = t.home();
        adapters.put(ScannerId.CHECKSTYLE, new CheckstyleAdapter(t.java(), home.resolve("checkstyle"), t.checkstyleConfig()));
        adapters.put(ScannerId.PMD, new PmdAdapter(t.java(), home.resolve("pmd")));
        adapters.put(ScannerId.ESLINT, new EslintAdapter(home.resolve("node/bin/node"), home.resolve("eslint")));
        adapters.put(ScannerId.PHPCS, new PhpcsAdapter(Path.of("/usr/bin/php"), home.resolve("phpcs/bin/phpcs")));
        adapters.put(ScannerId.CPPCHECK, new CppcheckAdapter(Path.of("/usr/bin/cppcheck")));
        adapters.put(ScannerId.SQLFLUFF, new SqlfluffAdapter(home.resolve("sqlfluff/bin/sqlfluff")));
        return new ScannerAdapters(adapters);
    }

    @Bean
    ResultWriter resultWriter(NamedParameterJdbcTemplate jdbc, JobQueue queue, ScoreService scores, WebhookService webhooks) {
        return new ResultWriter(jdbc, queue, scores, webhooks);
    }

    @Bean
    ScanPlanner scanPlanner(NamedParameterJdbcTemplate jdbc, TransactionTemplate tx, ScanSourceService sources,
                            JobQueue queue) {
        return new ScanPlanner(jdbc, tx, sources, queue);
    }

    @Bean
    TrivyDbUpdater trivyDbUpdater(ProcessSandbox sandbox, ScanProperties properties, Clock clock) {
        return new TrivyDbUpdater(sandbox, properties.tools(), properties.worker().workDir(), clock);
    }

    /** Reports the scanner isolation of this worker (shown on the "Scanners & branches" page). */
    @Bean
    ApplicationRunner scannerIsolationReport(WorkerStatusService status, ScannerIsolation isolation, ScanProperties properties) {
        return args -> {
            String id = properties.worker().id() == null || properties.worker().id().isBlank() ? "worker" : properties.worker().id();
            org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(ScanEngineConfig.class);
            log.info("scanner isolation: dedicated account {}, network {}",
                    isolation.enabled() ? "yes" : "no (" + isolation.disabledReason().orElse("") + ")", isolation.networkStatus());
            try {
                status.publish(id, isolation);
            } catch (RuntimeException e) {
                log.warn("could not record the scanner isolation status: {}", e.getMessage());
            }
        };
    }

    @Bean(initMethod = "start", destroyMethod = "stop")
    ScanWorker scanWorker(ScanProperties properties, JobQueue queue, ScanPlanner planner, ResultWriter writer,
                          ScanJobRunner runner, ScanSourceService sources, ScannerConfigService configs,
                          ScannerAdapters scannerAdapters, TrivyDbUpdater trivyDb) {
        String id = properties.worker().id();
        if (id == null || id.isBlank()) {
            try {
                id = InetAddress.getLocalHost().getHostName();
            } catch (UnknownHostException e) {
                id = "worker";
            }
        }
        return new ScanWorker(properties.worker(), id, queue, planner, writer, runner, sources, configs,
                scannerAdapters.byId(), trivyDb);
    }
}
