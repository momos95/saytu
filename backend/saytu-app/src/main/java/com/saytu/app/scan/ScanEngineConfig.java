package com.saytu.app.scan;

import com.saytu.app.git.GitProperties;
import com.saytu.app.scanner.ScannerConfigService;
import com.saytu.app.source.ScanSourceService;
import com.saytu.core.domain.ScannerId;
import com.saytu.core.scan.ResourceLimits;
import com.saytu.core.scan.ScannerAdapter;
import com.saytu.scan.ScanJobRunner;
import com.saytu.scan.adapter.GitleaksAdapter;
import com.saytu.scan.adapter.OpengrepAdapter;
import com.saytu.scan.adapter.TrivyAdapter;
import com.saytu.scan.git.GitCheckout;
import com.saytu.scan.sandbox.ProcessSandbox;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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

    @Bean
    ScanJobRunner scanJobRunner(ProcessSandbox sandbox, GitCheckout checkout, ScanProperties properties) {
        Path workDir = properties.worker().workDir();
        try {
            Files.createDirectories(workDir);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot create the scan work directory " + workDir, e);
        }
        return new ScanJobRunner(sandbox, checkout, workDir);
    }

    /** Integrated scanners (PMD, Checkstyle and Dependency-Check arrive in phase 5). */
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
        return new ScannerAdapters(adapters);
    }

    @Bean
    ResultWriter resultWriter(NamedParameterJdbcTemplate jdbc, JobQueue queue) {
        return new ResultWriter(jdbc, queue);
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
