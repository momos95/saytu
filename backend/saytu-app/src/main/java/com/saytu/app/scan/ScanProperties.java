package com.saytu.app.scan;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

/**
 * Scan engine settings (prefix {@code saytu.scan}). The API and the worker share the same image; only
 * the worker sets {@code worker.enabled=true}.
 *
 * @param worker  job execution
 * @param tools   scanner binaries and their data (rules, databases)
 * @param checkout clone limits
 */
@ConfigurationProperties(prefix = "saytu.scan")
public record ScanProperties(Worker worker, Tools tools, Checkout checkout) {

    public ScanProperties {
        worker = worker == null ? new Worker(false, null, 0, null, null, null) : worker;
        tools = tools == null ? new Tools(null, null, null, null, null, null, null, null, null, false, null, null) : tools;
        checkout = checkout == null ? new Checkout(null, 0, 0) : checkout;
    }

    /**
     * @param enabled         run the planner and the job queue consumer in this process
     * @param id              worker name written in {@code scan_job.locked_by} (defaults to the host name)
     * @param maxParallelJobs jobs executed at the same time by this worker
     * @param pollInterval    queue polling period
     * @param lease           lease of a running job, renewed every third of it; an expired lease re-queues the job
     * @param workDir         private directory for checkouts and reports (wiped after each job)
     */
    public record Worker(boolean enabled, String id, int maxParallelJobs, Duration pollInterval, Duration lease,
                         Path workDir) {
        public Worker {
            maxParallelJobs = maxParallelJobs <= 0 ? 2 : Math.min(maxParallelJobs, 32);
            pollInterval = pollInterval == null ? Duration.ofSeconds(5) : pollInterval;
            lease = lease == null || lease.compareTo(Duration.ofMinutes(1)) < 0 ? Duration.ofMinutes(5) : lease;
            workDir = workDir == null || workDir.toString().isBlank() ? Path.of("/var/lib/saytu/work") : workDir;
        }
    }

    /**
     * @param git                 git executable
     * @param opengrep            opengrep executable
     * @param opengrepRuntime     cache where the self-extracting opengrep binary was unpacked at image build
     * @param opengrepRules       rule pack directories (bundled packs, then the administrator's packs)
     * @param trivy               trivy executable
     * @param trivyCacheDir       Trivy cache holding the vulnerability database
     * @param gitleaks            gitleaks executable
     * @param gitleaksConfig      gitleaks configuration shipped with SAYTU
     * @param trivyDbRepository   OCI repository of the vulnerability database ({@code null} = Trivy default)
     * @param trivyDbAutoUpdate   download / refresh the database from the worker (disable on air-gapped sites)
     * @param trivyDbUpdateInterval refresh period
     * @param home                directory of the other tools: checkstyle/ and pmd/ (jars), eslint/
     *                            (config + node_modules), node/bin/node, phpcs/bin/phpcs, sqlfluff/bin/sqlfluff;
     *                            php and cppcheck come from the system ({@code /usr/bin})
     */
    public record Tools(Path git, Path opengrep, Path opengrepRuntime, List<Path> opengrepRules, Path trivy,
                        Path trivyCacheDir, Path gitleaks, Path gitleaksConfig, String trivyDbRepository,
                        boolean trivyDbAutoUpdate, Duration trivyDbUpdateInterval, Path home) {
        public Tools {
            home = orDefault(home, "/opt/saytu/tools");
            git = orDefault(git, "/usr/bin/git");
            opengrep = orDefault(opengrep, "/opt/saytu/tools/opengrep");
            opengrepRuntime = blankToNull(opengrepRuntime);
            opengrepRules = opengrepRules == null || opengrepRules.isEmpty()
                    ? List.of(Path.of("/opt/saytu/rules/opengrep"), Path.of("/etc/saytu/rules/opengrep"))
                    : List.copyOf(opengrepRules);
            trivy = orDefault(trivy, "/opt/saytu/tools/trivy");
            trivyCacheDir = orDefault(trivyCacheDir, "/var/lib/saytu/trivy");
            gitleaks = orDefault(gitleaks, "/opt/saytu/tools/gitleaks");
            gitleaksConfig = orDefault(gitleaksConfig, "/opt/saytu/rules/gitleaks/gitleaks.toml");
            trivyDbRepository = trivyDbRepository == null || trivyDbRepository.isBlank() ? null : trivyDbRepository.strip();
            trivyDbUpdateInterval = trivyDbUpdateInterval == null ? Duration.ofHours(12) : trivyDbUpdateInterval;
        }

        /** Java launcher for Checkstyle and PMD: the worker's own runtime. */
        public Path java() {
            return Path.of(System.getProperty("java.home"), "bin", "java");
        }

        public Path checkstyleConfig() {
            return Path.of("/opt/saytu/rules/checkstyle/saytu-checks.xml");
        }
    }

    /**
     * @param timeout  clone timeout
     * @param maxMb    quota on the checked-out tree
     * @param maxFiles quota on the number of files
     */
    public record Checkout(Duration timeout, int maxMb, int maxFiles) {
        public Checkout {
            timeout = timeout == null ? Duration.ofMinutes(10) : timeout;
            maxMb = maxMb <= 0 ? 2048 : maxMb;
            maxFiles = maxFiles <= 0 ? 500_000 : maxFiles;
        }
    }

    private static Path orDefault(Path p, String def) {
        return p == null || p.toString().isBlank() ? Path.of(def) : p;
    }

    private static Path blankToNull(Path p) {
        return p == null || p.toString().isBlank() ? null : p;
    }
}
