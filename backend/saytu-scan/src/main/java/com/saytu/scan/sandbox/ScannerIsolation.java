package com.saytu.scan.sandbox;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Runs the scanners of each job under a dedicated, unprivileged Linux account.
 * <p>
 * Requires the worker to run as root with only the capabilities SETUID, SETGID, CHOWN, DAC_OVERRIDE, FOWNER
 * and KILL (Docker Compose {@code worker} service). Each running job leases a uid/gid from a pool
 * ({@code baseId} … {@code baseId + slots - 1}); its scanners are started through util-linux {@code setpriv}
 * with that identity, no supplementary group, no capability (bounding set emptied) and {@code no_new_privs}.
 * Consequences:
 * <ul>
 *   <li>a scanner (or a parser exploit inside it) cannot read the worker's memory or environment
 *       ({@code /proc/<worker>/environ} holds the database password and the master key), the job's
 *       Git credentials, or the files of another job (job directory {@code 0750 root:<job gid>});</li>
 *   <li>the checked-out sources belong to root: a scanner cannot alter them for the next scanner;</li>
 *   <li>every process left by a scanner under the job uid is killed after each run, even if it escaped
 *       the process tree (double fork, {@code setsid});</li>
 *   <li>the worker entrypoint blocks all network traffic of the pool uids ({@code iptables -m owner}),
 *       when the kernel allows it ({@link #networkStatus()}).</li>
 * </ul>
 * Git (checkout, {@code ls-remote}) and the vulnerability database download are trusted and run as the
 * worker itself.
 */
public final class ScannerIsolation {

    public enum Mode {
        /** isolate when possible (worker running as root with setpriv), else run as the worker and warn */
        AUTO,
        /** refuse to start the worker when isolation is not possible */
        REQUIRED,
        OFF
    }

    /** Identity of the scanners of one job. */
    public record Identity(int uid, int gid) {
        public Identity {
            if (uid <= 0 || gid <= 0) {
                throw new IllegalArgumentException("scanner identity must not be root");
            }
        }
    }

    private static final Logger LOG = Logger.getLogger(ScannerIsolation.class.getName());
    private static final List<Path> SETPRIV_LOCATIONS = List.of(Path.of("/usr/bin/setpriv"), Path.of("/bin/setpriv"));
    /** Written by the worker entrypoint: "blocked" or "open: reason". */
    public static final Path NETWORK_STATUS_FILE = Path.of("/tmp/saytu-scanner-network");

    private final Path setpriv;
    private final int baseId;
    private final int slots;
    private final Set<Integer> leased = ConcurrentHashMap.newKeySet();
    private final String disabledReason;

    private ScannerIsolation(Path setpriv, int baseId, int slots, String disabledReason) {
        this.setpriv = setpriv;
        this.baseId = baseId;
        this.slots = slots;
        this.disabledReason = disabledReason;
    }

    /** No isolation: scanners run as the worker (developer machine, tests). */
    public static ScannerIsolation disabled(String reason) {
        return new ScannerIsolation(null, 0, 0, Objects.requireNonNull(reason));
    }

    /**
     * @param baseId first uid / gid of the pool (default 20000, must match the worker entrypoint's firewall rule)
     * @param slots  size of the pool: at least the number of jobs run in parallel
     */
    public static ScannerIsolation detect(Mode mode, int baseId, int slots) {
        if (baseId < 1000 || slots < 1 || slots > 1000) {
            throw new IllegalArgumentException("invalid scanner uid pool " + baseId + " + " + slots);
        }
        if (mode == Mode.OFF) {
            return disabled("disabled by configuration (saytu.scan.isolation.mode=OFF)");
        }
        Path found = SETPRIV_LOCATIONS.stream().filter(Files::isExecutable).findFirst().orElse(null);
        String reason = null;
        if (found == null) {
            reason = "setpriv (util-linux) not found";
        } else if (effectiveUid() != 0) {
            reason = "the worker does not run as root (uid " + effectiveUid() + "): scanners share the worker account";
        }
        if (reason != null) {
            if (mode == Mode.REQUIRED) {
                throw new IllegalStateException("scanner isolation required but unavailable: " + reason);
            }
            LOG.warning("scanner isolation unavailable: " + reason);
            return disabled(reason);
        }
        return new ScannerIsolation(found, baseId, slots, null);
    }

    public boolean enabled() {
        return setpriv != null;
    }

    /** Why the scanners are not isolated, or empty. */
    public Optional<String> disabledReason() {
        return Optional.ofNullable(disabledReason);
    }

    /** "blocked", "open: …" (entrypoint could not install the firewall rule) or "not applicable". */
    public String networkStatus() {
        if (!enabled()) {
            return "open: scanners are not isolated";
        }
        try {
            String s = Files.readString(NETWORK_STATUS_FILE, StandardCharsets.UTF_8).strip();
            if (s.isEmpty()) {
                return "open: unknown";
            }
            return s.length() > 300 ? s.substring(0, 300) : s;
        } catch (IOException e) {
            return "open: the worker entrypoint did not set up the firewall rule";
        }
    }

    /** Leases an identity for one job; {@code null} when disabled. Release it with {@link #release}. */
    public Identity acquire() {
        if (!enabled()) {
            return null;
        }
        for (int attempt = 0; attempt < 600; attempt++) {
            for (int i = 0; i < slots; i++) {
                int id = baseId + i;
                if (leased.add(id)) {
                    Identity identity = new Identity(id, id);
                    killAll(identity); // leftovers of a crashed worker
                    return identity;
                }
            }
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted while waiting for a scanner identity", e);
            }
        }
        throw new IllegalStateException("no free scanner identity (pool of " + slots + ")");
    }

    public void release(Identity identity) {
        if (identity != null) {
            killAll(identity);
            leased.remove(identity.uid());
        }
    }

    /** Kills every process still running under the identity; no-op when null. */
    public void reap(Identity identity) {
        if (identity != null) {
            killAll(identity);
        }
    }

    /** Job directory: owned by root, traversable by the job's group only ({@code 0750 root:<gid>}). */
    public void shareWithJob(Path dir, Identity identity) throws IOException {
        if (identity == null) {
            return;
        }
        Files.setAttribute(dir, "unix:gid", identity.gid());
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwxr-x---"));
    }

    /** Scanner working directory: owned by the job identity ({@code 0700}). */
    public void handOver(Path dir, Identity identity) throws IOException {
        if (identity == null) {
            return;
        }
        Files.setAttribute(dir, "unix:uid", identity.uid());
        Files.setAttribute(dir, "unix:gid", identity.gid());
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
    }

    /** Parent of the job directories: listing forbidden, traversal allowed ({@code 0711}). */
    public void prepareWorkRoot(Path workRoot) throws IOException {
        if (enabled()) {
            Files.createDirectories(workRoot);
            Files.setPosixFilePermissions(workRoot, PosixFilePermissions.fromString("rwx--x--x"));
        }
    }

    /**
     * Makes a tree of public data (Trivy vulnerability database) readable by the scanner accounts:
     * directories {@code 0755}, files {@code 0644} (executables {@code 0755}); symbolic links are not followed.
     * Best effort: failures are logged.
     */
    public static void makeReadable(Path root) {
        if (!Files.isDirectory(root, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        try (java.util.stream.Stream<Path> walk = Files.walk(root)) {
            for (Path p : walk.toList()) {
                if (Files.isSymbolicLink(p)) {
                    continue;
                }
                boolean dir = Files.isDirectory(p, java.nio.file.LinkOption.NOFOLLOW_LINKS);
                boolean exec = !dir && Files.getPosixFilePermissions(p, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                        .contains(java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE);
                Files.setPosixFilePermissions(p, PosixFilePermissions.fromString(dir || exec ? "rwxr-xr-x" : "rw-r--r--"));
            }
        } catch (IOException | RuntimeException e) {
            LOG.warning("could not make " + root + " readable by the scanner accounts: " + e.getMessage());
        }
    }

    /** setpriv prefix that drops to the identity, without group, capability or privilege gain. */
    List<String> prefix(Identity identity) {
        if (identity == null || setpriv == null) {
            return List.of();
        }
        return List.of(setpriv.toString(), "--reuid=" + identity.uid(), "--regid=" + identity.gid(), "--clear-groups",
                "--inh-caps=-all", "--bounding-set=-all", "--no-new-privs", "--");
    }

    /** Kills every process of the identity (including those that left the scanner's process tree). */
    void killAll(Identity identity) {
        for (int round = 0; round < 3; round++) {
            List<ProcessHandle> found = ProcessHandle.allProcesses()
                    .filter(p -> uidOf(p.pid()) == identity.uid())
                    .toList();
            if (found.isEmpty()) {
                return;
            }
            found.forEach(ProcessHandle::destroyForcibly);
            found.forEach(p -> {
                try {
                    p.onExit().get(2, TimeUnit.SECONDS);
                } catch (Exception e) {
                    // retried in the next round
                }
            });
        }
    }

    /** Real uid of a process from /proc, -1 when unknown. */
    static int uidOf(long pid) {
        return statusUid(Path.of("/proc", Long.toString(pid), "status"), 0);
    }

    static int effectiveUid() {
        return statusUid(Path.of("/proc/self/status"), 1);
    }

    private static int statusUid(Path status, int field) {
        try {
            for (String line : Files.readAllLines(status, StandardCharsets.ISO_8859_1)) {
                if (line.startsWith("Uid:")) {
                    return Integer.parseInt(line.substring(4).trim().split("\\s+")[field]);
                }
            }
        } catch (IOException | RuntimeException e) {
            // process gone, or not Linux
        }
        return -1;
    }
}
