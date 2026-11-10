package com.saytu.scan.sandbox;

import com.saytu.core.scan.CommandSpec;
import com.saytu.scan.TestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Real privilege drop with setpriv: runs only when the tests run as root (as the worker does). */
class ScannerIsolationTest {

    private Path root;
    private ScannerIsolation isolation;
    private ScannerIsolation.Identity identity;

    @BeforeEach
    void setUp() throws Exception {
        assumeTrue(ScannerIsolation.effectiveUid() == 0, "needs root, like the worker container");
        root = TestSupport.tempDir("isolation");
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx--x--x"));
        isolation = ScannerIsolation.detect(ScannerIsolation.Mode.REQUIRED, 21000, 2);
        identity = isolation.acquire();
    }

    @AfterEach
    void tearDown() {
        if (isolation != null) {
            isolation.release(identity);
        }
        if (root != null) {
            TestSupport.delete(root);
        }
    }

    private SandboxResult sh(Path dir, String script) throws Exception {
        CommandSpec spec = new CommandSpec(List.of("/bin/sh", "-c", script), Map.of("PATH", "/usr/bin:/bin"), dir,
                dir.resolve("report"));
        return ProcessSandbox.detect(false).run(spec, TestSupport.SMALL, isolation, identity);
    }

    @Test
    void scannerRunsUnprivilegedAndCannotReadTheWorkerSecrets() throws Exception {
        assertTrue(isolation.enabled());
        Path job = root.resolve("job");
        Files.createDirectory(job);
        isolation.shareWithJob(job, identity);
        Path sources = job.resolve("src");
        Files.createDirectory(sources);
        Files.writeString(sources.resolve("App.java"), "class App {}");
        Path secretDir = job.resolve("refs");
        Files.createDirectory(secretDir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Files.writeString(secretDir.resolve("token"), "glpat-secret");
        Path work = job.resolve("scanner-test");
        Files.createDirectory(work);
        isolation.handOver(work, identity);

        SandboxResult r = sh(work, "id -u; id -G; grep CapEff /proc/self/status; grep NoNewPrivs /proc/self/status; "
                + "cat " + sources.resolve("App.java") + "; "
                + "echo report > report && echo WROTE; "
                + "cat " + secretDir.resolve("token") + " 2>/dev/null || echo NO_TOKEN; "
                + "cat /proc/" + ProcessHandle.current().pid() + "/environ 2>/dev/null | head -c 1 | wc -c; "
                + "echo x > " + sources.resolve("App.java") + " 2>/dev/null || echo SOURCES_READ_ONLY; "
                + "ls " + root + " 2>/dev/null || echo NO_LISTING");

        String out = r.stdoutTail();
        assertEquals(0, r.exitCode(), out + r.stderrTail());
        List<String> lines = out.lines().toList();
        assertEquals("21000", lines.get(0));
        assertEquals("21000", lines.get(1), "no supplementary group");
        assertTrue(lines.get(2).endsWith("0000000000000000"), "no capability: " + lines.get(2));
        assertTrue(lines.get(3).endsWith("1"), "no_new_privs: " + lines.get(3));
        assertTrue(out.contains("class App {}"), "sources are readable");
        assertTrue(out.contains("WROTE"), "its own directory is writable");
        assertTrue(out.contains("NO_TOKEN"), "private files of the job are not readable");
        assertTrue(lines.contains("0"), "worker environment not readable: " + out);
        assertTrue(out.contains("SOURCES_READ_ONLY"), "sources cannot be altered");
        assertTrue(out.contains("NO_LISTING"), "other jobs cannot be listed");
    }

    @Test
    void processesLeftBehindAreKilled() throws Exception {
        Path work = root.resolve("scanner-daemon");
        Files.createDirectory(work);
        isolation.handOver(work, identity);
        // detached grandchild that outlives the tool and leaves its process tree
        SandboxResult r = sh(work, "setsid sh -c 'sleep 300' </dev/null >/dev/null 2>&1 & echo started");
        assertEquals(0, r.exitCode());
        Thread.sleep(300);
        assertTrue(hasProcessOf(identity.uid()), "daemon still alive before reaping");
        isolation.reap(identity);
        assertFalse(hasProcessOf(identity.uid()), "daemon killed");
    }

    @Test
    void identitiesAreNotSharedBetweenJobs() {
        ScannerIsolation.Identity other = isolation.acquire();
        try {
            assertFalse(other.equals(identity));
            assertEquals(List.of("/usr/bin/setpriv", "--reuid=21001", "--regid=21001", "--clear-groups",
                    "--inh-caps=-all", "--bounding-set=-all", "--no-new-privs", "--").get(1), isolation.prefix(other).get(1));
        } finally {
            isolation.release(other);
        }
    }

    @Test
    void publicDatabaseIsMadeReadableWithoutFollowingLinks() throws Exception {
        Path db = root.resolve("trivy/db");
        Files.createDirectories(db, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Files.setPosixFilePermissions(root.resolve("trivy"), PosixFilePermissions.fromString("rwx------"));
        Files.writeString(db.resolve("trivy.db"), "advisories");
        Files.setPosixFilePermissions(db.resolve("trivy.db"), PosixFilePermissions.fromString("rw-------"));
        Path outside = root.resolve("private");
        Files.writeString(outside, "secret");
        Files.setPosixFilePermissions(outside, PosixFilePermissions.fromString("rw-------"));
        Files.createSymbolicLink(db.resolve("link"), outside);

        ScannerIsolation.makeReadable(root.resolve("trivy"));

        assertEquals("rwxr-xr-x", PosixFilePermissions.toString(Files.getPosixFilePermissions(db)));
        assertEquals("rw-r--r--", PosixFilePermissions.toString(Files.getPosixFilePermissions(db.resolve("trivy.db"))));
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(outside)), "link not followed");
        Path work = root.resolve("scanner-db");
        Files.createDirectory(work);
        isolation.handOver(work, identity);
        assertTrue(sh(work, "cat " + db.resolve("trivy.db")).stdoutTail().contains("advisories"));
    }

    private static boolean hasProcessOf(int uid) {
        return ProcessHandle.allProcesses().anyMatch(p -> ScannerIsolation.uidOf(p.pid()) == uid);
    }
}
