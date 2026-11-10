package com.saytu.scan.git;

import com.saytu.core.domain.GitProviderType;
import com.saytu.core.scan.ResourceLimits;
import com.saytu.core.security.SensitiveValue;
import com.saytu.scan.TestSupport;
import com.saytu.scan.sandbox.ProcessSandbox;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class GitCheckoutTest {

    private Path tmp;
    private Path root;
    private Path jobDir;

    @BeforeEach
    void setUp() throws Exception {
        assumeTrue(Files.isExecutable(TestSupport.GIT), "git not installed");
        tmp = TestSupport.tempDir("checkout");
        root = tmp.resolve("repos");
        jobDir = tmp.resolve("job");
        Files.createDirectories(root);
        Files.createDirectories(jobDir);
    }

    @AfterEach
    void tearDown() {
        if (tmp != null) {
            TestSupport.delete(tmp);
        }
    }

    private GitCheckout checkout(long maxBytes, boolean allowHttp) {
        return new GitCheckout(ProcessSandbox.detect(false), new GitCheckout.Settings(TestSupport.GIT, TestSupport.SMALL,
                maxBytes, 100_000, null, allowHttp, root, Map.of()));
    }

    private GitCheckout checkout() {
        return checkout(50L * 1024 * 1024, false);
    }

    @Test
    void clonesTheRequestedBranchWithoutGitMetadataNorSymlinks() throws Exception {
        Path repo = TestSupport.repo(root, "app", Map.of("README.md", "hello\n"));
        TestSupport.git(repo, "checkout", "-q", "-b", "develop");
        TestSupport.write(repo, Map.of("src/App.java", "class App {}\n"));
        Files.createSymbolicLink(repo.resolve("passwd"), Path.of("/etc/passwd"));
        TestSupport.write(repo, Map.of(".gitmodules", "[submodule \"x\"]\n\tpath = x\n\turl = https://example.invalid/x.git\n"));
        TestSupport.git(repo, "add", "-A");
        TestSupport.git(repo, "commit", "-q", "-m", "develop");
        String expected = TestSupport.git(repo, "rev-parse", "develop");
        TestSupport.git(repo, "checkout", "-q", "main");

        CheckoutResult r = checkout().checkout(new CheckoutRequest(repo.toUri(), "develop", null, true), jobDir);

        assertEquals(expected, r.commitSha());
        assertTrue(Files.isRegularFile(r.sourceDir().resolve("src/App.java")));
        assertFalse(Files.exists(r.sourceDir().resolve(".git")), ".git must be removed");
        Path link = r.sourceDir().resolve("passwd");
        assertFalse(Files.isSymbolicLink(link), "symlinks are checked out as plain files");
        assertEquals("/etc/passwd", Files.readString(link));
        assertFalse(Files.exists(r.sourceDir().resolve("x")), "submodules are not fetched");
        assertEquals(4, r.fileCount());
    }

    @Test
    void listsBranchesAndTagsWithAnnotatedTagsPeeled() throws Exception {
        Path repo = TestSupport.repo(root, "flow", Map.of("README.md", "v1\n"));
        String v1 = TestSupport.git(repo, "rev-parse", "HEAD");
        TestSupport.git(repo, "-c", "user.name=t", "-c", "user.email=t@example.org", "tag", "-a", "v1.0.0", "-m", "release 1.0.0");
        TestSupport.git(repo, "tag", "light-1", v1);
        TestSupport.git(repo, "checkout", "-q", "-b", "develop");
        TestSupport.write(repo, Map.of("work.txt", "wip\n"));
        TestSupport.git(repo, "add", "-A");
        TestSupport.git(repo, "commit", "-q", "-m", "work");
        String dev = TestSupport.git(repo, "rev-parse", "HEAD");
        TestSupport.git(repo, "checkout", "-q", "main");

        RemoteRefs refs = checkout().listRefs(new CheckoutRequest(repo.toUri(), "main", null, true), jobDir);

        assertEquals(Map.of("main", v1, "develop", dev), refs.branches());
        assertEquals(v1, refs.tags().get("v1.0.0"), "annotated tag resolved to its commit");
        assertEquals(v1, refs.tags().get("light-1"));
        com.saytu.core.workflow.WorkflowCheck.Report report = com.saytu.core.workflow.WorkflowCheck.evaluate(refs.branches(), refs.tags());
        assertEquals(com.saytu.core.workflow.WorkflowCheck.Status.PASS, report.status());
    }

    @Test
    void lsRemoteOutputIsParsedDefensively() {
        String a = "a".repeat(40);
        String b = "b".repeat(40);
        RemoteRefs r = RemoteRefs.parse(a + "\trefs/heads/main\n" + b + "\trefs/tags/v2\n" + a + "\trefs/tags/v2^{}\n"
                + "garbage line\n" + a + "\trefs/pull/1/head\n" + "zz" + "\trefs/heads/x\n");
        assertEquals(Map.of("main", a), r.branches());
        assertEquals(Map.of("v2", a), r.tags());
    }

    @Test
    void unknownBranchIsReported() throws Exception {
        Path repo = TestSupport.repo(root, "app", Map.of("a.txt", "a"));
        CheckoutException e = assertThrows(CheckoutException.class,
                () -> checkout().checkout(new CheckoutRequest(repo.toUri(), "release/9", null, true), jobDir));
        assertEquals(CheckoutException.Kind.BRANCH_NOT_FOUND, e.kind());
    }

    @Test
    void quotaIsEnforced() throws Exception {
        Path repo = TestSupport.repo(root, "big", Map.of("big.txt", "x".repeat(3 * 1024 * 1024)));
        CheckoutException e = assertThrows(CheckoutException.class,
                () -> checkout(1024 * 1024, false).checkout(new CheckoutRequest(repo.toUri(), "main", null, true), jobDir));
        assertEquals(CheckoutException.Kind.TOO_LARGE, e.kind());
    }

    @Test
    void urlsOutsideThePolicyAreRefused() throws Exception {
        Path outside = TestSupport.repo(tmp, "outside", Map.of("a.txt", "a"));
        for (URI uri : new URI[]{outside.toUri(), URI.create("file:///etc"), URI.create("ssh://git@example.org/a.git"),
                URI.create("https://user:pw@example.org/a.git"), URI.create("http://example.org/a.git"),
                URI.create("ext::sh")}) {
            CheckoutException e = assertThrows(CheckoutException.class,
                    () -> checkout().checkout(new CheckoutRequest(uri, "main", null, true), jobDir), uri.toString());
            assertTrue(e.kind() == CheckoutException.Kind.BLOCKED_BY_POLICY || e.kind() == CheckoutException.Kind.NOT_FOUND,
                    uri + " -> " + e.kind());
        }
    }

    @Test
    void branchNamesThatLookLikeOptionsAreRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> new CheckoutRequest(URI.create("https://example.org/a.git"), "--upload-pack=touch /tmp/x", null, true));
    }

    @Test
    void credentialsTravelAsHeaderAndNeverLeak() throws Exception {
        Path bare = root.resolve("srv");
        Files.createDirectories(bare);
        Path work = TestSupport.repo(tmp, "work", Map.of("a.txt", "secret project\n"));
        TestSupport.git(bare, "clone", "-q", "--bare", work.toString(), bare.resolve("app.git").toString());
        String token = "glpat-" + "Zx81kQ0pR4mN7vB2cT6y";
        String expectedHeader = "Basic " + Base64.getEncoder().encodeToString(("oauth2:" + token).getBytes(StandardCharsets.UTF_8));

        try (GitHttpServer server = new GitHttpServer(bare, expectedHeader)) {
            URI url = URI.create(server.url("app.git"));
            GitCredentials good = GitCredentials.forProvider(GitProviderType.GITLAB, null, SensitiveValue.of(token));
            CheckoutResult r = checkout(50L * 1024 * 1024, true).checkout(new CheckoutRequest(url, "main", good, true), jobDir);
            assertEquals("secret project\n", Files.readString(r.sourceDir().resolve("a.txt")));
            assertTrue(server.receivedAuthorizations.contains(expectedHeader));
            assertFalse(Files.exists(r.sourceDir().resolve(".git")), "remote URL and config are not left behind");

            Path job2 = tmp.resolve("job2");
            Files.createDirectories(job2);
            String wrongToken = "glpat-" + "WRONGwrongWRONG12345";
            GitCredentials bad = GitCredentials.forProvider(GitProviderType.GITLAB, null, SensitiveValue.of(wrongToken));
            CheckoutException e = assertThrows(CheckoutException.class,
                    () -> checkout(50L * 1024 * 1024, true).checkout(new CheckoutRequest(url, "main", bad, true), job2));
            assertEquals(CheckoutException.Kind.AUTHENTICATION_FAILED, e.kind());
            assertFalse(e.getMessage().contains(wrongToken));

            Path job3 = tmp.resolve("job3");
            Files.createDirectories(job3);
            CheckoutException anonymous = assertThrows(CheckoutException.class,
                    () -> checkout(50L * 1024 * 1024, true).checkout(new CheckoutRequest(url, "main", null, true), job3));
            assertEquals(CheckoutException.Kind.AUTHENTICATION_FAILED, anonymous.kind());
        }
    }

    @Test
    void cloneTimeoutIsReported() throws Exception {
        Path repo = TestSupport.repo(root, "app", Map.of("a.txt", "a"));
        ResourceLimits tiny = new ResourceLimits(java.time.Duration.ofMillis(1), 10, 512L * 1024 * 1024, 64L * 1024 * 1024, 256);
        GitCheckout c = new GitCheckout(ProcessSandbox.detect(false),
                new GitCheckout.Settings(TestSupport.GIT, tiny, 50L * 1024 * 1024, 1000, null, false, root, Map.of()));
        CheckoutException e = assertThrows(CheckoutException.class,
                () -> c.checkout(new CheckoutRequest(repo.toUri(), "main", null, true), jobDir));
        assertEquals(CheckoutException.Kind.TIMEOUT, e.kind());
    }

    @Test
    void providerConventions() {
        SensitiveValue t = SensitiveValue.of("tok");
        assertEquals("Authorization: Basic " + b64("x-access-token:tok"),
                GitCredentials.forProvider(GitProviderType.GITHUB, null, t).authorizationHeader());
        assertEquals("Authorization: Basic " + b64("x-token-auth:tok"),
                GitCredentials.forProvider(GitProviderType.BITBUCKET_CLOUD, "me@example.org", t).authorizationHeader());
        assertEquals("Authorization: Bearer tok",
                GitCredentials.forProvider(GitProviderType.BITBUCKET_DATA_CENTER, null, t).authorizationHeader());
        assertEquals("Authorization: Basic " + b64("jdoe:tok"),
                GitCredentials.forProvider(GitProviderType.BITBUCKET_DATA_CENTER, "jdoe", t).authorizationHeader());
        assertFalse(GitCredentials.forProvider(GitProviderType.GITHUB, null, SensitiveValue.of("Q9zWm")).toString().contains("Q9zWm"));
        assertThrows(IllegalArgumentException.class, () -> GitCredentials.forProvider(GitProviderType.LOCAL, null, t));
    }

    @Test
    void errorClassification() {
        assertEquals(CheckoutException.Kind.TLS_ERROR, GitCheckout.classify(
                "fatal: unable to access 'https://x/': SSL certificate problem: self-signed certificate", "main").kind());
        assertEquals(CheckoutException.Kind.UNREACHABLE, GitCheckout.classify(
                "fatal: unable to access 'https://x/': Could not resolve host: x", "main").kind());
        assertEquals(CheckoutException.Kind.NOT_FOUND, GitCheckout.classify(
                "remote: Repository not found.\nfatal: repository 'https://x/' not found", "main").kind());
    }

    private static String b64(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }
}
