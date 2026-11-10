package com.saytu.core.workflow;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.saytu.core.workflow.WorkflowCheck.Report;
import com.saytu.core.workflow.WorkflowCheck.Status;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class WorkflowCheckTest {

    static final String A = "a".repeat(40);
    static final String B = "b".repeat(40);
    static final String C = "c".repeat(40);

    private static Status check(Report r, String id) {
        return r.checks().stream().filter(c -> c.id().equals(id)).findFirst().orElseThrow().status();
    }

    @Test
    void mainOnTheLatestTagWithDevelopIsCompliant() {
        Report r = WorkflowCheck.evaluate(Map.of("main", A, "develop", B, "feature/x", C),
                Map.of("v1.9.0", C, "v1.10.0", A, "v1.10.1-rc1", B));
        assertEquals(Status.PASS, r.status());
        assertEquals("main", r.productionBranch());
        assertEquals("v1.10.0", r.latestTag(), "1.10 > 1.9 and the release wins over a newer release candidate");
        assertEquals(3, r.releaseTags());
    }

    @Test
    void commitsOnMainAfterTheLastReleaseFail() {
        Report r = WorkflowCheck.evaluate(Map.of("master", A, "develop", B), Map.of("2.0.0", C));
        assertEquals(Status.FAIL, r.status());
        assertEquals(Status.FAIL, check(r, "PRODUCTION_ON_LATEST_TAG"));
        String msg = r.checks().getLast().message();
        assertTrue(msg.contains("master (aaaaaaaa) ne pointe pas sur le dernier tag 2.0.0 (cccccccc)"), msg);
    }

    @Test
    void missingDevelopAndTagsFail() {
        Report r = WorkflowCheck.evaluate(Map.of("main", A), Map.of());
        assertEquals(Status.FAIL, check(r, "DEVELOP_BRANCH"));
        assertEquals(Status.FAIL, check(r, "RELEASE_TAGS"));
        assertEquals(Status.WARN, check(r, "PRODUCTION_ON_LATEST_TAG"));
        assertNull(r.latestTag());
    }

    @Test
    void ambiguousOrMissingProductionBranch() {
        Report both = WorkflowCheck.evaluate(Map.of("main", A, "master", B, "develop", C), Map.of("v1.0.0", A));
        assertEquals(Status.WARN, check(both, "PRODUCTION_BRANCH"));
        assertEquals("main", both.productionBranch());
        assertEquals(Status.WARN, both.status());
        Report none = WorkflowCheck.evaluate(Map.of("trunk", A, "develop", B), Map.of("v1.0.0", A));
        assertEquals(Status.FAIL, check(none, "PRODUCTION_BRANCH"));
    }

    @Test
    void tagsThatAreNotVersionsCannotTellTheLatestRelease() {
        Report r = WorkflowCheck.evaluate(Map.of("main", A, "develop", B), Map.of("prod-deploy", A, "sprint-12", A));
        assertEquals(Status.WARN, check(r, "RELEASE_TAGS"));
        assertEquals(List.of(), WorkflowCheck.latestRelease(List.of()).stream().toList());
        assertEquals("v2.0.0-beta", WorkflowCheck.latestRelease(List.of("v2.0.0-alpha", "v2.0.0-beta")).orElseThrow(),
                "only pre-releases: the highest one");
    }
}
