package com.saytu.app.scan;

import com.saytu.core.workflow.WorkflowCheck;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class WorkflowJsonTest {

    @Test
    @SuppressWarnings("unchecked")
    void reportIsStoredWithEveryCheckAndReadBackByTheOverview() {
        String a = "a".repeat(40);
        String c = "c".repeat(40);
        WorkflowCheck.Report report = WorkflowCheck.evaluate(Map.of("main", a), Map.of("v1.2.0", c));
        String json = Json.write(ResultWriter.workflowJson(report));

        InsightService.Workflow view = InsightService.workflow("FAIL", null, null, json);
        assertEquals("FAIL", view.status());
        assertEquals("main", view.report().get("productionBranch"));
        assertEquals("v1.2.0", view.report().get("latestTag"));
        List<Map<String, Object>> checks = (List<Map<String, Object>>) view.report().get("checks");
        assertEquals(4, checks.size());
        assertEquals(List.of("PRODUCTION_BRANCH", "DEVELOP_BRANCH", "RELEASE_TAGS", "PRODUCTION_ON_LATEST_TAG"),
                checks.stream().map(m -> m.get("id")).toList());
        assertEquals("FAIL", checks.get(3).get("status"));
        assertEquals(null, InsightService.workflow(null, null, "timeout", null).report());
    }
}
