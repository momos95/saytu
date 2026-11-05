package com.saytu.app.scan;

import com.saytu.app.scan.ScanViews.PlanningNote;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ScanSupportTest {

    @Test
    void planningNotesRoundTripThroughJson() {
        UUID id = UUID.randomUUID();
        Map<String, String> note = new LinkedHashMap<>();
        note.put("repositoryId", id.toString());
        note.put("repository", "acme/\"quoted\"\\path");
        note.put("note", "line1\nline2\u0001");
        String json = ScanPlanner.toJson(List.of(note));
        List<PlanningNote> parsed = ScanService.parseNotes(json);
        assertEquals(1, parsed.size());
        assertEquals(id, parsed.getFirst().repositoryId());
        assertEquals("acme/\"quoted\"\\path", parsed.getFirst().repository());
        assertEquals("line1\nline2\u0001", parsed.getFirst().note());
        assertEquals("[]", ScanPlanner.toJson(List.of()));
    }

    @Test
    void scopeLabels() {
        assertEquals("ALL_TARGETS", ScanService.scopeLabel("{\"allTargets\": true}"));
        assertEquals("2 REPOSITORIES", ScanService.scopeLabel("{\"repositoryIds\": [\"a\", \"b\"]}"));
    }

    @Test
    void findingFiltersAreValidated() {
        var f = new FindingQueryService.Filter(null, " main ", List.of("high", "HIGH"), null, List.of(), "Opengrep", " sql ");
        assertEquals(List.of("HIGH"), f.severities());
        assertEquals("main", f.branch());
        assertEquals("opengrep", f.scanner());
        assertEquals("sql", f.text());
        assertEquals(null, f.statuses());
        assertThrows(IllegalArgumentException.class,
                () -> new FindingQueryService.Filter(null, null, List.of("URGENT"), null, null, null, null));
        assertThrows(IllegalArgumentException.class,
                () -> new FindingQueryService.Filter(null, null, null, null, null, "sonar", null));
        assertEquals("100\\%\\_a\\\\b", FindingQueryService.escapeLike("100%_a\\b"));
    }
}
