package com.saytu.app.scan;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WorkerStatusTest {

    @Test
    void isolationReportIsReadBack() {
        WorkerStatusService.Isolation ok = WorkerStatusService.parse("{\"separateUser\": true, \"network\": \"blocked\", "
                + "\"detail\": null, \"workerId\": \"worker-1\", \"reportedAt\": \"2026-11-10T21:00:00Z\"}");
        assertTrue(ok.separateUser());
        assertTrue(ok.networkBlocked());
        assertEquals("worker-1", ok.workerId());
        assertEquals(java.time.Instant.parse("2026-11-10T21:00:00Z"), ok.reportedAt());

        WorkerStatusService.Isolation degraded = WorkerStatusService.parse("{\"separateUser\": false, "
                + "\"network\": \"open: scanners are not isolated\", \"detail\": \"the worker does not run as root\"}");
        assertFalse(degraded.separateUser());
        assertFalse(degraded.networkBlocked());
        assertEquals(null, degraded.reportedAt());
    }
}
