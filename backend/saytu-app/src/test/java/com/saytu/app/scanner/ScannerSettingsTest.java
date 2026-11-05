package com.saytu.app.scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

class ScannerSettingsTest {

    @Test
    void acceptsWhitelistedValuesAndDropsBlankOnes() {
        assertEquals(Map.of("standard", "PSR2"), ScannerSettings.validate("phpcs", Map.of("standard", " PSR2 ")));
        assertEquals(Map.of("dialect", "postgres", "processes", "4"),
                ScannerSettings.validate("sqlfluff", Map.of("dialect", "postgres", "processes", "4")));
        assertTrue(ScannerSettings.validate("opengrep", Map.of("exclude", "")).isEmpty());
        assertTrue(ScannerSettings.validate("trivy", null).isEmpty());
    }

    @Test
    void refusesUnknownKeysAndValuesThatCouldBecomeOptions() {
        assertThrows(IllegalArgumentException.class, () -> ScannerSettings.validate("trivy", Map.of("jobs", "2")));
        assertThrows(IllegalArgumentException.class, () -> ScannerSettings.validate("phpcs", Map.of("standard", "/etc/x.xml")));
        assertThrows(IllegalArgumentException.class, () -> ScannerSettings.validate("sqlfluff", Map.of("dialect", "--templater=jinja")));
        assertThrows(IllegalArgumentException.class, () -> ScannerSettings.validate("cppcheck", Map.of("jobs", "64")));
        assertThrows(IllegalArgumentException.class, () -> ScannerSettings.validate("opengrep", Map.of("exclude", "a b;rm")));
    }
}
