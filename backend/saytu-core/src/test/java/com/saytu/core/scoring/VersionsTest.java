package com.saytu.core.scoring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

class VersionsTest {

    @Test
    void picksTheHighestFixedVersion() {
        assertEquals(Optional.of("2.13.4.2"), Versions.highest(List.of("2.12.6.1, 2.13.4.2", "2.13.4")));
        assertEquals(Optional.of("1.10.0"), Versions.highest(List.of("1.9.9", "1.10.0")));
        assertEquals(Optional.of("v4.1.94.Final"), Versions.highest(Arrays.asList(null, "4.1.86.Final", "v4.1.94.Final")));
        assertEquals(Optional.empty(), Versions.highest(List.of(" ", ",")));
        assertTrue(Versions.compare("1.2", "1.2.0") == 0);
        assertTrue(Versions.compare("2.0.0-beta", "2.0.0") > 0, "qualifiers sort after the release: acceptable for advisories");
    }
}
