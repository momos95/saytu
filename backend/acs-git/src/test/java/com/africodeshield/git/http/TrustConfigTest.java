package com.africodeshield.git.http;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TrustConfigTest {

    private static Path resource(String name) throws Exception {
        return Path.of(TrustConfigTest.class.getResource("/" + name).toURI());
    }

    @Test
    void loadsInternalCaBundleOnTopOfSystemTrust() throws Exception {
        var certs = TrustConfig.loadPem(resource("test-ca.pem"));
        assertEquals(1, certs.size());
        assertTrue(certs.getFirst().getSubjectX500Principal().getName().contains("AfriCodeShield Test CA"));
        assertNotNull(TrustConfig.create(resource("test-ca.pem")));
    }

    @Test
    void defaultContextWithoutBundle() {
        assertNotNull(TrustConfig.create(null));
    }

    @Test
    void invalidBundleFailsFast() throws Exception {
        Path empty = Files.createTempFile("empty", ".pem");
        try {
            assertThrows(RuntimeException.class, () -> TrustConfig.create(empty));
        } finally {
            Files.deleteIfExists(empty);
        }
    }
}
