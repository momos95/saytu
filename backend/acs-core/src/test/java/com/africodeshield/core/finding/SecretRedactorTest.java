package com.africodeshield.core.finding;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecretRedactorTest {

    @Test
    void masksKnownSecretKeepingShortPrefix() {
        String secret = "ghp_" + "a".repeat(36);
        String out = SecretRedactor.redact("token: " + secret + " end", List.of(secret));
        assertFalse(out.contains(secret));
        assertTrue(out.contains("ghp_…[REDACTED]"), out);
    }

    @Test
    void shortKnownSecretIsFullyMasked() {
        String out = SecretRedactor.redact("pin=12345", List.of("12345"));
        assertEquals("pin=[REDACTED]", out);
    }

    @Test
    void masksGenericTokenPatternsWithoutHints() {
        String input = """
                aws = AKIAIOSFODNN7EXAMPLE
                gl = glpat-abcdefghijklmnopqrstuv
                jwt = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
                url = https://alice:s3cr3tP4ss@git.example.org/repo.git
                """;
        String out = SecretRedactor.redact(input);
        assertFalse(out.contains("AKIAIOSFODNN7EXAMPLE"));
        assertFalse(out.contains("glpat-abcdefghijklmnopqrstuv"));
        assertFalse(out.contains("dozjgNryP4J3jVmNHl0w5N"));
        assertFalse(out.contains("s3cr3tP4ss"));
        assertTrue(out.contains("https://[REDACTED]@git.example.org"), out);
    }

    @Test
    void masksPrivateKeyBlocks() {
        String input = "key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nabc\n-----END RSA PRIVATE KEY-----\nafter";
        String out = SecretRedactor.redact(input);
        assertFalse(out.contains("MIIEow"));
        assertTrue(out.endsWith("after"));
    }

    @Test
    void masksCredentialAssignmentsAndBearerTokens() {
        assertEquals("password = \"[REDACTED]\"", SecretRedactor.redact("password = \"hunter22\""));
        assertEquals("api_key: [REDACTED]", SecretRedactor.redact("api_key: 0123456789abcdef"));
        assertEquals("Authorization: Bearer [REDACTED]",
                SecretRedactor.redact("Authorization: Bearer abcdefghijklmnop"));
    }

    @Test
    void leavesOrdinaryCodeUntouched() {
        String code = "int total = items.size(); // compute total";
        assertEquals(code, SecretRedactor.redact(code));
    }

    @Test
    void isIdempotent() {
        String secret = "glpat-abcdefghijklmnopqrstuv";
        String once = SecretRedactor.redact("token=" + secret, List.of(secret));
        assertEquals(once, SecretRedactor.redact(once));
    }

    @Test
    void handlesNullAndEmpty() {
        assertNull(SecretRedactor.redact(null));
        assertEquals("", SecretRedactor.redact(""));
    }
}
