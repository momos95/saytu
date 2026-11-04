package com.saytu.core.security;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenCipherTest {

    private static byte[] key(int seed) {
        byte[] k = new byte[32];
        for (int i = 0; i < k.length; i++) {
            k[i] = (byte) (seed * 31 + i);
        }
        return k;
    }

    private final TokenCipher cipher = TokenCipher.create(key(1), List.of());

    @Test
    void roundTripWithUnicode() {
        var encrypted = cipher.encrypt(SensitiveValue.of("glpat-abc€é✓"), "git_connection:42");
        assertEquals("glpat-abc€é✓", cipher.decrypt(encrypted.ciphertext(), encrypted.keyId(), "git_connection:42").reveal());
        assertEquals(cipher.activeKeyId(), encrypted.keyId());
    }

    @Test
    void ciphertextDoesNotContainPlaintextAndIsRandomised() {
        var a = cipher.encrypt(SensitiveValue.of("ghp_secretsecretsecret"), "x");
        var b = cipher.encrypt(SensitiveValue.of("ghp_secretsecretsecret"), "x");
        assertFalse(new String(a.ciphertext(), StandardCharsets.ISO_8859_1).contains("secret"));
        assertNotEquals(a, b);
        assertEquals(1 + 12 + "ghp_secretsecretsecret".length() + 16, a.ciphertext().length);
    }

    @Test
    void associatedDataBindsCiphertextToItsOwner() {
        var e = cipher.encrypt(SensitiveValue.of("t0ken"), "git_connection:1");
        var ex = assertThrows(TokenCipher.TokenDecryptionException.class,
                () -> cipher.decrypt(e.ciphertext(), e.keyId(), "git_connection:2"));
        assertTrue(ex.getMessage().contains("integrity"));
    }

    @Test
    void tamperingIsDetected() {
        var e = cipher.encrypt(SensitiveValue.of("t0ken"), "o");
        byte[] blob = e.ciphertext();
        blob[blob.length - 1] ^= 1;
        assertThrows(TokenCipher.TokenDecryptionException.class, () -> cipher.decrypt(blob, e.keyId(), "o"));
        byte[] truncated = java.util.Arrays.copyOf(e.ciphertext(), 10);
        assertThrows(TokenCipher.TokenDecryptionException.class, () -> cipher.decrypt(truncated, e.keyId(), "o"));
    }

    @Test
    void rotationKeepsOldCiphertextsReadable() {
        var old = cipher.encrypt(SensitiveValue.of("legacy"), "o");
        var rotated = TokenCipher.create(key(2), List.of(key(1)));
        assertEquals("legacy", rotated.decrypt(old.ciphertext(), old.keyId(), "o").reveal());
        assertTrue(rotated.needsReEncryption(old.keyId()));
        assertFalse(rotated.needsReEncryption(rotated.activeKeyId()));
        var ex = assertThrows(TokenCipher.TokenDecryptionException.class,
                () -> TokenCipher.create(key(2), List.of()).decrypt(old.ciphertext(), old.keyId(), "o"));
        assertTrue(ex.getMessage().contains("SAYTU_PREVIOUS_MASTER_KEYS"));
    }

    @Test
    void keyIdIsStableAndDoesNotRevealTheKey() {
        assertEquals(TokenCipher.keyId(key(1)), TokenCipher.keyId(key(1)));
        assertEquals(13, TokenCipher.keyId(key(1)).length());
        assertNotEquals(TokenCipher.keyId(key(1)), TokenCipher.keyId(key(2)));
    }

    @Test
    void rejectsWeakOrMalformedKeys() {
        assertThrows(IllegalArgumentException.class, () -> TokenCipher.create(new byte[32], List.of()));
        assertThrows(IllegalArgumentException.class, () -> TokenCipher.create(new byte[16], List.of()));
        var e = assertThrows(IllegalArgumentException.class,
                () -> TokenCipher.parseBase64Key(Base64.getEncoder().encodeToString(new byte[16]), "SAYTU_MASTER_KEY"));
        assertTrue(e.getMessage().contains("32 bytes"));
        var notB64 = assertThrows(IllegalArgumentException.class,
                () -> TokenCipher.parseBase64Key("not*base64!secretvalue", "SAYTU_MASTER_KEY"));
        assertFalse(notB64.getMessage().contains("secretvalue"));
        assertThrows(IllegalArgumentException.class, () -> TokenCipher.parseBase64Key(" ", "SAYTU_MASTER_KEY"));
        assertEquals(32, TokenCipher.parseBase64Key(Base64.getEncoder().encodeToString(key(3)), "K").length);
    }

    @Test
    void encryptedToStringHidesBytes() {
        var e = cipher.encrypt(SensitiveValue.of("abc"), "o");
        assertTrue(e.toString().startsWith("Encrypted[keyId="));
    }

    @Test
    void associatedDataIsMandatory() {
        assertThrows(IllegalArgumentException.class, () -> cipher.encrypt(SensitiveValue.of("a"), " "));
    }
}
