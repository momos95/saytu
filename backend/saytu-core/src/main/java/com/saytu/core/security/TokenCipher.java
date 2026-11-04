package com.saytu.core.security;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Encrypts secrets at rest (Git tokens, webhook secrets) with AES-256-GCM. See ADR-0004.
 * <p>
 * Stored format: {@code version(1) || iv(12) || ciphertext || tag(16)}. The associated data binds a
 * ciphertext to its owner (e.g. {@code git_connection:<uuid>}): a blob copied to another row does
 * not decrypt. Each blob is stored with the id of the key that produced it, so the master key can be
 * rotated: new encryptions use the active key, old blobs stay readable with the previous keys until
 * re-encrypted ({@link #needsReEncryption(String)}).
 * <p>
 * Thread-safe. No dependency outside the JDK.
 */
public final class TokenCipher {

    public static final int KEY_LENGTH_BYTES = 32;
    private static final byte FORMAT_VERSION = 1;
    private static final int IV_LENGTH = 12;
    private static final int TAG_BITS = 128;
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String AAD_PREFIX = "saytu:v1:";

    private final SecureRandom random = new SecureRandom();
    private final String activeKeyId;
    private final Map<String, SecretKey> keys;

    private TokenCipher(String activeKeyId, Map<String, SecretKey> keys) {
        this.activeKeyId = activeKeyId;
        this.keys = Map.copyOf(keys);
    }

    /**
     * @param activeKey    key used for new encryptions (32 bytes)
     * @param previousKeys keys still accepted for decryption, oldest last
     */
    public static TokenCipher create(byte[] activeKey, List<byte[]> previousKeys) {
        Map<String, SecretKey> keys = new LinkedHashMap<>();
        String active = register(keys, activeKey);
        for (byte[] previous : previousKeys == null ? List.<byte[]>of() : previousKeys) {
            register(keys, previous);
        }
        return new TokenCipher(active, keys);
    }

    /**
     * Decodes a base64 key as found in {@code SAYTU_MASTER_KEY}. Error messages never echo the value.
     */
    public static byte[] parseBase64Key(String base64, String variableName) {
        if (base64 == null || base64.isBlank()) {
            throw new IllegalArgumentException(variableName + " is not set");
        }
        byte[] key;
        try {
            key = Base64.getDecoder().decode(base64.strip());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(variableName + " is not valid base64");
        }
        if (key.length != KEY_LENGTH_BYTES) {
            int length = key.length;
            Arrays.fill(key, (byte) 0);
            throw new IllegalArgumentException(variableName + " must decode to " + KEY_LENGTH_BYTES
                    + " bytes, got " + length + " (generate one with: head -c 32 /dev/urandom | base64)");
        }
        return key;
    }

    /** Public, non-secret identifier of a key: first 12 hex chars of its SHA-256. */
    public static String keyId(byte[] key) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(key);
            return "k" + HexFormat.of().formatHex(digest, 0, 6);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public String activeKeyId() {
        return activeKeyId;
    }

    /** {@code true} when the blob was encrypted with a key other than the active one. */
    public boolean needsReEncryption(String keyId) {
        return !activeKeyId.equals(keyId);
    }

    public Encrypted encrypt(SensitiveValue plaintext, String associatedData) {
        Objects.requireNonNull(plaintext, "plaintext");
        byte[] clear = encodeUtf8(plaintext.revealChars());
        try {
            byte[] iv = new byte[IV_LENGTH];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, keys.get(activeKeyId), new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(aad(associatedData));
            byte[] sealed = cipher.doFinal(clear);
            byte[] blob = ByteBuffer.allocate(1 + IV_LENGTH + sealed.length)
                    .put(FORMAT_VERSION).put(iv).put(sealed).array();
            return new Encrypted(blob, activeKeyId);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Encryption failed", e);
        } finally {
            Arrays.fill(clear, (byte) 0);
        }
    }

    /**
     * @throws TokenDecryptionException when the key is unknown, the data was tampered with, or the
     *                                  associated data does not match
     */
    public SensitiveValue decrypt(byte[] blob, String keyId, String associatedData) {
        Objects.requireNonNull(blob, "blob");
        SecretKey key = keys.get(keyId);
        if (key == null) {
            throw new TokenDecryptionException("Unknown encryption key id " + keyId
                    + ": the master key was changed without keeping the previous one in SAYTU_PREVIOUS_MASTER_KEYS");
        }
        if (blob.length < 1 + IV_LENGTH + TAG_BITS / 8 || blob[0] != FORMAT_VERSION) {
            throw new TokenDecryptionException("Unsupported or truncated ciphertext");
        }
        byte[] clear = null;
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, blob, 1, IV_LENGTH));
            cipher.updateAAD(aad(associatedData));
            clear = cipher.doFinal(blob, 1 + IV_LENGTH, blob.length - 1 - IV_LENGTH);
            char[] chars = decodeUtf8(clear);
            try {
                return SensitiveValue.of(chars);
            } finally {
                Arrays.fill(chars, '\0');
            }
        } catch (AEADBadTagException e) {
            throw new TokenDecryptionException("Ciphertext integrity check failed (tampered data or wrong owner)");
        } catch (CharacterCodingException e) {
            throw new TokenDecryptionException("Decrypted secret is not valid UTF-8");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Decryption failed", e);
        } finally {
            if (clear != null) {
                Arrays.fill(clear, (byte) 0);
            }
        }
    }

    private static String register(Map<String, SecretKey> keys, byte[] key) {
        Objects.requireNonNull(key, "key");
        if (key.length != KEY_LENGTH_BYTES) {
            throw new IllegalArgumentException("AES-256 keys must be " + KEY_LENGTH_BYTES + " bytes");
        }
        boolean allZero = true;
        for (byte b : key) {
            allZero &= b == 0;
        }
        if (allZero) {
            throw new IllegalArgumentException("Refusing an all-zero key");
        }
        String id = keyId(key);
        keys.putIfAbsent(id, new SecretKeySpec(key.clone(), "AES"));
        return id;
    }

    private static byte[] aad(String associatedData) {
        if (associatedData == null || associatedData.isBlank()) {
            throw new IllegalArgumentException("associatedData is required");
        }
        return (AAD_PREFIX + associatedData).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] encodeUtf8(char[] chars) {
        try {
            ByteBuffer buffer = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(chars));
            byte[] bytes = new byte[buffer.remaining()];
            buffer.get(bytes);
            if (buffer.hasArray()) {
                Arrays.fill(buffer.array(), (byte) 0);
            }
            return bytes;
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Secret is not valid text");
        } finally {
            Arrays.fill(chars, '\0');
        }
    }

    private static char[] decodeUtf8(byte[] bytes) throws CharacterCodingException {
        CharBuffer buffer = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes));
        char[] chars = new char[buffer.remaining()];
        buffer.get(chars);
        if (buffer.hasArray()) {
            Arrays.fill(buffer.array(), '\0');
        }
        return chars;
    }

    /** Ciphertext and the id of the key that produced it (both persisted). */
    public record Encrypted(byte[] ciphertext, String keyId) {
        public Encrypted {
            ciphertext = ciphertext.clone();
        }

        @Override
        public byte[] ciphertext() {
            return ciphertext.clone();
        }

        @Override
        public String toString() {
            return "Encrypted[keyId=" + keyId + ", length=" + ciphertext.length + "]";
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Encrypted e && keyId.equals(e.keyId) && Arrays.equals(ciphertext, e.ciphertext);
        }

        @Override
        public int hashCode() {
            return 31 * keyId.hashCode() + Arrays.hashCode(ciphertext);
        }
    }

    public static final class TokenDecryptionException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public TokenDecryptionException(String message) {
            super(message);
        }
    }
}
