package com.africodeshield.app.vault;

import com.africodeshield.core.security.SensitiveValue;
import com.africodeshield.core.security.TokenCipher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * Encrypts and decrypts secrets stored in the database (ADR-0004). The application refuses to start
 * when {@code ACS_MASTER_KEY} is missing or malformed: running without encryption is not an option.
 */
@Component
public class TokenVault {

    private static final Logger log = LoggerFactory.getLogger(TokenVault.class);

    private final TokenCipher cipher;

    public TokenVault(VaultProperties properties) {
        byte[] active = TokenCipher.parseBase64Key(properties.masterKey(), "ACS_MASTER_KEY");
        List<byte[]> previous = new ArrayList<>();
        for (String k : properties.previousMasterKeys()) {
            previous.add(TokenCipher.parseBase64Key(k, "ACS_PREVIOUS_MASTER_KEYS"));
        }
        this.cipher = TokenCipher.create(active, previous);
        Arrays.fill(active, (byte) 0);
        previous.forEach(k -> Arrays.fill(k, (byte) 0));
        log.info("Secret vault ready (active key id {}, {} previous key(s))", cipher.activeKeyId(), previous.size());
    }

    /** Associated data binding a ciphertext to one row, so it cannot be copied to another. */
    public static String owner(String table, UUID id) {
        return table + ":" + id;
    }

    public TokenCipher.Encrypted encrypt(SensitiveValue secret, String owner) {
        return cipher.encrypt(secret, owner);
    }

    public SensitiveValue decrypt(byte[] ciphertext, String keyId, String owner) {
        return cipher.decrypt(ciphertext, keyId, owner);
    }

    public boolean needsReEncryption(String keyId) {
        return cipher.needsReEncryption(keyId);
    }
}
