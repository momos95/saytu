package com.africodeshield.app.vault;

import com.africodeshield.app.TestKeys;
import com.africodeshield.core.security.SensitiveValue;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenVaultTest {

    @Test
    void refusesToStartWithoutAValidMasterKey() {
        assertThatThrownBy(() -> new TokenVault(new VaultProperties(null, List.of())))
                .hasMessageContaining("ACS_MASTER_KEY is not set");
        assertThatThrownBy(() -> new TokenVault(new VaultProperties("c2hvcnQ=", List.of())))
                .hasMessageContaining("32 bytes");
    }

    @Test
    void encryptsPerOwner() {
        TokenVault vault = new TokenVault(new VaultProperties(TestKeys.MASTER_KEY, List.of("")));
        UUID id = UUID.randomUUID();
        var encrypted = vault.encrypt(SensitiveValue.of("glpat-x"), TokenVault.owner("git_connection", id));
        assertThat(vault.decrypt(encrypted.ciphertext(), encrypted.keyId(), TokenVault.owner("git_connection", id)).reveal())
                .isEqualTo("glpat-x");
        assertThat(vault.needsReEncryption(encrypted.keyId())).isFalse();
    }

    @Test
    void propertiesNeverPrintKeys() {
        assertThat(new VaultProperties(TestKeys.MASTER_KEY, List.of(TestKeys.MASTER_KEY)).toString())
                .doesNotContain(TestKeys.MASTER_KEY).contains("previousMasterKeys=1");
    }
}
