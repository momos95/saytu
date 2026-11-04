package com.africodeshield.app.vault;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Master keys for secrets at rest (prefix {@code acs.vault}).
 *
 * @param masterKey          {@code ACS_MASTER_KEY}: base64 of 32 random bytes
 * @param previousMasterKeys {@code ACS_PREVIOUS_MASTER_KEYS}: comma-separated former keys, kept during a rotation
 */
@ConfigurationProperties(prefix = "acs.vault")
public record VaultProperties(String masterKey, List<String> previousMasterKeys) {

    public VaultProperties {
        previousMasterKeys = previousMasterKeys == null ? List.of()
                : previousMasterKeys.stream().filter(k -> k != null && !k.isBlank()).toList();
    }

    /** Never prints key material. */
    @Override
    public String toString() {
        return "VaultProperties[masterKey=" + (masterKey == null || masterKey.isBlank() ? "<unset>" : "********")
                + ", previousMasterKeys=" + previousMasterKeys.size() + "]";
    }
}
