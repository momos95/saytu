package com.africodeshield.app.source;

import com.africodeshield.app.vault.TokenVault;
import com.africodeshield.core.git.GitConnectionSpec;
import com.africodeshield.core.git.GitProvider;
import com.africodeshield.core.security.SensitiveValue;
import com.africodeshield.git.provider.GitProviders;

import java.net.URI;

/**
 * A connection ready for provider calls: the token is decrypted for the lifetime of this object and
 * wiped by {@link #close()}. Always use with try-with-resources.
 */
record OpenConnection(GitConnectionSpec spec, GitProvider provider) implements AutoCloseable {

    static OpenConnection open(GitConnectionEntity entity, TokenVault vault, GitProviders providers) {
        if (!entity.isEnabled()) {
            throw new IllegalArgumentException("Connection '" + entity.getName() + "' is disabled");
        }
        SensitiveValue token = entity.hasToken()
                ? vault.decrypt(entity.getTokenCiphertext(), entity.getTokenKeyId(),
                TokenVault.owner(GitConnectionService.OWNER_TABLE, entity.getId()))
                : null;
        GitConnectionSpec spec = new GitConnectionSpec(entity.getProviderType(), URI.create(entity.getBaseUrl()),
                entity.getApiUrl() == null ? null : URI.create(entity.getApiUrl()), entity.getUsername(), token, true);
        return new OpenConnection(spec, providers.get(entity.getProviderType()));
    }

    @Override
    public void close() {
        if (spec.token() != null) {
            spec.token().destroy();
        }
    }
}
