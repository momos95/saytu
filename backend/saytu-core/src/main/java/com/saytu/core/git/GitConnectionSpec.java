package com.saytu.core.git;

import com.saytu.core.domain.GitProviderType;
import com.saytu.core.security.SensitiveValue;

import java.net.URI;
import java.util.Objects;

/**
 * Everything a {@link GitProvider} needs to talk to one Git platform.
 * The token is a {@link SensitiveValue}: printing this record never exposes it.
 *
 * @param providerType platform family
 * @param baseUrl      web URL of the instance (e.g. https://gitlab.example.org); for LOCAL, a {@code file:} URI of the root directory
 * @param apiUrl       API root; {@code null} to derive it from {@code baseUrl}
 * @param username     required for Bitbucket app passwords / HTTP access tokens with basic auth, otherwise {@code null}
 * @param token        access token, {@code null} for anonymous access to public repositories
 * @param verifyTls    {@code false} only for lab instances with self-signed certificates (logged as a warning)
 */
public record GitConnectionSpec(
        GitProviderType providerType,
        URI baseUrl,
        URI apiUrl,
        String username,
        SensitiveValue token,
        boolean verifyTls) {

    public GitConnectionSpec {
        Objects.requireNonNull(providerType, "providerType");
        Objects.requireNonNull(baseUrl, "baseUrl");
        String scheme = baseUrl.getScheme();
        if (providerType == GitProviderType.LOCAL) {
            if (!"file".equalsIgnoreCase(scheme)) {
                throw new IllegalArgumentException("LOCAL connections require a file: URI");
            }
        } else {
            if (!"https".equalsIgnoreCase(scheme) && !"http".equalsIgnoreCase(scheme)) {
                throw new IllegalArgumentException("Git platform URL must be http(s): " + baseUrl);
            }
            if (baseUrl.getUserInfo() != null) {
                throw new IllegalArgumentException("Credentials must not be embedded in the URL");
            }
        }
    }

    public boolean hasToken() {
        return token != null && !token.isDestroyed() && !token.isBlank();
    }

    @Override
    public String toString() {
        return "GitConnectionSpec[providerType=" + providerType + ", baseUrl=" + baseUrl + ", apiUrl=" + apiUrl
                + ", username=" + username + ", token=" + (token == null ? "none" : SensitiveValue.MASK)
                + ", verifyTls=" + verifyTls + "]";
    }
}
