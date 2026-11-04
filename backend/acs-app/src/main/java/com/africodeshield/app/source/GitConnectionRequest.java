package com.africodeshield.app.source;

import com.africodeshield.core.domain.GitProviderType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Creation, update or dry-run test of a connection.
 *
 * @param token      write-only: on update, {@code null} keeps the stored token, a value replaces it
 * @param clearToken on update, {@code true} removes the stored token (anonymous access)
 * @param version    optimistic-locking version from the last read, required on update
 */
public record GitConnectionRequest(
        @NotBlank @Size(max = 120) @Pattern(regexp = "[\\p{L}\\p{N} ._()\\-]+",
                message = "letters, digits, spaces and . _ - ( ) only") String name,
        @NotNull GitProviderType providerType,
        @Size(max = 2048) @Schema(description = "Web URL; empty for gitlab.com, github.com, bitbucket.org") String baseUrl,
        @Size(max = 2048) @Schema(description = "Only when the API is not at the standard location") String apiUrl,
        @Size(max = 255) @Schema(description = "Bitbucket Cloud: Atlassian account e-mail for API tokens; "
                + "Bitbucket Data Center: optional, enables Basic auth") String username,
        @Size(max = 4096) @Schema(accessMode = Schema.AccessMode.WRITE_ONLY, format = "password") String token,
        boolean clearToken,
        Boolean enabled,
        Long version) {

    /** The token never appears in logs, even when the request object is printed. */
    @Override
    public String toString() {
        return "GitConnectionRequest[name=" + name + ", providerType=" + providerType + ", baseUrl=" + baseUrl
                + ", apiUrl=" + apiUrl + ", username=" + username + ", token=" + (token == null ? "unchanged" : "********")
                + ", clearToken=" + clearToken + ", enabled=" + enabled + ", version=" + version + "]";
    }

    boolean hasNewToken() {
        return token != null && !token.isBlank();
    }
}
