package com.africodeshield.app.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;

/**
 * Application settings (prefix {@code acs}). Values come from environment variables in Docker
 * Compose, see .env.example.
 *
 * @param security security settings
 * @param cors     origins allowed to call the API from a browser (the Angular front-end)
 */
@Validated
@ConfigurationProperties(prefix = "acs")
public record AcsProperties(@Valid Security security, @Valid Cors cors) {

    public AcsProperties {
        if (security == null) {
            security = new Security("africodeshield-web", false);
        }
        if (cors == null) {
            cors = new Cors(List.of());
        }
    }

    /**
     * @param webClientId      Keycloak client id used by the Angular front-end (reported by /system/info)
     * @param exposeApiDocs    publish Swagger UI and /v3/api-docs without authentication
     */
    public record Security(@NotBlank String webClientId, boolean exposeApiDocs) {
    }

    public record Cors(List<String> allowedOrigins) {
        public Cors {
            allowedOrigins = allowedOrigins == null ? List.of() : List.copyOf(allowedOrigins);
        }
    }
}
