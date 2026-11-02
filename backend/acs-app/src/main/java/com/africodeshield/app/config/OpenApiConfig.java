package com.africodeshield.app.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    private static final String BEARER = "keycloak-bearer";

    @Bean
    OpenAPI africodeshieldOpenApi(@Value("${acs.version:dev}") String version) {
        return new OpenAPI()
                .info(new Info()
                        .title("AfriCodeShield API")
                        .version(version)
                        .description("On-premise security and code-quality audit platform. "
                                + "All endpoints require a Keycloak access token (roles ADMIN, AUDITOR, VIEWER).")
                        .license(new License().name("Apache-2.0").url("https://www.apache.org/licenses/LICENSE-2.0")))
                .components(new Components().addSecuritySchemes(BEARER,
                        new SecurityScheme().type(SecurityScheme.Type.HTTP).scheme("bearer").bearerFormat("JWT")))
                .addSecurityItem(new SecurityRequirement().addList(BEARER));
    }
}
