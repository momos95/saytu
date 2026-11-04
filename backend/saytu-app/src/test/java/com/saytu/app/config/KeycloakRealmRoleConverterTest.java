package com.saytu.app.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class KeycloakRealmRoleConverterTest {

    private final KeycloakRealmRoleConverter converter = new KeycloakRealmRoleConverter();

    private static Jwt jwt(Map<String, Object> claims) {
        Jwt.Builder builder = Jwt.withTokenValue("t").header("alg", "RS256")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).subject("u1");
        claims.forEach(builder::claim);
        return builder.build();
    }

    @Test
    void mapsApplicationRealmRolesOnly() {
        var jwt = jwt(Map.of("realm_access",
                Map.of("roles", List.of("offline_access", "auditor", "VIEWER", "uma_authorization", "VIEWER"))));

        assertThat(converter.convert(jwt))
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_AUDITOR", "ROLE_VIEWER");
    }

    @Test
    void missingOrMalformedClaimGivesNoAuthority() {
        assertThat(converter.convert(jwt(Map.of("scope", "openid")))).isEmpty();
        assertThat(converter.convert(jwt(Map.of("realm_access", "ADMIN")))).isEmpty();
        assertThat(converter.convert(jwt(Map.of("realm_access", Map.of("roles", "ADMIN"))))).isEmpty();
    }
}
