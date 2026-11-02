package com.africodeshield.app.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Maps the Keycloak {@code realm_access.roles} claim to Spring authorities ({@code ROLE_ADMIN}...).
 * Only the three application roles are kept: Keycloak default roles such as
 * {@code offline_access} or {@code uma_authorization} are ignored.
 */
public class KeycloakRealmRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    static final String REALM_ACCESS = "realm_access";
    static final String ROLES = "roles";

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Object realmAccess = jwt.getClaims().get(REALM_ACCESS);
        if (!(realmAccess instanceof Map<?, ?> map)) {
            return List.of();
        }
        Object roles = map.get(ROLES);
        if (!(roles instanceof Collection<?> values)) {
            return List.of();
        }
        return values.stream()
                .filter(Objects::nonNull)
                .map(v -> v.toString().toUpperCase(Locale.ROOT))
                .filter(Roles.ALL::contains)
                .distinct()
                .sorted()
                .<GrantedAuthority>map(r -> new SimpleGrantedAuthority(Roles.PREFIX + r))
                .toList();
    }
}
