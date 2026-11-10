package com.saytu.app.user;

import com.fasterxml.jackson.databind.JsonNode;
import com.saytu.app.audit.AuditService;
import com.saytu.app.web.ConflictException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * SAYTU users, stored in Keycloak (realm saytu). One SAYTU role per user: VIEWER (read), AUDITOR (launch
 * audits, triage) or ADMIN (everything). Passwords are never chosen by the administrator: a random
 * temporary password is shown once and must be changed at first login.
 */
@Service
public class UserService {

    public static final List<String> ROLES = List.of("VIEWER", "AUDITOR", "ADMIN");
    private static final Pattern USERNAME = Pattern.compile("^[a-z0-9][a-z0-9._@-]{1,59}$");
    private static final Pattern EMAIL = Pattern.compile("^[^@\\s]{1,64}@[^@\\s]{1,255}$");
    private static final String PASSWORD_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

    private final KeycloakAdminClient keycloak;
    private final AuditService audit;
    private final SecureRandom random = new SecureRandom();

    public UserService(KeycloakAdminClient keycloak, AuditService audit) {
        this.keycloak = keycloak;
        this.audit = audit;
    }

    public record Status(boolean configured, String message) {
    }

    /** @param role highest SAYTU role held directly, or null */
    public record UserView(String id, String username, String email, String firstName, String lastName, boolean enabled,
                           String role, Instant createdAt, List<String> requiredActions, boolean self) {
    }

    public record CreateUser(String username, String email, String firstName, String lastName, String role) {
    }

    /** The temporary password is returned once and never stored by SAYTU. */
    public record Credentials(UserView user, String temporaryPassword) {
    }

    public Status status() {
        return keycloak.configured()
                ? new Status(true, "Utilisateurs gérés dans Keycloak (royaume saytu) via le client saytu-admin-api")
                : new Status(false, "Pas encore prête : le service keycloak-config crée l'accès à Keycloak au démarrage. "
                + "Voir « docker compose logs keycloak-config » ; en attendant, la console Keycloak reste utilisable.");
    }

    public List<UserView> list() {
        Map<String, String> roleByUser = new HashMap<>();
        for (String role : ROLES) { // later roles win: ADMIN > AUDITOR > VIEWER
            for (JsonNode u : keycloak.get("/roles/" + role + "/users?first=0&max=1000")) {
                roleByUser.put(u.path("id").asText(), role);
            }
        }
        List<UserView> users = new ArrayList<>();
        for (JsonNode u : keycloak.get("/users?first=0&max=500&briefRepresentation=false")) {
            if (u.path("username").asText().startsWith("service-account-")) {
                continue;
            }
            users.add(view(u, roleByUser.get(u.path("id").asText())));
        }
        users.sort(java.util.Comparator.comparing(UserView::username));
        return users;
    }

    public Credentials create(CreateUser request) {
        String username = request.username() == null ? "" : request.username().strip().toLowerCase(Locale.ROOT);
        if (!USERNAME.matcher(username).matches()) {
            throw new IllegalArgumentException("Identifiant invalide : 2 à 60 caractères, minuscules, chiffres, . _ @ -");
        }
        String email = request.email() == null ? "" : request.email().strip();
        if (!email.isEmpty() && !EMAIL.matcher(email).matches()) {
            throw new IllegalArgumentException("E-mail invalide");
        }
        String role = role(request.role());
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("username", username);
        if (!email.isEmpty()) {
            body.put("email", email);
        }
        body.put("firstName", trim(request.firstName(), 100));
        body.put("lastName", trim(request.lastName(), 100));
        body.put("enabled", true);
        body.put("requiredActions", List.of("UPDATE_PASSWORD"));
        String location = keycloak.post("/users", body);
        String id = location == null ? null : location.substring(location.lastIndexOf('/') + 1);
        if (id == null || id.isBlank()) {
            throw new IllegalStateException("Keycloak n'a pas renvoyé l'identifiant de l'utilisateur créé");
        }
        String password = temporaryPassword();
        keycloak.put("/users/" + id + "/reset-password", Map.of("type", "password", "value", password, "temporary", true));
        setRealmRoles(id, Set.of(), role);
        audit.record("USER_CREATED", "keycloak_user", id, Map.of("username", username, "role", role));
        return new Credentials(get(id), password);
    }

    public UserView changeRole(String id, String requestedRole) {
        String role = role(requestedRole);
        UserView user = get(id);
        if (user.self() && !"ADMIN".equals(role)) {
            throw new ConflictException("Vous ne pouvez pas retirer votre propre rôle ADMIN");
        }
        setRealmRoles(id, currentRoles(id), role);
        audit.record("USER_ROLE_CHANGED", "keycloak_user", id, Map.of("username", user.username(), "from",
                String.valueOf(user.role()), "to", role));
        return get(id);
    }

    public UserView setEnabled(String id, boolean enabled) {
        UserView user = get(id);
        if (user.self() && !enabled) {
            throw new ConflictException("Vous ne pouvez pas désactiver votre propre compte");
        }
        keycloak.put("/users/" + id, Map.of("enabled", enabled));
        audit.record(enabled ? "USER_ENABLED" : "USER_DISABLED", "keycloak_user", id, Map.of("username", user.username()));
        return get(id);
    }

    public Credentials resetPassword(String id) {
        UserView user = get(id);
        String password = temporaryPassword();
        keycloak.put("/users/" + id + "/reset-password", Map.of("type", "password", "value", password, "temporary", true));
        audit.record("USER_PASSWORD_RESET", "keycloak_user", id, Map.of("username", user.username()));
        return new Credentials(get(id), password);
    }

    UserView get(String id) {
        checkId(id);
        JsonNode u = keycloak.get("/users/" + id);
        Set<String> roles = currentRoles(id);
        String role = null;
        for (String r : ROLES) {
            if (roles.contains(r)) {
                role = r;
            }
        }
        return view(u, role);
    }

    private Set<String> currentRoles(String id) {
        Set<String> roles = new HashSet<>();
        for (JsonNode r : keycloak.get("/users/" + id + "/role-mappings/realm")) {
            roles.add(r.path("name").asText());
        }
        return roles;
    }

    /** Keeps exactly one SAYTU role (other realm roles untouched). */
    private void setRealmRoles(String id, Set<String> current, String role) {
        List<JsonNode> remove = new ArrayList<>();
        for (String r : ROLES) {
            if (!r.equals(role) && current.contains(r)) {
                remove.add(keycloak.get("/roles/" + r));
            }
        }
        if (!remove.isEmpty()) {
            keycloak.delete("/users/" + id + "/role-mappings/realm", remove);
        }
        if (!current.contains(role)) {
            keycloak.post("/users/" + id + "/role-mappings/realm", List.of(keycloak.get("/roles/" + role)));
        }
    }

    private UserView view(JsonNode u, String role) {
        List<String> actions = new ArrayList<>();
        u.path("requiredActions").forEach(a -> actions.add(a.asText()));
        long created = u.path("createdTimestamp").asLong(0);
        return new UserView(u.path("id").asText(), u.path("username").asText(), text(u, "email"), text(u, "firstName"),
                text(u, "lastName"), u.path("enabled").asBoolean(true), role, created == 0 ? null : Instant.ofEpochMilli(created),
                actions, u.path("id").asText().equals(currentSubject()));
    }

    static String role(String value) {
        String r = value == null ? "" : value.strip().toUpperCase(Locale.ROOT);
        if (!ROLES.contains(r)) {
            throw new IllegalArgumentException("Rôle inconnu : " + value + " (VIEWER, AUDITOR ou ADMIN)");
        }
        return r;
    }

    static void checkId(String id) {
        if (id == null || !id.matches("[0-9a-fA-F-]{36}")) {
            throw new IllegalArgumentException("Identifiant d'utilisateur invalide");
        }
    }

    String temporaryPassword() {
        StringBuilder b = new StringBuilder("Tmp-");
        for (int i = 0; i < 16; i++) {
            b.append(PASSWORD_CHARS.charAt(random.nextInt(PASSWORD_CHARS.length())));
        }
        return b.append("9a").toString();
    }

    private static String text(JsonNode u, String field) {
        return u.hasNonNull(field) ? u.get(field).asText() : null;
    }

    private static String trim(String v, int max) {
        String t = v == null ? "" : v.strip();
        return t.length() > max ? t.substring(0, max) : t;
    }

    private static String currentSubject() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof org.springframework.security.oauth2.jwt.Jwt jwt) {
            return jwt.getSubject();
        }
        return "";
    }
}
