package com.saytu.app.user;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.saytu.app.web.ResourceNotFoundException;
import com.saytu.app.web.ServiceUnavailableException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;

/**
 * Minimal client of the Keycloak Admin REST API for the saytu realm, authenticated as the service
 * account of the confidential client {@code saytu-admin-api} (roles view-users, query-users,
 * manage-users of that realm only). Never logs tokens or passwords.
 */
@Component
public class KeycloakAdminClient {

    private final ObjectMapper json;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER).build();
    private final String baseUrl;
    private final String realm;
    private final String clientId;
    private final String clientSecret;
    private String token;
    private Instant tokenExpiry = Instant.EPOCH;

    public KeycloakAdminClient(ObjectMapper json,
                               @Value("${saytu.keycloak-admin.url:http://keycloak:8080}") String baseUrl,
                               @Value("${saytu.keycloak-admin.realm:saytu}") String realm,
                               @Value("${saytu.keycloak-admin.client-id:saytu-admin-api}") String clientId,
                               @Value("${saytu.keycloak-admin.client-secret:}") String clientSecret) {
        this.json = json;
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.realm = realm;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public boolean configured() {
        return clientSecret != null && !clientSecret.isBlank();
    }

    JsonNode get(String path) {
        return call("GET", path, null);
    }

    /** POST; returns the Location header (created resource) or null. */
    String post(String path, Object body) {
        HttpResponse<String> r = send("POST", path, body);
        return r.headers().firstValue("Location").orElse(null);
    }

    void put(String path, Object body) {
        send("PUT", path, body);
    }

    void delete(String path, Object body) {
        send("DELETE", path, body);
    }

    private JsonNode call(String method, String path, Object body) {
        HttpResponse<String> r = send(method, path, body);
        try {
            return r.body() == null || r.body().isBlank() ? json.nullNode() : json.readTree(r.body());
        } catch (IOException e) {
            throw new ServiceUnavailableException("Réponse illisible de Keycloak");
        }
    }

    private HttpResponse<String> send(String method, String path, Object body) {
        try {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + "/admin/realms/" + realm + path))
                    .timeout(Duration.ofSeconds(10)).header("Authorization", "Bearer " + token())
                    .header("Accept", "application/json");
            if (body == null) {
                b.method(method, HttpRequest.BodyPublishers.noBody());
            } else {
                b.header("Content-Type", "application/json").method(method,
                        HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body), StandardCharsets.UTF_8));
            }
            HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
            int status = r.statusCode();
            if (status == 404) {
                throw new ResourceNotFoundException("Utilisateur introuvable dans Keycloak");
            }
            if (status == 409) {
                throw new IllegalArgumentException("Un utilisateur avec ce nom ou cet e-mail existe déjà");
            }
            if (status == 400) {
                throw new IllegalArgumentException("Keycloak a refusé la demande : " + errorMessage(r.body()));
            }
            if (status == 401 || status == 403) {
                throw new ServiceUnavailableException("Le client saytu-admin-api n'a pas les droits nécessaires "
                        + "(relancer scripts/keycloak-admin-client)");
            }
            if (status >= 300) {
                throw new ServiceUnavailableException("Keycloak a répondu HTTP " + status);
            }
            return r;
        } catch (IOException e) {
            throw new ServiceUnavailableException("Keycloak injoignable (" + e.getClass().getSimpleName() + ")");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ServiceUnavailableException("Interrompu");
        }
    }

    private String errorMessage(String body) {
        try {
            JsonNode n = json.readTree(body == null ? "{}" : body);
            String m = n.path("errorMessage").asText(n.path("error_description").asText(n.path("error").asText("")));
            return m.length() > 200 ? m.substring(0, 200) : m;
        } catch (IOException e) {
            return "";
        }
    }

    private synchronized String token() throws IOException, InterruptedException {
        if (!configured()) {
            throw new ServiceUnavailableException("Gestion des utilisateurs non configurée : lancer scripts/keycloak-admin-client "
                    + "(crée le client saytu-admin-api et renseigne SAYTU_KEYCLOAK_ADMIN_CLIENT_SECRET), puis redémarrer l'API");
        }
        if (token != null && Instant.now().isBefore(tokenExpiry)) {
            return token;
        }
        String form = "grant_type=client_credentials&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(baseUrl + "/realms/" + realm
                        + "/protocol/openid-connect/token")).timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form)).build(), HttpResponse.BodyHandlers.ofString());
        if (r.statusCode() != 200) {
            throw new ServiceUnavailableException("Authentification du client saytu-admin-api refusée (HTTP " + r.statusCode()
                    + ") : vérifier SAYTU_KEYCLOAK_ADMIN_CLIENT_SECRET");
        }
        JsonNode n = json.readTree(r.body());
        token = n.path("access_token").asText();
        tokenExpiry = Instant.now().plusSeconds(Math.max(10, n.path("expires_in").asLong(60) - 15));
        return token;
    }
}
