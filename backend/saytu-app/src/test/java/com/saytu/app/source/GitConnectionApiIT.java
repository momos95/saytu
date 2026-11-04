package com.saytu.app.source;

import com.saytu.app.TestKeys;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End to end through HTTP, security, service, vault, Flyway schema and a real provider (LOCAL,
 * which needs no external network). Requires Docker.
 */
@SpringBootTest(properties = TestKeys.MASTER_KEY_PROPERTY)
@AutoConfigureMockMvc
@Testcontainers
class GitConnectionApiIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    static Path localRoot;

    @DynamicPropertySource
    static void localRepos(DynamicPropertyRegistry registry) throws IOException {
        localRoot = Files.createTempDirectory("saytu-it-git");
        Files.createDirectories(localRoot.resolve("team/app/.git"));
        registry.add("saytu.git.local-repos-root", () -> localRoot.toString());
    }

    @AfterAll
    static void cleanup() throws IOException {
        try (Stream<Path> walk = Files.walk(localRoot)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    @Autowired
    MockMvc mvc;
    @Autowired
    JdbcTemplate jdbc;

    private static org.springframework.test.web.servlet.request.RequestPostProcessor admin() {
        return jwt().jwt(j -> j.subject("u-admin").claim("preferred_username", "admin"))
                .authorities(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }

    @Test
    void tokenIsStoredEncryptedAndAuditTrailIsWritten() throws Exception {
        mvc.perform(post("/api/v1/git-connections").with(admin()).contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name":"GitHub IT","providerType":"GITHUB","token":"ghp_IntegrationSecret123"}"""))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.baseUrl").value("https://github.com"))
                .andExpect(jsonPath("$.hasToken").value(true));

        byte[] stored = jdbc.queryForObject("SELECT token_ciphertext FROM git_connection WHERE name = 'GitHub IT'", byte[].class);
        assertThat(new String(stored, StandardCharsets.ISO_8859_1)).doesNotContain("IntegrationSecret");
        assertThat(jdbc.queryForObject("SELECT token_key_id FROM git_connection WHERE name = 'GitHub IT'", String.class))
                .startsWith("k");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_event WHERE action = 'GIT_CONNECTION_CREATED' "
                + "AND actor_username = 'admin'", Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_event WHERE details::text LIKE '%IntegrationSecret%'",
                Integer.class)).isZero();
    }

    @Test
    void localConnectionIsTestedForReal() throws Exception {
        String body = mvc.perform(post("/api/v1/git-connections").with(admin()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Local IT\",\"providerType\":\"LOCAL\",\"baseUrl\":\"" + localRoot + "\"}"))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        String id = body.replaceAll(".*\"id\":\"([^\"]+)\".*", "$1");

        mvc.perform(post("/api/v1/git-connections/" + id + "/test").with(admin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.serverVersion").value("1 repository found"));

        mvc.perform(get("/api/v1/git-connections/" + id).with(admin()))
                .andExpect(jsonPath("$.lastTest.status").value("OK"));
    }

    @Test
    void localPathOutsideTheRootIsBlocked() throws Exception {
        mvc.perform(post("/api/v1/git-connections/test").with(admin()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"x\",\"providerType\":\"LOCAL\",\"baseUrl\":\"/etc\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.status").value("BLOCKED_BY_POLICY"));
    }

    @Test
    void metadataEndpointIsBlockedBeforeAnyRequest() throws Exception {
        mvc.perform(post("/api/v1/git-connections/test").with(admin()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"x\",\"providerType\":\"GITLAB\",\"baseUrl\":\"https://169.254.169.254\",\"token\":\"t\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("BLOCKED_BY_POLICY"));
    }
}
