package com.saytu.app.source;

import com.saytu.app.TestKeys;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Discovery → selection → branches → scope, end to end with a LOCAL connection (no external network). */
@SpringBootTest(properties = TestKeys.MASTER_KEY_PROPERTY)
@AutoConfigureMockMvc
@Testcontainers
class DiscoveryApiIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    static Path root;

    @DynamicPropertySource
    static void localRepos(DynamicPropertyRegistry registry) throws IOException {
        root = Files.createTempDirectory("saytu-it-disc");
        Path git = Files.createDirectories(root.resolve("team/api/.git"));
        Files.writeString(git.resolve("HEAD"), "ref: refs/heads/main\n");
        Files.createDirectories(git.resolve("refs/heads"));
        Files.writeString(git.resolve("refs/heads/main"), "a".repeat(40) + "\n");
        Files.writeString(git.resolve("refs/heads/develop"), "b".repeat(40) + "\n");
        registry.add("saytu.git.local-repos-root", () -> root.toString());
    }

    @AfterAll
    static void cleanup() throws IOException {
        try (Stream<Path> walk = Files.walk(root)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    @Autowired
    MockMvc mvc;

    private static RequestPostProcessor admin() {
        return jwt().jwt(j -> j.subject("u-admin").claim("preferred_username", "admin"))
                .authorities(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }

    private static String extract(String json, String field) {
        return json.replaceAll("(?s).*?\"" + field + "\":\"([^\"]+)\".*", "$1");
    }

    @Test
    void fromDiscoveryToScanScope() throws Exception {
        String connection = mvc.perform(post("/api/v1/git-connections").with(admin()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Local disc\",\"providerType\":\"LOCAL\",\"baseUrl\":\"" + root + "\"}"))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        String connectionId = extract(connection, "id");

        mvc.perform(post("/api/v1/git-connections/" + connectionId + "/discovery").with(admin()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("OK")).andExpect(jsonPath("$.found").value(1));
        String namespaces = mvc.perform(get("/api/v1/git-connections/" + connectionId + "/namespaces").with(admin()))
                .andExpect(jsonPath("$[0].kind").value("LOCAL_DIRECTORY")).andReturn().getResponse().getContentAsString();
        String namespaceId = extract(namespaces, "id");

        mvc.perform(post("/api/v1/namespaces/" + namespaceId + "/discovery").with(admin()))
                .andExpect(jsonPath("$.found").value(1));
        String repos = mvc.perform(get("/api/v1/namespaces/" + namespaceId + "/repositories?q=API").with(admin()))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.items[0].defaultBranch").value("main"))
                .andExpect(jsonPath("$.items[0].scanTarget").value(false))
                .andReturn().getResponse().getContentAsString();
        String repoId = extract(repos, "id");

        mvc.perform(put("/api/v1/repositories/selection").with(admin()).contentType(MediaType.APPLICATION_JSON)
                .content("{\"repositoryIds\":[\"" + repoId + "\"],\"selected\":true}")).andExpect(status().isOk());
        mvc.perform(get("/api/v1/scan-targets/summary").with(admin()))
                .andExpect(jsonPath("$.repositories").value(1)).andExpect(jsonPath("$.selectedNamespaces").value(1));

        mvc.perform(get("/api/v1/repositories/" + repoId + "/remote-branches").with(admin()))
                .andExpect(jsonPath("$.branches.length()").value(2));
        mvc.perform(put("/api/v1/repositories/" + repoId + "/branches").with(admin()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"branches\":[\"develop\",\"main\"]}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.branchMode").value("CUSTOM"));
        mvc.perform(put("/api/v1/repositories/" + repoId + "/branches").with(admin()).contentType(MediaType.APPLICATION_JSON)
                .content("{\"branches\":[\"--upload-pack=evil\"]}")).andExpect(status().isBadRequest());
        mvc.perform(get("/api/v1/repositories/targets").with(admin()))
                .andExpect(jsonPath("$.items[0].branches.length()").value(2));
    }
}
