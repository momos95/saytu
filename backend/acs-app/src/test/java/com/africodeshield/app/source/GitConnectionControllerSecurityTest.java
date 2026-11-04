package com.africodeshield.app.source;

import com.africodeshield.app.config.AcsProperties;
import com.africodeshield.app.config.SecurityConfig;
import com.africodeshield.core.domain.GitProviderType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(GitConnectionController.class)
@Import(SecurityConfig.class)
@EnableConfigurationProperties(AcsProperties.class)
class GitConnectionControllerSecurityTest {

    private static final String BODY = """
            {"name":"Corp","providerType":"GITLAB","baseUrl":"https://gitlab.corp.sn","token":"glpat-secret-value"}""";

    @Autowired
    private MockMvc mvc;

    @MockitoBean
    private GitConnectionService service;

    private static RequestPostProcessor role(String role) {
        return jwt().authorities(new SimpleGrantedAuthority("ROLE_" + role));
    }

    private static GitConnectionView view() {
        return new GitConnectionView(UUID.randomUUID(), "Corp", GitProviderType.GITLAB, "https://gitlab.corp.sn", null,
                null, true, true, null, null, "admin", Instant.EPOCH, Instant.EPOCH, 0);
    }

    @Test
    void viewerCanReadButResponseHasNoToken() throws Exception {
        when(service.list()).thenReturn(List.of(view()));
        mvc.perform(get("/api/v1/git-connections").with(role("VIEWER")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].hasToken").value(true))
                .andExpect(jsonPath("$[0].token").doesNotExist())
                .andExpect(jsonPath("$[0].tokenCiphertext").doesNotExist());
    }

    @Test
    void viewerAndAuditorCannotChangeConnections() throws Exception {
        for (String r : List.of("VIEWER", "AUDITOR")) {
            mvc.perform(post("/api/v1/git-connections").with(role(r))
                            .contentType(MediaType.APPLICATION_JSON).content(BODY))
                    .andExpect(status().isForbidden());
            mvc.perform(post("/api/v1/git-connections/test").with(role(r))
                            .contentType(MediaType.APPLICATION_JSON).content(BODY))
                    .andExpect(status().isForbidden());
            mvc.perform(delete("/api/v1/git-connections/" + UUID.randomUUID()).with(role(r)))
                    .andExpect(status().isForbidden());
        }
        verify(service, never()).create(any());
    }

    @Test
    void adminCreatesAndTheTokenIsNotEchoed() throws Exception {
        when(service.create(any())).thenReturn(view());
        mvc.perform(post("/api/v1/git-connections").with(role("ADMIN"))
                        .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isCreated())
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("glpat-secret-value"))));
    }

    @Test
    void invalidPayloadIsRejectedBeforeTheService() throws Exception {
        mvc.perform(post("/api/v1/git-connections").with(role("ADMIN"))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"\",\"providerType\":null}"))
                .andExpect(status().isBadRequest());
        verify(service, never()).create(any());
    }

    @Test
    void anonymousIsUnauthorized() throws Exception {
        mvc.perform(get("/api/v1/git-connections")).andExpect(status().isUnauthorized());
    }
}
