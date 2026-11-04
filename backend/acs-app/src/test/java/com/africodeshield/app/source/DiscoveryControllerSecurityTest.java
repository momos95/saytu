package com.africodeshield.app.source;

import com.africodeshield.app.config.AcsProperties;
import com.africodeshield.app.config.SecurityConfig;
import com.africodeshield.app.source.SourceViews.ScanTargetSummary;
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

import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(DiscoveryController.class)
@Import(SecurityConfig.class)
@EnableConfigurationProperties(AcsProperties.class)
class DiscoveryControllerSecurityTest {

    @Autowired
    private MockMvc mvc;
    @MockitoBean
    private DiscoveryService discovery;
    @MockitoBean
    private SelectionService selection;

    private static RequestPostProcessor role(String role) {
        return jwt().authorities(new SimpleGrantedAuthority("ROLE_" + role));
    }

    @Test
    void everyRoleCanReadTheScope() throws Exception {
        when(selection.summary()).thenReturn(new ScanTargetSummary(2, 10, 7, 2, 1));
        mvc.perform(get("/api/v1/scan-targets/summary").with(role("VIEWER")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.repositories").value(10));
    }

    @Test
    void onlyAdminsSynchroniseOrChangeTheScope() throws Exception {
        UUID id = UUID.randomUUID();
        for (String r : List.of("VIEWER", "AUDITOR")) {
            mvc.perform(post("/api/v1/git-connections/" + id + "/discovery").with(role(r))).andExpect(status().isForbidden());
            mvc.perform(put("/api/v1/namespaces/" + id + "/selection").with(role(r)).contentType(MediaType.APPLICATION_JSON)
                    .content("{\"selected\":true,\"includeAllRepositories\":true}")).andExpect(status().isForbidden());
            mvc.perform(get("/api/v1/repositories/" + id + "/remote-branches").with(role(r))).andExpect(status().isForbidden());
        }
        verify(discovery, never()).syncNamespaces(any());
        verify(selection, never()).selectNamespace(any(), anyBoolean(), anyBoolean());
    }

    @Test
    void requestsAreValidated() throws Exception {
        mvc.perform(put("/api/v1/repositories/selection").with(role("ADMIN")).contentType(MediaType.APPLICATION_JSON)
                .content("{\"repositoryIds\":[],\"selected\":true}")).andExpect(status().isBadRequest());
        mvc.perform(put("/api/v1/repositories/branch-mode").with(role("ADMIN")).contentType(MediaType.APPLICATION_JSON)
                .content("{\"repositoryIds\":[\"" + UUID.randomUUID() + "\"],\"mode\":\"EVERYTHING\"}")).andExpect(status().isBadRequest());
        mvc.perform(post("/api/v1/git-connections/" + UUID.randomUUID() + "/namespaces").with(role("ADMIN"))
                .contentType(MediaType.APPLICATION_JSON).content("{\"path\":\" \"}")).andExpect(status().isBadRequest());
    }
}
