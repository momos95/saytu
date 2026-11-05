package com.saytu.app.scan;

import com.saytu.app.config.SaytuProperties;
import com.saytu.app.config.SecurityConfig;
import com.saytu.app.scan.ScanViews.PageView;
import com.saytu.app.scan.ScanViews.ScanCreated;
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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(ScanController.class)
@Import(SecurityConfig.class)
@EnableConfigurationProperties(SaytuProperties.class)
class ScanControllerSecurityTest {

    @Autowired
    private MockMvc mvc;
    @MockitoBean
    private ScanService scans;

    private static RequestPostProcessor role(String role) {
        return jwt().authorities(new SimpleGrantedAuthority("ROLE_" + role));
    }

    @Test
    void everyRoleReadsTheHistory() throws Exception {
        when(scans.list(0, 20)).thenReturn(new PageView<>(List.of(), 0, 20, 0, 0));
        mvc.perform(get("/api/v1/scans").with(role("VIEWER")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(0));
    }

    @Test
    void viewersCannotLaunchNorCancel() throws Exception {
        mvc.perform(post("/api/v1/scans").with(role("VIEWER")).contentType(MediaType.APPLICATION_JSON)
                .content("{\"allTargets\":true}")).andExpect(status().isForbidden());
        mvc.perform(post("/api/v1/scans/" + UUID.randomUUID() + "/cancel").with(role("VIEWER")))
                .andExpect(status().isForbidden());
        verify(scans, never()).request(any());
        verify(scans, never()).cancel(any());
    }

    @Test
    void auditorsLaunchScans() throws Exception {
        UUID id = UUID.randomUUID();
        when(scans.request(any())).thenReturn(new ScanCreated(id));
        mvc.perform(post("/api/v1/scans").with(role("AUDITOR")).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"allTargets\":true}"))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.id").value(id.toString()));
    }

    @Test
    void anonymousCallsAreRejected() throws Exception {
        mvc.perform(get("/api/v1/scans")).andExpect(status().isUnauthorized());
    }
}
