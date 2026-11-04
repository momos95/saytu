package com.saytu.app.system;

import com.saytu.app.config.SaytuProperties;
import com.saytu.app.config.SecurityConfig;
import com.saytu.app.scanner.ScannerConfigEntity;
import com.saytu.app.scanner.ScannerConfigRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(SystemInfoController.class)
@Import(SecurityConfig.class)
@EnableConfigurationProperties(SaytuProperties.class)
class SystemInfoControllerSecurityTest {

    @Autowired
    private MockMvc mvc;

    @MockitoBean
    private ScannerConfigRepository scanners;

    @BeforeEach
    void setUp() {
        ScannerConfigEntity trivy = mock(ScannerConfigEntity.class);
        when(trivy.getScannerId()).thenReturn("trivy");
        when(trivy.isEnabled()).thenReturn(true);
        when(trivy.getTimeoutSeconds()).thenReturn(900);
        when(trivy.getMemoryMb()).thenReturn(2048);
        when(scanners.findAllByOrderByScannerIdAsc()).thenReturn(List.of(trivy));
    }

    @Test
    void anonymousCallIsRejected() throws Exception {
        mvc.perform(get("/api/v1/system/info"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().exists("WWW-Authenticate"));
    }

    @Test
    void tokenWithoutApplicationRoleIsForbidden() throws Exception {
        mvc.perform(get("/api/v1/system/info").with(jwt().authorities(new SimpleGrantedAuthority("ROLE_OTHER"))))
                .andExpect(status().isForbidden());
    }

    @Test
    void viewerGetsRealConfiguration() throws Exception {
        mvc.perform(get("/api/v1/system/info")
                        .with(jwt().jwt(j -> j.claim("preferred_username", "awa"))
                                .authorities(new SimpleGrantedAuthority("ROLE_VIEWER"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles[0]").value("VIEWER"))
                .andExpect(jsonPath("$.scanners[0].id").value("trivy"))
                .andExpect(jsonPath("$.scanners[0].enabled").value(true))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().exists("Content-Security-Policy"));
    }

    @Test
    void unknownPathsAreDeniedEvenWhenAuthenticated() throws Exception {
        mvc.perform(get("/internal/anything").with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isForbidden());
    }
}
