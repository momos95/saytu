package com.saytu.app.system;

import com.saytu.app.config.SaytuProperties;
import com.saytu.app.config.SecurityConfig;
import com.saytu.app.scanner.ScannerConfigService;
import com.saytu.app.scanner.ScannerConfigService.ScannerView;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;

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
    private ScannerConfigService scanners;

    @BeforeEach
    void setUp() {
        when(scanners.list()).thenReturn(List.of(new ScannerView("trivy", true, 900, 1800, 2048, false,
                List.of("DEPENDENCY", "SECURITY"), null, Instant.EPOCH)));
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
