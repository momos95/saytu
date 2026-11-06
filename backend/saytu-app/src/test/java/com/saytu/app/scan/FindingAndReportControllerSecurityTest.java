package com.saytu.app.scan;

import com.saytu.app.config.SaytuProperties;
import com.saytu.app.config.SecurityConfig;
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

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest({FindingController.class, ReportController.class, InsightController.class})
@Import(SecurityConfig.class)
@EnableConfigurationProperties(SaytuProperties.class)
class FindingAndReportControllerSecurityTest {

    @Autowired
    private MockMvc mvc;
    @MockitoBean
    private FindingQueryService findings;
    @MockitoBean
    private FindingTriageService triage;
    @MockitoBean
    private ReportService reports;
    @MockitoBean
    private InsightService insights;

    private static RequestPostProcessor role(String role) {
        return jwt().authorities(new SimpleGrantedAuthority("ROLE_" + role));
    }

    @Test
    void viewersCannotTriage() throws Exception {
        mvc.perform(put("/api/v1/findings/" + UUID.randomUUID() + "/status").with(role("VIEWER"))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"FALSE_POSITIVE\",\"reason\":\"x\"}"))
                .andExpect(status().isForbidden());
        verify(triage, never()).changeStatus(any(), any());
    }

    @Test
    void auditorsTriageAndBadRequestsAreRejected() throws Exception {
        UUID id = UUID.randomUUID();
        when(triage.changeStatus(eq(id), any())).thenThrow(new IllegalArgumentException("Une justification est obligatoire"));
        mvc.perform(put("/api/v1/findings/" + id + "/status").with(role("AUDITOR"))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"FALSE_POSITIVE\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void reportsAreDownloadsThatAreNeverCached() throws Exception {
        when(reports.generate(eq("pdf"), any())).thenReturn(new ReportService.Report(ReportService.Format.PDF,
                "saytu-global-20261106-0930.pdf", "%PDF-1.4".getBytes(StandardCharsets.US_ASCII)));
        mvc.perform(get("/api/v1/reports/findings").param("format", "pdf").with(role("VIEWER")))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/pdf"))
                .andExpect(header().string("Cache-Control", org.hamcrest.Matchers.containsString("no-store")))
                .andExpect(header().string("Content-Disposition",
                        org.hamcrest.Matchers.startsWith("attachment; filename=\"saytu-global-20261106-0930.pdf\"")));
    }

    @Test
    void anonymousCallsAreRejected() throws Exception {
        mvc.perform(get("/api/v1/dashboard")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/reports/findings").param("format", "json")).andExpect(status().isUnauthorized());
    }
}
