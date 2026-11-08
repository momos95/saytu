package com.saytu.app.scan;

import com.saytu.app.config.SaytuProperties;
import com.saytu.app.config.SecurityConfig;
import com.saytu.app.user.UserController;
import com.saytu.app.user.UserService;
import com.saytu.app.web.ServiceUnavailableException;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest({ScheduleController.class, WebhookController.class, AiController.class, JobComparisonController.class,
        UserController.class})
@Import(SecurityConfig.class)
@EnableConfigurationProperties(SaytuProperties.class)
class AutomationControllerSecurityTest {

    @Autowired
    private MockMvc mvc;
    @MockitoBean
    private ScheduleService schedules;
    @MockitoBean
    private WebhookService webhooks;
    @MockitoBean
    private AiService ai;
    @MockitoBean
    private JobComparisonService comparisons;
    @MockitoBean
    private UserService users;

    private static RequestPostProcessor role(String role) {
        return jwt().authorities(new SimpleGrantedAuthority("ROLE_" + role));
    }

    @Test
    void administrationIsForAdminsOnly() throws Exception {
        mvc.perform(get("/api/v1/webhooks").with(role("AUDITOR"))).andExpect(status().isForbidden());
        mvc.perform(get("/api/v1/users").with(role("AUDITOR"))).andExpect(status().isForbidden());
        mvc.perform(post("/api/v1/schedules").with(role("AUDITOR")).contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"n\",\"cronExpression\":\"0 2 * * *\"}")).andExpect(status().isForbidden());
        mvc.perform(put("/api/v1/settings/ai").with(role("AUDITOR")).contentType(MediaType.APPLICATION_JSON)
                .content("{\"enabled\":true,\"baseUrl\":\"http://ollama:11434\",\"model\":\"m\",\"timeoutSeconds\":60}"))
                .andExpect(status().isForbidden());
        verify(schedules, never()).create(any());
        verify(ai, never()).update(any());
    }

    @Test
    void viewersReadSchedulesButCannotGenerateExplanations() throws Exception {
        when(schedules.list()).thenReturn(List.of());
        mvc.perform(get("/api/v1/schedules").with(role("VIEWER"))).andExpect(status().isOk());
        mvc.perform(post("/api/v1/findings/" + UUID.randomUUID() + "/ai-explanation").with(role("VIEWER")))
                .andExpect(status().isForbidden());
        verify(ai, never()).generate(any());
    }

    @Test
    void anUnconfiguredIntegrationAnswers503() throws Exception {
        when(users.list()).thenThrow(new ServiceUnavailableException("Gestion des utilisateurs non configurée"));
        mvc.perform(get("/api/v1/users").with(role("ADMIN"))).andExpect(status().isServiceUnavailable());
        UUID id = UUID.randomUUID();
        when(ai.generate(id)).thenThrow(new ServiceUnavailableException("IA locale désactivée"));
        mvc.perform(post("/api/v1/findings/" + id + "/ai-explanation").with(role("AUDITOR")))
                .andExpect(status().isServiceUnavailable());
    }
}
