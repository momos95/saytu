package com.saytu.app.scan;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/webhooks")
@Tag(name = "Webhooks")
@PreAuthorize("hasRole('ADMIN')")
public class WebhookController {

    private final WebhookService webhooks;

    public WebhookController(WebhookService webhooks) {
        this.webhooks = webhooks;
    }

    @GetMapping
    public List<WebhookService.WebhookView> list() {
        return webhooks.list();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Create a webhook (generic JSON or Slack-compatible, minimum severity, optional HMAC secret)")
    public WebhookService.WebhookView create(@RequestBody WebhookService.WebhookRequest request) {
        return webhooks.create(request);
    }

    @PutMapping("/{id}")
    public WebhookService.WebhookView update(@PathVariable UUID id, @RequestBody WebhookService.WebhookRequest request) {
        return webhooks.update(id, request);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable UUID id) {
        webhooks.delete(id);
    }

    @PostMapping("/{id}/test")
    @Operation(summary = "Send a test message now and report the HTTP result")
    public WebhookService.TestResult test(@PathVariable UUID id) {
        return webhooks.test(id);
    }

    @GetMapping("/{id}/deliveries")
    @Operation(summary = "Last 20 deliveries of the endpoint")
    public List<WebhookService.DeliveryView> deliveries(@PathVariable UUID id) {
        return webhooks.deliveries(id);
    }
}
