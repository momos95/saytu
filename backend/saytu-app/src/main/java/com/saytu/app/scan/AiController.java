package com.saytu.app.scan;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1")
@Tag(name = "Local AI")
public class AiController {

    private final AiService ai;

    public AiController(AiService ai) {
        this.ai = ai;
    }

    @GetMapping("/settings/ai")
    @Operation(summary = "Local AI (Ollama) settings; enabled=false by default")
    public AiSettings settings() {
        return ai.settings();
    }

    @PutMapping("/settings/ai")
    @PreAuthorize("hasRole('ADMIN')")
    public AiSettings update(@RequestBody AiSettings settings) {
        return ai.update(settings);
    }

    @PostMapping("/settings/ai/test")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Check that Ollama answers and has the configured model")
    public AiService.TestResult test() {
        return ai.test();
    }

    @GetMapping("/findings/{id}/ai-explanation")
    @Operation(summary = "Last explanation generated for the finding (204 if none)")
    public ResponseEntity<AiService.Explanation> cached(@PathVariable UUID id) {
        AiService.Explanation e = ai.cached(id);
        return e == null ? ResponseEntity.noContent().build() : ResponseEntity.ok(e);
    }

    @PostMapping("/findings/{id}/ai-explanation")
    @PreAuthorize("hasAnyRole('AUDITOR', 'ADMIN')")
    @Operation(summary = "Generate an explanation with the local model (never applied to the code)")
    public AiService.Explanation generate(@PathVariable UUID id) {
        return ai.generate(id);
    }
}
