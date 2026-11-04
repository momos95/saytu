package com.africodeshield.app.source;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
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

/** "Connexions Git" page. Reading is open to every role; changes and tests are reserved to ADMIN. */
@RestController
@RequestMapping("/api/v1/git-connections")
@Tag(name = "Git connections")
public class GitConnectionController {

    private final GitConnectionService service;

    public GitConnectionController(GitConnectionService service) {
        this.service = service;
    }

    @GetMapping
    @Operation(summary = "List connections (tokens are never returned)")
    public List<GitConnectionView> list() {
        return service.list();
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get one connection")
    public GitConnectionView get(@PathVariable UUID id) {
        return service.get(id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Register a connection; the token is encrypted before storage")
    public GitConnectionView create(@Valid @RequestBody GitConnectionRequest request) {
        return service.create(request);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Update a connection; omit the token to keep it, it must be re-typed if the host changes")
    public GitConnectionView update(@PathVariable UUID id, @Valid @RequestBody GitConnectionRequest request) {
        return service.update(id, request);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Delete a connection with its namespaces, repositories and results")
    public void delete(@PathVariable UUID id) {
        service.delete(id);
    }

    @PostMapping("/{id}/test")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Test a saved connection and store the outcome")
    public ConnectionTestView test(@PathVariable UUID id) {
        return service.test(id);
    }

    @PostMapping("/test")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Test connection settings before saving them")
    public ConnectionTestView testDraft(@Valid @RequestBody GitConnectionRequest request) {
        return service.testDraft(request);
    }
}
