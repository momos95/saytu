package com.saytu.app.user;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/users")
@Tag(name = "Users")
@PreAuthorize("hasRole('ADMIN')")
public class UserController {

    private final UserService users;

    public UserController(UserService users) {
        this.users = users;
    }

    public record RoleChange(String role) {
    }

    public record EnabledChange(boolean enabled) {
    }

    @GetMapping("/status")
    @Operation(summary = "Is user management configured (Keycloak client saytu-admin-api)?")
    public UserService.Status status() {
        return users.status();
    }

    @GetMapping
    public List<UserService.UserView> list() {
        return users.list();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Create a user with one role; returns a temporary password, shown once")
    public UserService.Credentials create(@RequestBody UserService.CreateUser request) {
        return users.create(request);
    }

    @PutMapping("/{id}/role")
    public UserService.UserView role(@PathVariable String id, @RequestBody RoleChange change) {
        return users.changeRole(id, change.role());
    }

    @PutMapping("/{id}/enabled")
    public UserService.UserView enabled(@PathVariable String id, @RequestBody EnabledChange change) {
        return users.setEnabled(id, change.enabled());
    }

    @PostMapping("/{id}/reset-password")
    @Operation(summary = "New temporary password, shown once; must be changed at next login")
    public UserService.Credentials resetPassword(@PathVariable String id) {
        return users.resetPassword(id);
    }
}
