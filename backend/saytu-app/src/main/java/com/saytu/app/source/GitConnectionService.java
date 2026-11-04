package com.saytu.app.source;

import com.saytu.app.audit.AuditService;
import com.saytu.app.vault.TokenVault;
import com.saytu.app.web.ConflictException;
import com.saytu.app.web.ResourceNotFoundException;
import com.saytu.core.domain.GitProviderType;
import com.saytu.core.git.GitConnectionSpec;
import com.saytu.core.git.GitProvider.ConnectionTestResult;
import com.saytu.core.security.SensitiveValue;
import com.saytu.core.security.TokenCipher;
import com.saytu.git.provider.ConnectionUrls;
import com.saytu.git.provider.GitProviders;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Use cases of the "Connexions Git" page. Tokens enter as request strings, are wrapped in
 * {@link SensitiveValue} immediately, encrypted with the row id as associated data, and are only
 * decrypted for the duration of a provider call.
 */
@Service
public class GitConnectionService {

    static final String OWNER_TABLE = "git_connection";

    private final GitConnectionRepository repository;
    private final TokenVault vault;
    private final GitProviders providers;
    private final AuditService audit;
    private final Clock clock;

    public GitConnectionService(GitConnectionRepository repository, TokenVault vault, GitProviders providers,
                                AuditService audit, Clock clock) {
        this.repository = repository;
        this.vault = vault;
        this.providers = providers;
        this.audit = audit;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public List<GitConnectionView> list() {
        return repository.findAll(Sort.by("name")).stream().map(GitConnectionView::of).toList();
    }

    @Transactional(readOnly = true)
    public GitConnectionView get(UUID id) {
        return GitConnectionView.of(find(id));
    }

    @Transactional
    public GitConnectionView create(GitConnectionRequest request) {
        GitProviderType type = request.providerType();
        URI base = ConnectionUrls.normalizeBaseUrl(type, request.baseUrl());
        URI api = ConnectionUrls.normalizeApiUrl(type, request.apiUrl());
        validateCredentials(type, request.username(), request.hasNewToken());
        if (repository.existsByName(request.name().strip())) {
            throw new ConflictException("A connection named '" + request.name().strip() + "' already exists");
        }
        GitConnectionEntity entity = new GitConnectionEntity(request.name().strip(), type, base.toString(), currentUser());
        entity.setApiUrl(api == null ? null : api.toString());
        entity.setUsername(blankToNull(request.username()));
        entity.setEnabled(request.enabled() == null || request.enabled());
        entity = saveFlush(entity);
        if (request.hasNewToken()) {
            storeToken(entity, request.token());
        }
        audit.record(AuditService.CONNECTION_CREATED, OWNER_TABLE, entity.getId().toString(), details(entity));
        return GitConnectionView.of(entity);
    }

    @Transactional
    public GitConnectionView update(UUID id, GitConnectionRequest request) {
        GitConnectionEntity entity = find(id);
        if (request.version() == null || request.version() != entity.getVersion()) {
            throw new ConflictException("The connection was modified meanwhile (version " + entity.getVersion()
                    + "); reload it before saving");
        }
        if (request.providerType() != entity.getProviderType()) {
            throw new IllegalArgumentException("The platform type of an existing connection cannot be changed");
        }
        GitProviderType type = entity.getProviderType();
        URI newBase = ConnectionUrls.normalizeBaseUrl(type, request.baseUrl());
        URI newApi = ConnectionUrls.normalizeApiUrl(type, request.apiUrl());
        boolean keepsStoredToken = entity.hasToken() && !request.hasNewToken() && !request.clearToken();
        if (keepsStoredToken && ConnectionUrls.tokenReentryRequired(URI.create(entity.getBaseUrl()),
                entity.getApiUrl() == null ? null : URI.create(entity.getApiUrl()), newBase, newApi)) {
            throw new IllegalArgumentException("The server address changed: type the token again so that the stored "
                    + "token is never sent to a different host");
        }
        boolean willHaveToken = request.hasNewToken() || keepsStoredToken;
        validateCredentials(type, request.username(), willHaveToken);

        String newName = request.name().strip();
        if (!newName.equals(entity.getName()) && repository.existsByName(newName)) {
            throw new ConflictException("A connection named '" + newName + "' already exists");
        }
        boolean credentialsChanged = request.hasNewToken() || (request.clearToken() && entity.hasToken())
                || !Objects.equals(blankToNull(request.username()), entity.getUsername())
                || !newBase.toString().equals(entity.getBaseUrl())
                || !Objects.equals(newApi == null ? null : newApi.toString(), entity.getApiUrl());

        entity.setName(newName);
        entity.setBaseUrl(newBase.toString());
        entity.setApiUrl(newApi == null ? null : newApi.toString());
        entity.setUsername(blankToNull(request.username()));
        if (request.enabled() != null) {
            entity.setEnabled(request.enabled());
        }
        if (request.hasNewToken()) {
            storeToken(entity, request.token());
        } else if (request.clearToken() && entity.hasToken()) {
            entity.setEncryptedToken(null, null);
            audit.record(AuditService.CONNECTION_TOKEN_CHANGED, OWNER_TABLE, id.toString(), Map.of("token", "removed"));
        }
        if (credentialsChanged) {
            entity.clearTestResult();
        }
        audit.record(AuditService.CONNECTION_UPDATED, OWNER_TABLE, id.toString(), details(entity));
        return GitConnectionView.of(saveFlush(entity));
    }

    @Transactional
    public void delete(UUID id) {
        GitConnectionEntity entity = find(id);
        Map<String, Object> details = details(entity);
        repository.delete(entity);
        audit.record(AuditService.CONNECTION_DELETED, OWNER_TABLE, id.toString(), details);
    }

    /** Tests a saved connection with its stored token and records the outcome. */
    @Transactional
    public ConnectionTestView test(UUID id) {
        GitConnectionEntity entity = find(id);
        Instant now = clock.instant();
        ConnectionTestResult result;
        try (SensitiveValue token = decryptToken(entity)) {
            result = runTest(entity.getProviderType(), URI.create(entity.getBaseUrl()),
                    entity.getApiUrl() == null ? null : URI.create(entity.getApiUrl()), entity.getUsername(), token);
        }
        entity.recordTest(ConnectionTestView.status(result), result.success() ? null : result.errorMessage(),
                result.authenticatedAs(), result.serverVersion(), result.warnings(), result.tokenExpiresAt(), now);
        if (result.success() && entity.hasToken() && vault.needsReEncryption(entity.getTokenKeyId())) {
            // Lazy key rotation: re-encrypt with the active master key on first successful use.
            try (SensitiveValue token = decryptToken(entity)) {
                TokenCipher.Encrypted e = vault.encrypt(token, TokenVault.owner(OWNER_TABLE, entity.getId()));
                entity.setEncryptedToken(e.ciphertext(), e.keyId());
            }
        }
        audit.record(AuditService.CONNECTION_TESTED, OWNER_TABLE, id.toString(),
                Map.of("status", ConnectionTestView.status(result)));
        return ConnectionTestView.of(result, now);
    }

    /** Tests connection settings before saving them. Nothing is persisted except the audit entry. */
    @Transactional
    public ConnectionTestView testDraft(GitConnectionRequest request) {
        GitProviderType type = request.providerType();
        URI base = ConnectionUrls.normalizeBaseUrl(type, request.baseUrl());
        URI api = ConnectionUrls.normalizeApiUrl(type, request.apiUrl());
        validateCredentials(type, request.username(), request.hasNewToken());
        ConnectionTestResult result;
        try (SensitiveValue token = request.hasNewToken() ? SensitiveValue.of(request.token().strip()) : null) {
            result = runTest(type, base, api, request.username(), token);
        }
        audit.record(AuditService.CONNECTION_TESTED, OWNER_TABLE, null,
                Map.of("draft", true, "providerType", type.name(), "host", hostOf(base),
                        "status", ConnectionTestView.status(result)));
        return ConnectionTestView.of(result, clock.instant());
    }

    // ------------------------------------------------------------------ internals

    private ConnectionTestResult runTest(GitProviderType type, URI base, URI api, String username, SensitiveValue token) {
        GitConnectionSpec spec = new GitConnectionSpec(type, base, api, blankToNull(username), token, true);
        return providers.get(type).testConnection(spec);
    }

    private void storeToken(GitConnectionEntity entity, String token) {
        try (SensitiveValue value = SensitiveValue.of(token.strip())) {
            TokenCipher.Encrypted e = vault.encrypt(value, TokenVault.owner(OWNER_TABLE, entity.getId()));
            entity.setEncryptedToken(e.ciphertext(), e.keyId());
        }
        audit.record(AuditService.CONNECTION_TOKEN_CHANGED, OWNER_TABLE, entity.getId().toString(), Map.of("token", "set"));
    }

    private SensitiveValue decryptToken(GitConnectionEntity entity) {
        if (!entity.hasToken()) {
            return null;
        }
        return vault.decrypt(entity.getTokenCiphertext(), entity.getTokenKeyId(),
                TokenVault.owner(OWNER_TABLE, entity.getId()));
    }

    static void validateCredentials(GitProviderType type, String username, boolean hasToken) {
        if (type == GitProviderType.LOCAL && (hasToken || username != null && !username.isBlank())) {
            throw new IllegalArgumentException("Local connections take no token nor username");
        }
        if (username != null && !username.isBlank() && !hasToken) {
            throw new IllegalArgumentException("A username is only used together with a token");
        }
        if (username != null && username.contains(":")) {
            throw new IllegalArgumentException("The username must not contain ':'");
        }
    }

    private GitConnectionEntity saveFlush(GitConnectionEntity entity) {
        try {
            return repository.saveAndFlush(entity);
        } catch (DataIntegrityViolationException e) {
            throw new ConflictException("The connection conflicts with an existing one (duplicate name?)");
        }
    }

    private GitConnectionEntity find(UUID id) {
        return repository.findById(id).orElseThrow(() -> new ResourceNotFoundException("Git connection " + id + " not found"));
    }

    private static Map<String, Object> details(GitConnectionEntity e) {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("name", e.getName());
        d.put("providerType", e.getProviderType().name());
        d.put("baseUrl", e.getBaseUrl());
        d.put("hasToken", e.hasToken());
        d.put("enabled", e.isEnabled());
        return d;
    }

    private static String currentUser() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        return auth == null ? "system" : auth.getName();
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s.strip();
    }

    private static String hostOf(URI uri) {
        return uri.getHost() != null ? uri.getHost() : "local";
    }
}
