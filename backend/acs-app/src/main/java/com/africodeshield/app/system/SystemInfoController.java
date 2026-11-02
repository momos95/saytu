package com.africodeshield.app.system;

import com.africodeshield.app.config.AcsProperties;
import com.africodeshield.app.config.Roles;
import com.africodeshield.app.scanner.ScannerConfigRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.info.BuildProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Platform information for the UI header and the "Paramètres" page. Phase 1 endpoint: it proves
 * the end-to-end chain (Keycloak token → role mapping → JPA → PostgreSQL) with real data.
 */
@RestController
@RequestMapping("/api/v1/system")
@Tag(name = "System")
public class SystemInfoController {

    private final ScannerConfigRepository scanners;
    private final ObjectProvider<BuildProperties> buildProperties;
    private final AcsProperties properties;

    public SystemInfoController(ScannerConfigRepository scanners, ObjectProvider<BuildProperties> buildProperties,
                                AcsProperties properties) {
        this.scanners = scanners;
        this.buildProperties = buildProperties;
        this.properties = properties;
    }

    @GetMapping("/info")
    @Transactional(readOnly = true)
    @Operation(summary = "Version, configured scanners and roles of the caller")
    public SystemInfo info(Authentication authentication) {
        BuildProperties build = buildProperties.getIfAvailable();
        List<ScannerInfo> scannerInfos = scanners.findAllByOrderByScannerIdAsc().stream()
                .map(s -> new ScannerInfo(s.getScannerId(), s.isEnabled(), s.getTimeoutSeconds(), s.getMemoryMb()))
                .toList();
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(a -> a.startsWith(Roles.PREFIX))
                .map(a -> a.substring(Roles.PREFIX.length()))
                .sorted()
                .toList();
        return new SystemInfo(
                build != null ? build.getVersion() : "dev",
                build != null && build.getTime() != null ? build.getTime().toString() : null,
                authentication.getName(),
                roles,
                scannerInfos,
                properties.security().webClientId());
    }

    public record SystemInfo(String version, String buildTime, String username, List<String> roles,
                             List<ScannerInfo> scanners, String webClientId) {
    }

    /**
     * Configuration only: whether the tool binary is installed and which version it reports is
     * added in phase 4, when the worker probes the tools.
     */
    public record ScannerInfo(String id, boolean enabled, int timeoutSeconds, int memoryMb) {
    }
}
