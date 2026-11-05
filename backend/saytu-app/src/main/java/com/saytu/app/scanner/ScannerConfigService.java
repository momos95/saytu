package com.saytu.app.scanner;

import com.saytu.app.audit.AuditService;
import com.saytu.app.web.ResourceNotFoundException;
import com.saytu.core.domain.ScannerId;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.List;
import java.util.Map;

/** Global configuration of the scanners ("Scanners & branches" page). */
@Service
public class ScannerConfigService {

    private final ScannerConfigRepository repository;
    private final AuditService audit;
    private final Clock clock;

    public ScannerConfigService(ScannerConfigRepository repository, AuditService audit, Clock clock) {
        this.repository = repository;
        this.audit = audit;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public List<ScannerView> list() {
        return repository.findAllByOrderByScannerIdAsc().stream().map(ScannerView::of).toList();
    }

    /** Configuration read by the worker before each job. */
    @Transactional(readOnly = true)
    public List<RuntimeConfig> runtimeConfigs() {
        return repository.findAllByOrderByScannerIdAsc().stream()
                .map(e -> new RuntimeConfig(e.getScannerId(), e.isEnabled(), e.toResourceLimits(), stringSettings(e.getSettings())))
                .toList();
    }

    private static Map<String, String> stringSettings(Map<String, Object> settings) {
        Map<String, String> out = new java.util.HashMap<>();
        settings.forEach((k, v) -> {
            if (k != null && v != null) {
                out.put(k, String.valueOf(v));
            }
        });
        return Map.copyOf(out);
    }

    /** Scanner settings as the scan engine consumes them. */
    public record RuntimeConfig(String scannerId, boolean enabled, com.saytu.core.scan.ResourceLimits limits,
                                Map<String, String> settings) {
    }

    @Transactional
    public ScannerView update(String scannerId, ScannerUpdate update) {
        ScannerConfigEntity entity = repository.findById(scannerId)
                .orElseThrow(() -> new ResourceNotFoundException("Unknown scanner " + scannerId));
        var auth = SecurityContextHolder.getContext().getAuthentication();
        entity.update(update.enabled(), update.timeoutSeconds(), update.cpuSeconds(), update.memoryMb(),
                auth == null ? "system" : auth.getName(), clock.instant());
        if (update.settings() != null) {
            entity.replaceSettings(ScannerSettings.validate(scannerId, update.settings()));
        }
        audit.record("SCANNER_CONFIG_UPDATED", "scanner_config", scannerId, Map.of(
                "enabled", update.enabled(), "timeoutSeconds", update.timeoutSeconds(),
                "cpuSeconds", update.cpuSeconds(), "memoryMb", update.memoryMb(),
                "settings", update.settings() == null ? Map.of() : update.settings()));
        return ScannerView.of(entity);
    }

    /**
     * @param optional            not enabled by default (OWASP Dependency-Check)
     * @param producedTypes       finding types this scanner can produce
     */
    /**
     * @param languages        languages the tool analyses (empty: every repository)
     * @param settings         current tool options
     * @param settingKeys      options that can be changed
     */
    public record ScannerView(String id, boolean enabled, int timeoutSeconds, int cpuSeconds, int memoryMb,
                              boolean optional, List<String> producedTypes, List<String> languages,
                              Map<String, String> settings, List<String> settingKeys,
                              String updatedBy, java.time.Instant updatedAt) {
        static ScannerView of(ScannerConfigEntity e) {
            var known = ScannerId.fromKey(e.getScannerId());
            return new ScannerView(e.getScannerId(), e.isEnabled(), e.getTimeoutSeconds(), e.getCpuSeconds(), e.getMemoryMb(),
                    known.map(k -> !k.enabledByDefault()).orElse(false),
                    known.map(k -> k.producedTypes().stream().map(Enum::name).sorted().toList()).orElse(List.of()),
                    LANGUAGES.getOrDefault(e.getScannerId(), List.of()),
                    stringSettings(e.getSettings()),
                    ScannerSettings.ALLOWED.getOrDefault(e.getScannerId(), Map.of()).keySet().stream().sorted().toList(),
                    e.getUpdatedBy(), e.getUpdatedAt());
        }
    }

    /** Languages per tool, for display (the worker uses the adapters' own declaration). */
    static final Map<String, List<String>> LANGUAGES = Map.of(
            "checkstyle", List.of("java"), "pmd", List.of("java"), "eslint", List.of("javascript", "typescript"),
            "phpcs", List.of("php"), "cppcheck", List.of("c", "cpp"), "sqlfluff", List.of("sql"));

    public record ScannerUpdate(boolean enabled,
                                @jakarta.validation.constraints.Min(30) @jakarta.validation.constraints.Max(21_600) int timeoutSeconds,
                                @jakarta.validation.constraints.Min(1) @jakarta.validation.constraints.Max(86_400) int cpuSeconds,
                                @jakarta.validation.constraints.Min(64) @jakarta.validation.constraints.Max(65_536) int memoryMb,
                                Map<String, String> settings) {
    }
}
