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

    @Transactional
    public ScannerView update(String scannerId, ScannerUpdate update) {
        ScannerConfigEntity entity = repository.findById(scannerId)
                .orElseThrow(() -> new ResourceNotFoundException("Unknown scanner " + scannerId));
        var auth = SecurityContextHolder.getContext().getAuthentication();
        entity.update(update.enabled(), update.timeoutSeconds(), update.cpuSeconds(), update.memoryMb(),
                auth == null ? "system" : auth.getName(), clock.instant());
        audit.record("SCANNER_CONFIG_UPDATED", "scanner_config", scannerId, Map.of(
                "enabled", update.enabled(), "timeoutSeconds", update.timeoutSeconds(),
                "cpuSeconds", update.cpuSeconds(), "memoryMb", update.memoryMb()));
        return ScannerView.of(entity);
    }

    /**
     * @param optional            not enabled by default (OWASP Dependency-Check)
     * @param producedTypes       finding types this scanner can produce
     */
    public record ScannerView(String id, boolean enabled, int timeoutSeconds, int cpuSeconds, int memoryMb,
                              boolean optional, List<String> producedTypes, String updatedBy, java.time.Instant updatedAt) {
        static ScannerView of(ScannerConfigEntity e) {
            var known = ScannerId.fromKey(e.getScannerId());
            return new ScannerView(e.getScannerId(), e.isEnabled(), e.getTimeoutSeconds(), e.getCpuSeconds(), e.getMemoryMb(),
                    known.map(k -> !k.enabledByDefault()).orElse(false),
                    known.map(k -> k.producedTypes().stream().map(Enum::name).sorted().toList()).orElse(List.of()),
                    e.getUpdatedBy(), e.getUpdatedAt());
        }
    }

    public record ScannerUpdate(boolean enabled,
                                @jakarta.validation.constraints.Min(30) @jakarta.validation.constraints.Max(21_600) int timeoutSeconds,
                                @jakarta.validation.constraints.Min(1) @jakarta.validation.constraints.Max(86_400) int cpuSeconds,
                                @jakarta.validation.constraints.Min(64) @jakarta.validation.constraints.Max(65_536) int memoryMb) {
    }
}
