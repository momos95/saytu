package com.saytu.app.scanner;

import com.saytu.app.scanner.ScannerConfigService.ScannerUpdate;
import com.saytu.app.scanner.ScannerConfigService.ScannerView;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/scanners")
@Tag(name = "Scanners")
public class ScannerConfigController {

    private final ScannerConfigService service;

    public ScannerConfigController(ScannerConfigService service) {
        this.service = service;
    }

    @GetMapping
    @Operation(summary = "Scanner configuration (enabled, limits)")
    public List<ScannerView> list() {
        return service.list();
    }

    @PutMapping("/{scannerId}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Enable or disable a scanner and set its limits")
    public ScannerView update(@PathVariable String scannerId, @Valid @RequestBody ScannerUpdate update) {
        return service.update(scannerId, update);
    }
}
