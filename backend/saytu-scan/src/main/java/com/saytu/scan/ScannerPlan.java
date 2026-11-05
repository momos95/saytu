package com.saytu.scan;

import com.saytu.core.scan.ResourceLimits;
import com.saytu.core.scan.ScannerAdapter;

import java.util.Map;
import java.util.Objects;

/**
 * One scanner to run on a job, with its configuration.
 *
 * @param adapter  the tool
 * @param enabled  {@code false} records the scanner as SKIPPED
 * @param limits   sandbox limits
 * @param settings tool options from {@code scanner_config.settings}
 */
public record ScannerPlan(ScannerAdapter adapter, boolean enabled, ResourceLimits limits, Map<String, String> settings) {
    public ScannerPlan {
        Objects.requireNonNull(adapter, "adapter");
        Objects.requireNonNull(limits, "limits");
        settings = settings == null ? Map.of() : Map.copyOf(settings);
    }
}
