package com.saytu.core.scoring;

import com.saytu.core.domain.FindingType;
import com.saytu.core.domain.Severity;

import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * An OPEN security, secret or dependency finding as the security score sees it.
 *
 * @param severity     effective severity (a secret is never below HIGH)
 * @param category     what kind of fix it needs, which sets its weight
 * @param group        findings fixed by the same action (one package upgrade, one rule) share a group:
 *                     the score counts the first one fully and the next ones less and less
 * @param fixAvailable for dependencies: a fixed version is published
 */
public record SecurityIssue(Severity severity, Category category, String group, boolean fixAvailable) {

    public enum Category {
        /** vulnerability in the application code (SAST) */
        CODE,
        /** credential committed to the repository */
        SECRET,
        /** vulnerable third-party package */
        DEPENDENCY,
        /** deployment or infrastructure configuration (Dockerfile, Kubernetes, Terraform, Compose…) */
        CONFIGURATION
    }

    private static final Set<String> SECRET_CWES = Set.of("CWE-798", "CWE-259", "CWE-321", "CWE-522", "CWE-312");
    private static final Pattern CONFIG_FILE = Pattern.compile(
            "(?i)(^|.*/)(dockerfile[^/]*|[^/]*\\.dockerfile|containerfile|docker-compose[^/]*\\.ya?ml|compose\\.ya?ml"
                    + "|[^/]*\\.tf|[^/]*\\.tfvars|[^/]*\\.hcl|chart\\.yaml|values[^/]*\\.ya?ml"
                    + "|(k8s|kubernetes|deploy|deployment|deployments|manifests|helm|charts|kustomize|openshift|infra)/.*\\.ya?ml)$");

    public SecurityIssue {
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(category, "category");
        group = group == null || group.isBlank() ? "?" : group;
    }

    /**
     * Classifies a finding; returns null for QUALITY findings (they belong to the quality score).
     */
    public static SecurityIssue of(FindingType type, Severity severity, String scanner, String ruleId, String filePath,
                                   List<String> cwes, String packageName, String packageVersion, String fixedVersion) {
        if (type == FindingType.QUALITY) {
            return null;
        }
        String rule = ruleId == null ? "" : ruleId;
        Category category;
        if (type == FindingType.SECRET || cwes != null && cwes.stream().anyMatch(SECRET_CWES::contains)) {
            category = Category.SECRET;
        } else if (type == FindingType.DEPENDENCY) {
            category = Category.DEPENDENCY;
        } else if ("trivy".equals(scanner) || filePath != null && CONFIG_FILE.matcher(filePath).matches()) {
            category = Category.CONFIGURATION;
        } else {
            category = Category.CODE;
        }
        Severity effective = category == Category.SECRET && severity.ordinal() > Severity.HIGH.ordinal() ? Severity.HIGH : severity;
        String group = switch (category) {
            case DEPENDENCY -> "dependency:" + (packageName == null || packageName.isBlank() ? rule
                    : packageName.toLowerCase(Locale.ROOT) + "@" + Objects.toString(packageVersion, ""));
            case SECRET -> "secret:" + rule;
            case CONFIGURATION -> "configuration:" + rule;
            case CODE -> "code:" + scanner + ":" + rule;
        };
        return new SecurityIssue(effective, category, group, fixedVersion != null && !fixedVersion.isBlank());
    }
}
