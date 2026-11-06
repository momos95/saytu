package com.saytu.core.report;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.Map;

/** French labels shared by the HTML and PDF reports. */
final class Labels {

    static final Map<String, String> SEVERITY = Map.of("CRITICAL", "Critique", "HIGH", "Élevée", "MEDIUM", "Moyenne",
            "LOW", "Faible", "INFO", "Info");
    static final Map<String, String> TYPE = Map.of("SECURITY", "Sécurité", "QUALITY", "Qualité", "SECRET", "Secret",
            "DEPENDENCY", "Dépendance");
    static final Map<String, String> STATUS = Map.of("OPEN", "Ouverte", "RESOLVED", "Corrigée",
            "ACCEPTED_RISK", "Risque accepté", "FALSE_POSITIVE", "Faux positif");
    static final Map<String, String> EXECUTION = Map.of("SUCCEEDED", "réussi", "FAILED", "échec",
            "TIMED_OUT", "délai dépassé", "SKIPPED", "non exécuté", "NOT_APPLICABLE", "rien à analyser");
    static final Map<String, String> RELIABILITY = Map.of("HIGH", "élevée", "MEDIUM", "moyenne", "LOW", "faible",
            "INSUFFICIENT", "couverture insuffisante");
    static final String[] SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"};

    private static final DateTimeFormatter DATE_TIME = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm 'UTC'", Locale.FRANCE)
            .withZone(ZoneOffset.UTC);

    private Labels() {
    }

    static String of(Map<String, String> labels, String key) {
        return key == null ? "" : labels.getOrDefault(key, key);
    }

    static String tool(String scanner) {
        return SarifReport.TOOL_NAMES.getOrDefault(scanner, scanner);
    }

    static String date(Instant i) {
        return i == null ? "—" : DATE_TIME.format(i);
    }

    /** "82" or "—" (score not computed: coverage too low). */
    static String score(Double d) {
        return d == null ? "—" : Long.toString(Math.round(d));
    }

    static String percent(double d) {
        return Math.round(d) + " %";
    }

    static String shortSha(String sha) {
        return sha == null ? "—" : sha.length() > 10 ? sha.substring(0, 10) : sha;
    }
}
