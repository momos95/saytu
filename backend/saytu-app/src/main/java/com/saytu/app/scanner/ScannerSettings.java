package com.saytu.app.scanner;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Tool options an administrator may change, per scanner, with their allowed values. Anything else is
 * refused: options end up on a command line (as separate arguments, never through a shell).
 */
public final class ScannerSettings {

    private static final Pattern NUMBER_1_TO_16 = Pattern.compile("^(?:[1-9]|1[0-6])$");
    private static final Pattern SECONDS = Pattern.compile("^[1-9][0-9]{0,2}$");
    private static final Pattern GLOBS = Pattern.compile("^[A-Za-z0-9_.*/\\-]+(?:,[A-Za-z0-9_.*/\\-]+)*$");
    private static final Pattern BOOLEAN = Pattern.compile("^(?:true|false)$");
    private static final Pattern PHPCS_STANDARD = Pattern.compile("^(?:PSR12|PSR2|PSR1|PEAR|Squiz|Zend)$");
    private static final Pattern SQL_DIALECT = Pattern.compile(
            "^(?:ansi|athena|bigquery|clickhouse|databricks|db2|duckdb|exasol|greenplum|hive|mariadb|materialize|mysql|"
                    + "oracle|postgres|redshift|snowflake|soql|sparksql|sqlite|teradata|trino|tsql|vertica)$");

    /** Allowed keys and value formats per scanner id. */
    static final Map<String, Map<String, Pattern>> ALLOWED = Map.of(
            "opengrep", Map.of("jobs", NUMBER_1_TO_16, "fileTimeoutSeconds", SECONDS, "exclude", GLOBS),
            "gitleaks", Map.of("honorInlineAllow", BOOLEAN),
            "pmd", Map.of("threads", NUMBER_1_TO_16),
            "cppcheck", Map.of("jobs", NUMBER_1_TO_16),
            "phpcs", Map.of("standard", PHPCS_STANDARD),
            "sqlfluff", Map.of("dialect", SQL_DIALECT, "processes", NUMBER_1_TO_16));

    private ScannerSettings() {
    }

    /** Validated copy; blank values remove the option. */
    public static Map<String, String> validate(String scannerId, Map<String, String> settings) {
        Map<String, Pattern> allowed = ALLOWED.getOrDefault(scannerId, Map.of());
        Map<String, String> result = new LinkedHashMap<>();
        if (settings == null) {
            return result;
        }
        for (var e : settings.entrySet()) {
            String key = e.getKey();
            String value = e.getValue() == null ? "" : e.getValue().strip();
            Pattern format = allowed.get(key);
            if (format == null) {
                throw new IllegalArgumentException("Unknown option '" + key + "' for " + scannerId);
            }
            if (value.isEmpty()) {
                continue;
            }
            if (value.length() > 300 || !format.matcher(value).matches()) {
                throw new IllegalArgumentException("Invalid value for " + scannerId + "." + key);
            }
            result.put(key, value);
        }
        return result;
    }
}
