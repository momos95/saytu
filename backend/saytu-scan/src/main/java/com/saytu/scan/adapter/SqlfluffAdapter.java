package com.saytu.scan.adapter;

import com.saytu.core.domain.FindingType;
import com.saytu.core.domain.Language;
import com.saytu.core.domain.ScannerId;
import com.saytu.core.domain.Severity;
import com.saytu.core.finding.NormalizedFinding;
import com.saytu.core.scan.CommandSpec;
import com.saytu.core.scan.ScanContext;
import com.saytu.core.scan.ScannerAdapter;
import com.saytu.git.json.JsonNode;
import com.saytu.scan.lang.SourceFiles;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * SQLFluff (MIT): SQL linting. Hardened for untrusted repositories: {@code --ignore-local-config}
 * (a {@code .sqlfluff} file may select the Python templater, which runs code), {@code --templater raw}
 * (no Jinja rendering), {@code --disable-noqa}, {@code --disregard-sqlfluffignores}.
 * <p>
 * Setting {@code dialect} (default {@code ansi}): postgres, mysql, tsql, oracle, bigquery,
 * snowflake, sqlite... Parsing errors caused by a dialect mismatch are not findings.
 * Layout and capitalisation rules are INFO, the others LOW.
 */
public final class SqlfluffAdapter implements ScannerAdapter {

    static final int MAX_FILES = 2_000;
    static final Pattern DIALECT = Pattern.compile("^[a-z][a-z0-9_]{1,30}$");

    private final Path sqlfluff;

    /** @param sqlfluff the {@code sqlfluff} entry point (virtual environment) */
    public SqlfluffAdapter(Path sqlfluff) {
        this.sqlfluff = Objects.requireNonNull(sqlfluff, "sqlfluff");
    }

    @Override
    public ScannerId id() {
        return ScannerId.SQLFLUFF;
    }

    @Override
    public Set<Language> languages() {
        return Set.of(Language.SQL);
    }

    @Override
    public CommandSpec versionCommand(Path workDir) {
        return new CommandSpec(List.of(sqlfluff.toString(), "--version"), AdapterSupport.environment(workDir), workDir,
                workDir.resolve("version.txt"));
    }

    /** "sqlfluff, version 4.4.0". */
    @Override
    public String parseVersion(String stdout) {
        return stdout == null ? null : stdout.strip().replaceFirst("(?i)^.*version\\s+", "");
    }

    @Override
    public boolean isApplicable(Path sourceDir) {
        return true;
    }

    static String dialect(Map<String, String> settings) {
        String d = settings.getOrDefault("dialect", "ansi").strip().toLowerCase(java.util.Locale.ROOT);
        return DIALECT.matcher(d).matches() ? d : "ansi";
    }

    @Override
    public CommandSpec buildCommand(ScanContext context) {
        Path report = context.workDir().resolve("sqlfluff.json");
        List<Path> files;
        try {
            files = SourceFiles.list(context.sourceDir(), Set.of(Language.SQL), MAX_FILES);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        int processes = Math.clamp(AdapterSupport.intSetting(context.settings(), "processes", 2), 1, 8);
        List<String> argv = new ArrayList<>(List.of(sqlfluff.toString(), "lint",
                "--format", "json", "--write-output", report.toString(),
                "--dialect", dialect(context.settings()),
                "--templater", "raw",
                "--ignore-local-config", "--disregard-sqlfluffignores", "--disable-noqa",
                "--nofail", "--disable-progress-bar", "--nocolor",
                "--processes", String.valueOf(processes), "--"));
        files.forEach(f -> argv.add(f.toString()));
        Map<String, String> env = AdapterSupport.environment(context.workDir());
        env.put("PYTHONDONTWRITEBYTECODE", "1");
        env.put("PYTHONNOUSERSITE", "1");
        return new CommandSpec(argv, env, context.workDir(), report);
    }

    @Override
    public boolean isSuccessfulExit(int exitCode) {
        return exitCode == 0;
    }

    @Override
    public List<NormalizedFinding> parse(Path reportFile, ScanContext context) throws IOException {
        JsonNode root = AdapterSupport.readJson(reportFile);
        if (!root.isArray()) {
            throw new IOException("unexpected SQLFluff report");
        }
        List<NormalizedFinding> findings = new ArrayList<>();
        for (JsonNode file : root.elements()) {
            String path = AdapterSupport.relativePath(context.sourceDir(), file.get("filepath").asText());
            if (path == null) {
                continue;
            }
            for (JsonNode v : file.get("violations").elements()) {
                String code = v.get("code").asText();
                if (code == null || code.isBlank() || code.equals("PRS") || code.equals("TMP") || code.equals("LXR")) {
                    continue; // parse / templating / lexing problems: limits of the tool, not findings
                }
                Integer start = AdapterSupport.positiveInt(v.get("start_line_no"));
                Integer end = AdapterSupport.positiveInt(v.get("end_line_no"));
                String description = v.get("description").asText();
                String name = v.get("name").asText();
                findings.add(new NormalizedFinding(ScannerId.SQLFLUFF, "sqlfluff:" + code, FindingType.QUALITY,
                        severity(code), AdapterSupport.firstSentence(description, 200),
                        description + (name == null ? "" : "\n\nRule: " + code + " (" + name + ")"),
                        new NormalizedFinding.SourceLocation(path, start, end == null ? start : end),
                        List.of(), null, null, null, null,
                        AdapterSupport.truncate(AdapterSupport.sourceLine(context.sourceDir(), path, start), 500),
                        v.get("fixes").size() > 0 ? "Automatically fixable with sqlfluff fix (same dialect)."
                                : "Rewrite the statement as described by the rule.",
                        List.of("https://docs.sqlfluff.com/en/stable/reference/rules.html"),
                        AdapterSupport.contextHash(context.sourceDir(), path, start)));
            }
        }
        return findings;
    }

    static Severity severity(String code) {
        return code.startsWith("LT") || code.startsWith("CP") ? Severity.INFO : Severity.LOW;
    }
}
