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
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * PHP_CodeSniffer (BSD-3-Clause): PHP coding standard, PSR-12 by default (setting {@code standard}:
 * PSR12, PSR2, PSR1, PEAR, Squiz, Zend). The standard is always passed explicitly, so a
 * {@code phpcs.xml} of the audited repository is never loaded, and {@code phpcs:ignore} annotations
 * are disregarded.
 */
public final class PhpcsAdapter implements ScannerAdapter {

    static final Set<String> STANDARDS = Set.of("PSR12", "PSR2", "PSR1", "PEAR", "SQUIZ", "ZEND");
    static final int MAX_FILES = 50_000;

    private final Path php;
    private final Path phpcs;

    /**
     * @param php   php CLI executable
     * @param phpcs the {@code bin/phpcs} script of PHP_CodeSniffer
     */
    public PhpcsAdapter(Path php, Path phpcs) {
        this.php = Objects.requireNonNull(php, "php");
        this.phpcs = Objects.requireNonNull(phpcs, "phpcs");
    }

    @Override
    public ScannerId id() {
        return ScannerId.PHPCS;
    }

    @Override
    public Set<Language> languages() {
        return Set.of(Language.PHP);
    }

    @Override
    public CommandSpec versionCommand(Path workDir) {
        return new CommandSpec(List.of(php.toString(), phpcs.toString(), "--version"), AdapterSupport.environment(workDir),
                workDir, workDir.resolve("version.txt"));
    }

    /** "PHP_CodeSniffer version 4.0.2 (stable) by Squiz and PHPCSStandards". */
    @Override
    public String parseVersion(String stdout) {
        if (stdout == null) {
            return null;
        }
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("version (\\S+)").matcher(stdout);
        return m.find() ? m.group(1) : stdout.strip();
    }

    @Override
    public boolean isApplicable(Path sourceDir) {
        return true;
    }

    static String standard(Map<String, String> settings) {
        String s = settings.getOrDefault("standard", "PSR12").strip().toUpperCase(Locale.ROOT);
        if (!STANDARDS.contains(s)) {
            return "PSR12";
        }
        return s.equals("SQUIZ") ? "Squiz" : s.equals("ZEND") ? "Zend" : s;
    }

    @Override
    public Optional<String> rulesetVersion() {
        return Optional.empty();
    }

    @Override
    public CommandSpec buildCommand(ScanContext context) {
        Path report = context.workDir().resolve("phpcs.json");
        Path list;
        try {
            list = SourceFiles.writeList(SourceFiles.list(context.sourceDir(), Set.of(Language.PHP), MAX_FILES),
                    context.workDir().resolve("phpcs-files.txt"));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        List<String> argv = List.of(php.toString(), "-d", "memory_limit=" + Math.max(128, context.limits().memoryBytes() / (1024 * 1024) * 3 / 4) + "M",
                phpcs.toString(),
                "--standard=" + standard(context.settings()),
                "--report=json", "--report-file=" + report,
                "--file-list=" + list,
                "--basepath=" + context.sourceDir(),
                "--extensions=php,phtml,inc",
                "--ignore-annotations", "--no-cache", "--no-colors", "-q",
                "--runtime-set", "ignore_warnings_on_exit", "1");
        return new CommandSpec(argv, AdapterSupport.environment(context.workDir()), context.workDir(), report);
    }

    /** Exit code is a bit mask: 1 / 2 = issues found (fixable / not), 4 and above = failure. */
    @Override
    public boolean isSuccessfulExit(int exitCode) {
        return exitCode >= 0 && exitCode <= 3;
    }

    @Override
    public List<NormalizedFinding> parse(Path reportFile, ScanContext context) throws IOException {
        JsonNode root = AdapterSupport.readJson(reportFile);
        if (!root.get("files").isObject()) {
            throw new IOException("unexpected PHP_CodeSniffer report");
        }
        List<NormalizedFinding> findings = new ArrayList<>();
        for (String file : root.get("files").fieldNames()) {
            String path = AdapterSupport.relativePath(context.sourceDir(), file);
            if (path == null) {
                continue;
            }
            for (JsonNode m : root.get("files").get(file).get("messages").elements()) {
                String source = m.get("source").asText();
                if (source == null || source.isBlank() || source.startsWith("Internal.")) {
                    continue;
                }
                Integer line = AdapterSupport.positiveInt(m.get("line"));
                String message = m.get("message").asText();
                Severity severity = "ERROR".equals(m.get("type").asText()) ? Severity.LOW : Severity.INFO;
                findings.add(new NormalizedFinding(ScannerId.PHPCS, "phpcs:" + source, FindingType.QUALITY, severity,
                        AdapterSupport.firstSentence(message, 200), message,
                        new NormalizedFinding.SourceLocation(path, line, line), List.of(), null, null, null, null,
                        AdapterSupport.truncate(AdapterSupport.sourceLine(context.sourceDir(), path, line), 500),
                        m.get("fixable").asBoolean(false)
                                ? "Automatically fixable with phpcbf (same standard)."
                                : "Adjust the code to the coding standard (" + standard(context.settings()) + ").",
                        List.of("https://www.php-fig.org/psr/psr-12/"),
                        AdapterSupport.contextHash(context.sourceDir(), path, line)));
            }
        }
        return findings;
    }
}
