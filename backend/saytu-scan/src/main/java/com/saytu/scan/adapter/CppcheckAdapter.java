package com.saytu.scan.adapter;

import com.saytu.core.domain.FindingType;
import com.saytu.core.domain.Language;
import com.saytu.core.domain.ScannerId;
import com.saytu.core.domain.Severity;
import com.saytu.core.finding.NormalizedFinding;
import com.saytu.core.scan.CommandSpec;
import com.saytu.core.scan.ScanContext;
import com.saytu.core.scan.ScannerAdapter;
import com.saytu.scan.lang.SourceFiles;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Cppcheck (GPL-3.0, run as a separate program): undefined behaviour, memory errors and bad
 * practices in C and C++, without compiling (no build system involved). Inline suppressions of the
 * audited code are not enabled and no project file of the repository is read.
 * <p>
 * Errors whose CWE is a memory-safety or injection weakness are SECURITY findings, the others QUALITY.
 */
public final class CppcheckAdapter implements ScannerAdapter {

    static final int MAX_FILES = 20_000;
    /** Memory safety, integer, format string and similar weaknesses reported by Cppcheck. */
    static final Set<String> SECURITY_CWES = Set.of("119", "120", "121", "122", "125", "129", "131", "134", "170",
            "190", "191", "369", "401", "415", "416", "457", "467", "476", "562", "590", "664", "665", "676", "682",
            "758", "762", "786", "787", "788", "822", "823", "824", "825");
    /** Information about the analysis itself, not about the code. */
    static final Set<String> TOOL_MESSAGES = Set.of("missingInclude", "missingIncludeSystem", "toomanyconfigs",
            "checkersReport", "normalCheckLevelMaxBranches", "noValidConfiguration", "unmatchedSuppression",
            "preprocessorErrorDirective", "syntaxError", "internalAstError", "unknownMacro", "checkLevelNormal");

    private final Path cppcheck;

    public CppcheckAdapter(Path cppcheck) {
        this.cppcheck = Objects.requireNonNull(cppcheck, "cppcheck");
    }

    @Override
    public ScannerId id() {
        return ScannerId.CPPCHECK;
    }

    @Override
    public Set<Language> languages() {
        return Set.of(Language.C, Language.CPP);
    }

    @Override
    public CommandSpec versionCommand(Path workDir) {
        return new CommandSpec(List.of(cppcheck.toString(), "--version"), AdapterSupport.environment(workDir), workDir,
                workDir.resolve("version.txt"));
    }

    @Override
    public String parseVersion(String stdout) {
        return stdout == null ? null : stdout.strip().replaceFirst("(?i)^cppcheck\\s+", "");
    }

    @Override
    public boolean isApplicable(Path sourceDir) {
        return true;
    }

    @Override
    public CommandSpec buildCommand(ScanContext context) {
        Path report = context.workDir().resolve("cppcheck.xml");
        Path list;
        try {
            list = SourceFiles.writeList(SourceFiles.list(context.sourceDir(), Set.of(Language.C, Language.CPP), MAX_FILES)
                    .stream().filter(p -> !p.getFileName().toString().endsWith(".h")).toList(),
                    context.workDir().resolve("cppcheck-files.txt"));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        int jobs = Math.clamp(AdapterSupport.intSetting(context.settings(), "jobs", 2), 1, 8);
        List<String> argv = List.of(cppcheck.toString(),
                "--xml", "--xml-version=2", "--output-file=" + report,
                "--enable=warning,style,performance,portability",
                "--file-list=" + list,
                "--max-configs=1", "--quiet", "-j", String.valueOf(jobs),
                "--suppress=missingIncludeSystem",
                "--cppcheck-build-dir=" + context.workDir());
        return new CommandSpec(argv, AdapterSupport.environment(context.workDir()), context.workDir(), report);
    }

    @Override
    public boolean isSuccessfulExit(int exitCode) {
        return exitCode == 0;
    }

    @Override
    public List<NormalizedFinding> parse(Path reportFile, ScanContext context) throws IOException {
        Document doc = XmlReports.parse(reportFile);
        if (!"results".equals(doc.getDocumentElement().getTagName())) {
            throw new IOException("unexpected Cppcheck report");
        }
        List<NormalizedFinding> findings = new ArrayList<>();
        NodeList errors = doc.getElementsByTagName("error");
        for (int i = 0; i < errors.getLength(); i++) {
            Element e = (Element) errors.item(i);
            String id = e.getAttribute("id");
            String sev = e.getAttribute("severity");
            if (id.isEmpty() || TOOL_MESSAGES.contains(id) || "information".equals(sev) || "debug".equals(sev)) {
                continue;
            }
            NodeList locations = e.getElementsByTagName("location");
            if (locations.getLength() == 0) {
                continue;
            }
            Element loc = (Element) locations.item(0);
            String path = AdapterSupport.relativePath(context.sourceDir(), loc.getAttribute("file"));
            if (path == null) {
                continue;
            }
            Integer line = XmlReports.intAttr(loc, "line");
            String cwe = e.getAttribute("cwe");
            boolean security = "error".equals(sev) && SECURITY_CWES.contains(cwe);
            String message = e.getAttribute("verbose").isEmpty() ? e.getAttribute("msg") : e.getAttribute("verbose");
            findings.add(new NormalizedFinding(ScannerId.CPPCHECK, "cppcheck:" + id,
                    security ? FindingType.SECURITY : FindingType.QUALITY, severity(sev),
                    AdapterSupport.firstSentence(e.getAttribute("msg"), 200), message,
                    new NormalizedFinding.SourceLocation(path, line, line),
                    cwe.isEmpty() || "0".equals(cwe) ? List.of() : List.of("CWE-" + cwe), null, null, null, null,
                    AdapterSupport.truncate(AdapterSupport.sourceLine(context.sourceDir(), path, line), 500),
                    "See the Cppcheck check " + id + "; fix the code path it describes.",
                    List.of("https://cppcheck.sourceforge.io/"),
                    AdapterSupport.contextHash(context.sourceDir(), path, line)));
        }
        return findings;
    }

    static Severity severity(String cppcheckSeverity) {
        return switch (cppcheckSeverity) {
            case "error" -> Severity.HIGH;
            case "warning" -> Severity.MEDIUM;
            case "style", "performance", "portability" -> Severity.LOW;
            default -> Severity.INFO;
        };
    }
}
