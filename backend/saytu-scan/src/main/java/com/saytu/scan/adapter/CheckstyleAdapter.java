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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Checkstyle (LGPL-2.1+): Java conventions, with the SAYTU configuration
 * ({@code scanners/checkstyle/saytu-checks.xml}). Severities are SAYTU's, per check: probable bugs
 * MEDIUM, complexity and size LOW, naming / imports / readability INFO.
 */
public final class CheckstyleAdapter implements ScannerAdapter {

    static final String MAIN = "com.puppycrawl.tools.checkstyle.Main";

    private static final Set<String> PROBABLE_BUGS = Set.of("EqualsHashCode", "StringLiteralEquality", "EmptyCatchBlock",
            "FallThrough", "MissingSwitchDefault", "InnerAssignment", "IllegalInstantiation", "EmptyStatement",
            "CovariantEquals", "SuperClone", "SuperFinalize", "ModifiedControlVariable", "IllegalCatch");
    private static final Set<String> MAINTAINABILITY = Set.of("CyclomaticComplexity", "BooleanExpressionComplexity",
            "NestedIfDepth", "NestedForDepth", "NestedTryDepth", "MethodLength", "ParameterNumber", "ReturnCount",
            "FileLength");
    private static final Map<String, String> RECOMMENDATIONS = Map.ofEntries(
            Map.entry("EqualsHashCode", "Override hashCode() whenever equals() is overridden, using the same fields."),
            Map.entry("StringLiteralEquality", "Compare strings with equals(), not == (which compares references)."),
            Map.entry("EmptyCatchBlock", "Handle the exception, log it, or rethrow it; at least explain why it can be ignored."),
            Map.entry("FallThrough", "End each case with break / return, or make the fall-through explicit."),
            Map.entry("MissingSwitchDefault", "Add a default branch that handles or rejects unexpected values."),
            Map.entry("IllegalCatch", "Catch the specific exceptions you can handle; never Throwable or Error."),
            Map.entry("CyclomaticComplexity", "Split the method into smaller ones with a single responsibility."),
            Map.entry("MethodLength", "Extract cohesive blocks into well-named private methods."),
            Map.entry("ParameterNumber", "Group related parameters into an object (parameter object / record)."),
            Map.entry("MagicNumber", "Replace the literal with a named constant."),
            Map.entry("UnusedImports", "Remove the unused import."),
            Map.entry("AvoidStarImport", "Import the classes explicitly."));

    private final Path java;
    private final Path classpath;
    private final Path config;

    /**
     * @param java      java executable
     * @param classpath directory with the Checkstyle jars
     * @param config    Checkstyle configuration shipped with SAYTU
     */
    public CheckstyleAdapter(Path java, Path classpath, Path config) {
        this.java = Objects.requireNonNull(java, "java");
        this.classpath = Objects.requireNonNull(classpath, "classpath");
        this.config = Objects.requireNonNull(config, "config");
    }

    @Override
    public ScannerId id() {
        return ScannerId.CHECKSTYLE;
    }

    @Override
    public Set<Language> languages() {
        return Set.of(Language.JAVA);
    }

    @Override
    public CommandSpec versionCommand(Path workDir) {
        return new CommandSpec(List.of(java.toString(), "-cp", classpath.resolve("*").toString(), MAIN, "--version"),
                AdapterSupport.environment(workDir), workDir, workDir.resolve("version.txt"));
    }

    @Override
    public String parseVersion(String stdout) {
        // "Checkstyle version: 14.3.0"
        return stdout == null ? null : stdout.strip().replaceFirst("(?i)^checkstyle version:\\s*", "");
    }

    @Override
    public boolean isApplicable(Path sourceDir) {
        return true;
    }

    @Override
    public Optional<String> rulesetVersion() {
        try {
            return Optional.of(config.getFileName() + "@" + AdapterSupport.sha256Hex(Files.readString(config)).substring(0, 12));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    @Override
    public CommandSpec buildCommand(ScanContext context) {
        Path report = context.workDir().resolve("checkstyle.xml");
        List<String> argv = new ArrayList<>(JvmTool.command(java, classpath, MAIN, context));
        argv.addAll(List.of("-c", config.toString(), "-f", "xml", "-o", report.toString(),
                "-x", SourceFiles.excludedDirectoryRegex(), context.sourceDir().toString()));
        return new CommandSpec(argv, AdapterSupport.environment(context.workDir()), context.workDir(), report);
    }

    /** Every module reports "warning": 0 means the run completed; negative codes (254, 255) are failures. */
    @Override
    public boolean isSuccessfulExit(int exitCode) {
        return exitCode == 0;
    }

    @Override
    public List<NormalizedFinding> parse(Path reportFile, ScanContext context) throws IOException {
        Document doc = XmlReports.parse(reportFile);
        if (!"checkstyle".equals(doc.getDocumentElement().getTagName())) {
            throw new IOException("unexpected Checkstyle report");
        }
        List<NormalizedFinding> findings = new ArrayList<>();
        NodeList files = doc.getElementsByTagName("file");
        for (int i = 0; i < files.getLength(); i++) {
            Element file = (Element) files.item(i);
            String path = AdapterSupport.relativePath(context.sourceDir(), file.getAttribute("name"));
            if (path == null) {
                continue;
            }
            NodeList errors = file.getElementsByTagName("error");
            for (int j = 0; j < errors.getLength(); j++) {
                Element e = (Element) errors.item(j);
                String check = checkName(e.getAttribute("source"));
                if (check.isEmpty()) {
                    continue;
                }
                Integer line = XmlReports.intAttr(e, "line");
                String message = e.getAttribute("message");
                findings.add(new NormalizedFinding(ScannerId.CHECKSTYLE, "checkstyle:" + check, FindingType.QUALITY,
                        severity(check), AdapterSupport.firstSentence(message, 200), message,
                        new NormalizedFinding.SourceLocation(path, line, line), List.of(), null, null, null, null,
                        AdapterSupport.truncate(AdapterSupport.sourceLine(context.sourceDir(), path, line), 500),
                        RECOMMENDATIONS.getOrDefault(check, "See the Checkstyle documentation of " + check + "."),
                        List.of("https://checkstyle.org/checks.html"),
                        AdapterSupport.contextHash(context.sourceDir(), path, line)));
            }
        }
        return findings;
    }

    /** "com.puppycrawl.tools.checkstyle.checks.coding.EqualsHashCodeCheck" -> "EqualsHashCode". */
    static String checkName(String source) {
        if (source == null || source.isBlank()) {
            return "";
        }
        String s = source.substring(source.lastIndexOf('.') + 1);
        return s.endsWith("Check") ? s.substring(0, s.length() - 5) : s;
    }

    static Severity severity(String check) {
        if (PROBABLE_BUGS.contains(check)) {
            return Severity.MEDIUM;
        }
        return MAINTAINABILITY.contains(check) ? Severity.LOW : Severity.INFO;
    }
}
