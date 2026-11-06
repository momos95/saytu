package com.saytu.core.report;

import com.saytu.core.report.PdfDocument.Color;
import com.saytu.core.report.PdfDocument.Font;
import com.saytu.core.report.ReportData.Dependency;
import com.saytu.core.report.ReportData.Finding;
import com.saytu.core.report.ReportData.ScanLine;
import com.saytu.core.report.ReportData.ScoreLine;
import com.saytu.core.report.ReportData.ToolRun;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** PDF version of the HTML report (same sections), printable A4. */
public final class PdfReport {

    private static final Color GREEN = Color.hex(0x11734b);
    private static final Map<String, Color> SEVERITY_COLORS = Map.of(
            "CRITICAL", Color.hex(0xa3122a), "HIGH", Color.hex(0xc4410c), "MEDIUM", Color.hex(0xa86200),
            "LOW", Color.hex(0x2f6f9f), "INFO", Color.MUTED);

    private PdfReport() {
    }

    public static byte[] write(ReportData r) {
        PdfDocument pdf = new PdfDocument("SAYTU " + r.producerVersion() + " · " + r.title() + " · "
                + Labels.date(r.generatedAt()));
        pdf.paragraph("◆ SAYTU", Font.BOLD, 11, GREEN, 0, 0);
        pdf.paragraph(r.title(), Font.BOLD, 18, Color.BLACK, 0, 3);
        pdf.paragraph("Généré le " + Labels.date(r.generatedAt()) + " par " + r.generatedBy(), Font.REGULAR, 9, Color.MUTED, 0, 0);
        if (!r.scope().isEmpty()) {
            pdf.paragraph("Périmètre : " + String.join(" · ", r.scope()), Font.REGULAR, 9, Color.MUTED, 0, 4);
        }
        pdf.space(6);
        pdf.rule(GREEN);

        heading(pdf, "Synthèse");
        StringBuilder counts = new StringBuilder();
        for (String s : Labels.SEVERITIES) {
            counts.append(counts.isEmpty() ? "" : "   ").append(Labels.of(Labels.SEVERITY, s)).append(" : ")
                    .append(r.bySeverity().getOrDefault(s, 0L));
        }
        pdf.paragraph(counts.toString(), Font.BOLD, 10, Color.BLACK, 0, 0);
        pdf.paragraph(r.totalFindings() + " vulnérabilité(s) correspondent au périmètre"
                + (r.truncated() ? " ; les " + r.findings().size() + " plus graves sont détaillées (exports JSON / SARIF : liste complète)." : "."),
                Font.REGULAR, 9, Color.BLACK, 0, 0);

        scores(pdf, r.scores());
        scans(pdf, r.scans());
        dependencies(pdf, r.dependencies());
        findings(pdf, r.findings());
        pdf.space(10);
        pdf.paragraph("Rapport produit localement par SAYTU. Preuves expurgées des secrets. Un scanner non exécuté ou en échec "
                + "n'est jamais compté comme une absence de problème.", Font.REGULAR, 8, Color.MUTED, 0, 0);
        return pdf.finish(r.title(), r.generatedAt());
    }

    private static void heading(PdfDocument pdf, String title) {
        pdf.ensure(60);
        pdf.space(12);
        pdf.paragraph(title, Font.BOLD, 13, Color.BLACK, 0, 0);
        pdf.space(3);
        pdf.rule(Color.LINE);
        pdf.space(2);
    }

    private static void scores(PdfDocument pdf, List<ScoreLine> scores) {
        if (scores.isEmpty()) {
            return;
        }
        heading(pdf, "Scores");
        float[] w = {175, 50, 55, 50, 65, 104};
        header(pdf, w, "Portée", "Global", "Sécurité", "Qualité", "Couverture", "Fiabilité");
        for (ScoreLine s : scores) {
            pdf.row(new String[]{s.label(), Labels.score(s.global()), Labels.score(s.security()), Labels.score(s.quality()),
                            Labels.percent(s.coverage()), Labels.of(Labels.RELIABILITY, s.reliability())}, w,
                    fonts(6, Font.REGULAR, 1, 2, 3), new Color[]{Color.BLACK, tone(s.global()), tone(s.security()),
                            tone(s.quality()), Color.BLACK, Color.BLACK}, 9);
        }
        pdf.paragraph("« — » : trop peu d'analyses réussies pour calculer ce score (formule " + scores.getFirst().formulaVersion() + ").",
                Font.REGULAR, 7.5f, Color.MUTED, 0, 0);
    }

    private static void scans(PdfDocument pdf, List<ScanLine> scans) {
        if (scans.isEmpty()) {
            return;
        }
        heading(pdf, "Analyses prises en compte");
        for (ScanLine s : scans) {
            pdf.ensure(40);
            pdf.paragraph(s.repository() + " · " + s.branch() + " · commit " + Labels.shortSha(s.commitSha()) + " · "
                    + Labels.date(s.finishedAt()) + (s.languages().isEmpty() ? "" : " · " + String.join(", ", s.languages())),
                    Font.BOLD, 9, Color.BLACK, 0, 2);
            List<String> tools = new ArrayList<>();
            for (ToolRun t : s.tools()) {
                tools.add(Labels.tool(t.scanner()) + (t.toolVersion() == null ? "" : " " + t.toolVersion()) + " : "
                        + Labels.of(Labels.EXECUTION, t.status())
                        + ("SUCCEEDED".equals(t.status()) ? " (" + t.findings() + ")" : "")
                        + (t.rulesetVersion() == null ? "" : ", règles " + t.rulesetVersion()));
            }
            pdf.paragraph(String.join(" · ", tools), Font.REGULAR, 8, Color.MUTED, 10, 8);
            pdf.space(3);
        }
    }

    private static void dependencies(PdfDocument pdf, List<Dependency> deps) {
        if (deps.isEmpty()) {
            return;
        }
        heading(pdf, "Dépendances concernées");
        float[] w = {150, 70, 95, 55, 129};
        header(pdf, w, "Paquet", "Version", "Corrigée en", "Gravité", "CVE");
        for (Dependency d : deps) {
            pdf.row(new String[]{d.name() + (d.ecosystem() == null ? "" : " (" + d.ecosystem() + ")"), d.version(),
                            d.fixedVersions().isEmpty() ? "inconnue" : d.fixedVersions(),
                            Labels.of(Labels.SEVERITY, d.worstSeverity()), String.join(", ", d.cves())}, w,
                    fonts(5, Font.REGULAR), new Color[]{Color.BLACK, Color.BLACK, Color.BLACK,
                            SEVERITY_COLORS.getOrDefault(d.worstSeverity(), Color.BLACK), Color.BLACK}, 8);
        }
    }

    private static void findings(PdfDocument pdf, List<Finding> findings) {
        heading(pdf, "Vulnérabilités");
        if (findings.isEmpty()) {
            pdf.paragraph("Aucune vulnérabilité ne correspond au périmètre.", Font.REGULAR, 9, Color.BLACK, 0, 0);
            return;
        }
        int n = 0;
        for (Finding f : findings) {
            n++;
            pdf.ensure(70);
            pdf.space(4);
            pdf.paragraph(Labels.of(Labels.SEVERITY, f.severity()).toUpperCase(java.util.Locale.ROOT) + "  " + n + ". " + f.title(),
                    Font.BOLD, 10, SEVERITY_COLORS.getOrDefault(f.severity(), Color.BLACK), 0, 3);
            line(pdf, "Dépôt", f.repository() + " · " + f.branch() + (f.commitSha() == null ? "" : " · " + Labels.shortSha(f.commitSha())));
            line(pdf, "Emplacement", f.location());
            line(pdf, "Type / statut", Labels.of(Labels.TYPE, f.type()) + " · " + Labels.of(Labels.STATUS, f.status())
                    + (f.statusReason() == null ? "" : " (" + f.statusReason() + ")"));
            line(pdf, "Règle", Labels.tool(f.scanner()) + " · " + f.ruleId());
            if (!f.cwes().isEmpty() || f.cve() != null || f.cvss() != null) {
                line(pdf, "Références", String.join(", ", f.cwes()) + (f.cve() == null ? "" : " " + f.cve())
                        + (f.cvss() == null ? "" : " · CVSS " + f.cvss().toPlainString()));
            }
            if (f.packageName() != null) {
                line(pdf, "Paquet", f.packageName() + (f.packageVersion() == null ? "" : " " + f.packageVersion())
                        + (f.fixedVersion() == null ? "" : " → corrigé en " + f.fixedVersion()));
            }
            if (f.description() != null && !f.description().isBlank() && !f.description().equals(f.title())) {
                pdf.paragraph(f.description(), Font.REGULAR, 8.5f, Color.BLACK, 0, 12);
            }
            if (f.evidence() != null && !f.evidence().isBlank()) {
                pdf.paragraph(f.evidence(), Font.MONO, 7.5f, Color.MUTED, 10, 10);
            }
            if (f.recommendation() != null && !f.recommendation().isBlank()) {
                pdf.paragraph("Recommandation : " + f.recommendation(), Font.REGULAR, 8.5f, GREEN, 0, 10);
            }
            pdf.space(4);
            pdf.rule(Color.LINE);
        }
    }

    private static void line(PdfDocument pdf, String label, String value) {
        if (value == null || value.isBlank()) {
            return;
        }
        pdf.paragraph(label + " : " + value, Font.REGULAR, 8.5f, Color.BLACK, 0, 3);
    }

    private static void header(PdfDocument pdf, float[] widths, String... titles) {
        Color[] colors = new Color[titles.length];
        java.util.Arrays.fill(colors, Color.MUTED);
        pdf.row(titles, widths, fonts(titles.length, Font.BOLD), colors, 8.5f);
    }

    /** n fonts of the given kind; columns listed in {@code bold} use bold. */
    private static Font[] fonts(int n, Font font, int... bold) {
        Font[] f = new Font[n];
        java.util.Arrays.fill(f, font);
        for (int i : bold) {
            f[i] = Font.BOLD;
        }
        return f;
    }

    private static Color tone(Double score) {
        if (score == null) {
            return Color.MUTED;
        }
        return score >= 80 ? GREEN : score >= 60 ? SEVERITY_COLORS.get("MEDIUM") : SEVERITY_COLORS.get("CRITICAL");
    }
}
