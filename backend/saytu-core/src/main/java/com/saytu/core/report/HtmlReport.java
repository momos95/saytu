package com.saytu.core.report;

import com.saytu.core.report.ReportData.Dependency;
import com.saytu.core.report.ReportData.Finding;
import com.saytu.core.report.ReportData.ScanLine;
import com.saytu.core.report.ReportData.ScoreLine;
import com.saytu.core.report.ReportData.ToolRun;

import java.util.List;

/**
 * Self-contained HTML report: inline CSS, no script, no external resource (a strict CSP forbids any),
 * every value escaped. Opens offline and prints cleanly.
 */
public final class HtmlReport {

    private HtmlReport() {
    }

    public static String write(ReportData r) {
        StringBuilder h = new StringBuilder(64 * 1024);
        h.append("<!doctype html>\n<html lang=\"fr\"><head><meta charset=\"utf-8\">")
                .append("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">")
                .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
                .append("<meta name=\"referrer\" content=\"no-referrer\">")
                .append("<title>").append(esc(r.title())).append("</title><style>").append(CSS).append("</style></head><body>");
        h.append("<header><div class=\"brand\">◆ SAYTU</div><h1>").append(esc(r.title())).append("</h1><p class=\"meta\">Généré le ")
                .append(esc(Labels.date(r.generatedAt()))).append(" par ").append(esc(r.generatedBy()))
                .append(" · SAYTU ").append(esc(r.producerVersion())).append("</p>");
        if (!r.scope().isEmpty()) {
            h.append("<p class=\"meta\">Périmètre : ").append(esc(String.join(" · ", r.scope()))).append("</p>");
        }
        h.append("</header><main>");
        summary(h, r);
        scores(h, r.scores());
        scans(h, r.scans());
        dependencies(h, r.dependencies());
        findings(h, r);
        h.append("</main><footer>Rapport produit localement par SAYTU. Les preuves sont expurgées des secrets. ")
                .append("Un scanner « non exécuté » ou en échec n'est jamais compté comme une absence de problème.</footer>")
                .append("</body></html>\n");
        return h.toString();
    }

    private static void summary(StringBuilder h, ReportData r) {
        h.append("<section><h2>Synthèse</h2><div class=\"cards\">");
        for (String s : Labels.SEVERITIES) {
            h.append("<div class=\"card sev-").append(s).append("\"><span>").append(Labels.of(Labels.SEVERITY, s))
                    .append("</span><strong>").append(r.bySeverity().getOrDefault(s, 0L)).append("</strong></div>");
        }
        h.append("</div><p>").append(r.totalFindings()).append(" vulnérabilité(s) correspondent au périmètre");
        if (r.truncated()) {
            h.append(" ; les ").append(r.findings().size())
                    .append(" plus graves sont détaillées ci-dessous (export JSON ou SARIF pour la liste complète)");
        }
        h.append(".</p></section>");
    }

    private static void scores(StringBuilder h, List<ScoreLine> scores) {
        if (scores.isEmpty()) {
            return;
        }
        h.append("<section><h2>Scores</h2><table><thead><tr><th>Portée</th><th>Global</th><th>Sécurité</th><th>Qualité</th>")
                .append("<th>Couverture</th><th>Fiabilité</th><th>Calculé le</th></tr></thead><tbody>");
        for (ScoreLine s : scores) {
            h.append("<tr><td>").append(esc(s.label())).append("</td>").append(scoreCell(s.global()))
                    .append(scoreCell(s.security())).append(scoreCell(s.quality())).append("<td>")
                    .append(Labels.percent(s.coverage())).append("</td><td>")
                    .append(esc(Labels.of(Labels.RELIABILITY, s.reliability()))).append("</td><td>")
                    .append(esc(Labels.date(s.computedAt()))).append("</td></tr>");
        }
        h.append("</tbody></table><p class=\"note\">« — » : trop peu d'analyses réussies pour calculer ce score ")
                .append("(formule ").append(esc(scores.getFirst().formulaVersion())).append(").</p></section>");
    }

    private static String scoreCell(Double score) {
        String tone = score == null ? "none" : score >= 80 ? "good" : score >= 60 ? "fair" : "poor";
        return "<td class=\"score " + tone + "\">" + Labels.score(score) + "</td>";
    }

    private static void scans(StringBuilder h, List<ScanLine> scans) {
        if (scans.isEmpty()) {
            return;
        }
        h.append("<section><h2>Analyses prises en compte</h2><table><thead><tr><th>Dépôt / branche</th><th>Commit</th>")
                .append("<th>Terminée le</th><th>Langages</th><th>Outils</th></tr></thead><tbody>");
        for (ScanLine s : scans) {
            h.append("<tr><td>").append(esc(s.repository())).append(" <span class=\"muted\">").append(esc(s.branch()))
                    .append("</span></td><td><code>").append(esc(Labels.shortSha(s.commitSha()))).append("</code></td><td>")
                    .append(esc(Labels.date(s.finishedAt()))).append("</td><td>").append(esc(String.join(", ", s.languages())))
                    .append("</td><td class=\"tools\">");
            for (ToolRun t : s.tools()) {
                h.append("<span class=\"tool ").append(esc(t.status())).append("\" title=\"")
                        .append(esc(t.message() == null ? "" : t.message())).append("\">")
                        .append(esc(Labels.tool(t.scanner()))).append(" ").append(esc(t.toolVersion() == null ? "" : t.toolVersion()))
                        .append(" : ").append(esc(Labels.of(Labels.EXECUTION, t.status())));
                if ("SUCCEEDED".equals(t.status())) {
                    h.append(" (").append(t.findings()).append(")");
                }
                if (t.rulesetVersion() != null) {
                    h.append(" · règles ").append(esc(t.rulesetVersion()));
                }
                h.append("</span>");
            }
            h.append("</td></tr>");
        }
        h.append("</tbody></table></section>");
    }

    private static void dependencies(StringBuilder h, List<Dependency> deps) {
        if (deps.isEmpty()) {
            return;
        }
        h.append("<section><h2>Dépendances concernées</h2><table><thead><tr><th>Paquet</th><th>Version</th>")
                .append("<th>Corrigée en</th><th>Gravité max.</th><th>CVE</th><th>Dépôts</th></tr></thead><tbody>");
        for (Dependency d : deps) {
            h.append("<tr><td>").append(esc(d.name())).append(d.ecosystem() == null ? "" : " <span class=\"muted\">" + esc(d.ecosystem()) + "</span>")
                    .append("</td><td><code>").append(esc(d.version() == null ? "" : d.version())).append("</code></td><td>")
                    .append(esc(d.fixedVersions().isEmpty() ? "pas de version corrigée connue" : d.fixedVersions()))
                    .append("</td><td class=\"sev-").append(esc(d.worstSeverity())).append("\">")
                    .append(esc(Labels.of(Labels.SEVERITY, d.worstSeverity()))).append("</td><td>")
                    .append(esc(String.join(", ", d.cves()))).append("</td><td>").append(esc(String.join(", ", d.repositories())))
                    .append("</td></tr>");
        }
        h.append("</tbody></table></section>");
    }

    private static void findings(StringBuilder h, ReportData r) {
        h.append("<section><h2>Vulnérabilités</h2>");
        if (r.findings().isEmpty()) {
            h.append("<p>Aucune vulnérabilité ne correspond au périmètre.</p></section>");
            return;
        }
        int n = 0;
        for (Finding f : r.findings()) {
            n++;
            h.append("<article class=\"finding\"><h3><span class=\"badge sev-").append(esc(f.severity())).append("\">")
                    .append(esc(Labels.of(Labels.SEVERITY, f.severity()))).append("</span> ").append(n).append(". ")
                    .append(esc(f.title())).append("</h3><dl>");
            row(h, "Dépôt / branche", f.repository() + " · " + f.branch() + (f.commitSha() == null ? "" : " · " + Labels.shortSha(f.commitSha())));
            row(h, "Emplacement", f.location());
            row(h, "Type / statut", Labels.of(Labels.TYPE, f.type()) + " · " + Labels.of(Labels.STATUS, f.status())
                    + (f.statusReason() == null ? "" : " (" + f.statusReason() + ")"));
            row(h, "Règle", Labels.tool(f.scanner()) + " · " + f.ruleId()
                    + (f.scanners().size() > 1 ? " — aussi détectée par " + String.join(", ", f.scanners().stream().filter(s -> !s.equals(f.scanner())).map(Labels::tool).toList()) : ""));
            if (!f.cwes().isEmpty() || f.cve() != null || f.cvss() != null) {
                row(h, "Références", String.join(", ", f.cwes()) + (f.cve() == null ? "" : " " + f.cve())
                        + (f.cvss() == null ? "" : " · CVSS " + f.cvss().toPlainString()));
            }
            if (f.packageName() != null) {
                row(h, "Paquet", f.packageName() + (f.packageVersion() == null ? "" : " " + f.packageVersion())
                        + (f.fixedVersion() == null ? "" : " → corrigé en " + f.fixedVersion()));
            }
            row(h, "Vue depuis", Labels.date(f.firstSeenAt()) + " (dernière détection " + Labels.date(f.lastSeenAt()) + ")");
            h.append("</dl>");
            if (f.description() != null && !f.description().isBlank() && !f.description().equals(f.title())) {
                h.append("<p>").append(esc(f.description())).append("</p>");
            }
            if (f.evidence() != null && !f.evidence().isBlank()) {
                h.append("<pre>").append(esc(f.evidence())).append("</pre>");
            }
            if (f.recommendation() != null && !f.recommendation().isBlank()) {
                h.append("<p class=\"reco\"><strong>Recommandation :</strong> ").append(esc(f.recommendation())).append("</p>");
            }
            if (!f.references().isEmpty()) {
                h.append("<ul class=\"refs\">");
                for (String ref : f.references()) {
                    if (ref.startsWith("https://") || ref.startsWith("http://")) {
                        h.append("<li><a rel=\"noopener noreferrer\" href=\"").append(esc(ref)).append("\">").append(esc(ref)).append("</a></li>");
                    } else {
                        h.append("<li>").append(esc(ref)).append("</li>");
                    }
                }
                h.append("</ul>");
            }
            h.append("</article>");
        }
        h.append("</section>");
    }

    private static void row(StringBuilder h, String label, String value) {
        if (value == null || value.isBlank()) {
            return;
        }
        h.append("<dt>").append(esc(label)).append("</dt><dd>").append(esc(value)).append("</dd>");
    }

    /** HTML escaping for text and attribute values. */
    static String esc(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder b = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '<' -> b.append("&lt;");
                case '>' -> b.append("&gt;");
                case '&' -> b.append("&amp;");
                case '"' -> b.append("&quot;");
                case '\'' -> b.append("&#39;");
                default -> b.append(c < 0x20 && c != '\n' && c != '\t' ? ' ' : c);
            }
        }
        return b.toString();
    }

    private static final String CSS = """
            :root{--fg:#1d2329;--muted:#5d6b78;--line:#d8dee4;--bg:#fff;--soft:#f5f7f9;--crit:#a3122a;--high:#c4410c;--med:#a86200;--low:#2f6f9f;--info:#5d6b78;--good:#11734b}
            *{box-sizing:border-box}body{margin:0;font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--fg);background:var(--bg)}
            header{padding:24px 32px;border-bottom:3px solid var(--good)}main{padding:8px 32px 32px}footer{padding:16px 32px;color:var(--muted);font-size:12px;border-top:1px solid var(--line)}
            .brand{font-weight:700;color:var(--good)}h1{margin:4px 0 8px;font-size:24px}h2{font-size:18px;margin:28px 0 10px;border-bottom:1px solid var(--line);padding-bottom:4px}h3{font-size:15px;margin:0 0 8px}
            .meta,.muted,.note{color:var(--muted)}.note{font-size:12px}
            table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{background:var(--soft)}
            .cards{display:flex;gap:10px;flex-wrap:wrap}.card{border:1px solid var(--line);border-radius:8px;padding:8px 14px;min-width:110px}.card span{display:block;color:var(--muted);font-size:12px}.card strong{font-size:22px}
            .sev-CRITICAL{color:var(--crit)}.sev-HIGH{color:var(--high)}.sev-MEDIUM{color:var(--med)}.sev-LOW{color:var(--low)}.sev-INFO{color:var(--info)}
            .score{font-weight:700}.score.good{color:var(--good)}.score.fair{color:var(--med)}.score.poor{color:var(--crit)}.score.none{color:var(--muted)}
            .tools .tool{display:inline-block;margin:0 6px 4px 0;padding:1px 6px;border:1px solid var(--line);border-radius:4px;font-size:12px}.tool.FAILED,.tool.TIMED_OUT{border-color:var(--crit);color:var(--crit)}.tool.SKIPPED,.tool.NOT_APPLICABLE{color:var(--muted)}
            .finding{border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin:10px 0;page-break-inside:avoid}
            .badge{display:inline-block;font-size:12px;border:1px solid currentColor;border-radius:4px;padding:0 6px;margin-right:4px}
            dl{display:grid;grid-template-columns:max-content 1fr;gap:2px 12px;margin:0 0 8px;font-size:13px}dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}
            pre{background:var(--soft);padding:8px;border-radius:6px;white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}.reco{background:#eef8f2;padding:8px;border-radius:6px}.refs{font-size:12px;overflow-wrap:anywhere}
            code{font-size:12px}@media print{header,main,footer{padding-left:0;padding-right:0}.finding{break-inside:avoid}}
            """;
}
