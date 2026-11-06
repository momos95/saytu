package com.saytu.core.report;

import com.saytu.core.report.ReportData.Dependency;
import com.saytu.core.report.ReportData.Finding;
import com.saytu.core.report.ReportData.ScanLine;
import com.saytu.core.report.ReportData.ScoreLine;
import com.saytu.core.report.ReportData.ToolRun;

/** SAYTU JSON report, format {@code saytu-report/1}: stable field names, nulls kept. */
public final class JsonReport {

    public static final String FORMAT = "saytu-report/1";

    private JsonReport() {
    }

    public static String write(ReportData r) {
        JsonOut j = new JsonOut().beginObject()
                .field("format", FORMAT)
                .field("title", r.title())
                .field("generatedAt", r.generatedAt())
                .field("generatedBy", r.generatedBy())
                .field("producer", "SAYTU " + r.producerVersion())
                .field("scope", r.scope())
                .field("totalFindings", r.totalFindings())
                .field("includedFindings", r.findings().size())
                .field("truncated", r.truncated())
                .field("bySeverity", r.bySeverity());
        j.name("scores").beginArray();
        for (ScoreLine s : r.scores()) {
            j.beginObject().field("label", s.label()).field("security", s.security()).field("quality", s.quality())
                    .field("global", s.global()).field("coveragePercent", s.coverage())
                    .field("reliability", s.reliability()).field("formulaVersion", s.formulaVersion())
                    .field("computedAt", s.computedAt()).endObject();
        }
        j.endArray();
        j.name("scans").beginArray();
        for (ScanLine s : r.scans()) {
            j.beginObject().field("repository", s.repository()).field("branch", s.branch())
                    .field("commitSha", s.commitSha()).field("finishedAt", s.finishedAt()).field("status", s.status())
                    .field("languages", s.languages());
            j.name("tools").beginArray();
            for (ToolRun t : s.tools()) {
                j.beginObject().field("scanner", t.scanner()).field("status", t.status())
                        .field("toolVersion", t.toolVersion()).field("rulesetVersion", t.rulesetVersion())
                        .field("findings", t.findings()).field("message", t.message()).endObject();
            }
            j.endArray().endObject();
        }
        j.endArray();
        j.name("dependencies").beginArray();
        for (Dependency d : r.dependencies()) {
            j.beginObject().field("ecosystem", d.ecosystem()).field("name", d.name()).field("version", d.version())
                    .field("fixedVersions", d.fixedVersions()).field("worstSeverity", d.worstSeverity())
                    .field("cves", d.cves()).field("repositories", d.repositories()).field("findings", d.findings())
                    .endObject();
        }
        j.endArray();
        j.name("findings").beginArray();
        for (Finding f : r.findings()) {
            j.beginObject().field("id", f.id()).field("fingerprint", f.fingerprint())
                    .field("repository", f.repository()).field("branch", f.branch()).field("commitSha", f.commitSha())
                    .field("type", f.type()).field("severity", f.severity()).field("status", f.status())
                    .field("statusReason", f.statusReason())
                    .field("scanner", f.scanner()).field("scanners", f.scanners()).field("ruleId", f.ruleId())
                    .field("title", f.title()).field("description", f.description()).field("cwe", f.cwes())
                    .field("cve", f.cve()).field("cvss", f.cvss()).field("filePath", f.filePath())
                    .field("startLine", f.startLine()).field("endLine", f.endLine())
                    .field("packageEcosystem", f.packageEcosystem()).field("packageName", f.packageName())
                    .field("packageVersion", f.packageVersion()).field("fixedVersion", f.fixedVersion())
                    .field("evidence", f.evidence()).field("recommendation", f.recommendation())
                    .field("references", f.references()).field("firstSeenAt", f.firstSeenAt())
                    .field("lastSeenAt", f.lastSeenAt()).endObject();
        }
        return j.endArray().endObject().toString();
    }
}
