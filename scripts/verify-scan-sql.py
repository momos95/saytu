#!/usr/bin/env python3
"""Runs every SQL statement of the scan engine (ScanSql.java) through a full scan lifecycle on a
throw-away PostgreSQL built from the Flyway migrations, and checks the results.

Needs: PostgreSQL server binaries (initdb, pg_ctl, psql) and a JSON dump of the ScanSql constants,
produced by scripts/verify-scan-sql.sh (javac + reflection). No JVM database driver involved: the
named parameters are replaced by SQL literals of the same type.

    scripts/verify-scan-sql.sh
"""
import json, os, re, subprocess, sys, uuid

SQL = json.load(open(sys.argv[1]))
PSQL = sys.argv[2:]          # psql command prefix (host, port, user, db)
failures = 0

def lit(v):
    if v is None: return "NULL"
    if isinstance(v, bool): return "TRUE" if v else "FALSE"
    if isinstance(v, (int, float)): return str(v)
    if isinstance(v, list):
        return "CAST(ARRAY[" + ",".join(lit(x) for x in v) + "]::varchar[] AS varchar[])" if v else "CAST('{}' AS varchar[])"
    return "'" + str(v).replace("'", "''") + "'"

def bind(sql, params):
    def rep(m):
        name = m.group(1)
        if name not in params:
            raise KeyError(f"missing parameter :{name}")
        return lit(params[name])
    return re.sub(r"(?<![:\w]):([A-Za-z][A-Za-z0-9_]*)", rep, sql)

def run(name, params=None, raw=None):
    sql = raw if raw is not None else bind(SQL[name], params or {})
    out = subprocess.run([a for a in PSQL if a != "-q"] + ["-tA", "-F", "|", "-v", "ON_ERROR_STOP=1", "-c", sql], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"{name}: {out.stderr.strip()}\n{sql}")
    lines = [l for l in out.stdout.splitlines() if l and not re.match(r"^(UPDATE|INSERT|DELETE) \d", l)]
    return [l.split("|") for l in lines], out.stdout

def check(cond, label):
    global failures
    print(("  ok   - " if cond else "  FAIL - ") + label)
    if not cond: failures += 1

def q(sql):
    return run("raw", raw=sql)[0]

# ---------------------------------------------------------------- fixtures
conn = str(uuid.uuid4()); ns = str(uuid.uuid4()); repo = str(uuid.uuid4()); repo2 = str(uuid.uuid4())
q(f"""INSERT INTO git_connection (id, name, provider_type, base_url, created_by) VALUES ('{conn}', 'gl', 'GITLAB', 'https://gitlab.example.org', 't');
INSERT INTO git_namespace (id, connection_id, external_id, kind, full_path, name, selected, include_all_repositories) VALUES ('{ns}', '{conn}', '1', 'GROUP', 'acme', 'acme', TRUE, TRUE);
INSERT INTO source_repository (id, connection_id, namespace_id, external_id, full_name, name, clone_url, default_branch) VALUES
 ('{repo}', '{conn}', '{ns}', '10', 'acme/api', 'api', 'https://gitlab.example.org/acme/api.git', 'main'),
 ('{repo2}', '{conn}', '{ns}', '11', 'acme/web', 'web', 'https://gitlab.example.org/acme/web.git', 'main');""")

print("== runs and planning")
run_id = run("INSERT_RUN", {"triggerType": "MANUAL", "requestedBy": "alice", "scope": '{"allTargets":true}'})[0][0][0]
check(uuid.UUID(run_id) is not None, "run created")
claimed = run("CLAIM_UNPLANNED_RUN")[0]
check(claimed and claimed[0][0] == run_id and '"allTargets": true' in claimed[0][1], "run claimed for planning with its scope")
check(run("CLAIM_UNPLANNED_RUN")[0] == [], "a planned run is not claimed twice")
j1 = run("INSERT_JOB", {"runId": run_id, "repositoryId": repo, "branch": "main", "priority": 5})[0]
j2 = run("INSERT_JOB", {"runId": run_id, "repositoryId": repo2, "branch": "main", "priority": 5})[0]
check(len(j1) == 1 and len(j2) == 1, "jobs inserted")
other = run("INSERT_RUN", {"triggerType": "MANUAL", "requestedBy": "bob", "scope": '{"repositoryIds":["%s"]}' % repo})[0][0][0]
dup = run("INSERT_JOB", {"runId": other, "repositoryId": repo, "branch": "main", "priority": 5})[0]
check(dup == [], "same repository/branch is not queued twice while active")
run("FINISH_PLANNING", {"runId": run_id, "notes": '[{"repositoryId":"%s","repository":"acme/x","note":"no branch"}]' % repo, "errorMessage": None})
row = q(f"SELECT total_jobs, jsonb_array_length(planning_notes) FROM scan_run WHERE id = '{run_id}'")[0]
check(row == ["2", "1"], "planning recorded total jobs and notes")

print("== queue")
job = run("CLAIM_JOB", {"workerId": "w1", "leaseSeconds": 300})[0]
check(len(job) == 1 and job[0][1] == run_id and job[0][4] == "1", "job claimed (attempt 1)")
job_id = job[0][0]
run("MARK_RUN_RUNNING", {"runId": run_id})
check(q(f"SELECT status FROM scan_job WHERE id = '{job_id}'")[0] == ["RUNNING"], "job RUNNING")
_, out = run("RENEW_LEASE", {"jobId": job_id, "workerId": "w1", "leaseSeconds": 300})
check("UPDATE 1" in out, "lease renewed by its owner")
_, out = run("RENEW_LEASE", {"jobId": job_id, "workerId": "w2", "leaseSeconds": 300})
check("UPDATE 0" in out, "lease not renewed by another worker")
check(run("CANCEL_REQUESTED", {"runId": run_id})[0] == [["f"]], "cancel flag readable")

print("== results")
run("DELETE_PREVIOUS_EXECUTIONS", {"jobId": job_id})
ex_og = run("INSERT_EXECUTION", {"jobId": job_id, "scannerId": "opengrep", "status": "SUCCEEDED", "toolVersion": "1.33.1",
        "rulesetVersion": "saytu@abc", "exitCode": 0, "durationMs": 1234, "findingsCount": 2, "errorMessage": None,
        "startedAt": "2026-11-05T10:00:00Z", "finishedAt": "2026-11-05T10:00:02Z"})[0][0][0]
ex_tr = run("INSERT_EXECUTION", {"jobId": job_id, "scannerId": "trivy", "status": "FAILED", "toolVersion": "0.76.1",
        "rulesetVersion": None, "exitCode": None, "durationMs": None, "findingsCount": 1, "errorMessage": "database missing",
        "startedAt": "2026-11-05T10:00:02Z", "finishedAt": "2026-11-05T10:00:03Z"})[0][0][0]

def finding(fp, scanner, rule, severity="HIGH", typ="SECURITY", path="src/A.java", line=10, cwes=("CWE-89",), pkg=None, cvss=None):
    return {"repositoryId": repo, "branch": "main", "fingerprint": fp, "type": typ, "severity": severity,
            "scannerId": scanner, "ruleId": rule, "title": "t " + rule, "description": "d", "cwes": list(cwes),
            "cve": None, "cvssScore": cvss, "cvssVector": None, "filePath": path, "startLine": line, "endLine": line,
            "ecosystem": None, "packageName": pkg, "packageVersion": None, "fixedVersion": None,
            "evidence": "st.executeQuery(sql)", "recommendation": "use ?", "references": ["https://owasp.org"],
            "commitSha": "a" * 40, "jobId": job_id}

fp1, fp2, fp3 = "1" * 64, "2" * 64, "3" * 64
r1 = run("UPSERT_FINDING", finding(fp1, "opengrep", "sqli"))[0]
r2 = run("UPSERT_FINDING", finding(fp2, "opengrep", "weak-hash", "MEDIUM", cwes=("CWE-328",), cvss=7.5))[0]
r3 = run("UPSERT_FINDING", finding(fp3, "trivy", "DS-0001", "MEDIUM", path="Dockerfile", cwes=()))[0]
check(r1[0][1] == "t" and r2[0][1] == "t" and r3[0][1] == "t", "new findings inserted (inserted = true)")
for fid, ex, sc, rule in ((r1[0][0], ex_og, "opengrep", "sqli"), (r2[0][0], ex_og, "opengrep", "weak-hash"), (r3[0][0], ex_tr, "trivy", "DS-0001")):
    run("INSERT_OCCURRENCE", {"findingId": fid, "executionId": ex, "jobId": job_id, "scannerId": sc, "ruleId": rule,
                              "severity": "HIGH", "filePath": "x", "startLine": 1, "endLine": 1})
run("INSERT_OCCURRENCE", {"findingId": r1[0][0], "executionId": ex_og, "jobId": job_id, "scannerId": "opengrep", "ruleId": "sqli",
                          "severity": "HIGH", "filePath": "x", "startLine": 1, "endLine": 1})
check(q(f"SELECT count(*) FROM finding_occurrence WHERE finding_id = '{r1[0][0]}'") == [["1"]], "duplicate occurrence ignored")
run("FINISH_JOB", {"jobId": job_id, "status": "PARTIAL", "commitSha": "a" * 40, "errorMessage": None, "checkoutBytes": 1000,
                   "checkoutFiles": 10, "findingsCount": 3, "newFindings": 3, "resolvedFindings": 0,
                   "languages": '{"java": {"files": 2, "bytes": 70000}, "typescript": {"files": 1, "bytes": 1000}}'})
run("RECORD_BRANCH_SCAN", {"commitSha": "a" * 40, "repositoryId": repo, "branch": "main"})
run("COMPLETE_RUN", {"runId": run_id})
check(q(f"SELECT status FROM scan_run WHERE id = '{run_id}'") == [["RUNNING"]], "run stays RUNNING while a job is queued")

job2 = run("CLAIM_JOB", {"workerId": "w1", "leaseSeconds": 300})[0][0][0]
run("FINISH_JOB", {"jobId": job2, "status": "SUCCEEDED", "commitSha": "b" * 40, "errorMessage": None, "checkoutBytes": None,
                   "checkoutFiles": None, "findingsCount": 0, "newFindings": 0, "resolvedFindings": 0, "languages": "{}"})
run("COMPLETE_RUN", {"runId": run_id})
check(q(f"SELECT status, finished_at IS NOT NULL FROM scan_run WHERE id = '{run_id}'") == [["PARTIAL", "t"]],
      "run PARTIAL when one job is PARTIAL and the other SUCCEEDED")

print("== second scan: re-detection and resolution")
q(f"UPDATE scan_job SET status = 'CANCELLED' WHERE scan_run_id = '{other}'")
run3 = run("INSERT_RUN", {"triggerType": "MANUAL", "requestedBy": "alice", "scope": '{"allTargets":true}'})[0][0][0]
run("CLAIM_UNPLANNED_RUN"); run("CLAIM_UNPLANNED_RUN")
job3 = run("INSERT_JOB", {"runId": run3, "repositoryId": repo, "branch": "main", "priority": 5})[0][0][0]
claimed3 = run("CLAIM_JOB", {"workerId": "w1", "leaseSeconds": 300})[0][0][0]
check(claimed3 == job3, "new job claimed")
f = finding(fp1, "opengrep", "sqli"); f["jobId"] = job3
again = run("UPSERT_FINDING", f)[0]
check(again[0][0] == r1[0][0] and again[0][1] == "f", "same fingerprint updates the finding (inserted = false)")
_, out = run("RESOLVE_MISSING", {"repositoryId": repo, "branch": "main", "jobId": job3, "succeeded": ["opengrep", "gitleaks"]})
check("INSERT 0 1" in out, "one finding resolved")
status = dict((r[0], r[1]) for r in q("SELECT fingerprint, status FROM finding"))
check(status[fp2] == "RESOLVED", "finding no longer reported by a successful scanner -> RESOLVED")
check(status[fp1] == "OPEN", "re-detected finding stays OPEN")
check(status[fp3] == "OPEN", "finding of a FAILED scanner (trivy) is NOT resolved")
check(q(f"SELECT from_status, to_status, changed_by FROM finding_status_history") == [["OPEN", "RESOLVED", "system"]], "resolution historised")
_, out = run("RESOLVE_MISSING", {"repositoryId": repo, "branch": "main", "jobId": job3, "succeeded": []})
check("INSERT 0 0" in out, "nothing resolved when no scanner succeeded")
f2 = finding(fp2, "opengrep", "weak-hash", "MEDIUM", cwes=("CWE-328",), cvss=7.5); f2["jobId"] = job3
run("UPSERT_FINDING", f2)
check(q(f"SELECT status, resolved_at IS NULL FROM finding WHERE fingerprint = '{fp2}'") == [["OPEN", "t"]], "resolved finding re-opened when it comes back")
q(f"UPDATE finding SET status = 'FALSE_POSITIVE', status_reason = 'test code', status_changed_by = 'alice' WHERE fingerprint = '{fp1}'")
run("UPSERT_FINDING", f)
check(q(f"SELECT status FROM finding WHERE fingerprint = '{fp1}'") == [["FALSE_POSITIVE"]], "human triage kept on re-detection")

print("== API reads")
base = {"repositoryId": None, "branch": None, "severities": None, "types": None, "statuses": None, "scanner": None, "text": None}
rows = run("LIST_FINDINGS", dict(base, limit=50, offset=0))[0]
check(len(rows) == 3 and rows[0][5] == "HIGH", "list ordered by severity")
check(rows[0][-1] == "{opengrep}", "scanners aggregated from occurrences")
check(run("COUNT_FINDINGS", base)[0] == [["3"]], "count without filter")
check(run("COUNT_FINDINGS", dict(base, severities=["MEDIUM"], scanner="trivy"))[0] == [["1"]], "filters severity + scanner")
check(run("COUNT_FINDINGS", dict(base, repositoryId=repo, branch="main", statuses=["OPEN"], types=["SECURITY"]))[0] == [["2"]], "filters repository, branch, status, type")
check(run("COUNT_FINDINGS", dict(base, text="%weak%"))[0] == [["1"]], "text search")
check(run("COUNT_FINDINGS", dict(base, text="%\\_%"))[0] == [["0"]], "escaped LIKE wildcard")
by = dict((r[0], r[1]) for r in run("FINDING_COUNTS_BY_SEVERITY", base)[0])
check(by == {"HIGH": "1", "MEDIUM": "2"}, "counts by severity")
detail = run("GET_FINDING", {"findingId": r2[0][0]})[0]
check(len(detail) == 1 and detail[0][14] == "7.5", "detail with CVSS")
check(len(run("FINDING_OCCURRENCES", {"findingId": r1[0][0]})[0]) == 1, "occurrences")
runs = run("LIST_RUNS", {"limit": 10, "offset": 0})[0]
check(len(runs) == 3, "runs listed")
check(run("COUNT_RUNS")[0] == [["3"]], "runs counted")
got = run("GET_RUN", {"runId": run_id})[0][0]
check(got[3] == "PARTIAL" and got[13] == "2" and got[14] == "1" and got[15] == "3", "run detail with job counters and new findings")
jobs_rows = run("RUN_JOBS", {"runId": run_id})[0]
check(len(jobs_rows) == 2, "run jobs")
check(any('"java"' in r[-1] for r in jobs_rows), "job languages returned")
check(len(run("RUN_EXECUTIONS", {"runId": run_id})[0]) == 2, "run executions")

print("== cancellation and crash recovery")
run4 = run("INSERT_RUN", {"triggerType": "MANUAL", "requestedBy": "alice", "scope": '{"allTargets":true}'})[0][0][0]
_, out = run("REQUEST_CANCEL", {"runId": run4}); check("UPDATE 1" in out, "cancel requested")
_, out = run("CANCEL_UNPLANNED_RUN", {"runId": run4}); check("UPDATE 1" in out, "unplanned run cancelled at once")
check(q(f"SELECT status FROM scan_run WHERE id = '{run4}'") == [["CANCELLED"]], "run CANCELLED")
check(run("CLAIM_UNPLANNED_RUN")[0] == [], "cancelled run never planned")
_, out = run("REQUEST_CANCEL", {"runId": run4}); check("UPDATE 0" in out, "finished run cannot be cancelled")

run5 = run("INSERT_RUN", {"triggerType": "MANUAL", "requestedBy": "alice", "scope": '{"allTargets":true}'})[0][0][0]
run("CLAIM_UNPLANNED_RUN")
j5 = run("INSERT_JOB", {"runId": run5, "repositoryId": repo2, "branch": "develop", "priority": 5})[0][0][0]
j6 = run("INSERT_JOB", {"runId": run5, "repositoryId": repo2, "branch": "release", "priority": 5})[0][0][0]
run("FINISH_PLANNING", {"runId": run5, "notes": "[]", "errorMessage": None})
q(f"UPDATE scan_job SET status = 'RUNNING', locked_by = 'dead', attempt = 1, lease_expires_at = now() - interval '1 minute' WHERE id = '{j5}'")
q(f"UPDATE scan_job SET status = 'RUNNING', locked_by = 'dead', attempt = 2, lease_expires_at = now() - interval '1 minute' WHERE id = '{j6}'")
back = run("REQUEUE_EXPIRED", {"workerId": None})[0]
check(len(back) == 2, "expired leases recovered")
st = dict(q(f"SELECT id, status FROM scan_job WHERE scan_run_id = '{run5}'"))
check(st[j5] == "QUEUED" and st[j6] == "FAILED", "retried below max_attempts, failed at max_attempts")
q(f"UPDATE scan_job SET status = 'RUNNING', locked_by = 'w9', lease_expires_at = now() + interval '1 hour' WHERE id = '{j5}'")
check(len(run("REQUEUE_EXPIRED", {"workerId": "w9"})[0]) == 1, "jobs of a restarted worker re-queued at start-up")
run("REQUEST_CANCEL", {"runId": run5}); run("CANCEL_QUEUED_JOBS", {"runId": run5}); run("COMPLETE_RUN", {"runId": run5})
check(q(f"SELECT status FROM scan_run WHERE id = '{run5}'") == [["CANCELLED"]], "run with cancelled + failed jobs -> CANCELLED")
check(run("CLAIM_JOB", {"workerId": "w1", "leaseSeconds": 60})[0] == [], "no job of a cancelled run is claimed")

empty = run("INSERT_RUN", {"triggerType": "MANUAL", "requestedBy": "alice", "scope": '{"repositoryIds":[]}'})[0][0][0]
run("CLAIM_UNPLANNED_RUN")
run("FINISH_PLANNING", {"runId": empty, "notes": "[]", "errorMessage": "nothing to scan"})
run("COMPLETE_RUN", {"runId": empty})
check(q(f"SELECT status, error_message FROM scan_run WHERE id = '{empty}'") == [["FAILED", "nothing to scan"]], "run without job FAILED with its reason")

print("== scores")
formula = run("FORMULA")[0]
check(formula and '"version": "v2"' in formula[0][0] and '"HYPERBOLIC"' in formula[0][0], "scoring formula v1 seeded by V5, replaced by v2 in V6")
run("UPDATE_FORMULA", {"value": '{"version": "v1-custom", "securityScale": 40}', "updatedBy": "admin"})
check('"v1-custom"' in run("FORMULA")[0][0][0], "formula updated")
counts = run("OPEN_COUNTS", {"repositoryId": repo, "branch": "main"})[0]
check(sorted(counts) == [["SECURITY", "MEDIUM", "2"]], "open counts: 2 OPEN, the FALSE_POSITIVE excluded: " + str(counts))
snap = {"namespaceId": None, "repositoryId": repo, "branch": "main", "scanJobId": job_id, "security": 81.87,
        "quality": 90.5, "global": 85.32, "coverage": 79.0, "reliability": "MEDIUM", "formulaVersion": "v1",
        "details": '{"codeBytes": 70000, "missingSecurityScanners": ["trivy"]}'}
run("INSERT_SNAPSHOT", dict(snap, scopeType="BRANCH"))
run("INSERT_SNAPSHOT", dict(snap, scopeType="BRANCH", branch="develop", scanJobId=None, security=None, quality=None, **{"global": None}, coverage=20, reliability="INSUFFICIENT"))
latest = run("LATEST_BRANCH_SNAPSHOTS", {"repositoryId": repo})[0]
check(len(latest) == 2 and latest[1][0] == "main" and latest[1][1] == "81.87", "latest snapshot per branch")
run("INSERT_SNAPSHOT", dict(snap, scopeType="REPOSITORY", branch=None, scanJobId=None))
run("INSERT_SNAPSHOT", dict(snap, scopeType="NAMESPACE", namespaceId=ns, repositoryId=None, branch=None, scanJobId=None))
run("INSERT_SNAPSHOT", dict(snap, scopeType="GLOBAL", repositoryId=None, branch=None, scanJobId=None))
try:
    run("INSERT_SNAPSHOT", dict(snap, scopeType="GLOBAL", branch=None, scanJobId=None))
    check(False, "GLOBAL snapshot with a repository refused")
except RuntimeError:
    check(True, "GLOBAL snapshot with a repository refused (ck_score_scope)")
check(len(run("LATEST_REPOSITORY_SNAPSHOTS", {"namespaceId": None})[0]) == 1, "latest repository snapshots")
check(len(run("LATEST_REPOSITORY_SNAPSHOTS", {"namespaceId": ns})[0]) == 1, "filtered by organisation")
check(run("LATEST_NAMESPACE_SNAPSHOTS")[0][0][1] == "acme", "latest organisation snapshot")
check(len(run("LATEST_GLOBAL_SNAPSHOT")[0]) == 1, "latest global snapshot")
check(run("REPOSITORY_NAMESPACE", {"repositoryId": repo})[0] == [[ns]], "namespace of a repository")
check(len(run("RUN_JOB_SCORES", {"runId": run_id})[0]) == 1, "branch score attached to the job")
run("RECORD_LANGUAGES", {"labels": '["java", "typescript"]', "repositoryId": repo})
check(q(f"SELECT languages::text FROM source_repository WHERE id = '{repo}'") == [['["java", "typescript"]']], "repository labels stored")
try:
    run("RECORD_LANGUAGES", {"labels": '{"java": 1}', "repositoryId": repo})
    check(False, "labels must be an array")
except RuntimeError:
    check(True, "labels must be a JSON array (ck_repository_languages)")

print("== triage (phase 6)")
fid2 = r2[0][0]
lock = run("LOCK_FINDING", {"findingId": fid2})[0]
check(len(lock) == 1 and lock[0][0] == "OPEN" and lock[0][1] == repo and lock[0][2] == "main", "finding status, repository and branch read for update")
tri = {"findingId": fid2, "status": "ACCEPTED_RISK", "reason": "compensating control", "user": "awa",
       "fromStatus": "OPEN", "toStatus": "ACCEPTED_RISK"}
before = int(q(f"SELECT version FROM finding WHERE id = '{fid2}'")[0][0])
run("UPDATE_FINDING_STATUS", tri); run("INSERT_STATUS_HISTORY", tri)
check(q(f"SELECT status, status_reason, status_changed_by, version FROM finding WHERE id = '{fid2}'")
      == [["ACCEPTED_RISK", "compensating control", "awa", str(before + 1)]], "status, reason, author updated, version incremented")
hist = run("STATUS_HISTORY", {"findingId": fid2})[0]
check(len(hist) == 2 and hist[0][1] == "RESOLVED" and hist[1][:4] == ["OPEN", "ACCEPTED_RISK", "compensating control", "awa"],
      "history oldest first (scanner resolution, then triage)")
try:
    run("UPDATE_FINDING_STATUS", dict(tri, status="FALSE_POSITIVE", reason=None))
    check(False, "triage without reason refused")
except RuntimeError:
    check(True, "triage without reason refused by ck_finding_triage_reason")
f2b = finding(fp2, "opengrep", "weak-hash", "MEDIUM", cwes=("CWE-328",), cvss=7.5); f2b["jobId"] = job3
run("UPSERT_FINDING", f2b)
check(q(f"SELECT status FROM finding WHERE id = '{fid2}'") == [["ACCEPTED_RISK"]], "accepted risk kept when the scanner reports it again")
reopen = dict(tri, status="OPEN", reason=None, fromStatus="ACCEPTED_RISK", toStatus="OPEN")
run("UPDATE_FINDING_STATUS", reopen); run("INSERT_STATUS_HISTORY", reopen)
check(q(f"SELECT status, status_reason FROM finding WHERE id = '{fid2}'") == [["OPEN", ""]], "reopened without reason")

print("== dashboard and repository detail (phase 6)")
c = run("DASHBOARD_COUNTERS")[0][0]
check(c[0] == "2" and c[1] == "2" and c[2] == "3" and c[3] == "0" and c[4] == "1" and c[5] != "", "counters: audited repos, open findings, triaged, last audit: " + str(c))
sev = run("OPEN_BY_SEVERITY_TYPE", {"repositoryId": None})[0]
check(sorted(sev) == [["MEDIUM", "SECURITY", "2"]], "open findings by severity and type: " + str(sev))
check(run("OPEN_BY_SEVERITY_TYPE", {"repositoryId": repo2})[0] == [], "filtered by repository")
q(f"UPDATE source_repository SET removed_at = now() WHERE id = '{repo2}'")
check(run("OPEN_BY_SEVERITY_TYPE", {"repositoryId": None})[0] == sev, "removed repositories ignored")
q(f"UPDATE source_repository SET removed_at = NULL WHERE id = '{repo2}'")
q("INSERT INTO score_snapshot (scope_type, security_score, quality_score, global_score, coverage_percent, reliability, formula_version, computed_at) "
  "VALUES ('GLOBAL', 40, 60, 48, 100, 'HIGH', 'v1', now() - interval '3 days'), ('GLOBAL', 45, 60, 51, 100, 'HIGH', 'v1', now() - interval '3 days' + interval '1 minute'), "
  "('GLOBAL', 10, 10, 10, 100, 'HIGH', 'v1', now() - interval '200 days')")
trend = run("SCORE_TREND", {"scopeType": "GLOBAL", "repositoryId": None, "days": 90})[0]
check(len(trend) == 2 and trend[0][1] == "45.00" and trend[-1][1] == "81.87", "one point per day (last of the day), 90 days: " + str([t[:2] for t in trend]))
check(len(run("SCORE_TREND", {"scopeType": "REPOSITORY", "repositoryId": repo, "days": 90})[0]) == 1, "repository trend")
flow = run("WEEKLY_FLOW", {"repositoryId": None})[0]
check(len(flow) == 12 and sum(int(r[1]) for r in flow) == 3, "12 weeks, 3 findings opened: " + str([r[1:] for r in flow]))
check(len(run("WEEKLY_FLOW", {"repositoryId": repo2})[0]) == 12, "weekly flow of a repository")
prio = run("PRIORITY_REPOSITORIES", {"limit": 10})[0]
check(len(prio) == 1 and prio[0][1] == "acme/api" and prio[0][6] == "2" and prio[0][9] == "85.32", "priority repositories with open counts and score: " + str(prio))
info = run("REPOSITORY_INFO", {"repositoryId": repo})[0]
check(len(info) == 1 and info[0][1] == "acme/api" and info[0][12] == "acme" and info[0][14] == "GITLAB", "repository info with organisation and platform")
check(sorted(run("OPEN_BY_BRANCH", {"repositoryId": repo})[0]) == [["main", "MEDIUM", "SECURITY", "2"]], "open findings per branch")
rules = run("TOP_RULES", {"repositoryId": repo})[0]
check(len(rules) == 2 and rules[0][4] == "2", "frequent rules with severity rank: " + str(rules))
check(len(run("RECENT_JOBS", {"repositoryId": repo})[0]) == 2, "recent jobs of the repository")

print("== scoring v2 (phase 6b)")
issues = run("SECURITY_ISSUES", {"repositoryId": repo, "branch": "main"})[0]
check(len(issues) == 2 and all(i[1] != "QUALITY" for i in issues) and issues[0][7] != "", "open security findings with CWE and package columns: " + str([i[1:5] for i in issues]))
latest = run("LATEST_FINISHED_JOBS", {"repositoryId": None, "branch": None})[0]
check(len(latest) == 2 and all(l[3] is not None for l in latest), "latest finished job of each branch: " + str([l[1:3] for l in latest]))
check(len(run("LATEST_FINISHED_JOBS", {"repositoryId": repo, "branch": "main"})[0]) == 1, "filtered by repository and branch")
check(any(run("JOB_EXECUTIONS", {"jobId": l[0]})[0] for l in latest), "scanner statuses of a job")
check(run("LATEST_BRANCH_FORMULA")[0] == [["v1"]], "formula of the latest branch score (v1 snapshots → rescore needed)")

check(run("CONSUME_RESCORE_REQUEST")[0] == [['"V7: PMD severity by category"']], "rescore request left by migration V7 is consumed once")
check(run("CONSUME_RESCORE_REQUEST")[0] == [], "and only once")

print("== reports (phase 6)")
rep = run("REPORT_FINDINGS", dict(base, statuses=["OPEN"], limit=100))[0]
check(len(rep) == 2 and all(len(r[-1]) == 64 for r in rep), "report findings with fingerprint")
check(len(run("REPORT_FINDINGS", dict(base, limit=1))[0]) == 1, "report limit")
scans = run("REPORT_SCANS", {"repositoryId": repo, "branch": None})[0]
check(len(scans) == 1 and scans[0][2] == "main" and scans[0][3] == "a" * 40, "latest finished analysis per branch: " + str([s[:4] for s in scans]))
check(len(run("REPORT_SCANS", {"repositoryId": None, "branch": "main"})[0]) == 2, "all repositories, one branch")
ex = run("REPORT_EXECUTIONS", {"jobIds": [scans[0][0]]})[0]
check([e[1] for e in ex] == ["opengrep", "trivy"] and ex[1][2] == "FAILED", "tool runs of those analyses")
run("INSERT_REPORT", {"format": "PDF", "sha256": "f" * 64, "size": 1234, "filters": '{"status": ["OPEN"]}', "user": "awa"})
check(q("SELECT format, status, created_by FROM report") == [["PDF", "READY", "awa"]], "report generation recorded")

print(f"== {'all scan SQL checks passed' if failures == 0 else str(failures) + ' FAILED'}")
sys.exit(1 if failures else 0)
