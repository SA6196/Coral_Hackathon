/**
 * submitRoutes.js — Real Developer Submission API
 * ─────────────────────────────────────────────────────────────────────
 * Developers POST their commit info here.
 * The Coral engine analyzes it instantly and returns a security report.
 *
 * POST /api/submit-commit   — submit a new commit for analysis
 * GET  /api/submissions     — list all submitted commits
 * GET  /api/submissions/:id — get single submission result
 * DELETE /api/submissions/:id — remove a submission
 * GET  /api/submissions/stats — aggregate stats across all submissions
 * ─────────────────────────────────────────────────────────────────────
 */

const express = require("express");
const router  = express.Router();

const { scanForSecrets } = require("../utils/secretScanner");

// In-memory store for submitted commits (persists until server restart)
// In production this would be a real DB table
const submissions = [];
let submissionCounter = 1000;

// Known vulnerability database (supplements OSV mock data)
const KNOWN_VULNS = {
  "lodash":             { cve: "CVE-2020-8203", severity: "high",     cvss: 7.4, summary: "Prototype pollution" },
  "jsonwebtoken":       { cve: "CVE-2022-23529", severity: "high",    cvss: 7.6, summary: "JWT algorithm confusion" },
  "axios":              { cve: "CVE-2023-45857", severity: "medium",   cvss: 6.5, summary: "CSRF token exposure" },
  "express":            { cve: "CVE-2024-29041", severity: "medium",   cvss: 5.3, summary: "Open redirect vulnerability" },
  "vm2":                { cve: "CVE-2023-29017", severity: "critical", cvss: 10.0, summary: "Sandbox escape RCE" },
  "node-serialize":     { cve: "CVE-2017-5941",  severity: "critical", cvss: 9.8, summary: "Remote code execution via deserialization" },
  "log4js":             { cve: "CVE-2022-21704", severity: "medium",   cvss: 5.5, summary: "ReDoS vulnerability" },
  "minimist":           { cve: "CVE-2021-44906", severity: "critical", cvss: 9.8, summary: "Prototype pollution" },
  "ejs":                { cve: "CVE-2022-29078", severity: "critical", cvss: 9.8, summary: "Template injection RCE" },
  "stripe":             { cve: "CVE-2026-9999",  severity: "critical", cvss: 9.1, summary: "Payment data exposure" },
  "aws-sdk":            { cve: "CVE-2026-8888",  severity: "critical", cvss: 9.5, summary: "Credential exposure" },
  "shelljs":            { cve: "CVE-2022-0144",  severity: "high",     cvss: 7.8, summary: "Privilege escalation" },
  "path-parse":         { cve: "CVE-2021-23343", severity: "high",     cvss: 7.5, summary: "ReDoS" },
  "tar":                { cve: "CVE-2021-37713", severity: "high",     cvss: 7.5, summary: "Arbitrary file write" },
  "semver":             { cve: "CVE-2022-25883", severity: "medium",   cvss: 5.3, summary: "ReDoS in version parsing" },
  "bcrypt":             { cve: "CVE-2026-4444",  severity: "medium",   cvss: 5.3, summary: "Timing attack" },
  "pg":                 { cve: "CVE-2024-1234",  severity: "high",     cvss: 7.5, summary: "SQL injection via raw query" },
};

// Known policy violations
const POLICY_RULES = {
  "vm2":            { rule: "BANNED_PACKAGE",  severity: "critical", team: "security-engineering", reason: "CVE-2023-29017 allows complete sandbox escape" },
  "node-serialize": { rule: "BANNED_PACKAGE",  severity: "critical", team: "security-engineering", reason: "Known RCE vector - permanently banned" },
  "jsonwebtoken":   { rule: "AUDIT_REQUIRED",  severity: "high",     team: "auth-team",            reason: "JWT changes require security audit" },
  "stripe":         { rule: "BANNED_PACKAGE",  severity: "critical", team: "security-engineering", reason: "Active critical CVE - deployment blocked" },
  "aws-sdk":        { rule: "SECRETS_RISK",    severity: "critical", team: "platform-team",        reason: "Must use IAM roles, not hardcoded keys" },
  "bcrypt":         { rule: "REVIEW_REQUIRED", severity: "medium",   team: "auth-team",            reason: "Auth changes need senior review" },
  "pg":             { rule: "AUDIT_REQUIRED",  severity: "high",     team: "security-engineering", reason: "DB queries need SQL injection audit" },
  "shelljs":        { rule: "AUDIT_REQUIRED",  severity: "high",     team: "security-engineering", reason: "Shell execution requires security sign-off" },
};

/**
 * Analyze a submitted commit against the Coral engine
 */
function analyzeCommit(submission) {
  const { developer, pr_title, package_name, commit_diff, slack_message } = submission;

  // 1. Vulnerability check
  const vuln = KNOWN_VULNS[package_name?.toLowerCase()] || { cve: "NO_CVE_FOUND", severity: "safe", cvss: 0, summary: "No known vulnerabilities" };

  // 2. Secret scan
  const secrets = scanForSecrets(
    `${pr_title} ${commit_diff}`,
    slack_message || ""
  );

  // 3. Policy check
  const policyMatch = POLICY_RULES[package_name?.toLowerCase()];

  // 4. Risk score
  const SEVERITY_BASE = { critical: 95, high: 75, medium: 45, safe: 10 };
  let riskScore = SEVERITY_BASE[vuln.severity] || 10;
  if (secrets.length > 0) riskScore = Math.min(100, riskScore + 10);
  if (policyMatch) {
    const BOOST = { BANNED_PACKAGE: 15, SECRETS_RISK: 20, AUDIT_REQUIRED: 8, REVIEW_REQUIRED: 5 };
    riskScore = Math.min(100, riskScore + (BOOST[policyMatch.rule] || 0));
  }

  // 5. AI Summary
  let aiSummary = "";
  const sevEmoji = { critical: "🔴", high: "🟠", medium: "🟡", safe: "✅" }[vuln.severity] || "⚪";
  if (vuln.severity === "critical" && secrets.length > 0) {
    aiSummary = `${sevEmoji} CRITICAL: ${developer} submitted ${package_name} which has ${vuln.cve} AND a secret leak detected (${secrets[0]?.name}). Immediate rollback and credential rotation required.`;
  } else if (vuln.severity === "critical") {
    aiSummary = `${sevEmoji} Critical vulnerability ${vuln.cve} in ${package_name} by ${developer}. ${vuln.summary}. ${policyMatch ? `Violates policy: ${policyMatch.rule}.` : ""} Immediate action required.`;
  } else if (vuln.severity === "high") {
    aiSummary = `${sevEmoji} High-risk package ${package_name} (${vuln.cve}) submitted by ${developer}. ${vuln.summary}. Security review mandatory.`;
  } else if (secrets.length > 0) {
    aiSummary = `⚠️ Potential secret detected in ${developer}'s commit: "${secrets[0]?.name}". Clean git history and rotate credentials.`;
  } else if (vuln.severity === "medium") {
    aiSummary = `${sevEmoji} Moderate risk: ${package_name} has ${vuln.cve}. ${vuln.summary}. Patch before next release.`;
  } else {
    aiSummary = `✅ ${pr_title} looks clean. No known CVEs in ${package_name}. Good to go after standard review.`;
  }

  // 6. Recommended action
  let action = "SAFE_TO_DEPLOY";
  if (vuln.severity === "critical") action = "ROLLBACK_DEPLOYMENT";
  else if (secrets.length > 0) action = "ROTATE_SECRETS_IMMEDIATELY";
  else if (policyMatch?.rule === "BANNED_PACKAGE") action = "ROLLBACK_DEPLOYMENT";
  else if (policyMatch?.rule === "SECRETS_RISK") action = "SECURITY_AUDIT_REQUIRED";
  else if (vuln.severity === "high") action = "SECURITY_REVIEW_REQUIRED";
  else if (vuln.severity === "medium") action = "MONITOR_AND_TEST";

  return {
    vulnerability: { cve: vuln.cve, severity: vuln.severity, cvss: vuln.cvss, summary: vuln.summary },
    secrets_detected: secrets.length > 0 ? { count: secrets.length, findings: secrets, highest_severity: secrets[0]?.severity } : null,
    policy_violation: policyMatch ? { rule: policyMatch.rule, severity: policyMatch.severity, team: policyMatch.team, reason: policyMatch.reason } : null,
    risk_score: riskScore,
    ai_summary: aiSummary,
    recommended_action: action,
  };
}

/* ─────────────────────────────────────────────────────────────────────
   POST /api/submit-commit
   Body: { developer, pr_title, package_name, commit_diff, slack_message, repo? }
   Returns: Full security analysis of the submitted commit
───────────────────────────────────────────────────────────────────── */
router.post("/submit-commit", (req, res) => {
  const { developer, pr_title, package_name, commit_diff, slack_message, repo } = req.body;

  // Validation
  if (!developer?.trim())    return res.status(400).json({ success: false, error: "developer is required" });
  if (!pr_title?.trim())     return res.status(400).json({ success: false, error: "pr_title is required" });
  if (!package_name?.trim()) return res.status(400).json({ success: false, error: "package_name is required" });

  const id = `SUB-${++submissionCounter}`;
  const submission = {
    id,
    developer:     developer.trim().slice(0, 50),
    pr_title:      pr_title.trim().slice(0, 200),
    package_name:  package_name.trim().toLowerCase().slice(0, 100),
    commit_diff:   (commit_diff || "").slice(0, 2000),
    slack_message: (slack_message || "").slice(0, 500),
    repo:          (repo || "unknown/repo").slice(0, 100),
    submitted_at:  new Date().toISOString(),
  };

  // Run Coral analysis
  const analysis = analyzeCommit(submission);

  const result = {
    ...submission,
    ...analysis,
    incident_id: id,
    pr_details: {
      pr_id:      submissionCounter,
      title:      submission.pr_title,
      developer:  submission.developer,
      merged_at:  submission.submitted_at,
    },
    package_details: { package_name: submission.package_name },
    internal_discussion: {
      slack_channel: "#dev-submissions",
      message: submission.slack_message || "No Slack message provided.",
    },
  };

  submissions.unshift(result); // newest first
  if (submissions.length > 200) submissions.pop(); // cap at 200

  console.log(`[SUBMIT] ${id} — ${developer} → ${package_name} | ${analysis.vulnerability.severity?.toUpperCase()} | score: ${analysis.risk_score}`);

  res.status(201).json({
    success: true,
    message: `Commit analyzed by Coral Security Engine`,
    submission: result,
  });
});

/* ─────────────────────────────────────────────────────────────────────
   GET /api/submissions
   Returns all submitted commits (newest first), with optional filtering
───────────────────────────────────────────────────────────────────── */
router.get("/submissions", (req, res) => {
  const { developer, severity, page = 1, limit = 20 } = req.query;

  let filtered = [...submissions];
  if (developer) filtered = filtered.filter(s => s.developer?.toLowerCase().includes(developer.toLowerCase()));
  if (severity)  filtered = filtered.filter(s => s.vulnerability?.severity === severity);

  const p     = Math.max(1, parseInt(page, 10));
  const l     = Math.min(50, Math.max(1, parseInt(limit, 10)));
  const start = (p - 1) * l;

  res.json({
    success: true,
    submissions: filtered.slice(start, start + l),
    total:       filtered.length,
    page:        p,
    limit:       l,
    total_pages: Math.ceil(filtered.length / l),
  });
});

/* ─────────────────────────────────────────────────────────────────────
   GET /api/submissions/stats
   Aggregate stats across all developer submissions
───────────────────────────────────────────────────────────────────── */
router.get("/submissions/stats", (req, res) => {
  if (submissions.length === 0) {
    return res.json({ success: true, stats: null, message: "No submissions yet" });
  }

  const critical = submissions.filter(s => s.vulnerability?.severity === "critical").length;
  const high     = submissions.filter(s => s.vulnerability?.severity === "high").length;
  const medium   = submissions.filter(s => s.vulnerability?.severity === "medium").length;
  const safe     = submissions.filter(s => s.vulnerability?.severity === "safe").length;
  const secrets  = submissions.filter(s => s.secrets_detected).length;
  const policies = submissions.filter(s => s.policy_violation).length;
  const avgScore = Math.round(submissions.reduce((s, i) => s + (i.risk_score || 0), 0) / submissions.length);

  // Per-developer breakdown
  const devMap = {};
  submissions.forEach(s => {
    const d = s.developer;
    if (!devMap[d]) devMap[d] = { developer: d, submissions: 0, critical: 0, high: 0, risk_total: 0, secrets: 0 };
    devMap[d].submissions++;
    devMap[d].risk_total += s.risk_score || 0;
    if (s.vulnerability?.severity === "critical") devMap[d].critical++;
    if (s.vulnerability?.severity === "high")     devMap[d].high++;
    if (s.secrets_detected) devMap[d].secrets++;
  });

  const developers = Object.values(devMap).map(d => ({
    ...d,
    avg_risk: Math.round(d.risk_total / d.submissions),
    risk_tier: d.critical > 0 || d.secrets > 0 ? "HIGH_RISK" : d.high > 0 ? "ELEVATED" : "STANDARD",
  })).sort((a, b) => b.risk_total - a.risk_total);

  res.json({
    success: true,
    stats: {
      total_submissions: submissions.length,
      by_severity: { critical, high, medium, safe },
      secret_leaks: secrets,
      policy_violations: policies,
      avg_risk_score: avgScore,
      overall_grade: avgScore >= 75 ? "D" : avgScore >= 50 ? "C" : avgScore >= 25 ? "B" : "A",
      developers,
    },
  });
});

/* ─────────────────────────────────────────────────────────────────────
   GET /api/submissions/:id
───────────────────────────────────────────────────────────────────── */
router.get("/submissions/:id", (req, res) => {
  const sub = submissions.find(s => s.id === req.params.id);
  if (!sub) return res.status(404).json({ success: false, error: "Submission not found" });
  res.json({ success: true, submission: sub });
});

/* ─────────────────────────────────────────────────────────────────────
   DELETE /api/submissions/:id
───────────────────────────────────────────────────────────────────── */
router.delete("/submissions/:id", (req, res) => {
  const idx = submissions.findIndex(s => s.id === req.params.id);
  if (idx === -1) return res.status(404).json({ success: false, error: "Submission not found" });
  submissions.splice(idx, 1);
  res.json({ success: true, message: "Submission removed" });
});

module.exports = router;
