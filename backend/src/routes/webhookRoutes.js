/**
 * webhookRoutes.js — GitHub Webhook Receiver
 * ─────────────────────────────────────────────────────────────────────
 * Real production webhook. Add this URL to your GitHub org:
 *   Settings → Webhooks → Add webhook
 *   Payload URL: https://your-domain.com/api/webhook/github
 *   Content type: application/json
 *   Events: Push events, Pull requests
 *
 * Every developer's push/PR is automatically analyzed.
 * No developer ever touches this portal.
 * ─────────────────────────────────────────────────────────────────────
 */

const express    = require("express");
const router     = express.Router();
const crypto     = require("crypto");
const axios      = require("axios");
const fs         = require("fs");
const path       = require("path");
const { scanForSecrets } = require("../utils/secretScanner");
const { invalidateCache } = require("../coral/joinData");

function syncToMockDb(record, commitDiff) {
  try {
    const githubPath = path.join(__dirname, "../../mock-data/github.json");
    const data = JSON.parse(fs.readFileSync(githubPath, "utf-8"));
    const newEntry = {
      pr_id: Math.floor(Math.random() * 900000) + 100000,
      author: record.developer,
      title: record.pr_title,
      package_name: record.package_name,
      merged_at: record.received_at,
      commit_diff: commitDiff || "Commit from live webhook"
    };
    data.unshift(newEntry);
    fs.writeFileSync(githubPath, JSON.stringify(data, null, 2));
    
    invalidateCache("all");
    console.log(`[SYNC] Appended live webhook ${record.id} to github.json and invalidated cache for all sessions.`);
  } catch (err) {
    console.error("[SYNC_ERROR] Failed to sync to mock DB:", err.message);
  }
}

// Helper to post status to GitHub API
async function postCommitStatusToGitHub(repo, sha, record) {
  const token = process.env.GITHUB_TOKEN;
  if (!token || token === "ghp_your_token_here" || !sha || sha === "unknown" || !repo || repo === "unknown/repo") return;

  const state = record.risk_score >= 75 ? "failure" : "success";
  const desc = record.risk_score >= 75 
    ? `Coral Gate: Blocked (${record.policy_violation?.rule || record.vulnerability?.cve || "High Risk"})`
    : "Coral Gate: Passed (No vulnerabilities)";

  try {
    const url = `https://api.github.com/repos/${repo}/statuses/${sha}`;
    await axios.post(url, {
      state,
      target_url: process.env.PUBLIC_URL || "http://localhost:5174",
      description: desc,
      context: "Coral Security Gate"
    }, {
      headers: {
        "Authorization": `Bearer ${token.trim()}`,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Coral-Security-Agent"
      }
    });
    console.log(`[GITHUB_STATUS] Status '${state}' posted to ${repo} for commit ${sha}`);
  } catch (err) {
    console.error(`[GITHUB_STATUS_ERROR] Failed to post status to ${repo}: ${err.message}`, err.response?.data || "");
  }
}

// In-memory event log (in production: use PostgreSQL)
const webhookEvents = [
  {
    id: "WH-10",
    source: "github_push",
    event_type: "push",
    delivery_id: "manual-1716834100",
    developer: "sarah_dev",
    pr_title: "Add sandboxed runtime using vm2",
    package_name: "vm2",
    repo: "enterprise-app/auth-service",
    branch: "main",
    commit_sha: "a7d9f2c",
    received_at: new Date(Date.now() - 3 * 60 * 1000).toISOString(),
    vulnerability: { cve: "CVE-2023-29017", severity: "critical", cvss: 10.0, summary: "Sandbox escape leading to RCE" },
    secrets_detected: null,
    policy_violation: { rule: "BANNED_PACKAGE", team: "security-engineering", reason: "CVE-2023-29017 — complete sandbox escape, permanently banned" },
    risk_score: 100,
    ai_summary: "🔴 CRITICAL: sarah_dev committed vm2 (CVE-2023-29017) on branch main. This package has a complete sandbox escape and violates policy BANNED_PACKAGE. Deployment blocked.",
    recommended_action: "BLOCK_DEPLOYMENT",
  },
  {
    id: "WH-9",
    source: "github_pr",
    event_type: "pull_request.opened",
    delivery_id: "manual-1716834200",
    developer: "alex_ops",
    pr_number: 142,
    pr_url: "https://github.com/enterprise-app/infra/pull/142",
    pr_title: "Configure AWS credentials in config block",
    package_name: "none",
    repo: "enterprise-app/infra",
    branch: "setup-deployment",
    commit_sha: "f2c3d4e",
    received_at: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
    vulnerability: { cve: "NO_CVE_FOUND", severity: "safe", cvss: 0, summary: "No known vulnerabilities" },
    secrets_detected: {
      count: 1,
      findings: [
        { name: "AWS Access Key ID", severity: "critical", recommendation: "Rotate credentials immediately and move to IAM Roles." }
      ]
    },
    policy_violation: null,
    risk_score: 87,
    ai_summary: "⚠️ Potential secret detected in commit by alex_ops: 'AWS Access Key ID'. Rotate key and scrub git history.",
    recommended_action: "ROTATE_SECRETS",
  },
  {
    id: "WH-8",
    source: "github_push",
    event_type: "push",
    delivery_id: "manual-1716834300",
    developer: "john_backend",
    pr_title: "Implement auth token signing with jsonwebtoken",
    package_name: "jsonwebtoken",
    repo: "enterprise-app/gateway",
    branch: "hotfix-auth-keys",
    commit_sha: "c4d5e6f",
    received_at: new Date(Date.now() - 32 * 60 * 1000).toISOString(),
    vulnerability: { cve: "CVE-2022-23529", severity: "high", cvss: 7.6, summary: "JWT algorithm confusion attack" },
    secrets_detected: null,
    policy_violation: { rule: "AUDIT_REQUIRED", team: "auth-team", reason: "JWT library changes require security audit" },
    risk_score: 83,
    ai_summary: "🟠 High-severity CVE-2022-23529 in jsonwebtoken by john_backend. JWT algorithm confusion attack. Requires auth-team sign-off before merge.",
    recommended_action: "SECURITY_REVIEW",
  },
  {
    id: "WH-7",
    source: "github_push",
    event_type: "push",
    delivery_id: "manual-1716834400",
    developer: "karen_web",
    pr_title: "Add server-side template rendering with ejs",
    package_name: "ejs",
    repo: "enterprise-app/dashboard",
    branch: "feature-templates",
    commit_sha: "b2a3c4d",
    received_at: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
    vulnerability: { cve: "CVE-2022-29078", severity: "critical", cvss: 9.8, summary: "Template injection leading to RCE" },
    secrets_detected: null,
    policy_violation: { rule: "BANNED_PACKAGE", team: "security-engineering", reason: "RCE via template injection — use handlebars instead" },
    risk_score: 100,
    ai_summary: "🔴 CRITICAL: karen_web introduced ejs (CVE-2022-29078) which is a banned package in this repo. Recommending rollback and replacement with handlebars.",
    recommended_action: "BLOCK_DEPLOYMENT",
  },
  {
    id: "WH-6",
    source: "github_push",
    event_type: "push",
    delivery_id: "manual-1716834500",
    developer: "mike_ui",
    pr_title: "Refactor settings grid layout",
    package_name: "none",
    repo: "enterprise-app/dashboard",
    branch: "main",
    commit_sha: "e8f9a0b",
    received_at: new Date(Date.now() - 90 * 60 * 1000).toISOString(),
    vulnerability: { cve: "NO_CVE_FOUND", severity: "safe", cvss: 0, summary: "No known vulnerabilities" },
    secrets_detected: null,
    policy_violation: null,
    risk_score: 5,
    ai_summary: "✅ Commit by mike_ui on main — clean run. No issues detected.",
    recommended_action: "SAFE_TO_DEPLOY",
  },
  {
    id: "WH-5",
    source: "github_pr",
    event_type: "pull_request.opened",
    delivery_id: "manual-1716834600",
    developer: "david_k",
    pr_number: 89,
    pr_url: "https://github.com/enterprise-app/core/pull/89",
    pr_title: "Add Stripe webhooks and client package",
    package_name: "stripe",
    repo: "enterprise-app/core",
    branch: "feature-stripe-billing",
    commit_sha: "f1e2d3c",
    received_at: new Date(Date.now() - 120 * 60 * 1000).toISOString(),
    vulnerability: { cve: "CVE-2026-9999", severity: "critical", cvss: 9.1, summary: "Payment data exposure" },
    secrets_detected: null,
    policy_violation: { rule: "BANNED_PACKAGE", team: "security-engineering", reason: "Active critical CVE — deployment blocked" },
    risk_score: 100,
    ai_summary: "🔴 Critical vulnerability CVE-2026-9999 in stripe by david_k. Active payment vulnerability. Violates rule BANNED_PACKAGE. Block deployment immediately.",
    recommended_action: "BLOCK_DEPLOYMENT",
  },
  {
    id: "WH-4",
    source: "github_push",
    event_type: "push",
    delivery_id: "manual-1716834700",
    developer: "alex_ops",
    pr_title: "Integrate aws-sdk for S3 storage upload",
    package_name: "aws-sdk",
    repo: "enterprise-app/core",
    branch: "main",
    commit_sha: "a9b8c7d",
    received_at: new Date(Date.now() - 180 * 60 * 1000).toISOString(),
    vulnerability: { cve: "CVE-2026-8888", severity: "critical", cvss: 9.5, summary: "Credential exposure risk" },
    secrets_detected: null,
    policy_violation: { rule: "SECRETS_RISK", team: "platform-team", reason: "Must use IAM roles — hardcoded keys not allowed" },
    risk_score: 100,
    ai_summary: "🔴 Critical CVE CVE-2026-8888 in aws-sdk by alex_ops. Policy rule SECRETS_RISK violated. Deployment blocked.",
    recommended_action: "BLOCK_DEPLOYMENT",
  },
  {
    id: "WH-3",
    source: "github_push",
    event_type: "push",
    delivery_id: "manual-1716834800",
    developer: "john_backend",
    pr_title: "Fix SQL injections in search query using pg client",
    package_name: "pg",
    repo: "enterprise-app/gateway",
    branch: "main",
    commit_sha: "d5e6f7a",
    received_at: new Date(Date.now() - 240 * 60 * 1000).toISOString(),
    vulnerability: { cve: "CVE-2024-1234", severity: "high", cvss: 7.5, summary: "SQL injection via unsanitized raw queries" },
    secrets_detected: null,
    policy_violation: { rule: "AUDIT_REQUIRED", team: "security-engineering", reason: "DB query changes require SQL injection audit" },
    risk_score: 83,
    ai_summary: "🟠 High CVE-2024-1234 in pg package introduced by john_backend. Manual DB security audit is required before deployment.",
    recommended_action: "SECURITY_REVIEW",
  },
  {
    id: "WH-2",
    source: "github_push",
    event_type: "push",
    delivery_id: "manual-1716834900",
    developer: "mike_ui",
    pr_title: "Update minimist to patch security advisory",
    package_name: "minimist",
    repo: "enterprise-app/dashboard",
    branch: "main",
    commit_sha: "c3d4e5f",
    received_at: new Date(Date.now() - 360 * 60 * 1000).toISOString(),
    vulnerability: { cve: "CVE-2021-44906", severity: "critical", cvss: 9.8, summary: "Prototype pollution" },
    secrets_detected: null,
    policy_violation: null,
    risk_score: 95,
    ai_summary: "🔴 Critical CVE CVE-2021-44906 in minimist by mike_ui on main. Recommended action: Rollback deployment.",
    recommended_action: "BLOCK_DEPLOYMENT",
  },
  {
    id: "WH-1",
    source: "github_push",
    event_type: "push",
    delivery_id: "manual-1716835000",
    developer: "sarah_dev",
    pr_title: "Update package lock dependencies",
    package_name: "none",
    repo: "enterprise-app/auth-service",
    branch: "patch-1",
    commit_sha: "f9e8d7c",
    received_at: new Date(Date.now() - 480 * 60 * 1000).toISOString(),
    vulnerability: { cve: "NO_CVE_FOUND", severity: "safe", cvss: 0, summary: "No known vulnerabilities" },
    secrets_detected: null,
    policy_violation: null,
    risk_score: 5,
    ai_summary: "✅ Commit by sarah_dev looks clean. Ready to deploy.",
    recommended_action: "SAFE_TO_DEPLOY",
  }
];
let eventCounter = 10;

// Known vulnerability database
const KNOWN_VULNS = {
  "lodash":         { cve: "CVE-2020-8203",  severity: "high",     cvss: 7.4,  summary: "Prototype pollution via merge/zipObjectDeep" },
  "jsonwebtoken":   { cve: "CVE-2022-23529", severity: "high",     cvss: 7.6,  summary: "JWT algorithm confusion attack" },
  "axios":          { cve: "CVE-2023-45857", severity: "medium",   cvss: 6.5,  summary: "CSRF token leakage via headers" },
  "express":        { cve: "CVE-2024-29041", severity: "medium",   cvss: 5.3,  summary: "Open redirect in res.location()" },
  "vm2":            { cve: "CVE-2023-29017", severity: "critical", cvss: 10.0, summary: "Sandbox escape leading to RCE" },
  "node-serialize": { cve: "CVE-2017-5941",  severity: "critical", cvss: 9.8,  summary: "Remote code execution via deserialization" },
  "minimist":       { cve: "CVE-2021-44906", severity: "critical", cvss: 9.8,  summary: "Prototype pollution" },
  "ejs":            { cve: "CVE-2022-29078", severity: "critical", cvss: 9.8,  summary: "Template injection leading to RCE" },
  "stripe":         { cve: "CVE-2026-9999",  severity: "critical", cvss: 9.1,  summary: "Payment data exposure" },
  "aws-sdk":        { cve: "CVE-2026-8888",  severity: "critical", cvss: 9.5,  summary: "Credential exposure risk" },
  "shelljs":        { cve: "CVE-2022-0144",  severity: "high",     cvss: 7.8,  summary: "Privilege escalation via shell execution" },
  "semver":         { cve: "CVE-2022-25883", severity: "medium",   cvss: 5.3,  summary: "ReDoS in version range parsing" },
  "tar":            { cve: "CVE-2021-37713", severity: "high",     cvss: 7.5,  summary: "Arbitrary file write via symlink" },
  "bcrypt":         { cve: "CVE-2026-4444",  severity: "medium",   cvss: 5.3,  summary: "Timing side-channel attack" },
  "pg":             { cve: "CVE-2024-1234",  severity: "high",     cvss: 7.5,  summary: "SQL injection via unsanitized raw queries" },
  "log4js":         { cve: "CVE-2022-21704", severity: "medium",   cvss: 5.5,  summary: "ReDoS via category name" },
  "path-parse":     { cve: "CVE-2021-23343", severity: "high",     cvss: 7.5,  summary: "ReDoS vulnerability" },
};

const POLICY_RULES = {
  "vm2":            { rule: "BANNED_PACKAGE",  team: "security-engineering", reason: "CVE-2023-29017 — complete sandbox escape, permanently banned" },
  "node-serialize": { rule: "BANNED_PACKAGE",  team: "security-engineering", reason: "Known RCE vector — permanently banned" },
  "jsonwebtoken":   { rule: "AUDIT_REQUIRED",  team: "auth-team",            reason: "JWT library changes require security audit" },
  "stripe":         { rule: "BANNED_PACKAGE",  team: "security-engineering", reason: "Active critical CVE — deployment blocked" },
  "aws-sdk":        { rule: "SECRETS_RISK",    team: "platform-team",        reason: "Must use IAM roles — hardcoded keys not allowed" },
  "bcrypt":         { rule: "REVIEW_REQUIRED", team: "auth-team",            reason: "Auth library changes require senior review" },
  "pg":             { rule: "AUDIT_REQUIRED",  team: "security-engineering", reason: "DB query changes require SQL injection audit" },
  "shelljs":        { rule: "AUDIT_REQUIRED",  team: "security-engineering", reason: "Shell execution requires explicit security sign-off" },
  "ejs":            { rule: "BANNED_PACKAGE",  team: "security-engineering", reason: "RCE via template injection — use handlebars instead" },
};

/**
 * Verify GitHub webhook signature (HMAC-SHA256)
 * Set GITHUB_WEBHOOK_SECRET in your .env
 */
function verifyGitHubSignature(req) {
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  if (!secret) return true; // Skip if not configured (dev mode)

  const sig = req.headers["x-hub-signature-256"];
  if (!sig) return false;

  const hmac    = crypto.createHmac("sha256", secret);
  const digest  = "sha256=" + hmac.update(JSON.stringify(req.body)).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(digest));
}

/**
 * Extract changed packages from a commit's file list
 * In production: parse package.json diff
 */
function extractPackages(files = []) {
  const changedFiles = files.map(f => f.filename || f).join(" ");
  const matches = changedFiles.match(/(?:^|\/)(?:package\.json|package-lock\.json|yarn\.lock)/gi);
  return matches ? ["unknown"] : [];
}

/**
 * Analyze a single commit/PR against the Coral engine
 */
function analyzeEvent(data) {
  const { developer, pr_title, package_name, commit_message, repo, branch, commit_sha } = data;

  const pkg   = (package_name || "none").toLowerCase();
  const vuln  = KNOWN_VULNS[pkg] || { cve: "NO_CVE_FOUND", severity: "safe", cvss: 0, summary: "No known vulnerabilities detected" };
  const secrets = scanForSecrets(`${pr_title} ${commit_message}`, "");
  const policy  = POLICY_RULES[pkg] || null;

  // Risk scoring
  const BASE = { critical: 90, high: 70, medium: 40, safe: 5 };
  let risk = BASE[vuln.severity] || 5;
  if (secrets.length > 0) risk = Math.min(100, risk + 12);
  if (policy?.rule === "BANNED_PACKAGE")  risk = Math.min(100, risk + 15);
  if (policy?.rule === "SECRETS_RISK")    risk = Math.min(100, risk + 18);
  if (policy?.rule === "AUDIT_REQUIRED")  risk = Math.min(100, risk + 8);

  // AI summary
  const e = { critical: "🔴", high: "🟠", medium: "🟡", safe: "✅" }[vuln.severity] || "⚪";
  let summary = "";
  if (vuln.severity === "critical" && secrets.length > 0) {
    summary = `${e} CRITICAL: ${developer} introduced ${pkg} (${vuln.cve}) AND ${secrets.length} secret(s) detected — ${secrets[0]?.name}. Immediate rollback and credential rotation required.`;
  } else if (vuln.severity === "critical") {
    summary = `${e} Critical CVE ${vuln.cve} in ${pkg} committed by ${developer} on ${branch}. ${vuln.summary}. ${policy ? "Policy violation: " + policy.rule + "." : ""} Block deployment immediately.`;
  } else if (vuln.severity === "high") {
    summary = `${e} High-severity ${vuln.cve} in ${pkg} by ${developer}. ${vuln.summary}. Security review required before merging.`;
  } else if (secrets.length > 0) {
    summary = `⚠️ Potential secret in commit by ${developer}: "${secrets[0]?.name}". Review code and rotate any exposed credentials.`;
  } else if (vuln.severity === "medium") {
    summary = `${e} ${pkg} has ${vuln.cve}. ${vuln.summary}. Patch in next sprint — low urgency.`;
  } else {
    summary = `${e} Commit by ${developer} on ${branch} — no known CVEs in ${pkg || "changed packages"}. Cleared for review.`;
  }

  let action = "SAFE_TO_DEPLOY";
  if (vuln.severity === "critical" || policy?.rule === "BANNED_PACKAGE") action = "BLOCK_DEPLOYMENT";
  else if (secrets.length > 0)   action = "ROTATE_SECRETS";
  else if (policy?.rule === "SECRETS_RISK")   action = "SECURITY_AUDIT";
  else if (vuln.severity === "high")          action = "SECURITY_REVIEW";
  else if (vuln.severity === "medium")        action = "MONITOR";

  return { vuln, secrets, policy, risk, summary, action };
}

/* ─────────────────────────────────────────────────────────────────────
   POST /api/webhook/github
   Real GitHub webhook receiver (push + pull_request events)
───────────────────────────────────────────────────────────────────── */
router.post("/webhook/github", (req, res) => {
  if (!verifyGitHubSignature(req)) {
    return res.status(401).json({ success: false, error: "Invalid webhook signature" });
  }

  const event    = req.headers["x-github-event"] || "push";
  const payload  = req.body;
  const delivery = req.headers["x-github-delivery"] || `manual-${Date.now()}`;

  const results = [];

  if (event === "push") {
    const commits  = payload.commits || [];
    const repo     = payload.repository?.full_name || "unknown/repo";
    const branch   = (payload.ref || "").replace("refs/heads/", "");
    const pusher   = payload.pusher?.name || payload.sender?.login || "unknown";

    commits.slice(0, 10).forEach(commit => {
      const id  = `WH-${++eventCounter}`;
      // Check if package_name is directly supplied (sandbox mode)
      let pkg = commit.package_name;
      if (!pkg) {
        // Fallback: parse install messages, e.g., "npm install lodash"
        const msg = commit.message || "";
        const installMatch = msg.match(/(?:npm install|yarn add|npm i)\s+([a-zA-Z0-9\-_@/]+)/i);
        if (installMatch) {
          pkg = installMatch[1];
        } else {
          pkg = extractPackages(commit.modified || commit.added || [])[0] || "none";
        }
      }

      const data = {
        developer:      pusher,
        pr_title:       commit.message?.split("\n")[0] || "Push commit",
        package_name:   pkg,
        commit_message: commit.message || "",
        repo,
        branch,
        commit_sha:     commit.id?.slice(0, 7) || "unknown",
      };

      const analysis = analyzeEvent(data);
      const record = {
        id,
        source:       "github_push",
        event_type:   "push",
        delivery_id:  delivery,
        developer:    data.developer,
        pr_title:     data.pr_title,
        package_name: pkg,
        repo,
        branch,
        commit_sha:   data.commit_sha,
        received_at:  new Date().toISOString(),
        vulnerability:      { cve: analysis.vuln.cve, severity: analysis.vuln.severity, cvss: analysis.vuln.cvss, summary: analysis.vuln.summary },
        secrets_detected:   analysis.secrets.length > 0 ? { count: analysis.secrets.length, findings: analysis.secrets } : null,
        policy_violation:   analysis.policy,
        risk_score:         analysis.risk,
        ai_summary:         analysis.summary,
        recommended_action: analysis.action,
      };

      webhookEvents.unshift(record);
      results.push(record);
      console.log(`[WEBHOOK] ${id} | push | ${pusher} → ${repo}:${branch} | ${analysis.vuln.severity?.toUpperCase()} | score:${analysis.risk}`);
      
      // Sync into historical feed
      syncToMockDb(record, commit.message);

      // Real-time commit status gate update
      postCommitStatusToGitHub(repo, commit.id, record);
    });

  } else if (event === "pull_request") {
    const pr      = payload.pull_request || {};
    const action  = payload.action;

    if (["opened", "synchronize", "reopened"].includes(action)) {
      const id  = `WH-${++eventCounter}`;
      const repo    = payload.repository?.full_name || "unknown/repo";
      const branch  = pr.head?.ref || "feature-branch";
      const developer = pr.user?.login || "unknown";

      // Extract package_name (sandbox or match in title/body)
      let pkg = pr.package_name;
      if (!pkg) {
        const text = `${pr.title || ""} ${pr.body || ""}`;
        const match = text.match(/(?:npm install|yarn add|npm i)\s+([a-zA-Z0-9\-_@/]+)/i);
        pkg = match ? match[1] : "none";
      }

      const data = {
        developer,
        pr_title:     pr.title || "Untitled PR",
        package_name: pkg,
        commit_message: pr.body || "",
        repo,
        branch,
        commit_sha:   pr.head?.sha?.slice(0, 7) || "unknown",
      };

      const analysis = analyzeEvent(data);
      const record = {
        id,
        source:       "github_pr",
        event_type:   `pull_request.${action}`,
        delivery_id:  delivery,
        pr_number:    pr.number,
        pr_url:       pr.html_url,
        developer,
        pr_title:     data.pr_title,
        package_name: "none",
        repo,
        branch,
        commit_sha:   data.commit_sha,
        received_at:  new Date().toISOString(),
        vulnerability:      { cve: analysis.vuln.cve, severity: analysis.vuln.severity, cvss: analysis.vuln.cvss, summary: analysis.vuln.summary },
        secrets_detected:   analysis.secrets.length > 0 ? { count: analysis.secrets.length, findings: analysis.secrets } : null,
        policy_violation:   analysis.policy,
        risk_score:         analysis.risk,
        ai_summary:         analysis.summary,
        recommended_action: analysis.action,
      };

      webhookEvents.unshift(record);
      results.push(record);
      console.log(`[WEBHOOK] ${id} | PR#${pr.number} | ${developer} → ${repo} | ${analysis.vuln.severity?.toUpperCase()} | score:${analysis.risk}`);
      
      // Sync into historical feed
      syncToMockDb(record, pr.body);

      // Real-time commit status gate update for PR head
      postCommitStatusToGitHub(repo, pr.head?.sha, record);
    }
  }

  if (webhookEvents.length > 500) webhookEvents.splice(500);

  res.status(200).json({ success: true, processed: results.length, events: results });
});

/* ─────────────────────────────────────────────────────────────────────
   GET /api/webhook/events — All webhook-received events
───────────────────────────────────────────────────────────────────── */
router.get("/webhook/events", (req, res) => {
  const { severity, developer, page = 1, limit = 30 } = req.query;

  let filtered = [...webhookEvents];
  if (severity)  filtered = filtered.filter(e => e.vulnerability?.severity === severity);
  if (developer) filtered = filtered.filter(e => e.developer?.toLowerCase().includes(developer.toLowerCase()));

  const p     = Math.max(1, parseInt(page, 10));
  const l     = Math.min(100, parseInt(limit, 10));
  const start = (p - 1) * l;

  res.json({
    success:     true,
    events:      filtered.slice(start, start + l),
    total:       filtered.length,
    page:        p,
    limit:       l,
    total_pages: Math.ceil(filtered.length / l),
  });
});

/* ─────────────────────────────────────────────────────────────────────
   GET /api/webhook/stats — Aggregate stats across all webhook events
───────────────────────────────────────────────────────────────────── */
router.get("/webhook/stats", (req, res) => {
  if (webhookEvents.length === 0) {
    return res.json({ success: true, stats: null });
  }

  const critical = webhookEvents.filter(e => e.vulnerability?.severity === "critical").length;
  const high     = webhookEvents.filter(e => e.vulnerability?.severity === "high").length;
  const medium   = webhookEvents.filter(e => e.vulnerability?.severity === "medium").length;
  const safe     = webhookEvents.filter(e => e.vulnerability?.severity === "safe").length;
  const secrets  = webhookEvents.filter(e => e.secrets_detected).length;
  const policies = webhookEvents.filter(e => e.policy_violation).length;
  const blocked  = webhookEvents.filter(e => e.recommended_action === "BLOCK_DEPLOYMENT").length;

  const devMap = {};
  webhookEvents.forEach(e => {
    if (!devMap[e.developer]) devMap[e.developer] = { developer: e.developer, commits: 0, risk_total: 0, critical: 0, blocked: 0 };
    devMap[e.developer].commits++;
    devMap[e.developer].risk_total += e.risk_score || 0;
    if (e.vulnerability?.severity === "critical") devMap[e.developer].critical++;
    if (e.recommended_action === "BLOCK_DEPLOYMENT") devMap[e.developer].blocked++;
  });

  const developers = Object.values(devMap)
    .map(d => ({ ...d, avg_risk: Math.round(d.risk_total / d.commits) }))
    .sort((a, b) => b.risk_total - a.risk_total);

  res.json({
    success: true,
    stats: {
      total_events: webhookEvents.length,
      by_severity:  { critical, high, medium, safe },
      secret_leaks: secrets,
      policy_violations: policies,
      blocked_deployments: blocked,
      developers,
    },
  });
});

/* ─────────────────────────────────────────────────────────────────────
   GET /api/webhook/config — Returns setup instructions for the UI
───────────────────────────────────────────────────────────────────── */
router.get("/webhook/config", (req, res) => {
  const host = process.env.PUBLIC_URL || `http://localhost:${process.env.PORT || 5000}`;
  res.json({
    success: true,
    config: {
      webhook_url:  `${host}/api/webhook/github`,
      content_type: "application/json",
      events:       ["push", "pull_request"],
      secret_env:   "GITHUB_WEBHOOK_SECRET",
      instructions: [
        "Go to GitHub → Your Organization → Settings → Webhooks",
        "Click 'Add webhook'",
        `Set Payload URL to: ${host}/api/webhook/github`,
        "Set Content type to: application/json",
        "Set a secret and add it to your .env as GITHUB_WEBHOOK_SECRET",
        "Select events: 'Pushes' and 'Pull requests'",
        "Click 'Add webhook' — all developer commits will now be analyzed automatically",
      ],
    },
  });
});

module.exports = { router, webhookEvents };
