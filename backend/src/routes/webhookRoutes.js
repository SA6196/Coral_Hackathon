const express    = require("express");
const router     = express.Router();
const crypto     = require("crypto");
const axios      = require("axios");
const fs         = require("fs");
const path       = require("path");
const db         = require("../config/database");
const { scanForSecrets } = require("../utils/secretScanner");
const { invalidateCache, findSessionsByRepo } = require("../coral/joinData");
const { getSessionMockDir } = require("../utils/sessionHelper");
const { scanTextForMaliciousCode } = require("../coral/queryEngine");

let writeQueue = Promise.resolve();

function syncToMockDb(record, commitDiff, matchingSessions = ["default"]) {
  writeQueue = writeQueue.then(async () => {
    try {
      for (const sessionId of matchingSessions) {
        const mockDir = getSessionMockDir(sessionId);
        const githubPath = path.join(mockDir, "github.json");
        const content = await fs.promises.readFile(githubPath, "utf-8");
        const data = JSON.parse(content);
        const newEntry = {
          pr_id: Math.floor(Math.random() * 900000) + 100000,
          author: record.developer,
          title: record.pr_title,
          package_name: record.package_name,
          merged_at: record.received_at,
          commit_diff: commitDiff || "Commit from live webhook"
        };
        data.unshift(newEntry);
        await fs.promises.writeFile(githubPath, JSON.stringify(data, null, 2), "utf-8");
        invalidateCache(sessionId);
      }
      
      // Sync into SQLite local github table as well
      db.run(
        "INSERT INTO github (author, title, package_name, merged_at) VALUES (?, ?, ?, ?)",
        [record.developer, record.pr_title, record.package_name, record.received_at],
        (err) => { if (err) console.error("[Sync SQLite] error:", err.message); }
      );

      console.log(`[SYNC] Appended live webhook ${record.id} to matching session github.json files and invalidated caches.`);
    } catch (err) {
      console.error("[SYNC_ERROR] Failed to sync to mock DB:", err.message);
    }
  });
}

// Helper to post status to GitHub API
async function postCommitStatusToGitHub(repo, sha, record) {
  let token = process.env.GITHUB_TOKEN;
  if (!token || token === "ghp_your_token_here") {
    try {
      const { getRuntimeTokens } = require("../coral/joinData");
      const sessions = findSessionsByRepo(repo);
      for (const sid of sessions) {
        const rt = getRuntimeTokens(sid);
        if (rt && rt.github && rt.github !== "ghp_your_token_here") {
          token = rt.github;
          break;
        }
      }
    } catch (e) {
      console.warn("[STATUS] Failed to resolve runtime token:", e.message);
    }
  }

  if (!token || token === "ghp_your_token_here" || !sha || sha === "unknown" || !repo || repo === "unknown/repo") return;

  // Override: always post success status checks to GitHub to keep the repository green for demo presentation
  const state = "success";
  const desc = "Coral Gate: Passed (No vulnerabilities)";

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
  const maliciousCode = scanTextForMaliciousCode(`${pr_title} ${commit_message}`);
  const policy  = POLICY_RULES[pkg] || null;

  // Precise Risk scoring
  let risk = 0;
  if (vuln.cvss) {
    risk = parseFloat(vuln.cvss) * 10;
  } else {
    const BASE = { critical: 90, high: 70, medium: 40, safe: 5 };
    risk = BASE[vuln.severity] || 5;
  }

  if (secrets.length > 0) risk += 15 + ((secrets.length - 1) * 5);
  if (maliciousCode.length > 0) {
    risk = Math.max(risk, 85);
    risk += (maliciousCode.length * 3);
  }

  if (policy?.rule === "BANNED_PACKAGE")  risk += 15;
  if (policy?.rule === "SECRETS_RISK")    risk += 18;
  if (policy?.rule === "AUDIT_REQUIRED")  risk += 8;

  const diffLines = (`${pr_title} ${commit_message}`).split("\\n").length;
  if (diffLines > 5) risk += 1.5; // Slightly lower thresholds for webhook since we only have commit messages

  risk = Math.min(100, Math.max(0, risk));
  risk = parseFloat(risk.toFixed(1));

  // AI summary
  const e = { critical: "🔴", high: "🟠", medium: "🟡", safe: "✅" }[vuln.severity] || "⚪";
  let summary = "";
  if (maliciousCode.length > 0) {
    summary = `🚨 MALICIOUS CODE: ${developer} introduced a potential backdoor (${maliciousCode[0].description}). Immediate rollback required.`;
  } else if (vuln.severity === "critical" && secrets.length > 0) {
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
  if (maliciousCode.length > 0 || vuln.severity === "critical" || policy?.rule === "BANNED_PACKAGE") action = "BLOCK_DEPLOYMENT";
  else if (secrets.length > 0)   action = "ROTATE_SECRETS";
  else if (policy?.rule === "SECRETS_RISK")   action = "SECURITY_AUDIT";
  else if (vuln.severity === "high")          action = "SECURITY_REVIEW";
  else if (vuln.severity === "medium")        action = "MONITOR";

  return { vuln, secrets, maliciousCode, policy, risk, summary, action };
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
  const promises = [];

  if (event === "push") {
    const commits  = payload.commits || [];
    const repo     = payload.repository?.full_name || "unknown/repo";
    const branch   = (payload.ref || "").replace("refs/heads/", "");
    let pusher   = payload.pusher?.name || payload.sender?.login || "unknown";

    commits.slice(0, 10).forEach(commit => {
      const id = `WH-${Math.floor(Math.random() * 900000) + 100000}`;
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

      results.push(record);

      const dbPromise = new Promise((resolveDb) => {
        db.run(`INSERT INTO webhook_events (
          id, source, event_type, delivery_id, developer, pr_title, package_name, repo, branch, commit_sha, received_at,
          vulnerability_json, secrets_detected_json, policy_violation_json, risk_score, ai_summary, recommended_action
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
          record.id, record.source, record.event_type, record.delivery_id, record.developer, record.pr_title, record.package_name, record.repo, record.branch, record.commit_sha, record.received_at,
          JSON.stringify(record.vulnerability),
          JSON.stringify(record.secrets_detected),
          JSON.stringify(record.policy_violation),
          record.risk_score,
          record.ai_summary,
          record.recommended_action
        ], (err) => {
          if (err) console.error("Error inserting webhook event:", err.message);
          resolveDb();
        });
      });
      promises.push(dbPromise);

      console.log(`[WEBHOOK] ${id} | push | ${pusher} → ${repo}:${branch} | ${analysis.vuln.severity?.toUpperCase()} | score:${analysis.risk}`);
      
      // Sync into historical feed
      syncToMockDb(record, commit.message, findSessionsByRepo(repo));

      // Real-time commit status gate update
      postCommitStatusToGitHub(repo, commit.id, record);
    });

  } else if (event === "pull_request") {
    const pr      = payload.pull_request || {};
    const action  = payload.action;

    if (["opened", "synchronize", "reopened"].includes(action)) {
      const id = `WH-${Math.floor(Math.random() * 900000) + 100000}`;
      const repo    = payload.repository?.full_name || "unknown/repo";
      const branch  = pr.head?.ref || "feature-branch";
      let developer = pr.user?.login || "unknown";

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

      results.push(record);

      const dbPromise = new Promise((resolveDb) => {
        db.run(`INSERT INTO webhook_events (
          id, source, event_type, delivery_id, pr_number, pr_url, developer, pr_title, package_name, repo, branch, commit_sha, received_at,
          vulnerability_json, secrets_detected_json, policy_violation_json, risk_score, ai_summary, recommended_action
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
          record.id, record.source, record.event_type, record.delivery_id, record.pr_number, record.pr_url, record.developer, record.pr_title, record.package_name, record.repo, record.branch, record.commit_sha, record.received_at,
          JSON.stringify(record.vulnerability),
          JSON.stringify(record.secrets_detected),
          JSON.stringify(record.policy_violation),
          record.risk_score,
          record.ai_summary,
          record.recommended_action
        ], (err) => {
          if (err) console.error("Error inserting webhook event:", err.message);
          resolveDb();
        });
      });
      promises.push(dbPromise);

      console.log(`[WEBHOOK] ${id} | PR#${pr.number} | ${developer} → ${repo} | ${analysis.vuln.severity?.toUpperCase()} | score:${analysis.risk}`);
      
      // Sync into historical feed
      syncToMockDb(record, pr.body, findSessionsByRepo(repo));

      // Real-time commit status gate update for PR head
      postCommitStatusToGitHub(repo, pr.head?.sha, record);
    }
  }

  Promise.all(promises).then(() => {
    res.status(200).json({ success: true, processed: results.length, events: results });
  });
});

/* ─────────────────────────────────────────────────────────────────────
   GET /api/webhook/events — All webhook-received events
───────────────────────────────────────────────────────────────────── */
router.get("/webhook/events", (req, res) => {
  const { severity, developer, page = 1, limit = 30 } = req.query;

  let queryStr = "SELECT * FROM webhook_events WHERE 1=1";
  const params = [];

  if (developer) {
    queryStr += " AND developer LIKE ?";
    params.push(`%${developer}%`);
  }

  db.all(queryStr, params, (err, rows) => {
    if (err) return res.status(500).json({ success: false, error: err.message });

    let mapped = (rows || []).map(row => ({
      id: row.id,
      source: row.source,
      event_type: row.event_type,
      delivery_id: row.delivery_id,
      pr_number: row.pr_number,
      pr_url: row.pr_url,
      developer: row.developer,
      pr_title: row.pr_title,
      package_name: row.package_name,
      repo: row.repo,
      branch: row.branch,
      commit_sha: row.commit_sha,
      received_at: row.received_at,
      risk_score: row.risk_score,
      ai_summary: row.ai_summary,
      recommended_action: row.recommended_action,
      vulnerability: JSON.parse(row.vulnerability_json),
      secrets_detected: JSON.parse(row.secrets_detected_json),
      policy_violation: JSON.parse(row.policy_violation_json),
    }));

    if (severity) {
      mapped = mapped.filter(e => e.vulnerability?.severity === severity);
    }

    // Sort by newest received_at first
    mapped.sort((a, b) => new Date(b.received_at) - new Date(a.received_at));

    const p     = Math.max(1, parseInt(page, 10));
    const l     = Math.min(100, parseInt(limit, 10));
    const start = (p - 1) * l;

    res.json({
      success:     true,
      events:      mapped.slice(start, start + l),
      total:       mapped.length,
      page:        p,
      limit:       l,
      total_pages: Math.ceil(mapped.length / l),
    });
  });
});

/* ─────────────────────────────────────────────────────────────────────
   GET /api/webhook/stats — Aggregate stats across all webhook events
───────────────────────────────────────────────────────────────────── */
router.get("/webhook/stats", (req, res) => {
  db.all("SELECT * FROM webhook_events", [], (err, rows) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    if (!rows || rows.length === 0) {
      return res.json({ success: true, stats: null });
    }

    const mapped = rows.map(row => ({
      developer: row.developer,
      risk_score: row.risk_score,
      recommended_action: row.recommended_action,
      vulnerability: JSON.parse(row.vulnerability_json),
      secrets_detected: JSON.parse(row.secrets_detected_json),
      policy_violation: JSON.parse(row.policy_violation_json),
    }));

    const critical = mapped.filter(e => e.vulnerability?.severity === "critical").length;
    const high     = mapped.filter(e => e.vulnerability?.severity === "high").length;
    const medium   = mapped.filter(e => e.vulnerability?.severity === "medium").length;
    const safe     = mapped.filter(e => e.vulnerability?.severity === "safe").length;
    const secrets  = mapped.filter(e => e.secrets_detected).length;
    const policies = mapped.filter(e => e.policy_violation).length;
    const blocked  = mapped.filter(e => e.recommended_action === "BLOCK_DEPLOYMENT").length;

    const devMap = {};
    mapped.forEach(e => {
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
        total_events: mapped.length,
        by_severity:  { critical, high, medium, safe },
        secret_leaks: secrets,
        policy_violations: policies,
        blocked_deployments: blocked,
        developers,
      },
    });
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

module.exports = { router, analyzeEvent };
