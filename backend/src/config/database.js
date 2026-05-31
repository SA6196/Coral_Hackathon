const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const dbPath = path.resolve(__dirname, "../../../security.db");
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error("Database Error:", err.message);
  } else {
    console.log("✅ SQLite Connected at", dbPath);
    initializeTables();
  }
});

function initializeTables() {
  db.serialize(() => {
    // Create submissions table for dev portal submissions
    db.run(`CREATE TABLE IF NOT EXISTS submissions (
      id TEXT PRIMARY KEY,
      developer TEXT,
      pr_title TEXT,
      package_name TEXT,
      commit_diff TEXT,
      slack_message TEXT,
      repo TEXT,
      submitted_at TEXT,
      vulnerability_json TEXT,
      secrets_detected_json TEXT,
      policy_violation_json TEXT,
      risk_score INTEGER,
      ai_summary TEXT,
      recommended_action TEXT
    )`, (err) => {
      if (err) console.error("Error creating submissions table:", err.message);
    });

    // Create webhook_events table for GitHub webhooks
    db.run(`CREATE TABLE IF NOT EXISTS webhook_events (
      id TEXT PRIMARY KEY,
      source TEXT,
      event_type TEXT,
      delivery_id TEXT,
      pr_number INTEGER,
      pr_url TEXT,
      developer TEXT,
      pr_title TEXT,
      package_name TEXT,
      repo TEXT,
      branch TEXT,
      commit_sha TEXT,
      received_at TEXT,
      vulnerability_json TEXT,
      secrets_detected_json TEXT,
      policy_violation_json TEXT,
      risk_score INTEGER,
      ai_summary TEXT,
      recommended_action TEXT
    )`, (err) => {
      if (err) console.error("Error creating webhook_events table:", err.message);
      else {
        // Remove any previously injected demo entries that should not appear in webhook history
        db.run(
          `DELETE FROM webhook_events WHERE developer IN ('tanmayshukla60-netizen', 'ci-bot') AND id LIKE 'WH-sync-%'`,
          (delErr) => {
            if (delErr) console.warn("[DB] Cleanup warning:", delErr.message);
            else console.log("[DB] Cleaned up any injected demo webhook entries.");
          }
        );
        seedDefaultWebhooks();
      }
    });

    // Auxiliary tables used by the webhook sync and seed services
    db.run(`CREATE TABLE IF NOT EXISTS github (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      author TEXT,
      title TEXT,
      package_name TEXT,
      merged_at TEXT,
      commit_diff TEXT
    )`, (err) => {
      if (err) console.error("Error creating github table:", err.message);
    });

    db.run(`CREATE TABLE IF NOT EXISTS osv (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      package_name TEXT,
      cve TEXT,
      severity TEXT
    )`, (err) => {
      if (err) console.error("Error creating osv table:", err.message);
    });

    db.run(`CREATE TABLE IF NOT EXISTS slack (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      channel TEXT,
      message TEXT
    )`, (err) => {
      if (err) console.error("Error creating slack table:", err.message);
    });

    // Users table for sign-up / registration
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'analyst',
      team TEXT DEFAULT 'security',
      created_at TEXT
    )`, (err) => {
      if (err) console.error("Error creating users table:", err.message);
    });
  });
}

function seedDefaultWebhooks() {
  db.get("SELECT COUNT(*) as count FROM webhook_events", [], (err, row) => {
    if (err) return console.error("Error checking webhook count:", err.message);
    if (row.count > 0) return; // already seeded

    console.log("[DB] Seeding default mock webhook events...");
    const defaultEvents = [
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
        vulnerability_json: JSON.stringify({ cve: "CVE-2023-29017", severity: "critical", cvss: 10.0, summary: "Sandbox escape leading to RCE" }),
        secrets_detected_json: null,
        policy_violation_json: JSON.stringify({ rule: "BANNED_PACKAGE", team: "security-engineering", reason: "CVE-2023-29017 — complete sandbox escape, permanently banned" }),
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
        pr_title: "Configure AWS credentials in config block",
        package_name: "none",
        repo: "enterprise-app/infra",
        branch: "setup-deployment",
        commit_sha: "f2c3d4e",
        received_at: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
        vulnerability_json: JSON.stringify({ cve: "NO_CVE_FOUND", severity: "safe", cvss: 0, summary: "No known vulnerabilities" }),
        secrets_detected_json: JSON.stringify({
          count: 1,
          findings: [{ name: "AWS Access Key ID", severity: "critical", recommendation: "Rotate credentials immediately and move to IAM Roles." }]
        }),
        policy_violation_json: null,
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
        vulnerability_json: JSON.stringify({ cve: "CVE-2022-23529", severity: "high", cvss: 7.6, summary: "JWT algorithm confusion attack" }),
        secrets_detected_json: null,
        policy_violation_json: JSON.stringify({ rule: "AUDIT_REQUIRED", team: "auth-team", reason: "JWT library changes require security audit" }),
        risk_score: 83,
        ai_summary: "🟠 High-severity CVE-2022-23529 in jsonwebtoken by john_backend. JWT algorithm confusion attack. Requires auth-team sign-off before merge.",
        recommended_action: "SECURITY_REVIEW",
      }
    ];

    const stmt = db.prepare(`INSERT INTO webhook_events (
      id, source, event_type, delivery_id, developer, pr_title, package_name, repo, branch, commit_sha, received_at,
      vulnerability_json, secrets_detected_json, policy_violation_json, risk_score, ai_summary, recommended_action
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);

    defaultEvents.forEach(e => {
      stmt.run([
        e.id, e.source, e.event_type, e.delivery_id, e.developer, e.pr_title, e.package_name, e.repo, e.branch, e.commit_sha, e.received_at,
        e.vulnerability_json, e.secrets_detected_json, e.policy_violation_json, e.risk_score, e.ai_summary, e.recommended_action
      ]);
    });
    stmt.finalize();
  });
}

module.exports = db;