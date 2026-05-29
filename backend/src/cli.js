#!/usr/bin/env node

/**
 * cli.js — Coral Command Line Security & Compliance Scanner
 * ─────────────────────────────────────────────────────────────────────
 * Executes a full security scan using the Coral Engine and exits with:
 *   - 0: Clean (no findings)
 *   - 1: Medium/High vulnerability findings
 *   - 2: Critical findings (leaked secrets, unprotected main branch, privilege escalation)
 * ─────────────────────────────────────────────────────────────────────
 */

const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "../.env") });

const { syncAllData } = require("./coral/fetchRealData");
const { getCriticalIncidents } = require("./services/coralSqlService");

const { joinSecurityData } = require("./coral/joinData");
const { runSecurityAnalysis } = require("./coral/queryEngine");

// Parse arguments
const args = process.argv.slice(2);
const updateBaseline = args.includes("--update-baseline");
const lookbackIndex = args.indexOf("--lookback");
const lookback = lookbackIndex !== -1 ? parseInt(args[lookbackIndex + 1], 10) || 20 : 20;
const noSlack = args.includes("--no-slack");

async function run() {
  console.log(`\n==================================================`);
  console.log(`🪸  CORAL SECURITY COMMAND CENTER — PIPELINE SCANNER`);
  console.log(`==================================================\n`);

  const repo = process.env.GITHUB_REPO;
  const token = process.env.GITHUB_TOKEN;

  if (!repo) {
    console.warn(`[WARN] GITHUB_REPO not configured in environment. Running scan on mock dataset...`);
  } else {
    console.log(`[SCAN] Initializing sync for repository: ${repo}`);
    const syncRes = await syncAllData({
      githubRepo: repo,
      githubToken: token,
      slackChannel: noSlack ? null : process.env.SLACK_CHANNEL,
      slackToken: noSlack ? null : process.env.SLACK_BOT_TOKEN,
      notionDb: process.env.NOTION_DB,
      notionToken: process.env.NOTION_TOKEN,
      updateBaseline
    });
    console.log(`[SCAN] Sync completed. Raw records fetched.`);
  }

  console.log(`[SCAN] Running Coral SQL Join and Security Analysis...`);
  const joinedResult = await joinSecurityData("default");
  const incidents = runSecurityAnalysis(joinedResult.data);

  let criticalCount = 0;
  let warningCount = 0;
  let cleanCount = 0;

  const secrets = [];
  const maliciousCodeAlerts = [];
  const accessAlerts = [];
  const cves = [];

  incidents.forEach(inc => {
    const pkg = inc.package_details?.package_name || "";
    const title = inc.pr_details?.title || "";
    const severity = (inc.vulnerability?.severity || "safe").toLowerCase();

    if (inc.malicious_code_detected) {
      maliciousCodeAlerts.push(inc);
      criticalCount++;
    } else if (inc.secrets_detected || pkg === "credentials" || title.includes("Leaked secret")) {
      secrets.push(inc);
      criticalCount++;
    } else if (pkg === "github-repo" || title.includes("main branch is unprotected")) {
      accessAlerts.push(inc);
      criticalCount++;
    } else if (pkg === "github-access" || title.includes("SECURITY ALERT")) {
      accessAlerts.push(inc);
      if (severity === "critical") {
        criticalCount++;
      } else {
        warningCount++;
      }
    } else if (severity === "critical") {
      cves.push(inc);
      criticalCount++;
    } else if (severity === "high" || severity === "medium") {
      cves.push(inc);
      warningCount++;
    } else {
      cleanCount++;
    }
  });

  console.log(`\n==================================================`);
  console.log(`📊 SECURITY ANALYSIS REPORT`);
  console.log(`==================================================`);

  if (maliciousCodeAlerts.length > 0) {
    console.log(`\n☠️  CRITICAL: MALICIOUS CODE / BACKDOOR PATTERNS DETECTED`);
    maliciousCodeAlerts.forEach(m => {
      console.log(`  - [Developer: ${m.pr_details?.developer || "unknown"}] ${m.pr_details?.title || "Commit"}`);
      if (m.malicious_code_detected.findings) {
        m.malicious_code_detected.findings.forEach(f => {
          console.log(`    ↳ Rule Match : ${f.description}`);
          console.log(`      Line No    : ${f.line || "unknown"}`);
          console.log(`      Preview    : "${f.preview}"`);
          console.log(`      Remediation: ${f.recommendation}`);
        });
      }
    });
  }
  
  if (secrets.length > 0) {
    console.log(`\n🚨 CRITICAL: LEAKED CREDENTIALS FOUND`);
    secrets.forEach(s => {
      console.log(`  - [Developer: ${s.pr_details?.developer || "unknown"}] ${s.pr_details?.title || "Commit"}`);
      if (s.secrets_detected && s.secrets_detected.findings) {
        s.secrets_detected.findings.forEach(f => {
          let msg = `    ↳ Found: ${f.name || f.description || "Credential Pattern"}`;
          if (f.line) msg += ` | Line: ${f.line}`;
          if (f.preview || f.matched_preview) msg += ` | Preview: ${f.preview || f.matched_preview}`;
          console.log(msg);
        });
      } else {
        console.log(`    Detail: ${s.github?.commit_diff || "No diff content"}`);
      }
    });
  }

  if (accessAlerts.length > 0) {
    console.log(`\n🔓 HIGH/CRITICAL: REPOSITORY ACCESS ALERTS`);
    accessAlerts.forEach(a => {
      console.log(`  - ${a.pr_details?.title || "Access event"}`);
      console.log(`    Detail: ${a.github?.commit_diff || "No details"}`);
    });
  }

  if (cves.length > 0) {
    console.log(`\n⚠️  WARNING: VULNERABILITY FINDINGS (CVEs)`);
    cves.slice(0, 10).forEach(c => {
      console.log(`  - [${(c.vulnerability?.severity || "HIGH").toUpperCase()}] ${c.package_details?.package_name || "pkg"} (${c.vulnerability?.cve || "CVE"}): ${c.pr_details?.title || "Title"}`);
    });
    if (cves.length > 10) {
      console.log(`  ... and ${cves.length - 10} more vulnerability records.`);
    }
  }

  console.log(`\n==================================================`);
  console.log(`📉 SCAN SUMMARY`);
  console.log(`==================================================`);
  console.log(`  • Critical Risks : ${criticalCount}`);
  console.log(`  • Warnings       : ${warningCount}`);
  console.log(`  • Clean Packages : ${cleanCount}`);
  console.log(`==================================================`);

  if (criticalCount > 0) {
    console.log(`\n🔴 STATUS: FAILED (Critical threats detected)`);
    console.log(`[EXIT] Returning code 2\n`);
    process.exit(2);
  } else if (warningCount > 0) {
    console.log(`\n🟡 STATUS: WARNING (Vulnerability findings present)`);
    console.log(`[EXIT] Returning code 1\n`);
    process.exit(1);
  } else {
    console.log(`\n🟢 STATUS: PASSED (Clean scan result)`);
    console.log(`[EXIT] Returning code 0\n`);
    process.exit(0);
  }
}

run().catch(err => {
  console.error(`\n❌ ERROR: Compliance scan failed:`, err.message);
  process.exit(2);
});
