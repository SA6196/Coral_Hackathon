const express = require("express");
const router  = express.Router();
const fs      = require("fs");
const path    = require("path");

const MOCK_DIR = path.join(__dirname, "../../mock-data");
function readMock(name) {
  try { return JSON.parse(fs.readFileSync(path.join(MOCK_DIR, name), "utf-8")); }
  catch { return []; }
}

const { joinSecurityData, invalidateCache, getCacheInfo, setSessionData, getRuntimeTokens, setRuntimeTokens } = require("../coral/joinData");
const { runSecurityAnalysis }                             = require("../coral/queryEngine");

const { syncAllData } = require("../coral/fetchRealData");

/* ── GET /api/source-status ───────────────────────────────────────── */
router.get("/source-status", (req, res) => {
  const sessionId = req.headers["x-session-id"] || "default";
  const runtimeTokens = getRuntimeTokens(sessionId);
  const now = Date.now();

  // Read live counts from disk so post-sync values are always fresh
  const githubData = readMock("github.json");
  const osvData    = readMock("osv.json");
  const slackData  = readMock("slack.json");
  const notionData = readMock("notion.json");

  const sources = [
    {
      id: "github", name: "GitHub",
      description: "Commits, PRs, code diffs",
      color: "#58a6ff", icon: "github",
      configured: !!runtimeTokens.github,
      status: runtimeTokens.github ? "connected" : "not_configured",
      coral_table: "github_commits",
      join_key: "package_name, author",
      env_var: "GITHUB_TOKEN",
      rate_limit: "60 req/min",
      last_synced: new Date(now - 120_000).toISOString(),
      records: githubData.length,
    },
    {
      id: "slack", name: "Slack",
      description: "Team messages & security discussions",
      color: "#e01e5a", icon: "slack",
      configured: !!runtimeTokens.slack,
      status: runtimeTokens.slack ? "connected" : "not_configured",
      coral_table: "slack_messages",
      join_key: "user → github.author",
      env_var: "SLACK_BOT_TOKEN",
      rate_limit: "50 req/min",
      last_synced: new Date(now - 65_000).toISOString(),
      records: slackData.length,
    },
    {
      id: "osv", name: "OSV Database",
      description: "Open Source Vulnerabilities (public)",
      color: "#fbbf24", icon: "shield",
      configured: true,
      status: "connected",
      coral_table: "vulnerabilities",
      join_key: "package_name → github.package_name",
      env_var: null,
      rate_limit: "100 req/min",
      last_synced: new Date(now - 30_000).toISOString(),
      records: osvData.length,
      is_public: true,
    },
    {
      id: "notion", name: "Notion",
      description: "Internal policy docs & rules",
      color: "#e2e8f0", icon: "notion",
      configured: !!runtimeTokens.notion,
      status: runtimeTokens.notion ? "connected" : "not_configured",
      coral_table: "policies",
      join_key: "applies_to → github.package_name",
      env_var: "NOTION_TOKEN",
      rate_limit: "30 req/min",
      last_synced: new Date(now - 90_000).toISOString(),
      records: notionData.length,
    },
  ];

  res.json({
    success: true,
    sources,
    configured_count: sources.filter(s => s.configured).length,
    total: sources.length,
    cache: getCacheInfo(sessionId),
    coral_sql: `SELECT g.*, o.severity, s.message, n.policy_rule\nFROM github_commits g\nLEFT JOIN vulnerabilities o ON g.package_name = o.package_name\nLEFT JOIN slack_messages  s ON g.author       = s.user\nLEFT JOIN policies        n ON g.package_name = n.applies_to`,
  });
});

/* ── POST /api/config-sources ─────────────────────────────────────── */
router.post("/config-sources", (req, res) => {
  const sessionId = req.headers["x-session-id"] || "default";
  const { github, slack, notion } = req.body;
  
  const tokensToUpdate = {};
  if (github?.token)   tokensToUpdate.github = github.token;
  if (github?.repo)    tokensToUpdate.github_repo = github.repo;
  if (slack?.token)    tokensToUpdate.slack  = slack.token;
  if (slack?.channel)  tokensToUpdate.slack_channel = slack.channel;
  if (notion?.token)   tokensToUpdate.notion = notion.token;
  if (notion?.db)      tokensToUpdate.notion_db = notion.db;
  
  setRuntimeTokens(sessionId, tokensToUpdate);
  const runtimeTokens = getRuntimeTokens(sessionId);

  invalidateCache(sessionId);
  res.json({
    success: true,
    message: "Tokens saved in memory. Cache invalidated.",
    configured: Object.keys(runtimeTokens).filter(k => runtimeTokens[k]),
    note: "Tokens stored in-memory only. For persistence add to .env file.",
  });
});

/* ── POST /api/sync-real-data ─────────────────────────────────────── */
router.post("/sync-real-data", async (req, res) => {
  const sessionId = req.headers["x-session-id"] || "default";
  const runtimeTokens = getRuntimeTokens(sessionId);

  const results = await syncAllData({
    githubRepo: runtimeTokens.github_repo,
    githubToken: runtimeTokens.github,
    slackChannel: runtimeTokens.slack_channel,
    slackToken: runtimeTokens.slack,
    notionDb: runtimeTokens.notion_db,
    notionToken: runtimeTokens.notion
  });

  const sessionData = {
    github: results.github?.data,
    osv: results.osv?.data,
    slack: results.slack?.data,
    notion: results.notion?.data
  };

  setSessionData(sessionId, sessionData);
  invalidateCache(sessionId);

  res.json({
    success: true,
    message: "Live sync complete. Data isolated to your session.",
    results
  });
});

/* ── POST /api/refresh-cache ──────────────────────────────────────── */
router.post("/refresh-cache", (req, res) => {
  const sessionId = req.headers["x-session-id"] || "default";
  invalidateCache(sessionId);
  res.json({
    success: true,
    message: "Coral cache cleared for session. Next query re-fetches all sources.",
    cache: getCacheInfo(sessionId),
    timestamp: new Date().toISOString(),
  });
});

/* ── GET /api/policy-violations ───────────────────────────────────── */
router.get("/policy-violations", async (req, res) => {
  const sessionId = req.headers["x-session-id"] || "default";
  const result    = await joinSecurityData(sessionId);
  const incidents = runSecurityAnalysis(result.data);
  const violations = incidents.filter(i => i.policy_violation);

  const byCounts = violations.reduce((acc, i) => {
    const r = i.policy_violation.policy_rule;
    acc[r] = (acc[r] || 0) + 1;
    return acc;
  }, {});

  res.json({
    success: true,
    total_violations: violations.length,
    by_rule: byCounts,
    violations: violations.map(i => ({
      incident_id:  i.incident_id,
      developer:    i.pr_details?.developer,
      package:      i.package_details?.package_name,
      policy_name:  i.policy_violation.policy_name,
      policy_rule:  i.policy_violation.policy_rule,
      owner_team:   i.policy_violation.owner_team,
      severity:     i.policy_violation.severity,
      cve:          i.vulnerability?.cve,
      risk_score:   i.risk_score,
    })),
    coral_sql: `SELECT g.author, g.package_name, n.policy_name, n.policy_rule, n.owner_team\nFROM github_commits g\nJOIN policies n ON g.package_name = n.applies_to\nORDER BY n.severity DESC`,
  });
});

/* ── GET /api/export-report ───────────────────────────────────────── */
router.get("/export-report", async (req, res) => {
  const sessionId = req.headers["x-session-id"] || "default";
  const result    = await joinSecurityData(sessionId);
  const incidents = runSecurityAnalysis(result.data);

  const critical = incidents.filter(i => i.vulnerability?.severity === "critical").length;
  const high     = incidents.filter(i => i.vulnerability?.severity === "high").length;
  const medium   = incidents.filter(i => i.vulnerability?.severity === "medium").length;
  const secrets  = incidents.filter(i => i.secrets_detected).length;
  const policies = incidents.filter(i => i.policy_violation).length;
  const topRisk  = [...incidents].sort((a,b) => (b.risk_score||0) - (a.risk_score||0))[0];

  res.json({
    success: true,
    report: {
      meta: {
        generated_at: new Date().toISOString(),
        title: "Coral Security & Compliance Report",
        agent: "coral-security-monitor",
        sources: ["GitHub", "Slack", "OSV", "Notion"],
        coral_features: ["SQL JOIN", "Schema Learning", "Caching", "MCP", "Secret Detection"],
      },
      executive_summary: {
        overall_risk: critical > 0 ? "CRITICAL" : high > 0 ? "HIGH" : medium > 0 ? "MEDIUM" : "SAFE",
        total_incidents: incidents.length,
        critical, high, medium,
        secrets_leaked: secrets,
        policy_violations: policies,
        bluf: critical > 0
          ? `CRITICAL: ${critical} critical vulnerability(ies). Immediate rollback required.`
          : `${high} high severity incident(s) require security review.`,
        top_risk_incident: topRisk ? {
          id: topRisk.incident_id,
          risk_score: topRisk.risk_score,
          developer: topRisk.pr_details?.developer,
          cve: topRisk.vulnerability?.cve,
        } : null,
      },
      incidents,
      recommendations: [
        critical > 0 ? "🚨 Roll back all critical deployments immediately." : null,
        secrets  > 0 ? "🔑 Rotate all exposed credentials now." : null,
        policies > 0 ? "📋 Open Notion policy exceptions for flagged packages." : null,
        "🔍 Run `npm audit` after patching all vulnerable packages.",
        "⚙️ Add secret scanning to CI/CD (trufflehog or git-secrets).",
      ].filter(Boolean),
    },
  });
});

module.exports = router;
