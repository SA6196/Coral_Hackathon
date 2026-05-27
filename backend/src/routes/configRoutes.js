/**
 * configRoutes.js — Source config, status, export, refresh, policy-violations
 */
const express = require("express");
const router  = express.Router();

const { joinSecurityData, invalidateCache, getCacheInfo } = require("../coral/joinData");
const { runSecurityAnalysis }                             = require("../coral/queryEngine");

// In-memory token store (never written to disk)
const runtimeTokens = {
  github: process.env.GITHUB_TOKEN || null,
  slack:  process.env.SLACK_BOT_TOKEN || null,
  notion: process.env.NOTION_TOKEN || null,
};

/* ── GET /api/source-status ───────────────────────────────────────── */
router.get("/source-status", (req, res) => {
  const now = Date.now();
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
      records: 3,
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
      records: 3,
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
      records: 3,
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
      records: 3,
    },
  ];

  res.json({
    success: true,
    sources,
    configured_count: sources.filter(s => s.configured).length,
    total: sources.length,
    cache: getCacheInfo(),
    coral_sql: `SELECT g.*, o.severity, s.message, n.policy_rule\nFROM github_commits g\nLEFT JOIN vulnerabilities o ON g.package_name = o.package_name\nLEFT JOIN slack_messages  s ON g.author       = s.user\nLEFT JOIN policies        n ON g.package_name = n.applies_to`,
  });
});

/* ── POST /api/config-sources ─────────────────────────────────────── */
router.post("/config-sources", (req, res) => {
  const { github, slack, notion } = req.body;
  if (github?.token)   runtimeTokens.github = github.token;
  if (slack?.token)    runtimeTokens.slack  = slack.token;
  if (notion?.token)   runtimeTokens.notion = notion.token;
  invalidateCache();
  res.json({
    success: true,
    message: "Tokens saved in memory. Cache invalidated.",
    configured: Object.keys(runtimeTokens).filter(k => runtimeTokens[k]),
    note: "Tokens stored in-memory only. For persistence add to .env file.",
  });
});

/* ── POST /api/refresh-cache ──────────────────────────────────────── */
router.post("/refresh-cache", (req, res) => {
  invalidateCache();
  res.json({
    success: true,
    message: "Coral cache cleared. Next query re-fetches all sources.",
    cache: getCacheInfo(),
    timestamp: new Date().toISOString(),
  });
});

/* ── GET /api/policy-violations ───────────────────────────────────── */
router.get("/policy-violations", (req, res) => {
  const result    = joinSecurityData();
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
router.get("/export-report", (req, res) => {
  const result    = joinSecurityData();
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
