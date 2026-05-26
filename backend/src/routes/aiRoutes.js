/**
 * aiRoutes.js — AI Investigation, Chat, Remediation & NL Search
 * All endpoints previously expected on Flask :5001, now served by Node :5000
 */

const express = require("express");
const router  = express.Router();

const { joinSecurityData } = require("../coral/joinData");
const { runSecurityAnalysis } = require("../coral/queryEngine");

/* ── helpers ───────────────────────────────────────────────────────── */
function getIncidents() {
  const result = joinSecurityData();
  return runSecurityAnalysis(result.data);
}

function getIncidentById(id) {
  const incidents = getIncidents();
  const idx = Math.max(0, Math.min(Number(id) - 1, incidents.length - 1));
  return incidents[idx] || incidents[0];
}

/* ─────────────────────────────────────────────────────────────────────
   GET /api/investigate?id=<1-3>
   Returns a detailed AI analysis markdown report for an incident
───────────────────────────────────────────────────────────────────── */
router.get("/investigate", (req, res) => {
  const id = req.query.id || 1;
  const inc = getIncidentById(id);

  const sev      = inc.vulnerability?.severity || "safe";
  const cve      = inc.vulnerability?.cve      || "N/A";
  const dev      = inc.pr_details?.developer   || "Unknown";
  const pkg      = inc.package_details?.package_name || "unknown";
  const action   = inc.recommended_action || "SAFE_TO_DEPLOY";
  const hasSecret = !!inc.secrets_detected;
  const hasPolicy = !!inc.policy_violation;

  const report = [
    `## 🔍 AI Security Investigation — ${inc.incident_id}`,
    ``,
    `### Incident Overview`,
    `- **Severity:** ${sev.toUpperCase()}`,
    `- **Risk Score:** ${inc.risk_score}/100`,
    `- **CVE:** ${cve}`,
    `- **Package:** \`${pkg}\``,
    `- **Developer:** ${dev}`,
    `- **PR:** ${inc.pr_details?.title || "Unknown PR"}`,
    ``,
    `### AI Analysis`,
    inc.ai_summary || "No AI summary available.",
    ``,
    `### Threat Assessment`,
    sev === "critical"
      ? `🚨 **CRITICAL THREAT** — Immediate action required. This vulnerability has a CVSS score placing it in the highest risk category. Active exploitation is possible.`
      : sev === "high"
      ? `🟠 **HIGH RISK** — Security review mandatory before next deployment. This vulnerability could be exploited under certain conditions.`
      : sev === "medium"
      ? `🟡 **MODERATE RISK** — Monitor and test. This vulnerability poses limited risk but should be patched in the next release cycle.`
      : `✅ **LOW RISK** — No immediate action required. Continue standard monitoring.`,
    ``,
    hasSecret ? `### 🔑 Secret Exposure Detected\n- **${inc.secrets_detected.count} secret(s)** found in commit\n- Highest severity: **${inc.secrets_detected.highest_severity}**\n- **Immediate credential rotation required**` : null,
    hasPolicy ? `### 📋 Policy Violation\n- Policy: **${inc.policy_violation.policy_name}**\n- Rule: \`${inc.policy_violation.policy_rule}\`\n- Team: ${inc.policy_violation.owner_team}` : null,
    ``,
    `### Recommended Action`,
    `> **${action.replace(/_/g, " ")}**`,
    ``,
    `### Slack Intelligence`,
    `- Channel: ${inc.internal_discussion?.slack_channel || "N/A"}`,
    `- Discussion: "${inc.internal_discussion?.message || "No discussion found."}"`,
  ].filter(line => line !== null).join("\n");

  res.json({
    success: true,
    mode: "mocked",
    ai_analysis_markdown: report,
    extracted_logs: [
      { id: inc.incident_id, severity: sev, cve, package: pkg, developer: dev },
    ],
  });
});

/* ─────────────────────────────────────────────────────────────────────
   GET /api/remediate?id=<1-3>
   Returns structured remediation steps + CLI scripts
───────────────────────────────────────────────────────────────────── */
router.get("/remediate", (req, res) => {
  const id  = req.query.id || 1;
  const inc = getIncidentById(id);

  const sev       = inc.vulnerability?.severity || "safe";
  const pkg       = inc.package_details?.package_name || "unknown";
  const dev       = inc.pr_details?.developer || "Unknown";
  const cve       = inc.vulnerability?.cve || "N/A";
  const hasSecret = !!inc.secrets_detected;
  const hasPolicy = !!inc.policy_violation;

  const actions = [
    `Perform a Git revert on the repository to revoke code modifications introduced by ${dev}`,
    hasSecret ? `Identify and purge any configuration strings containing API keys or credentials` : null,
    hasPolicy ? `Conduct a policy review in Notion to align branch guidelines` : null,
    `Upgrade \`${pkg}\` to its latest patched version to resolve ${cve}`,
    `Run \`npm audit\` to verify no remaining vulnerabilities`,
    `Notify the security team via Slack and document the incident`,
  ].filter(Boolean);

  const scripts = [
    `# Revert the vulnerable branch change\ngit revert HEAD --no-edit\ngit push origin HEAD`,
    hasSecret
      ? `# Scan for further credential leaks\npip install trufflehog\ntrufflehog git file://.\n\n# Remove secret from git history\ngit filter-repo --path <secret-file> --invert-paths`
      : null,
    `# Patch the vulnerable package\nnpm install ${pkg}@latest\nnpm audit --audit-level=high`,
    `# Rotate secrets on platform credentials dashboard\n# 1. Revoke the exposed key on AWS/GitHub/etc\n# 2. Generate new credentials\n# 3. Update environment variables in your secrets manager`,
  ].filter(Boolean);

  res.json({
    success: true,
    mode: "mocked",
    remediation: {
      title: `Immediate Rollback & Credential Rotation Guidelines — ${inc.incident_id}`,
      subtitle: sev === "critical"
        ? "Recommended strategy to resolve active vulnerability and enforce Notion compliance policies."
        : "Recommended strategy to resolve vulnerability.",
      severity: sev,
      actions,
      scripts,
    },
  });
});

/* ─────────────────────────────────────────────────────────────────────
   POST /api/chat
   Body: { message: string, log_id: number }
   AI Copilot — context-aware Q&A about incidents
───────────────────────────────────────────────────────────────────── */
router.post("/chat", (req, res) => {
  const { message = "", log_id = 1 } = req.body;
  const inc = getIncidentById(log_id);

  const sev  = inc.vulnerability?.severity || "safe";
  const cve  = inc.vulnerability?.cve || "N/A";
  const dev  = inc.pr_details?.developer || "Unknown";
  const pkg  = inc.package_details?.package_name || "unknown";
  const hasSecret = !!inc.secrets_detected;
  const hasPolicy = !!inc.policy_violation;

  const q = message.toLowerCase();
  let reply = "";

  /* ── Routing by keyword ── */
  if (q.includes("critical") || q.includes("why") || q.includes("blast") || q.includes("blast radius")) {
    reply = `## Why is ${inc.incident_id} Critical?\n\n${inc.ai_summary}\n\n**CVE:** ${cve}\n**Risk Score:** ${inc.risk_score}/100\n\nThe blast radius includes all services that depend on \`${pkg}\`. Immediate rollback is recommended to contain the exposure.`;
  } else if (q.includes("rollback") || q.includes("revert")) {
    reply = `## Rollback Procedure for ${inc.incident_id}\n\n\`\`\`bash\n# 1. Revert the commit\ngit revert HEAD --no-edit\n\n# 2. Push the revert\ngit push origin HEAD --force-with-lease\n\n# 3. Verify deployment\nnpm run deploy:staging\n\`\`\`\n\nAfter reverting, run \`npm audit\` to confirm no residual vulnerabilities. Notify the security channel.`;
  } else if (q.includes("secret") || q.includes("key") || q.includes("credential") || q.includes("rotate")) {
    if (hasSecret) {
      reply = `## Secret Exposure — ${inc.incident_id}\n\n**${inc.secrets_detected.count} secret(s)** detected with **${inc.secrets_detected.highest_severity}** severity.\n\n**Immediate steps:**\n* Revoke the exposed key on your platform dashboard immediately\n* Run \`trufflehog git file://.\` to scan for further leaks\n* Purge from git history: \`git filter-repo --path <file> --invert-paths\`\n* Rotate all secrets and update your secrets manager\n* Audit who had access to the leaked credentials`;
    } else {
      reply = `No secret leaks were detected for ${inc.incident_id}. However, always follow the principle of least privilege — rotate credentials regularly and never commit secrets to source code.\n\nUse tools like **trufflehog** or **git-secrets** in your CI pipeline to prevent future leaks.`;
    }
  } else if (q.includes("fix") || q.includes("patch") || q.includes("npm") || q.includes("lodash") || q.includes("package") || q.includes("remediat") || q.includes("cli")) {
    reply = `## Fix for \`${pkg}\` (${cve})\n\n\`\`\`bash\n# Audit current state\nnpm audit\n\n# Upgrade the vulnerable package\nnpm install ${pkg}@latest\n\n# Verify fix\nnpm audit --audit-level=high\n\`\`\`\n\nAfter patching, run your test suite to ensure no breaking changes: \`npm test\`.\n\nIf a compatible latest version isn't available, check the CVE advisory for a minimum safe version.`;
  } else if (q.includes("developer") || q.includes("contractor") || q.includes("who") || q.includes("pr") || q.includes("anomaly")) {
    reply = `## Developer Context — ${dev}\n\n**Incident:** ${inc.incident_id}\n**PR:** ${inc.pr_details?.title}\n**Merged:** ${inc.pr_details?.merged_at ? new Date(inc.pr_details.merged_at).toLocaleDateString() : "N/A"}\n\n${inc.ai_summary}\n\n**Slack Discussion:**\n> "${inc.internal_discussion?.message || "No discussion found."}" — ${inc.internal_discussion?.slack_channel}\n\n**Recommendation:** ${hasPolicy ? `Enforce policy \`${inc.policy_violation.policy_rule}\` and consider temporarily restricting ${dev}'s merge permissions pending review.` : `Notify ${dev} immediately about the vulnerability and require a security acknowledgment before next merge.`}`;
  } else if (q.includes("policy") || q.includes("notion") || q.includes("compliance")) {
    if (hasPolicy) {
      reply = `## Policy Violation — ${inc.incident_id}\n\n**Policy:** ${inc.policy_violation.policy_name}\n**Rule:** \`${inc.policy_violation.policy_rule}\`\n**Owner Team:** ${inc.policy_violation.owner_team}\n\nTo resolve:\n* Review and update branch protection rules in your repo settings\n* Conduct a policy review in Notion\n* Require security sign-off before re-merging\n* Add pre-commit hooks to enforce the policy automatically`;
    } else {
      reply = `No policy violations were detected for ${inc.incident_id}. Your current Notion policies are being enforced correctly for this incident.`;
    }
  } else if (q.includes("redeploy") || q.includes("safe") || q.includes("deploy")) {
    reply = sev === "critical" || sev === "high"
      ? `**Do NOT redeploy yet for ${inc.incident_id}.**\n\nRequired steps before redeployment:\n* ✅ Revert the vulnerable commit\n* ✅ Patch \`${pkg}\` to a safe version\n* ✅ Run \`npm audit\` — zero critical/high findings\n* ✅ Get security team sign-off\n${hasSecret ? "* ✅ Rotate all exposed credentials\n" : ""}* ✅ Deploy to staging and run smoke tests first`
      : `It should be safe to redeploy ${inc.incident_id} after:\n* Patching \`${pkg}\` to the latest version\n* Running \`npm audit\`\n* Standard QA testing`;
  } else {
    reply = `## Coral AI — ${inc.incident_id} Summary\n\n${inc.ai_summary}\n\n**Quick stats:**\n- Severity: **${sev.toUpperCase()}**\n- Risk Score: **${inc.risk_score}/100**\n- CVE: \`${cve}\`\n- Package: \`${pkg}\`\n- Developer: **${dev}**\n\nAsk me about: rollback, secrets rotation, package fixes, developer context, or policy compliance.`;
  }

  res.json({ success: true, mode: "mocked", reply });
});

/* ─────────────────────────────────────────────────────────────────────
   GET /api/query?q=<natural language>
   NL → SQL search simulation
───────────────────────────────────────────────────────────────────── */
router.get("/query", (req, res) => {
  const q = (req.query.q || "").toLowerCase();
  const incidents = getIncidents();

  let filtered = incidents;
  let sql = "SELECT * FROM incidents";

  if (q.includes("critical")) {
    filtered = incidents.filter(i => i.vulnerability?.severity === "critical");
    sql = "SELECT * FROM github LEFT JOIN osv ON github.package = osv.package WHERE severity = 'critical' ORDER BY risk_score DESC";
  } else if (q.includes("high")) {
    filtered = incidents.filter(i => i.vulnerability?.severity === "high");
    sql = "SELECT * FROM github LEFT JOIN osv ON github.package = osv.package WHERE severity = 'high' ORDER BY risk_score DESC";
  } else if (q.includes("secret") || q.includes("leak")) {
    filtered = incidents.filter(i => i.secrets_detected);
    sql = "SELECT * FROM github LEFT JOIN osv ON github.package = osv.package WHERE secrets_detected IS NOT NULL";
  } else if (q.includes("today") || q.includes("recent")) {
    filtered = incidents.slice(0, 3);
    sql = "SELECT * FROM github LEFT JOIN osv ON github.package = osv.package ORDER BY merged_at DESC LIMIT 10";
  } else if (q.includes("policy") || q.includes("violation")) {
    filtered = incidents.filter(i => i.policy_violation);
    sql = "SELECT * FROM github LEFT JOIN notion ON github.package = notion.applies_to WHERE policy_rule IS NOT NULL";
  }

  const rows = filtered.map(i => ({
    incident_id: i.incident_id,
    severity:    i.vulnerability?.severity,
    risk_score:  i.risk_score,
    cve:         i.vulnerability?.cve,
    package:     i.package_details?.package_name,
    developer:   i.pr_details?.developer,
    title:       i.pr_details?.title,
  }));

  res.json({ success: true, sql, rows, total: rows.length });
});

/* ─────────────────────────────────────────────────────────────────────
   GET /api/logs
   All raw security logs
───────────────────────────────────────────────────────────────────── */
router.get("/logs", (req, res) => {
  const incidents = getIncidents();
  res.json({ success: true, logs: incidents, total: incidents.length });
});

/* ─────────────────────────────────────────────────────────────────────
   GET /api/anomalies
   Developer anomaly detection
───────────────────────────────────────────────────────────────────── */
router.get("/anomalies", (req, res) => {
  const incidents = getIncidents();
  const devMap = {};

  incidents.forEach(inc => {
    const dev = inc.pr_details?.developer || "Unknown";
    if (!devMap[dev]) devMap[dev] = { developer: dev, incidents: [], risk_total: 0 };
    devMap[dev].incidents.push(inc.incident_id);
    devMap[dev].risk_total += inc.risk_score || 0;
  });

  const anomalies = Object.values(devMap)
    .filter(d => d.risk_total > 70 || d.incidents.length > 1)
    .map(d => ({ ...d, avg_risk: Math.round(d.risk_total / d.incidents.length) }))
    .sort((a, b) => b.risk_total - a.risk_total);

  res.json({ success: true, anomalies, total: anomalies.length });
});

module.exports = router;
