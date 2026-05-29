/**
 * queryEngine.js  — Coral AI Analysis Engine
 * ─────────────────────────────────────────────────────────────────────
 * Takes the 4-source joined dataset and produces enriched
 * security incidents with:
 *   • Severity-based risk scoring
 *   • Secret detection (11 pattern types)
 *   • Notion policy violation flags
 *   • Contextual AI summaries
 *   • Actionable recommendations
 * ─────────────────────────────────────────────────────────────────────
 */

const { scanForSecrets } = require("../utils/secretScanner");
const { scanTextForMaliciousCode } = require("../utils/maliciousCodeScanner");

// ── Risk scoring weights ─────────────────────────────────────────────
const SEVERITY_CONFIG = {
  critical: { base_score: 95, label: "CRITICAL" },
  high:     { base_score: 75, label: "HIGH"     },
  medium:   { base_score: 45, label: "MEDIUM"   },
  safe:     { base_score: 10, label: "SAFE"      },
};

const POLICY_BOOST = {
  BANNED_PACKAGE: 15,
  SECRETS_RISK:   20,
  AUDIT_REQUIRED: 8,
  REVIEW_REQUIRED: 5,
};

// ── Contextual AI summaries ──────────────────────────────────────────
function buildAiSummary(incident) {
  const { github, vulnerability, slack, notion_policy, secrets } = incident;
  const pkg      = github.package_name;
  const author   = github.author;
  const severity = (vulnerability.severity || "safe").toLowerCase(); // normalise
  const cve      = vulnerability.cve_id;
  const hasLeak  = secrets?.length > 0;
  const hasPolicy = notion_policy !== null;

  if (severity === "critical" && hasLeak) {
    return `🚨 CRITICAL: ${author} committed ${pkg} which contains ${cve} AND a secret leak (${secrets[0]?.name}). ${slack.message !== "No internal discussion found." ? `Slack alert in ${slack.channel}: "${slack.message}"` : "No internal discussion detected."} Immediate rollback required.`;
  }
  if (severity === "critical") {
    return `🔴 Critical vulnerability ${cve} detected in ${pkg} committed by ${author}. ${hasPolicy ? `Violates policy: "${notion_policy.policy_name}" (${notion_policy.owner_team}).` : ""} Immediate action required.`;
  }
  if (severity === "high" && hasPolicy) {
    return `🟠 High-risk package ${pkg} violates internal policy "${notion_policy.policy_name}". ${cve !== "NO_CVE_FOUND" ? `CVE: ${cve}.` : ""} Security review mandatory before next deployment.`;
  }
  if (severity === "high") {
    return `🟠 High-risk change by ${author}: ${github.title}. Package ${pkg} has known CVE ${cve}. Security team review required.`;
  }
  if (hasLeak) {
    return `⚠️ Potential secret detected in commit by ${author}: "${secrets[0]?.name}". ${slack.message}`;
  }
  if (severity === "medium") {
    return `🟡 Moderate risk: ${pkg} has ${cve}. ${hasPolicy ? `Policy "${notion_policy.policy_name}" applies.` : "Monitor and test before deploying to production."}`;
  }
  return `✅ ${github.title} appears safe. No critical vulnerabilities or policy violations detected.`;
}

function buildRecommendation(incident) {
  const { vulnerability, secrets, notion_policy } = incident;
  const severity = (vulnerability.severity || "safe").toLowerCase(); // normalise

  if (severity === "critical") return "ROLLBACK_DEPLOYMENT";
  if (secrets?.length > 0)     return "ROTATE_SECRETS_IMMEDIATELY";
  if (notion_policy?.policy_rule === "BANNED_PACKAGE") return "ROLLBACK_DEPLOYMENT";
  if (notion_policy?.policy_rule === "SECRETS_RISK")   return "SECURITY_AUDIT_REQUIRED";
  if (severity === "high")     return "SECURITY_REVIEW_REQUIRED";
  if (severity === "medium")   return "MONITOR_AND_TEST";
  return "SAFE_TO_DEPLOY";
}

// ── Main analysis function ───────────────────────────────────────────
const runSecurityAnalysis = (joinedData) => {
  return joinedData.map((incident, index) => {
    const severity    = (incident.vulnerability?.severity || "safe").toLowerCase();
    const cfg         = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.safe;

    // ── Secret detection (Feature 5) ──────────────────────────────
    const secrets = scanForSecrets(
      incident.github?.title   || "",
      incident.slack?.message  || ""
    );

    // ── Heuristic Backdoor/Malicious Code detection ────────────────
    const maliciousCode = scanTextForMaliciousCode(incident.github?.commit_diff || "");

    // ── Risk score calculation ─────────────────────────────────────
    let riskScore = cfg.base_score;
    if (secrets.length > 0) riskScore = Math.min(100, riskScore + 10);
    if (maliciousCode.length > 0) riskScore = 100; // Escalate immediately to maximum risk
    if (incident.notion_policy) {
      riskScore = Math.min(100, riskScore + (POLICY_BOOST[incident.notion_policy.policy_rule] || 0));
    }

    // ── Build final incident object ────────────────────────────────
    const enrichedIncident = { ...incident, secrets, maliciousCode };

    return {
      incident_id: `CORAL-${index + 1}`,

      risk_score: riskScore,

      ai_summary: buildAiSummary(enrichedIncident),

      recommended_action: buildRecommendation(enrichedIncident),

      pr_details: {
        pr_id:      incident.github?.pr_id || index + 1,
        title:      incident.github?.title    || "Unknown PR",
        developer:  incident.github?.author   || "Unknown",
        merged_at:  incident.github?.merged_at || null,
      },

      package_details: {
        package_name: incident.github?.package_name || "Unknown",
      },

      vulnerability: {
        cve:      incident.vulnerability?.cve_id   || "NO_CVE_FOUND",
        severity: severity, // already normalised to lowercase above
      },

      // Notion policy (Feature 3)
      policy_violation: incident.notion_policy ? {
        policy_id:   incident.notion_policy.policy_id,
        policy_name: incident.notion_policy.policy_name,
        policy_rule: incident.notion_policy.policy_rule,
        owner_team:  incident.notion_policy.owner_team,
        severity:    incident.notion_policy.severity,
        description: incident.notion_policy.description,
      } : null,

      internal_discussion: {
        slack_channel: incident.slack?.channel || "N/A",
        message:       incident.slack?.message || "No internal discussion found.",
      },

      // Secret detection results (Feature 5)
      secrets_detected: secrets.length > 0 ? {
        count:    secrets.length,
        findings: secrets,
        highest_severity: secrets.reduce((acc, s) =>
          ({ critical: 0, high: 1, medium: 2 }[s.severity] < ({ critical: 0, high: 1, medium: 2 }[acc] ?? 99)
            ? s.severity : acc
          ), "medium"),
      } : null,

      // Malicious Code results
      malicious_code_detected: maliciousCode.length > 0 ? {
        count:    maliciousCode.length,
        findings: maliciousCode,
        highest_severity: "critical"
      } : null,
    };
  });
};

module.exports = { runSecurityAnalysis };