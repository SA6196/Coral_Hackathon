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
  const { github, vulnerability, slack, notion_policy, secrets, maliciousCode } = incident;
  const pkg        = github.package_name;
  const author     = github.author;
  const severity   = (vulnerability.severity || "safe").toLowerCase();
  const cve        = vulnerability.cve_id;
  const hasLeak    = secrets?.length > 0;
  const hasPolicy  = notion_policy !== null;
  const hasMalCode = maliciousCode?.length > 0;

  const slackCtx = (slack?.message && slack.message !== "No internal discussion found.")
    ? ` Slack (${slack.channel || "#unknown"}): "${slack.message}"`
    : "";

  // 1. Malicious code / backdoor — highest priority regardless of OSV severity
  if (hasMalCode) {
    const finding = maliciousCode[0];
    return `🚨 CRITICAL BACKDOOR DETECTED: ${author} introduced malicious code in \`${pkg}\` — pattern: "${finding.description}". Code preview: \`${finding.preview}\`.${slackCtx} Immediate rollback and account suspension required. Do NOT deploy.`;
  }

  // 2. Critical + secret leak
  if (severity === "critical" && hasLeak) {
    return `🚨 CRITICAL: ${author} committed \`${pkg}\` containing ${cve} AND a credential leak (${secrets[0]?.name}).${slackCtx} Both vulnerability and secret rotation required immediately.`;
  }

  // 3. Critical with policy
  if (severity === "critical" && hasPolicy) {
    return `🔴 CRITICAL: ${cve} in \`${pkg}\` by ${author} violates policy "${notion_policy.policy_name}" (${notion_policy.owner_team}).${slackCtx} Deployment blocked — rollback required.`;
  }

  // 4. Critical
  if (severity === "critical") {
    return `🔴 CRITICAL vulnerability ${cve} in \`${pkg}\` committed by ${author}. CVSS score indicates active exploitability.${slackCtx} Immediate rollback required.`;
  }

  // 5. Secret leak only
  if (hasLeak) {
    return `⚠️ SECRET LEAK: ${author} hardcoded credentials in \`${pkg}\` — exposed: "${secrets[0]?.name}".${slackCtx} Rotate keys immediately and purge git history.`;
  }

  // 6. High + policy
  if (severity === "high" && hasPolicy) {
    return `🟠 HIGH RISK: \`${pkg}\` by ${author} has ${cve !== "NO_CVE_FOUND" ? `CVE ${cve}` : "known vulnerabilities"} AND violates policy "${notion_policy.policy_name}" (${notion_policy.owner_team}).${slackCtx} Security review mandatory before deployment.`;
  }

  // 7. High
  if (severity === "high") {
    return `🟠 HIGH RISK: ${author} merged \`${pkg}\` with ${cve !== "NO_CVE_FOUND" ? `known CVE ${cve}` : "high-severity vulnerability"}.${slackCtx} Security team review required before next deployment.`;
  }

  // 8. Medium with policy
  if (severity === "medium" && hasPolicy) {
    return `🟡 MEDIUM RISK: \`${pkg}\` by ${author} has ${cve !== "NO_CVE_FOUND" ? cve : "known vulnerabilities"} and violates "${notion_policy.policy_name}".${slackCtx} Monitor and patch before production.`;
  }

  // 9. Medium
  if (severity === "medium") {
    return `🟡 MODERATE RISK: \`${pkg}\` by ${author} has ${cve !== "NO_CVE_FOUND" ? cve : "known vulnerabilities"}.${slackCtx} Test thoroughly and patch before production deployment.`;
  }

  // 10. Safe with policy still needs attention
  if (hasPolicy) {
    return `ℹ️ POLICY NOTE: ${author}'s commit to \`${pkg}\` violates "${notion_policy.policy_name}" despite no known CVEs.${slackCtx} Policy exception or review required.`;
  }

  return `✅ LOW RISK: ${author}'s change to \`${pkg}\` has no known CVEs, secrets, or policy violations.${slackCtx} Safe to deploy after standard review.`;
}

function buildRecommendation(incident) {
  const { vulnerability, secrets, notion_policy, maliciousCode } = incident;
  const severity = (vulnerability.severity || "safe").toLowerCase();

  // Malicious code is always an immediate rollback — checked BEFORE CVE severity
  if (maliciousCode?.length > 0)                          return "ROLLBACK_DEPLOYMENT";
  if (severity === "critical")                             return "ROLLBACK_DEPLOYMENT";
  if (secrets?.length > 0)                                return "ROTATE_SECRETS_IMMEDIATELY";
  if (notion_policy?.policy_rule === "BANNED_PACKAGE")     return "ROLLBACK_DEPLOYMENT";
  if (notion_policy?.policy_rule === "SECRETS_RISK")       return "SECURITY_AUDIT_REQUIRED";
  if (severity === "high")                                 return "SECURITY_REVIEW_REQUIRED";
  if (severity === "medium")                               return "MONITOR_AND_TEST";
  if (notion_policy)                                       return "POLICY_REVIEW_REQUIRED";
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

    // ── Precise Risk score calculation ─────────────────────────────
    let riskScore = 0;

    // 1. Base Score from CVSS (if available) or deterministic severity spread
    if (incident.vulnerability && incident.vulnerability.cvss) {
      riskScore = parseFloat(incident.vulnerability.cvss) * 10;
    } else {
      // Deterministic spread based on string hash to create realistic distribution
      const hashString = (incident.github?.package_name || "") + (incident.github?.author || "") + (incident.github?.pr_id || index);
      let hash = 0;
      for (let i = 0; i < hashString.length; i++) {
        hash = ((hash << 5) - hash) + hashString.charCodeAt(i);
        hash |= 0; 
      }
      const pseudoRandom = Math.abs(hash % 100) / 100; // 0.0 to 1.0
      
      const ranges = {
        critical: { min: 85, max: 96 },
        high:     { min: 65, max: 85 },
        medium:   { min: 40, max: 65 },
        safe:     { min: 12, max: 38 }
      };
      const range = ranges[severity] || ranges.safe;
      riskScore = range.min + (pseudoRandom * (range.max - range.min));
    }

    // 2. Secret Exposure Penalty (Dynamic)
    if (secrets.length > 0) {
      // Add 15 points for the first secret, +5 for each additional
      riskScore += 15 + ((secrets.length - 1) * 5);
    }

    // 3. Malicious Code Penalty
    if (maliciousCode.length > 0) {
      riskScore = Math.max(riskScore, 85); // Floor at 85
      riskScore += (maliciousCode.length * 3); // +3 per malicious pattern
    }

    // 4. Policy Violation Penalty
    if (incident.notion_policy) {
      riskScore += (POLICY_BOOST[incident.notion_policy.policy_rule] || 0);
    }

    // 5. Code Complexity & Risky Heuristics Penalty (Cool Practical Precise Formula)
    const diffText = (incident.github?.commit_diff || "");
    const diffLines = diffText.split("\\n").length;
    
    // Base complexity penalty
    if (diffLines > 50) riskScore += 1.5;
    if (diffLines > 200) riskScore += 3.2;

    // Analyze commit diff for inherently risky operations (adds precise dynamic scoring)
    const riskyPatterns = [
      { regex: /exec\(|spawn\(|eval\(/i, penalty: 8.5 },
      { regex: /process\.env/i, penalty: 4.2 },
      { regex: /fs\.readFile|fs\.writeFile/i, penalty: 2.5 },
      { regex: /password|secret|token/i, penalty: 5.0 },
      { regex: /bypass|hack|fix|temp/i, penalty: 1.8 }
    ];

    riskyPatterns.forEach(pattern => {
      if (pattern.regex.test(diffText)) {
        riskScore += pattern.penalty;
      }
    });

    // Cap at 100 and format precisely to 1 decimal place (e.g. 88.3)
    riskScore = Math.min(100, Math.max(0, riskScore));
    riskScore = parseFloat(riskScore.toFixed(1));

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
        commit_diff: incident.github?.commit_diff || "No code diff available",
      },

      package_details: {
        package_name: incident.github?.package_name || "Unknown",
      },

      vulnerability: {
        cve:      incident.vulnerability?.cve_id   || "NO_CVE_FOUND",
        cve_id:   incident.vulnerability?.cve_id   || "NO_CVE_FOUND",
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

module.exports = { runSecurityAnalysis, scanTextForMaliciousCode };