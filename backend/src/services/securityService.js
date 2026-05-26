const loadJson = require("../utils/loadJson");
const calculateRiskScore = require("../utils/riskCalculator");

const getSecurityReport = () => {
  const githubData = loadJson("github.json");
  const slackData = loadJson("slack.json");
  const osvData = loadJson("osv.json");

  const report = githubData.map((pr) => {
    const slackMatch = slackData.find(
      (msg) => msg.user === pr.author
    );

    const vulnerabilityMatch = osvData.find(
      (vuln) =>
        vuln.package_name === pr.package_name
    );

    const severity =
      vulnerabilityMatch?.severity || "safe";

    return {
      incident_id: `SEC-${pr.pr_id}`,

      pr_details: {
        pr_id: pr.pr_id,
        title: pr.title,
        developer: pr.author,
        merged_at: pr.merged_at
      },

      package_details: {
        package_name: pr.package_name
      },

      vulnerability: {
        cve:
          vulnerabilityMatch?.cve_id ||
          "NO_CVE_FOUND",

        severity
      },

      internal_discussion: {
        slack_channel:
          slackMatch?.channel || "N/A",

        message:
          slackMatch?.message ||
          "No internal discussion found"
      },

      risk_score:
        calculateRiskScore(severity),

      ai_summary:
        severity === "critical"
          ? `Critical vulnerability detected in ${pr.package_name}. Immediate rollback recommended.`
          : severity === "high"
          ? `High-risk package detected. Monitoring strongly advised.`
          : `Package appears safe.`,

      recommended_action:
        severity === "critical"
          ? "ROLLBACK_DEPLOYMENT"
          : severity === "high"
          ? "SECURITY_REVIEW_REQUIRED"
          : "SAFE_TO_DEPLOY"
    };
  });

  return report;
};

const getSecuritySummary = () => {
  const report = getSecurityReport();

  const summary = {
    total_incidents: report.length,
    critical: 0,
    high: 0,
    medium: 0,
    safe: 0
  };

  report.forEach((item) => {
    const severity =
      item.vulnerability.severity;

    if (summary[severity] !== undefined) {
      summary[severity]++;
    }
  });

  return summary;
};

const getHighRiskIncidents = () => {
  const report = getSecurityReport();

  return report.filter(
    (item) =>
      item.vulnerability.severity === "critical" ||
      item.vulnerability.severity === "high"
  );
};

module.exports = {
  getSecurityReport,
  getSecuritySummary,
  getHighRiskIncidents
};