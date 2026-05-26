const githubData = require("../../mock-data/github.json");
const osvData = require("../../mock-data/osv.json");
const slackData = require("../../mock-data/slack.json");

const joinSecurityData = () => {

  return githubData.map((commit, index) => {

    const vuln = osvData[index] || {};
    const slack = slackData[index] || {};

    const severity = vuln.severity || "safe";

    let riskScore = 25;

    if (severity === "critical") riskScore = 95;
    else if (severity === "high") riskScore = 80;
    else if (severity === "medium") riskScore = 55;
    else riskScore = 20;

    return {
      incident_id: `CORAL-${index + 1}`,

      risk_score: riskScore,

      ai_summary:
        severity === "critical"
          ? "Critical vulnerability detected. Immediate rollback recommended."
          : severity === "high"
          ? "High-risk package detected. Security review required."
          : severity === "medium"
          ? "Moderate vulnerability detected. Monitor closely."
          : "No major threats detected.",

      recommended_action:
        severity === "critical"
          ? "ROLLBACK_DEPLOYMENT"
          : severity === "high"
          ? "SECURITY_REVIEW_REQUIRED"
          : "SAFE_TO_DEPLOY",

      pr_details: {
        title: commit.title,
        developer: commit.author,
        merged_at: commit.merged_at
      },

      package_details: {
        package_name: commit.package_name
      },

      vulnerability: {
        cve: vuln.cve_id || "NO_CVE_FOUND",
        severity: severity
      },

      internal_discussion: {
        slack_channel: slack.channel || "#general",
        message: slack.message || ""
      }
    };

  });

};

module.exports = {
  joinSecurityData
};