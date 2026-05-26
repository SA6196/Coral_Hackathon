const runSecurityAnalysis = (joinedData) => {

  return joinedData.map((incident, index) => {

    const severity =
      incident.vulnerability?.severity || "safe";

    let riskScore = 20;
    let aiSummary = "No major threats detected.";
    let recommendation = "SAFE_TO_DEPLOY";

    /*
    |--------------------------------------------------------------------------
    | AI RULE ENGINE
    |--------------------------------------------------------------------------
    */

    if (severity === "critical") {

      riskScore = 95;

      aiSummary =
        "Critical vulnerability detected. Immediate rollback recommended.";

      recommendation = "ROLLBACK_DEPLOYMENT";

    }

    else if (severity === "high") {

      riskScore = 80;

      aiSummary =
        "High-risk package detected. Security review required.";

      recommendation = "SECURITY_REVIEW_REQUIRED";

    }

    else if (severity === "medium") {

      riskScore = 55;

      aiSummary =
        "Moderate vulnerability found. Monitor before deployment.";

      recommendation = "MONITOR_AND_TEST";

    }

    /*
    |--------------------------------------------------------------------------
    | FINAL AI INCIDENT OBJECT
    |--------------------------------------------------------------------------
    */

    return {

      incident_id: `CORAL-${index + 1}`,

      risk_score: riskScore,

      ai_summary: aiSummary,

      recommended_action: recommendation,

      pr_details: {

        title: incident.github?.title || "Unknown PR",

        developer: incident.github?.author || "Unknown",

        merged_at: incident.github?.merged_at || null,

      },

      package_details: {

        package_name:
          incident.github?.package_name || "Unknown",

      },

      vulnerability: {

        cve:
          incident.vulnerability?.cve_id || "NO_CVE_FOUND",

        severity,

      },

      internal_discussion: {

        slack_channel:
          incident.slack?.channel || "#general",

        message:
          incident.slack?.message || "No internal discussion found.",

      },

    };

  });

};

module.exports = {
  runSecurityAnalysis,
};