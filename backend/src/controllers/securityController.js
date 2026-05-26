const { joinSecurityData } = require("../coral/joinData");

const getSecuritySummary = async (req, res) => {

  const incidents = joinSecurityData();

  const summary = {
    total_incidents: incidents.length,

    critical: incidents.filter(
      i => i.vulnerability.severity === "critical"
    ).length,

    high: incidents.filter(
      i => i.vulnerability.severity === "high"
    ).length,

    medium: incidents.filter(
      i => i.vulnerability.severity === "medium"
    ).length,

    safe: incidents.filter(
      i => i.vulnerability.severity === "safe"
    ).length,
  };

  res.status(200).json({
    success: true,
    data: summary
  });

};

const getHighRiskIncidents = async (req, res) => {

  const incidents = joinSecurityData();

  res.status(200).json({
    success: true,
    data: incidents
  });

};

module.exports = {
  getSecuritySummary,
  getHighRiskIncidents
};