const { joinSecurityData } = require("../coral/joinData");

const {
  runSecurityAnalysis
} = require("../coral/queryEngine");

/*
|--------------------------------------------------------------------------
| SECURITY SUMMARY
|--------------------------------------------------------------------------
*/

const getSecuritySummary = async (req, res) => {

  const joinedData = joinSecurityData();

  const incidents =
    runSecurityAnalysis(joinedData);

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

/*
|--------------------------------------------------------------------------
| HIGH RISK INCIDENTS
|--------------------------------------------------------------------------
*/

const getHighRiskIncidents = async (req, res) => {

  const joinedData = joinSecurityData();

  const analyzedData =
    runSecurityAnalysis(joinedData);

  res.status(200).json({
    success: true,
    data: analyzedData
  });

};

module.exports = {
  getSecuritySummary,
  getHighRiskIncidents
};