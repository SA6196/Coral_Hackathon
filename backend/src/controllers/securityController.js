const {
  getSecurityReport,
  getSecuritySummary,
  getHighRiskIncidents
} = require("../services/securityService");

const fetchSecurityReport = (req, res) => {
  const report = getSecurityReport();

  res.status(200).json({
    success: true,
    count: report.length,
    data: report
  });
};

const fetchSecuritySummary = (req, res) => {
  const summary = getSecuritySummary();

  res.status(200).json({
    success: true,
    data: summary
  });
};

const fetchHighRiskIncidents = (req, res) => {
  const incidents = getHighRiskIncidents();

  res.status(200).json({
    success: true,
    count: incidents.length,
    data: incidents
  });
};

module.exports = {
  fetchSecurityReport,
  fetchSecuritySummary,
  fetchHighRiskIncidents
};