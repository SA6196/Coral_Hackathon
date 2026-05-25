const express = require("express");

const router = express.Router();

const {
  fetchSecurityReport,
  fetchSecuritySummary,
  fetchHighRiskIncidents
} = require("../controllers/securityController");

router.get(
  "/security-report",
  fetchSecurityReport
);

router.get(
  "/security-summary",
  fetchSecuritySummary
);

router.get(
  "/high-risk-incidents",
  fetchHighRiskIncidents
);

module.exports = router;