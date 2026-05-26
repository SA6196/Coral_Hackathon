const express = require("express");

const router = express.Router();

const {
  getSecuritySummary,
  getHighRiskIncidents
} = require("../controllers/securityController");

router.get("/security-summary", getSecuritySummary);

router.get("/high-risk-incidents", getHighRiskIncidents);

module.exports = router;