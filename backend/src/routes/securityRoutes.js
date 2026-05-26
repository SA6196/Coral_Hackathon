const express = require("express");
const router  = express.Router();

const {
  getSecuritySummary,
  getHighRiskIncidents,
  getCacheStatus,
} = require("../controllers/securityController");

router.get("/security-summary",      getSecuritySummary);
router.get("/high-risk-incidents",   getHighRiskIncidents);
router.get("/cache-status",          getCacheStatus);

module.exports = router;