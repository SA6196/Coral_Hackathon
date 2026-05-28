const { joinSecurityData, getCacheInfo } = require("../coral/joinData");
const { runSecurityAnalysis }            = require("../coral/queryEngine");

/*
|--------------------------------------------------------------------------
| SECURITY SUMMARY  — GET /api/security-summary
|--------------------------------------------------------------------------
*/
const getSecuritySummary = async (req, res) => {
  const sessionId = req.headers["x-session-id"] || "default";
  const result   = await joinSecurityData(sessionId);          // { data, cache_hit, cached_at }
  const incidents = runSecurityAnalysis(result.data);

  const summary = {
    total_incidents: incidents.length,
    critical: incidents.filter(i => i.vulnerability.severity === "critical").length,
    high:     incidents.filter(i => i.vulnerability.severity === "high").length,
    medium:   incidents.filter(i => i.vulnerability.severity === "medium").length,
    safe:     incidents.filter(i => i.vulnerability.severity === "safe").length,

    // Feature 5 — secret scan stats
    secrets_detected: incidents.filter(i => i.secrets_detected !== null).length,

    // Feature 3 — policy violation stats
    policy_violations: incidents.filter(i => i.policy_violation !== null).length,
  };

  res.status(200).json({
    success: true,
    data: summary,
    // Feature 7 — cache metadata
    coral_meta: {
      query: "SELECT ... FROM github LEFT JOIN osv LEFT JOIN slack LEFT JOIN notion",
      sources_joined: 4,
      cache_hit: result.cache_hit,
      cached_at: result.cached_at,
      ...getCacheInfo(sessionId),
    },
  });
};

/*
|--------------------------------------------------------------------------
| HIGH RISK INCIDENTS  — GET /api/high-risk-incidents
|--------------------------------------------------------------------------
*/
const getHighRiskIncidents = async (req, res) => {
  const sessionId = req.headers["x-session-id"] || "default";
  const result    = await joinSecurityData(sessionId);
  const analyzed  = runSecurityAnalysis(result.data);

  res.status(200).json({
    success: true,
    data: analyzed,
    coral_meta: {
      query: "SELECT * FROM github LEFT JOIN osv LEFT JOIN slack LEFT JOIN notion ORDER BY risk_score DESC",
      sources_joined: 4,
      cache_hit: result.cache_hit,
      cached_at: result.cached_at,
      ...getCacheInfo(sessionId),
    },
  });
};

/*
|--------------------------------------------------------------------------
| CACHE STATUS  — GET /api/cache-status
|--------------------------------------------------------------------------
*/
const getCacheStatus = async (req, res) => {
  const sessionId = req.headers["x-session-id"] || "default";
  res.status(200).json({
    success: true,
    cache: getCacheInfo(sessionId),
  });
};

module.exports = { getSecuritySummary, getHighRiskIncidents, getCacheStatus };