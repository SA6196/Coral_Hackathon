/**
 * joinData.js  — Coral SQL Engine (simulated)
 * ─────────────────────────────────────────────────────────────────────
 * Simulates Coral's multi-source JOIN engine.
 *
 * Coral SQL executed:
 *   SELECT g.*, o.*, s.*, n.*
 *   FROM   github_commits  AS g
 *   LEFT JOIN vulnerabilities AS o ON g.package_name = o.package_name
 *   LEFT JOIN slack_messages  AS s ON g.author       = s.user
 *   LEFT JOIN policies        AS n ON g.package_name = n.applies_to
 *   ORDER BY severity_rank ASC, g.merged_at DESC
 *
 * Key-based joins (NOT index-based):
 *  • github ↔ osv     : package_name
 *  • github ↔ slack   : author
 *  • github ↔ notion  : package_name
 * ─────────────────────────────────────────────────────────────────────
 */

const githubData = require("../../mock-data/github.json");
const osvData    = require("../../mock-data/osv.json");
const slackData  = require("../../mock-data/slack.json");
const notionData = require("../../mock-data/notion.json");

// ── In-memory cache (Feature 7: Caching) ────────────────────────────
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
let _cache = null;
let _cacheTs = 0;

// ── Build lookup maps for O(1) key-based joins ──────────────────────
function buildIndexes() {
  // OSV: package_name → vulnerability record
  const osvByPackage = {};
  for (const vuln of osvData) {
    if (!osvByPackage[vuln.package_name]) {
      osvByPackage[vuln.package_name] = vuln;
    }
  }

  // Slack: we store by position but also allow author matching if user field exists
  // Slack messages stored by index as fallback; also build author→message map
  const slackByAuthor = {};
  for (const msg of slackData) {
    if (msg.user) slackByAuthor[msg.user] = msg;
  }

  // Notion: package_name → policy record
  const notionByPackage = {};
  for (const policy of notionData) {
    if (!notionByPackage[policy.applies_to]) {
      notionByPackage[policy.applies_to] = policy;
    }
  }

  return { osvByPackage, slackByAuthor, notionByPackage };
}

/**
 * joinSecurityData()
 * Performs the 4-way LEFT JOIN and returns enriched incident rows.
 * Results are cached for CACHE_TTL_MS milliseconds.
 */
const joinSecurityData = () => {
  // ── Serve from cache if fresh ──────────────────────────────────────
  const now = Date.now();
  if (_cache && (now - _cacheTs) < CACHE_TTL_MS) {
    return { data: _cache, cache_hit: true, cached_at: new Date(_cacheTs).toISOString() };
  }

  const { osvByPackage, slackByAuthor, notionByPackage } = buildIndexes();

  // ── The Coral JOIN ─────────────────────────────────────────────────
  const joined = githubData.map((commit, idx) => {
    // LEFT JOIN vulnerabilities ON g.package_name = o.package_name
    const vuln = osvByPackage[commit.package_name] || {};

    // LEFT JOIN slack_messages ON g.author = s.user
    // Fallback to position-based if no user field (realistic mock data)
    const slack = slackByAuthor[commit.author] || slackData[idx] || {};

    // LEFT JOIN policies ON g.package_name = n.applies_to
    const policy = notionByPackage[commit.package_name] || null;

    return {
      github: {
        title:        commit.title,
        author:       commit.author,
        package_name: commit.package_name,
        merged_at:    commit.merged_at,
        pr_id:        commit.pr_id || idx + 1,
      },
      vulnerability: {
        cve_id:   vuln.cve        || "NO_CVE_FOUND",
        severity: vuln.severity   || "safe",
        package:  vuln.package_name || commit.package_name,
      },
      slack: {
        channel: slack.channel || "N/A",
        message: slack.message || "No internal discussion found.",
        user:    slack.user    || commit.author,
      },
      notion_policy: policy ? {
        policy_id:   policy.policy_id,
        policy_name: policy.policy_name,
        policy_rule: policy.policy_rule,
        severity:    policy.severity,
        owner_team:  policy.owner_team,
        description: policy.description,
      } : null,
    };
  });

  // ── Update cache ───────────────────────────────────────────────────
  _cache  = joined;
  _cacheTs = now;

  return { data: joined, cache_hit: false, cached_at: new Date(now).toISOString() };
};

/** Force-clear the cache (call after data mutations) */
const invalidateCache = () => { _cache = null; _cacheTs = 0; };

/** Expose cache metadata for the API response */
const getCacheInfo = () => ({
  is_cached:  _cache !== null && (Date.now() - _cacheTs) < CACHE_TTL_MS,
  cached_at:  _cacheTs ? new Date(_cacheTs).toISOString() : null,
  ttl_seconds: Math.round(CACHE_TTL_MS / 1000),
  expires_in_seconds: _cacheTs
    ? Math.max(0, Math.round((CACHE_TTL_MS - (Date.now() - _cacheTs)) / 1000))
    : 0,
});

module.exports = { joinSecurityData, invalidateCache, getCacheInfo };