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

const fs = require("fs");
const path = require("path");

function getMockData(filename) {
  try {
    const data = fs.readFileSync(path.join(__dirname, "../../mock-data", filename), "utf-8");
    return JSON.parse(data);
  } catch (e) {
    console.warn(`[WARN] Could not read ${filename}, returning empty array.`);
    return [];
  }
}

// ── Multi-Tenant Stores ──────────────────────────────────────────────
const sessionStore = {}; // Holds synced raw data arrays per sessionId
const tokenStore = {};   // Holds runtime tokens per sessionId

// ── In-memory cache (Session aware) ────────────────────────────
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const _cache = {};
const _cacheTs = {};

function setSessionData(sessionId, data) {
  if (!sessionId) return;
  sessionStore[sessionId] = data;
}

function getRuntimeTokens(sessionId) {
  if (!sessionId) return {};
  return tokenStore[sessionId] || {
    github: process.env.GITHUB_TOKEN || null,
    github_repo: process.env.GITHUB_REPO || null,
    slack:  process.env.SLACK_BOT_TOKEN || null,
    slack_channel: process.env.SLACK_CHANNEL || null,
    notion: process.env.NOTION_TOKEN || null,
    notion_db: process.env.NOTION_DB || null,
  };
}

function setRuntimeTokens(sessionId, tokens) {
  if (!sessionId) return;
  tokenStore[sessionId] = { ...getRuntimeTokens(sessionId), ...tokens };
}

// ── Build lookup maps for O(1) key-based joins ──────────────────────
function buildIndexes(osvData, slackData, notionData) {
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
 * joinSecurityData(sessionId)
 * Performs the 4-way LEFT JOIN and returns enriched incident rows.
 * Results are cached per session.
 */
const joinSecurityData = (sessionId = "default") => {
  // ── Serve from cache if fresh ──────────────────────────────────────
  const now = Date.now();
  if (_cache[sessionId] && (now - (_cacheTs[sessionId] || 0)) < CACHE_TTL_MS) {
    return { data: _cache[sessionId], cache_hit: true, cached_at: new Date(_cacheTs[sessionId]).toISOString() };
  }

  const sData = sessionStore[sessionId] || {};
  const githubData = sData.github || getMockData("github.json");
  const osvData = sData.osv || getMockData("osv.json");
  const slackData = sData.slack || getMockData("slack.json");
  const notionData = sData.notion || getMockData("notion.json");

  const { osvByPackage, slackByAuthor, notionByPackage } = buildIndexes(osvData, slackData, notionData);

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
  _cache[sessionId] = joined;
  _cacheTs[sessionId] = now;

  return { data: joined, cache_hit: false, cached_at: new Date(now).toISOString() };
};

/** Force-clear the cache (call after data mutations) */
const invalidateCache = (sessionId = "default") => {
  if (sessionId === "all") {
    Object.keys(_cache).forEach(k => delete _cache[k]);
    Object.keys(_cacheTs).forEach(k => delete _cacheTs[k]);
  } else {
    delete _cache[sessionId];
    delete _cacheTs[sessionId];
  }
};

/** Expose cache metadata for the API response */
const getCacheInfo = (sessionId = "default") => {
  const ts = _cacheTs[sessionId] || 0;
  return {
    is_cached:  !!_cache[sessionId] && (Date.now() - ts) < CACHE_TTL_MS,
    cached_at:  ts ? new Date(ts).toISOString() : null,
    ttl_seconds: Math.round(CACHE_TTL_MS / 1000),
    expires_in_seconds: ts
      ? Math.max(0, Math.round((CACHE_TTL_MS - (Date.now() - ts)) / 1000))
      : 0,
  };
};

module.exports = { joinSecurityData, invalidateCache, getCacheInfo, setSessionData, getRuntimeTokens, setRuntimeTokens };