const axios = require("axios");
const fs = require("fs");
const path = require("path");

const MOCK_DIR = path.join(__dirname, "../../mock-data");

/**
 * 1. Fetch live GitHub Pull Requests and package.json dependencies
 */
async function fetchGithub(repoOwnerRepo, token) {
  try {
    const headers = { Accept: "application/vnd.github.v3+json" };
    if (token) headers.Authorization = `token ${token}`;

    console.log(`[SYNC] Fetching PRs from GitHub: ${repoOwnerRepo}`);
    const prsRes = await axios.get(`https://api.github.com/repos/${repoOwnerRepo}/pulls?state=all&per_page=15`, { headers });
    
    // We also want to fetch the package.json to get a list of real dependencies for the OSV scanner
    let packages = [];
    try {
      const pkgRes = await axios.get(`https://raw.githubusercontent.com/${repoOwnerRepo}/main/package.json`, { headers });
      const deps = { ...pkgRes.data.dependencies, ...pkgRes.data.devDependencies };
      packages = Object.keys(deps);
    } catch (e) {
      console.warn(`[SYNC WARN] Could not fetch package.json from ${repoOwnerRepo} - falling back to PR titles`);
    }

    const formattedData = prsRes.data.map((pr, idx) => {
      // Try to guess a package name from the PR title to simulate changes
      const words = pr.title.split(" ");
      let pkgName = packages[idx % packages.length] || "unknown";
      
      // If the PR title mentions a package like "bump axios" or "upgrade lodash", extract it
      const bumpIdx = words.findIndex(w => ["bump", "upgrade", "update", "install", "add"].includes(w.toLowerCase()));
      if (bumpIdx >= 0 && bumpIdx + 1 < words.length) {
        pkgName = words[bumpIdx + 1];
      }

      return {
        pr_id: pr.number,
        author: pr.user.login,
        title: pr.title,
        package_name: pkgName.toLowerCase(),
        merged_at: pr.merged_at || pr.created_at,
        commit_diff: pr.body || "No description provided."
      };
    });

    return { success: true, count: formattedData.length, packages, data: formattedData };
  } catch (err) {
    console.error("[SYNC ERROR] GitHub fetch failed:", err.message);
    return { success: false, error: err.message };
  }
}

/**
 * 2. Fetch live OSV Vulnerabilities
 */
async function fetchOSV(packages) {
  try {
    console.log(`[SYNC] Fetching OSV Vulnerabilities for ${packages.length} packages...`);
    // If no packages found from github, fallback to some defaults
    const pkgList = packages.length > 0 ? packages : ["lodash", "axios", "express", "react"];
    
    // Create batch query
    const queries = pkgList.map(pkg => ({
      package: { name: pkg, ecosystem: "npm" } // Assume npm for JS hackathon
    }));

    const res = await axios.post("https://api.osv.dev/v1/querybatch", { queries });
    
    let formattedData = [];
    
    if (res.data && res.data.results) {
      res.data.results.forEach((result, idx) => {
        if (result.vulns && result.vulns.length > 0) {
          result.vulns.forEach(vuln => {
            formattedData.push({
              cve: vuln.aliases ? vuln.aliases.find(a => a.startsWith("CVE")) || vuln.id : vuln.id,
              package_name: pkgList[idx],
              severity: vuln.database_specific?.severity?.toLowerCase() || "high",
              description: vuln.summary || vuln.details?.slice(0, 100) || "Vulnerability found"
            });
          });
        }
      });
    }

    // Add a default "safe" entry for packages with no vulns so the join works nicely
    pkgList.forEach(pkg => {
      if (!formattedData.find(v => v.package_name === pkg)) {
        formattedData.push({
          cve: "NO_CVE_FOUND",
          package_name: pkg,
          severity: "safe",
          description: "No known vulnerabilities"
        });
      }
    });

    return { success: true, count: formattedData.length, data: formattedData };
  } catch (err) {
    console.error("[SYNC ERROR] OSV fetch failed:", err.message);
    return { success: false, error: err.message };
  }
}

/**
 * 3. Fetch live Slack messages
 */
async function fetchSlack(channelId, token) {
  if (!token || !channelId) return { success: false, error: "Missing Slack token or channel ID" };
  try {
    console.log(`[SYNC] Fetching Slack history for channel ${channelId}`);
    const res = await axios.get(`https://slack.com/api/conversations.history?channel=${channelId}&limit=20`, {
      headers: { Authorization: `Bearer ${token}` }
    });

    if (!res.data.ok) throw new Error(res.data.error);

    // We also need to fetch user info to map Slack user IDs to names/github handles
    // For the hackathon, we will just use the ID as the name, or try to map it.
    const formattedData = res.data.messages.map(msg => ({
      user: msg.user, // Ideally this matches the GitHub handle, or we'd need a mapping table
      channel: channelId,
      message: msg.text,
      timestamp: new Date(msg.ts * 1000).toISOString()
    }));

    return { success: true, count: formattedData.length, data: formattedData };
  } catch (err) {
    console.error("[SYNC ERROR] Slack fetch failed:", err.message);
    return { success: false, error: err.message };
  }
}

/**
 * 4. Fetch live Notion policies
 */
async function fetchNotion(dbId, token) {
  if (!token || !dbId) return { success: false, error: "Missing Notion token or DB ID" };
  try {
    console.log(`[SYNC] Fetching Notion DB ${dbId}`);
    const res = await axios.post(`https://api.notion.com/v1/databases/${dbId}/query`, {}, {
      headers: {
        "Authorization": `Bearer ${token}`,
        "Notion-Version": "2022-06-28",
        "Content-Type": "application/json"
      }
    });

    // Assume standard column names: "Package", "Policy", "Rule", "Severity", "Team"
    const formattedData = res.data.results.map(page => {
      const props = page.properties;
      const getText = (prop) => prop?.title?.[0]?.plain_text || prop?.rich_text?.[0]?.plain_text || "";
      const getSelect = (prop) => prop?.select?.name || "unknown";

      return {
        policy_id: page.id,
        applies_to: getText(props["Package"]) || "unknown",
        policy_name: getText(props["Policy Name"]) || "Security Policy",
        policy_rule: getText(props["Rule"]) || "Must be secure",
        severity: getSelect(props["Severity"]).toLowerCase(),
        owner_team: getSelect(props["Team"]) || "Security",
        description: getText(props["Description"]) || ""
      };
    }).filter(p => p.applies_to !== "unknown");

    return { success: true, count: formattedData.length, data: formattedData };
  } catch (err) {
    console.error("[SYNC ERROR] Notion fetch failed:", err.message);
    return { success: false, error: err.message };
  }
}

/**
 * Main Orchestrator
 */
async function syncAllData(config) {
  const { githubRepo, githubToken, slackChannel, slackToken, notionDb, notionToken } = config;
  
  const results = {
    github: { success: false, count: 0 },
    osv: { success: false, count: 0 },
    slack: { success: false, count: 0 },
    notion: { success: false, count: 0 }
  };

  // 1. GitHub
  if (githubRepo) {
    const ghRes = await fetchGithub(githubRepo, githubToken);
    results.github = ghRes;
    
    // 2. OSV (Depends on GitHub packages)
    if (ghRes.success && ghRes.packages) {
      results.osv = await fetchOSV(ghRes.packages);
    } else {
      results.osv = await fetchOSV(["lodash", "axios", "react", "express", "jsonwebtoken"]);
    }
  } else {
    results.github.error = "No repo specified";
    results.osv.error = "Skipped because no repo specified";
  }

  // 3. Slack
  if (slackChannel && slackToken) {
    results.slack = await fetchSlack(slackChannel, slackToken);
  } else {
    results.slack.error = "No Slack token or channel specified";
  }

  // 4. Notion
  if (notionDb && notionToken) {
    results.notion = await fetchNotion(notionDb, notionToken);
  } else {
    results.notion.error = "No Notion token or DB specified";
  }

  return results;
}

module.exports = { syncAllData };
