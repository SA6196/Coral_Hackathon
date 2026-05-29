const axios = require("axios");
const fs = require("fs");
const path = require("path");
const { scanTextForSecrets } = require("../ai/tools");
const { scanTextForMaliciousCode } = require("../utils/maliciousCodeScanner");
const { diffAccessBaseline, saveBaseline, getBaseline } = require("../services/baselineService");

const MOCK_DIR = path.join(__dirname, "../../mock-data");

/**
 * 1. Fetch live GitHub Pull Requests, branch protection, collaborators, and commits
 */
async function fetchGithub(repoOwnerRepo, token, updateBaseline = false) {
  try {
    const headers = { Accept: "application/vnd.github.v3+json" };
    if (token) headers.Authorization = `token ${token}`;

    console.log(`[SYNC] Fetching PRs from GitHub: ${repoOwnerRepo}`);
    const prsRes = await axios.get(`https://api.github.com/repos/${repoOwnerRepo}/pulls?state=all&per_page=15`, { headers });
    
    // Fetch package.json dependencies
    let packages = [];
    try {
      const pkgRes = await axios.get(`https://raw.githubusercontent.com/${repoOwnerRepo}/main/package.json`, { headers });
      const deps = { ...pkgRes.data.dependencies, ...pkgRes.data.devDependencies };
      packages = Object.keys(deps);
    } catch (e) {
      console.warn(`[SYNC WARN] Could not fetch package.json from ${repoOwnerRepo} - falling back to PR titles`);
    }

    const formattedData = prsRes.data.map((pr, idx) => {
      const words = pr.title.split(" ");
      let pkgName = packages[idx % packages.length] || "unknown";
      
      const bumpIdx = words.findIndex(w => ["bump", "upgrade", "update", "install", "add"].includes(w.toLowerCase()));
      if (bumpIdx >= 0 && bumpIdx + 1 < words.length) {
        pkgName = words[bumpIdx + 1];
      }

      return {
        pr_id: pr.number,
        author: pr.user.login,
        title: pr.title,
        package_name: pkgName.toLowerCase().replace(/[^a-zA-Z0-9_-]/g, ""),
        merged_at: pr.merged_at || pr.created_at,
        commit_diff: pr.body || "No description provided."
      };
    });

    // ── Live Branch Protection Audit ──
    let branchProtected = true;
    try {
      console.log(`[SYNC] Checking branch protection for main...`);
      const bpRes = await axios.get(`https://api.github.com/repos/${repoOwnerRepo}/branches/main/protection`, { headers });
      if (bpRes.data && bpRes.data.required_pull_request_reviews) {
        branchProtected = true;
      }
    } catch (e) {
      if (e.response && e.response.status === 404) {
        branchProtected = false;
        console.warn(`[SYNC ALERT] main branch is unprotected!`);
      } else {
        console.warn(`[SYNC WARN] Could not check branch protection:`, e.message);
      }
    }

    if (!branchProtected) {
      formattedData.unshift({
        pr_id: 999,
        author: "system",
        title: "SECURITY ALERT: main branch is unprotected (Direct pushes allowed)",
        package_name: "github-repo",
        merged_at: new Date().toISOString(),
        commit_diff: "Branch protection is disabled on branch 'main'. Admin reviews are not required before merging."
      });
    }

    // ── Live Collaborator Audit ──
    let collaborators = [];
    try {
      console.log(`[SYNC] Fetching collaborators...`);
      const colRes = await axios.get(`https://api.github.com/repos/${repoOwnerRepo}/collaborators`, { headers });
      collaborators = colRes.data.map(u => ({
        login: u.login,
        role: { admin: u.permissions?.admin || false }
      }));
    } catch (e) {
      console.warn(`[SYNC WARN] Could not fetch collaborators:`, e.message);
    }

    if (collaborators.length > 0) {
      const currentBaseline = getBaseline();
      if (!currentBaseline.collaborators || currentBaseline.collaborators.length === 0 || updateBaseline) {
        saveBaseline({ collaborators });
      } else {
        const accessFindings = diffAccessBaseline(collaborators);
        accessFindings.forEach((finding, idx) => {
          formattedData.unshift({
            pr_id: 1000 + idx,
            author: finding.login,
            title: `SECURITY ALERT: ${finding.type.replace(/_/g, " ").toUpperCase()} detected`,
            package_name: "github-access",
            merged_at: new Date().toISOString(),
            commit_diff: `User ${finding.login} status changed. Event type: ${finding.type}. Severity: ${finding.severity}`
          });
        });
      }
    }

    // ── Live Commit Diff Scanning (Secrets & Backdoors) ──
    try {
      console.log(`[SYNC] Scanning recent commits for secrets and malicious patterns...`);
      const commitsRes = await axios.get(`https://api.github.com/repos/${repoOwnerRepo}/commits?per_page=5`, { headers });
      
      for (const commitObj of commitsRes.data) {
        const sha = commitObj.sha;
        try {
          const detailRes = await axios.get(`https://api.github.com/repos/${repoOwnerRepo}/commits/${sha}`, { headers });
          const files = detailRes.data.files || [];
          const diffText = files.map(f => `--- ${f.filename}\n${f.patch || ""}`).join("\n");
          
          // 1. Secrets Scan
          const findings = scanTextForSecrets(diffText);
          if (findings.length > 0) {
            findings.forEach((finding, idx) => {
              formattedData.unshift({
                pr_id: 2000 + idx,
                author: commitObj.commit?.author?.name || "unknown",
                title: `CRITICAL: Leaked secret detected in commit ${sha.substring(0, 8)}`,
                package_name: "credentials",
                merged_at: commitObj.commit?.author?.date || new Date().toISOString(),
                commit_diff: `Exposed ${finding.description} in file changes. Preview: ${finding.preview} (Line: ${finding.line || "unknown"})`
              });
            });
          }

          // 2. Malicious Code / Backdoor Scan
          const maliciousFindings = scanTextForMaliciousCode(diffText);
          if (maliciousFindings.length > 0) {
            maliciousFindings.forEach((finding, idx) => {
              formattedData.unshift({
                pr_id: 3000 + idx,
                author: commitObj.commit?.author?.name || "unknown",
                title: `CRITICAL: Malicious backdoor code detected in commit ${sha.substring(0, 8)}`,
                package_name: "malicious-code",
                merged_at: commitObj.commit?.author?.date || new Date().toISOString(),
                commit_diff: `Backdoor pattern: ${finding.description}. Preview: "${finding.preview}" (Line: ${finding.line || "unknown"})`
              });
            });
          }
        } catch (innerErr) {
          console.warn(`[SYNC WARN] Could not check commit details for ${sha}:`, innerErr.message);
        }
      }
    } catch (e) {
      console.warn(`[SYNC WARN] Could not scan commits:`, e.message);
    }

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
    const pkgList = packages.length > 0 ? packages : ["lodash", "axios", "express", "react"];
    
    const queries = pkgList.map(pkg => ({
      package: { name: pkg, ecosystem: "npm" }
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

    const formattedData = res.data.messages.map(msg => ({
      user: msg.user,
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
  const { githubRepo, githubToken, slackChannel, slackToken, notionDb, notionToken, updateBaseline } = config;
  
  const results = {
    github: { success: false, count: 0 },
    osv: { success: false, count: 0 },
    slack: { success: false, count: 0 },
    notion: { success: false, count: 0 }
  };

  // 1. GitHub
  if (githubRepo) {
    const ghRes = await fetchGithub(githubRepo, githubToken, updateBaseline);
    results.github = ghRes;
    
    // Save to github.json immediately so Coral SQL CLI queries are updated
    if (ghRes.success && ghRes.data) {
      fs.writeFileSync(path.join(MOCK_DIR, "github.json"), JSON.stringify(ghRes.data, null, 2));
    }
    
    // 2. OSV (Depends on GitHub packages)
    if (ghRes.success && ghRes.packages) {
      const osvRes = await fetchOSV(ghRes.packages);
      results.osv = osvRes;
      if (osvRes.success && osvRes.data) {
        fs.writeFileSync(path.join(MOCK_DIR, "osv.json"), JSON.stringify(osvRes.data, null, 2));
      }
    } else {
      const osvRes = await fetchOSV(["lodash", "axios", "react", "express", "jsonwebtoken"]);
      results.osv = osvRes;
      if (osvRes.success && osvRes.data) {
        fs.writeFileSync(path.join(MOCK_DIR, "osv.json"), JSON.stringify(osvRes.data, null, 2));
      }
    }
  } else {
    results.github.error = "No repo specified";
    results.osv.error = "Skipped because no repo specified";
  }

  // 3. Slack
  if (slackChannel && slackToken) {
    const slackRes = await fetchSlack(slackChannel, slackToken);
    results.slack = slackRes;
    if (slackRes.success && slackRes.data) {
      fs.writeFileSync(path.join(MOCK_DIR, "slack.json"), JSON.stringify(slackRes.data, null, 2));
    }
  } else {
    results.slack.error = "No Slack token or channel specified";
  }

  // 4. Notion
  if (notionDb && notionToken) {
    const notionRes = await fetchNotion(notionDb, notionToken);
    results.notion = notionRes;
    if (notionRes.success && notionRes.data) {
      fs.writeFileSync(path.join(MOCK_DIR, "notion.json"), JSON.stringify(notionRes.data, null, 2));
    }
  } else {
    results.notion.error = "No Notion token or DB specified";
  }

  return results;
}

module.exports = { syncAllData };
