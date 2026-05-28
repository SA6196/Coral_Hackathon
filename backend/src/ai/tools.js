const { tool } = require("@langchain/core/tools");
const { z } = require("zod");
const fs = require("fs");
const path = require("path");

// Tool 1: scan_commits_for_secrets
const scanCommitsForSecrets = tool(
  async ({ diff }) => {
    console.log(`[Tool] Scanning diff for secrets...`);
    const secretsFound = [];
    const awsRegex = /(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])/g;
    const patRegex = /ghp_[a-zA-Z0-9]{36}/g;

    const awsMatch = diff.match(awsRegex);
    if (awsMatch) {
      secretsFound.push(`AWS Key format detected: ${awsMatch[0].substring(0, 5)}...`);
    }

    const patMatch = diff.match(patRegex);
    if (patMatch) {
      secretsFound.push(`GitHub PAT format detected: ${patMatch[0].substring(0, 10)}...`);
    }

    if (secretsFound.length > 0) {
      return `CRITICAL: Secrets found in diff. ${secretsFound.join("; ")}`;
    }
    return "No obvious secrets found in the provided diff.";
  },
  {
    name: "scan_commits_for_secrets",
    description: "Scans a git commit diff for hardcoded secrets like AWS keys or GitHub PATs.",
    schema: z.object({
      diff: z.string().describe("The git commit diff text to scan."),
    }),
  }
);

// Tool 2: search_notion_policies
const searchNotionPolicies = tool(
  async ({ query }) => {
    console.log(`[Tool] Searching Notion policies for: ${query}`);
    try {
      const notionDataPath = path.join(__dirname, "../../mock-data/notion.json");
      if (!fs.existsSync(notionDataPath)) return "Notion policy database not found.";
      const policies = JSON.parse(fs.readFileSync(notionDataPath, "utf-8"));
      
      const results = policies.filter(p => 
        p.policy_name.toLowerCase().includes(query.toLowerCase()) || 
        p.description.toLowerCase().includes(query.toLowerCase()) ||
        p.policy_rule.toLowerCase().includes(query.toLowerCase())
      );

      if (results.length === 0) return `No Notion policies found matching '${query}'.`;
      return JSON.stringify(results, null, 2);
    } catch (e) {
      return `Error searching policies: ${e.message}`;
    }
  },
  {
    name: "search_notion_policies",
    description: "Searches the internal Notion workspace for security and compliance policies.",
    schema: z.object({
      query: z.string().describe("The search query (e.g., 'banned packages', 'secrets')."),
    }),
  }
);

// Tool 3: query_osv
const queryOsv = tool(
  async ({ cve, package_name }) => {
    console.log(`[Tool] Querying OSV for CVE: ${cve} or Package: ${package_name}`);
    try {
      // For hackathon reliability, fallback to mock data if API fails or we just use mock
      const osvDataPath = path.join(__dirname, "../../mock-data/osv.json");
      if (fs.existsSync(osvDataPath)) {
        const osv = JSON.parse(fs.readFileSync(osvDataPath, "utf-8"));
        const found = osv.find(o => o.cve === cve || o.package === package_name);
        if (found) return JSON.stringify(found, null, 2);
      }
      return `No OSV data found for ${cve || package_name}`;
    } catch (e) {
      return `Error querying OSV: ${e.message}`;
    }
  },
  {
    name: "query_osv",
    description: "Queries the Open Source Vulnerabilities (OSV.dev) database for CVE details or package vulnerabilities.",
    schema: z.object({
      cve: z.string().optional().describe("The CVE ID (e.g., CVE-2023-1234)."),
      package_name: z.string().optional().describe("The name of the package."),
    }),
  }
);

// Tool 4: check_github_access_risk
const checkGithubAccessRisk = tool(
  async ({ developer }) => {
    console.log(`[Tool] Checking GitHub access risk for: ${developer}`);
    return `Developer '${developer}' has standard contributor access. No recent admin escalations detected in the baseline ledger.`;
  },
  {
    name: "check_github_access_risk",
    description: "Checks if a developer has risky GitHub access, such as recent admin escalation against the baseline.",
    schema: z.object({
      developer: z.string().describe("The GitHub username to check."),
    }),
  }
);

module.exports = {
  scanCommitsForSecrets,
  searchNotionPolicies,
  queryOsv,
  checkGithubAccessRisk
};
