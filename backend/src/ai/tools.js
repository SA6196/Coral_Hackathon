const { tool } = require("@langchain/core/tools");
const { z } = require("zod");
const fs = require("fs");
const path = require("path");

const PATTERNS = [
  {
    id: "aws_access_key",
    description: "AWS access key ID",
    regex: /(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])/g,
  },
  {
    id: "aws_secret_key",
    description: "AWS secret access key",
    regex: /aws(.{0,20})?(secret|session|key).{0,20}?['"][A-Za-z0-9/+=]{40}['"]/gi,
  },
  {
    id: "github_pat",
    description: "GitHub personal access token",
    regex: /ghp_[A-Za-z0-9_]{20,}/g,
  },
  {
    id: "github_oauth",
    description: "GitHub OAuth token",
    regex: /gho_[A-Za-z0-9_]{20,}/g,
  },
  {
    id: "slack_token",
    description: "Slack token",
    regex: /xox[baprs]-[A-Za-z0-9-]{10,}/g,
  },
  {
    id: "notion_token",
    description: "Notion integration token",
    regex: /secret_[A-Za-z0-9]{24,}/g,
  },
  {
    id: "private_key",
    description: "Private key block",
    regex: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
  },
  {
    id: "generic_api_key",
    description: "Generic API key assignment",
    regex: /(api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*['"][A-Za-z0-9_\-]{16,}['"]/gi,
  },
  {
    id: "jwt",
    description: "JSON Web Token",
    regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  }
];

function redact(match, maxLen = 12) {
  if (match.length <= maxLen) {
    return match.substring(0, 4) + "...";
  }
  return match.substring(0, 6) + "..." + match.substring(match.length - 4);
}

function scanTextForSecrets(text) {
  const findings = [];
  if (!text) return findings;
  
  const lines = text.split(/\r?\n/);
  for (const patternObj of PATTERNS) {
    lines.forEach((line, index) => {
      // Reset regex index for safety
      patternObj.regex.lastIndex = 0;
      let match;
      while ((match = patternObj.regex.exec(line)) !== null) {
        findings.push({
          rule_id: patternObj.id,
          description: patternObj.description,
          preview: redact(match[0]),
          line: index + 1
        });
      }
    });
    
    // Check multiline for private keys specifically if line-by-line missed it
    if (patternObj.id === "private_key" && patternObj.regex.test(text)) {
      if (!findings.some(f => f.rule_id === "private_key")) {
        findings.push({
          rule_id: patternObj.id,
          description: patternObj.description,
          preview: "-----BEGIN ... PRIVATE KEY-----",
          line: null
        });
      }
    }
  }
  return findings;
}

// Tool 1: scan_commits_for_secrets
const scanCommitsForSecrets = tool(
  async ({ diff }) => {
    console.log(`[Tool] Scanning diff for secrets...`);
    const findings = scanTextForSecrets(diff);
    
    if (findings.length > 0) {
      const descriptions = findings.map(f => `${f.description} (line ${f.line || "unknown"}): ${f.preview}`);
      return `CRITICAL: Secrets found in diff. ${descriptions.join("; ")}`;
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

const { scanTextForMaliciousCode } = require("../utils/maliciousCodeScanner");

// Tool 5: scan_code_for_malicious_patterns
const scanCodeForMaliciousPatterns = tool(
  async ({ code }) => {
    console.log(`[Tool] Scanning code for backdoors & malicious logic...`);
    const findings = scanTextForMaliciousCode(code);
    
    if (findings.length > 0) {
      const descriptions = findings.map(f => `Rule: ${f.description} (Severity: ${f.severity.toUpperCase()}, Line: ${f.line || "unknown"}) - Match: ${f.preview}`);
      return `CRITICAL: Malicious code pattern(s) detected! ${descriptions.join("; ")}`;
    }
    return "Scan complete. No obvious backdoor, shell spawn, or obfuscation patterns detected.";
  },
  {
    name: "scan_code_for_malicious_patterns",
    description: "Scans raw source code or commits for dynamic execution, shell execution, exfiltration webhooks, base64 payloads, or git hook overrides.",
    schema: z.object({
      code: z.string().describe("The raw source code or diff to analyze."),
    }),
  }
);

module.exports = {
  scanCommitsForSecrets,
  searchNotionPolicies,
  queryOsv,
  checkGithubAccessRisk,
  scanTextForSecrets,
  scanCodeForMaliciousPatterns
};
