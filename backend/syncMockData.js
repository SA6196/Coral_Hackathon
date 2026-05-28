const fs = require('fs');
const path = require('path');

const KNOWN_VULNS = {
  "lodash":         { cve: "CVE-2020-8203",  severity: "high",     cvss: 7.4,  summary: "Prototype pollution via merge/zipObjectDeep" },
  "jsonwebtoken":   { cve: "CVE-2022-23529", severity: "high",     cvss: 7.6,  summary: "JWT algorithm confusion attack" },
  "axios":          { cve: "CVE-2023-45857", severity: "medium",   cvss: 6.5,  summary: "CSRF token leakage via headers" },
  "express":        { cve: "CVE-2024-29041", severity: "medium",   cvss: 5.3,  summary: "Open redirect in res.location()" },
  "vm2":            { cve: "CVE-2023-29017", severity: "critical", cvss: 10.0, summary: "Sandbox escape leading to RCE" },
  "node-serialize": { cve: "CVE-2017-5941",  severity: "critical", cvss: 9.8,  summary: "Remote code execution via deserialization" },
  "minimist":       { cve: "CVE-2021-44906", severity: "critical", cvss: 9.8,  summary: "Prototype pollution" },
  "ejs":            { cve: "CVE-2022-29078", severity: "critical", cvss: 9.8,  summary: "Template injection leading to RCE" },
  "stripe":         { cve: "CVE-2026-9999",  severity: "critical", cvss: 9.1,  summary: "Payment data exposure" },
  "aws-sdk":        { cve: "CVE-2026-8888",  severity: "critical", cvss: 9.5,  summary: "Credential exposure risk" },
  "shelljs":        { cve: "CVE-2022-0144",  severity: "high",     cvss: 7.8,  summary: "Privilege escalation via shell execution" },
  "semver":         { cve: "CVE-2022-25883", severity: "medium",   cvss: 5.3,  summary: "ReDoS in version range parsing" },
  "tar":            { cve: "CVE-2021-37713", severity: "high",     cvss: 7.5,  summary: "Arbitrary file write via symlink" },
  "bcrypt":         { cve: "CVE-2026-4444",  severity: "medium",   cvss: 5.3,  summary: "Timing side-channel attack" },
  "pg":             { cve: "CVE-2024-1234",  severity: "high",     cvss: 7.5,  summary: "SQL injection via unsanitized raw queries" },
  "log4js":         { cve: "CVE-2022-21704", severity: "medium",   cvss: 5.5,  summary: "ReDoS via category name" },
  "path-parse":     { cve: "CVE-2021-23343", severity: "high",     cvss: 7.5,  summary: "ReDoS vulnerability" },
};

const POLICY_RULES = {
  "vm2":            { rule: "BANNED_PACKAGE",  team: "security-engineering", reason: "CVE-2023-29017 — complete sandbox escape, permanently banned" },
  "node-serialize": { rule: "BANNED_PACKAGE",  team: "security-engineering", reason: "Known RCE vector — permanently banned" },
  "jsonwebtoken":   { rule: "AUDIT_REQUIRED",  team: "auth-team",            reason: "JWT library changes require security audit" },
  "stripe":         { rule: "BANNED_PACKAGE",  team: "security-engineering", reason: "Active critical CVE — deployment blocked" },
  "aws-sdk":        { rule: "SECRETS_RISK",    team: "platform-team",        reason: "Must use IAM roles — hardcoded keys not allowed" },
  "bcrypt":         { rule: "REVIEW_REQUIRED", team: "auth-team",            reason: "Auth library changes require senior review" },
  "pg":             { rule: "AUDIT_REQUIRED",  team: "security-engineering", reason: "DB query changes require SQL injection audit" },
  "shelljs":        { rule: "AUDIT_REQUIRED",  team: "security-engineering", reason: "Shell execution requires explicit security sign-off" },
  "ejs":            { rule: "BANNED_PACKAGE",  team: "security-engineering", reason: "RCE via template injection — use handlebars instead" },
};

const osvPath = path.join(__dirname, 'mock-data/osv.json');
let osvData = JSON.parse(fs.readFileSync(osvPath, 'utf8'));

for (const [pkg, vuln] of Object.entries(KNOWN_VULNS)) {
  const existing = osvData.find(o => o.package_name === pkg || o.package === pkg);
  if (!existing) {
    osvData.push({
      package_name: pkg,
      package: pkg,
      cve_id: vuln.cve,
      cve: vuln.cve,
      severity: vuln.severity,
      cvss_score: vuln.cvss,
      published_at: "2026-05-01T00:00:00Z",
      affected_versions: "all",
      summary: vuln.summary
    });
  } else {
      existing.cve = vuln.cve;
      existing.cve_id = vuln.cve;
      existing.severity = vuln.severity;
      existing.cvss_score = vuln.cvss;
      existing.summary = vuln.summary;
      existing.package = pkg;
      existing.package_name = pkg;
  }
}
fs.writeFileSync(osvPath, JSON.stringify(osvData, null, 2));

const notionPath = path.join(__dirname, 'mock-data/notion.json');
let notionData = JSON.parse(fs.readFileSync(notionPath, 'utf8'));

for (const [pkg, pol] of Object.entries(POLICY_RULES)) {
  const existing = notionData.find(n => n.applies_to === pkg);
  if (!existing) {
    notionData.push({
      policy_id: "POL-" + Math.floor(Math.random()*1000),
      applies_to: pkg,
      policy_name: pol.rule,
      policy_rule: pol.rule,
      severity: "high",
      description: pol.reason,
      owner_team: pol.team
    });
  } else {
      existing.policy_name = pol.rule;
      existing.policy_rule = pol.rule;
      existing.description = pol.reason;
      existing.owner_team = pol.team;
  }
}
fs.writeFileSync(notionPath, JSON.stringify(notionData, null, 2));

console.log('Synced successfully!');
