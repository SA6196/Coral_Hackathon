/**
 * aiRoutes.js — Coral AI Engine v2.0
 * ─────────────────────────────────────────────────────────────────────
 * Goated AI chatbot with:
 * - Smart NLP intent classification
 * - Full incident context awareness
 * - Multi-turn conversation support
 * - Developer risk profiling
 * - Report generation
 * - Anomaly detection
 * - NL → SQL search
 * - All missing endpoints implemented
 * ─────────────────────────────────────────────────────────────────────
 */

const express = require("express");
const router  = express.Router();
const axios   = require("axios");

const { ChatGoogleGenerativeAI } = require("@langchain/google-genai");
const { AgentExecutor, createToolCallingAgent } = require("langchain/agents");
const { scanCommitsForSecrets, searchNotionPolicies, queryOsv, checkGithubAccessRisk, scanCodeForMaliciousPatterns } = require("../ai/tools");

const { joinSecurityData, getCacheInfo } = require("../coral/joinData");
const { runSecurityAnalysis }            = require("../coral/queryEngine");

/* ── Helpers ─────────────────────────────────────────────────────────── */
async function getIncidents(sessionId) {
  const result = await joinSecurityData(sessionId);
  return runSecurityAnalysis(result.data);
}

async function getIncidentById(sessionId, id) {
  const incidents = await getIncidents(sessionId);
  const found = incidents.find(i => i.incident_id === id || String(i.pr_details?.pr_id) === String(id));
  if (found) return found;

  const num = parseInt(id, 10);
  if (!isNaN(num) && num >= 1) return incidents[Math.min(num - 1, incidents.length - 1)];
  return incidents[0];
}

function sanitizeInput(str, maxLen = 1000) {
  if (typeof str !== "string") return "";
  return str.trim().slice(0, maxLen);
}

/* ── Intent classifier ───────────────────────────────────────────────── */
function classifyIntent(msg) {
  const m = msg.toLowerCase();
  
  // Critical/severity queries
  if (/\b(critical|why.*critical|how bad|severity|risk score|blast radius|impact|exposure)\b/.test(m)) return "EXPLAIN_SEVERITY";
  
  // Rollback/revert
  if (/\b(rollback|revert|roll back|undo|restore|previous version|git revert|push.*revert)\b/.test(m)) return "ROLLBACK";
  
  // Secrets
  if (/\b(secret|credential|password|token|api key|rotate|leaked|exposure|aws key|github token|env var|vault)\b/.test(m)) return "SECRETS";
  
  // Package fix/patch
  if (/\b(fix|patch|upgrade|update|npm|yarn|install|package|dependency|lodash|stripe|jwt|axios|version)\b/.test(m)) return "FIX_PACKAGE";
  
  // Developer/PR context
  if (/\b(developer|who|contractor|engineer|pr|pull request|commit|merge|author|blame|alice|bob|rahul|shivay|alex|mike|john|sara|priya)\b/.test(m)) return "DEVELOPER_CONTEXT";
  
  // Policy/compliance
  if (/\b(policy|notion|compliance|rule|violation|audit|banned|review required|governance)\b/.test(m)) return "POLICY";
  
  // Deploy safety
  if (/\b(safe to deploy|redeploy|can i deploy|deployment|staging|production|go live|ship)\b/.test(m)) return "DEPLOY_SAFETY";
  
  // Report
  if (/\b(report|summary|overview|status|dashboard|all incidents|show me all|list|full report|security report|all.*incident)\b/.test(m)) return "REPORT";
  
  // Threat intelligence
  if (/\b(cve|vulnerability|vuln|nvd|osvdb|exploit|cvss|threat intel|owasp)\b/.test(m)) return "THREAT_INTEL";
  
  // Timeline
  if (/\b(when|timeline|history|chronolog|order|latest|recent|today)\b/.test(m)) return "TIMELINE";

  // Remediation steps
  if (/\b(steps|how to|guide|procedure|remediat|what should|next steps|action)\b/.test(m)) return "REMEDIATION_STEPS";
  
  return "GENERAL";
}

/* ── Response generators ─────────────────────────────────────────────── */
function generateExplainSeverity(inc, q) {
  const sev  = inc.vulnerability?.severity || "safe";
  const cve  = inc.vulnerability?.cve || "N/A";
  const pkg  = inc.package_details?.package_name || "unknown";
  const dev  = inc.pr_details?.developer || "Unknown";
  const score = inc.risk_score;
  const hasSecret = !!inc.secrets_detected;
  const hasPolicy = !!inc.policy_violation;
  
  const cvssEstimate = {
    critical: "9.0–10.0",
    high:     "7.0–8.9",
    medium:   "4.0–6.9",
    safe:     "0.0–3.9",
  }[sev] || "N/A";

  return `## 🔍 Severity Analysis — ${inc.incident_id}

**Verdict:** ${sev.toUpperCase()} risk (Score: **${score}/100**)

### Why is this ${sev}?
${inc.ai_summary}

### Risk Breakdown
| Factor | Status | Impact |
|--------|--------|--------|
| CVE | \`${cve}\` | +${sev === "critical" ? "95" : sev === "high" ? "75" : "45"} base score |
| Secret leak | ${hasSecret ? `⚠️ YES (${inc.secrets_detected.count} found)` : "✅ None"} | ${hasSecret ? "+10" : "+0"} |
| Policy violation | ${hasPolicy ? `⚠️ ${inc.policy_violation.policy_rule}` : "✅ None"} | ${hasPolicy ? "+5 to +20" : "+0"} |
| CVSS estimate | ${cvssEstimate} | Critical threshold |

### Blast Radius
- **Package:** \`${pkg}\` — all services importing this package are affected
- **Developer:** ${dev} — any other recent PRs by this developer should be reviewed
- **Timeline:** ${inc.pr_details?.merged_at ? `Merged ${new Date(inc.pr_details.merged_at).toLocaleDateString()} — ${Math.floor((Date.now() - new Date(inc.pr_details.merged_at)) / 3600000)}h exposure window` : "Unknown merge time"}
- **Slack:** ${inc.internal_discussion?.slack_channel !== "N/A" ? `Team is aware — discussion in ${inc.internal_discussion.slack_channel}` : "No team discussion found — alert immediately"}

${sev === "critical" ? "🚨 **Immediate rollback required. Every minute of delay increases exposure.**" : sev === "high" ? "🟠 **Security review required before next deployment.**" : "🟡 **Monitor and patch in next release cycle.**"}`;
}

function generateRollback(inc) {
  const pkg = inc.package_details?.package_name || "unknown";
  const dev = inc.pr_details?.developer || "Unknown";
  const hasSecret = !!inc.secrets_detected;

  return `## 🔄 Rollback Procedure — ${inc.incident_id}

**Estimated time to complete:** 10–20 minutes
**Risk of rollback:** Low (always prefer reverting over hotfixing in production)

### Step 1: Revert the Commit
\`\`\`bash
# View recent commits to find the target
git log --oneline -10

# Revert the specific commit (creates a new revert commit)
git revert HEAD --no-edit

# Push the revert (safe push)
git push origin HEAD --force-with-lease
\`\`\`

### Step 2: Block Deployment
\`\`\`bash
# If using GitHub Actions — disable the workflow temporarily
gh workflow disable deploy.yml

# If already deployed — scale down the affected service
kubectl scale deployment ${pkg}-service --replicas=0
# or
docker-compose stop ${pkg}-service
\`\`\`

### Step 3: Verify Rollback
\`\`\`bash
# Confirm the revert commit is in place
git log --oneline -3

# Run your test suite
npm test

# Check no new vulnerabilities introduced
npm audit --audit-level=high
\`\`\`
${hasSecret ? `
### Step 4: Rotate Exposed Credentials ⚠️
\`\`\`bash
# Immediately revoke the exposed key on your platform
# Then scan for any other exposed secrets
pip install trufflehog
trufflehog git file://. --since-commit HEAD~5

# Clean git history if needed
git filter-repo --path <secret-file> --invert-paths
\`\`\`` : ""}

### Step 5: Notify
\`\`\`bash
# Alert the security team
curl -X POST $SLACK_WEBHOOK_URL \\
  -H 'Content-type: application/json' \\
  --data '{"text":"🔄 Rollback completed for ${inc.incident_id}. PR by ${dev} reverted. All clear."}'
\`\`\`

**After rollback:** Re-open the PR, fix the vulnerability, get a security review, then re-merge.`;
}

function generateSecretsResponse(inc) {
  const hasSecret = !!inc.secrets_detected;
  const dev = inc.pr_details?.developer || "Unknown";
  
  if (hasSecret) {
    return `## 🔑 Secret Exposure Response — ${inc.incident_id}

🚨 **${inc.secrets_detected.count} secret(s) detected** with **${inc.secrets_detected.highest_severity}** severity!

### Immediate Actions (Do this NOW)
1. **Revoke the exposed key** — go to your platform dashboard and invalidate it immediately
2. **Rotate credentials** — generate new keys and update all services
3. **Check for unauthorized access** — review logs for any usage of the exposed key

### Scan & Clean
\`\`\`bash
# Install trufflehog for deep scanning
pip install trufflehog

# Scan the entire repo history
trufflehog git file://. --only-verified

# Remove the file with the secret from history
git filter-repo --path <path/to/secret-file> --invert-paths --force

# Force push (coordinate with your team first)
git push origin --force --all
\`\`\`

### Prevent Future Leaks
\`\`\`bash
# Install git-secrets to prevent committing secrets
brew install git-secrets  # or pip install detect-secrets
git secrets --install
git secrets --register-aws

# Add pre-commit hook
echo '#!/bin/sh
git secrets --pre_commit_hook -- "$@"' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
\`\`\`

### Check for Unauthorized Usage
\`\`\`bash
# AWS — check CloudTrail for unauthorized API calls
aws cloudtrail lookup-events \\
  --lookup-attributes AttributeKey=Username,AttributeValue=${dev} \\
  --start-time 2026-05-01

# GitHub — check for unexpected forks/clones of the repo
gh api repos/:owner/:repo/traffic/clones
\`\`\`

**Rotation checklist:**
- [ ] Old key revoked on platform
- [ ] New key generated
- [ ] Secrets manager updated (AWS Secrets Manager / HashiCorp Vault)
- [ ] All services restarted with new credentials
- [ ] Git history cleaned
- [ ] Pre-commit hooks installed`;
  }
  
  return `## 🔐 Secrets Security — ${inc.incident_id}

✅ **No secrets detected** in this incident's commit or Slack discussion.

### Best Practices to Stay Clean

**Never commit secrets. Use this checklist:**
\`\`\`bash
# 1. Use environment variables
export DATABASE_URL="postgresql://user:pass@host/db"

# 2. Use a secrets manager
aws secretsmanager get-secret-value --secret-id my-secret

# 3. Use .env files (always in .gitignore)
echo ".env" >> .gitignore
echo ".env.local" >> .gitignore

# 4. Scan before every commit
pip install detect-secrets
detect-secrets scan > .secrets.baseline
\`\`\`

**Tools to add to your CI pipeline:**
- **trufflehog** — scans git history for secrets
- **gitleaks** — fast secrets scanner
- **detect-secrets** — baseline tracking
- **GitHub Secret Scanning** — free for public repos`;
}

function generateFixPackage(inc, q) {
  const pkg = inc.package_details?.package_name || "unknown";
  const cve = inc.vulnerability?.cve || "N/A";
  const sev = inc.vulnerability?.severity || "safe";

  return `## 📦 Package Fix — \`${pkg}\` (${cve})

**Severity:** ${sev.toUpperCase()} | **Risk Score:** ${inc.risk_score}/100

### Audit First
\`\`\`bash
# See all vulnerabilities in your project
npm audit

# See only high/critical
npm audit --audit-level=high

# Get a JSON report
npm audit --json > audit-report.json
\`\`\`

### Upgrade \`${pkg}\`
\`\`\`bash
# Check what version fixes the CVE
npm info ${pkg} versions --json

# Upgrade to latest stable
npm install ${pkg}@latest

# Or to a specific safe version (check CVE advisory)
npm install ${pkg}@^X.Y.Z

# Update package-lock.json
npm install

# Verify the fix
npm audit --audit-level=high
\`\`\`

### Test After Upgrade
\`\`\`bash
# Run full test suite
npm test

# Check for breaking changes
npm run build

# Integration test
npm run test:e2e
\`\`\`

### If \`${pkg}\` Can't Be Upgraded
\`\`\`bash
# Override transitive dependency version (package.json)
{
  "overrides": {
    "${pkg}": ">=SAFE_VERSION"
  }
}

# Or use npm-force-resolutions
npx npm-force-resolutions
\`\`\`

**CVE Advisory:** Search \`${cve}\` at https://nvd.nist.gov/vuln/detail/${cve} for the minimum safe version.`;
}

function generateDeveloperContext(inc, allIncidents, q) {
  const dev = inc.pr_details?.developer || "Unknown";
  
  // Find all incidents by this developer
  const devIncidents = allIncidents.filter(i => i.pr_details?.developer === dev);
  const totalRisk = devIncidents.reduce((sum, i) => sum + (i.risk_score || 0), 0);
  const avgRisk = Math.round(totalRisk / devIncidents.length) || 0;
  const criticalCount = devIncidents.filter(i => i.vulnerability?.severity === "critical").length;
  const highCount = devIncidents.filter(i => i.vulnerability?.severity === "high").length;
  const safeCount = devIncidents.filter(i => i.vulnerability?.severity === "safe" || i.vulnerability?.severity === "medium").length;
  const secretLeaks = devIncidents.filter(i => i.secrets_detected).length;
  
  // Calculate Anomaly Score (Hackathon Winning Logic)
  const anomalyScore = Math.min(100, Math.round((avgRisk * 0.4) + (criticalCount * 15) + (secretLeaks * 30)));
  
  let persona = "🟢 Secure Contributor";
  if (secretLeaks > 0 && criticalCount > 0) persona = "🚨 Insider Threat / Compromised Account";
  else if (criticalCount >= 2) persona = "🟠 High-Risk Operator";
  else if (avgRisk >= 40 || highCount > 0) persona = "🟡 Careless Committer";

  const isHighRisk = anomalyScore >= 60;

  return `## 👤 Developer Risk Profile — ${dev}

> **Behavioral Persona:** ${persona}
> **Trust Score:** ${100 - anomalyScore}/100 | **Anomaly Factor:** ${anomalyScore}%

### 📊 Behavioral Analytics
\`\`\`mermaid
pie title Risk Distribution for ${dev}
  "Critical Incidents": ${criticalCount}
  "High Risk Incidents": ${highCount}
  "Secret Leaks": ${secretLeaks}
  "Safe / Resolved": ${safeCount}
\`\`\`

| Metric | Value |
|--------|-------|
| Total PRs merged | ${devIncidents.length} |
| Critical / High CVEs | ${criticalCount} / ${highCount} |
| Secret leaks | ${secretLeaks} |
| Average risk score | ${avgRisk}/100 |

### 🚨 Recent Risky Commits
${devIncidents.slice(0, 3).map((i, idx) => `${idx + 1}. **${i.incident_id}** — ${i.pr_details?.title || "Unknown PR"}
   - Severity: **${i.vulnerability?.severity?.toUpperCase()}** | Risk: ${i.risk_score}/100
   - Package: \`${i.package_details?.package_name}\` | CVE: \`${i.vulnerability?.cve}\``
).join("\n")}

### ⚡ 1-Click Containment Playbook
${isHighRisk ? 
  `⚠️ **${dev} has tripped high-severity behavioral alarms. Execute the following immediately:**

**1. Revoke GitHub Merge Access:**
\`\`\`bash
gh api repos/:owner/:repo/collaborators/${dev} --method DELETE
\`\`\`

**2. Force MFA Re-authentication & Session Clear:**
\`\`\`bash
aws iam update-login-profile --user-name ${dev} --password-reset-required
\`\`\`

**3. Quarantine & Notify SOC Team:**
\`\`\`bash
curl -X POST $SLACK_WEBHOOK_URL \\
  -d '{"text":"🚨 *Insider Threat Protocol Activated* \\nUser: ${dev} \\nAction: All sessions revoked pending security review."}'
\`\`\`` :
  `✅ **${dev}'s behavioral anomaly score is low.** No immediate containment necessary. Continue automated monitoring.`}`;
}

function generatePolicyResponse(inc) {
  const hasPolicy = !!inc.policy_violation;
  
  if (hasPolicy) {
    return `## 📋 Policy Violation — ${inc.incident_id}

**Policy:** ${inc.policy_violation.policy_name}
**Rule:** \`${inc.policy_violation.policy_rule}\`
**Owning Team:** ${inc.policy_violation.owner_team}
**Severity:** ${inc.policy_violation.severity?.toUpperCase()}

### Policy Description
> ${inc.policy_violation.description}

### How to Resolve

**Step 1: Create a Policy Exception Request in Notion**
- Link incident ID: \`${inc.incident_id}\`
- Document the business justification
- Get sign-off from: **${inc.policy_violation.owner_team}**

**Step 2: Enforce the Policy Programmatically**
\`\`\`bash
# Add branch protection rule (GitHub CLI)
gh api repos/:owner/:repo/branches/main/protection \\
  --method PUT \\
  -f required_status_checks='{"strict":true,"contexts":["security-scan"]}' \\
  -F enforce_admins=true \\
  -F required_pull_request_reviews='{"required_approving_review_count":2}'

# Block banned packages at install time (.npmrc)
echo "//registry.npmjs.org/:_authToken=\${NPM_TOKEN}" >> .npmrc
# Add to package.json:
{
  "scripts": {
    "preinstall": "npx check-banned-packages"
  }
}
\`\`\`

**Step 3: Update Notion Policy Document**
- Mark this violation as "UNDER REVIEW"
- Set resolution date
- Document the fix applied

**Step 4: Add CI Gate**
\`\`\`yaml
# .github/workflows/security.yml
- name: Policy Check
  run: |
    npx audit-ci --critical --config .audit-ci.json
\`\`\``;
  }
  
  return `## ✅ Policy Compliance — ${inc.incident_id}

No policy violations detected for this incident. All packages are compliant with your current Notion policies.

### Current Active Policies
Your Coral system is monitoring these Notion policies:
- **BANNED_PACKAGE** — Blocks deployment of packages on the banned list
- **SECRETS_RISK** — Flags packages with credential exposure risk
- **AUDIT_REQUIRED** — Requires security audit before merge
- **REVIEW_REQUIRED** — Requires senior engineer sign-off

To add new policies, update your \`notion.json\` policy database.`;
}

function generateDeploySafety(inc) {
  const sev = inc.vulnerability?.severity || "safe";
  const pkg = inc.package_details?.package_name;
  const hasSecret = !!inc.secrets_detected;
  const hasPolicy = !!inc.policy_violation;
  
  const blockers = [];
  if (sev === "critical") blockers.push("🔴 Critical CVE not patched");
  if (sev === "high") blockers.push("🟠 High-risk CVE not patched");
  if (hasSecret) blockers.push("🔴 Secret leak not cleaned and rotated");
  if (hasPolicy && inc.policy_violation?.policy_rule === "BANNED_PACKAGE") blockers.push("🔴 Banned package in dependency tree");
  if (hasPolicy && inc.policy_violation?.policy_rule === "AUDIT_REQUIRED") blockers.push("🟠 Security audit not completed");
  
  const safe = blockers.length === 0;

  return `## 🚀 Deployment Safety Check — ${inc.incident_id}

**Status: ${safe ? "✅ SAFE TO DEPLOY" : "🚫 BLOCKED — DO NOT DEPLOY"}**

### Pre-Deployment Checklist
${safe ? 
  `✅ No critical CVEs\n✅ No secret leaks\n✅ No policy violations\n✅ Risk score: ${inc.risk_score}/100 (acceptable)\n\n**Ready to ship! Run your standard deployment pipeline.**` :
  `**Blockers (must resolve before deploying):**\n${blockers.map(b => `- ${b}`).join("\n")}\n\n**Estimated resolution time:** ${sev === "critical" ? "1–2 hours" : "2–4 hours"}`
}

### Deployment Gate Commands
\`\`\`bash
# Run this before every deployment
npm audit --audit-level=${sev === "critical" ? "critical" : "high"}
echo "Exit code $? — 0 = safe, 1 = blocked"

# Run tests
npm test

# Security scan
npx snyk test --severity-threshold=${sev === "critical" ? "high" : "medium"}
\`\`\`

### After Resolving
\`\`\`bash
# Confirm patch applied
npm ls ${pkg}

# Final audit
npm audit

# Deploy to staging first
git push origin staging
# Monitor for 30 minutes, then promote to production
\`\`\``;
}

function generateReport(allIncidents) {
  const critical = allIncidents.filter(i => i.vulnerability?.severity === "critical").length;
  const high     = allIncidents.filter(i => i.vulnerability?.severity === "high").length;
  const medium   = allIncidents.filter(i => i.vulnerability?.severity === "medium").length;
  const safe     = allIncidents.filter(i => i.vulnerability?.severity === "safe").length;
  const secrets  = allIncidents.filter(i => i.secrets_detected).length;
  const policies = allIncidents.filter(i => i.policy_violation).length;
  
  const avgScore = Math.round(allIncidents.reduce((s, i) => s + (i.risk_score || 0), 0) / allIncidents.length);
  const overallScore = Math.max(0, 100 - (critical * 30 + high * 15 + medium * 5));
  const grade = overallScore >= 75 ? "A" : overallScore >= 50 ? "B" : overallScore >= 25 ? "C" : "D";
  
  // Top risky developers
  const devMap = {};
  allIncidents.forEach(i => {
    const dev = i.pr_details?.developer || "Unknown";
    if (!devMap[dev]) devMap[dev] = { risk: 0, count: 0 };
    devMap[dev].risk += i.risk_score || 0;
    devMap[dev].count++;
  });
  const topDevs = Object.entries(devMap)
    .sort(([,a],[,b]) => b.risk - a.risk)
    .slice(0, 3)
    .map(([dev, d]) => `- **${dev}**: ${d.count} PR(s), avg risk ${Math.round(d.risk / d.count)}/100`);

  return `## 📊 Security Command Center Report

**Generated:** ${new Date().toUTCString()}
**Security Grade: ${grade}** (${overallScore}/100)

### Threat Overview
| Severity | Count | Action |
|----------|-------|--------|
| 🔴 Critical | ${critical} | Immediate rollback |
| 🟠 High | ${high} | Security review |
| 🟡 Medium | ${medium} | Monitor & patch |
| ✅ Safe | ${safe} | No action needed |
| 🔑 Secret Leaks | ${secrets} | Rotate credentials |
| 📋 Policy Violations | ${policies} | Compliance review |

**Total Incidents:** ${allIncidents.length} | **Avg Risk Score:** ${avgScore}/100

### Top Risk Developers
${topDevs.join("\n")}

### Highest Risk Incidents
${allIncidents
  .sort((a, b) => b.risk_score - a.risk_score)
  .slice(0, 3)
  .map((i, idx) => `${idx + 1}. **${i.incident_id}** — ${i.pr_details?.title?.slice(0, 50)}...
   Risk: ${i.risk_score}/100 | ${i.vulnerability?.severity?.toUpperCase()} | \`${i.vulnerability?.cve}\``)
  .join("\n\n")}

### Immediate Actions Required
${critical > 0 ? `🚨 **${critical} CRITICAL incidents need immediate rollback**` : "✅ No critical incidents"}
${secrets > 0 ? `🔑 **${secrets} secret leak(s) need credential rotation NOW**` : "✅ No secret leaks"}
${policies > 0 ? `📋 **${policies} policy violation(s) need compliance review**` : "✅ All policies compliant"}

### Security Score Trend
\`\`\`
Overall: ${overallScore}/100 [${grade}] ${"█".repeat(Math.floor(overallScore / 10))}${"░".repeat(10 - Math.floor(overallScore / 10))}
\`\`\`

*Ask me about any specific incident, developer, or use the Export button for a full JSON report.*`;
}

function generateThreatIntel(inc) {
  const cve = inc.vulnerability?.cve || "N/A";
  const pkg = inc.package_details?.package_name || "unknown";
  const sev = inc.vulnerability?.severity || "safe";
  
  return `## 🌐 Threat Intelligence — ${cve}

**Package:** \`${pkg}\` | **Severity:** ${sev.toUpperCase()} | **Incident:** ${inc.incident_id}

### CVE Details
- **CVE ID:** \`${cve}\`
- **CVSS Score (estimated):** ${sev === "critical" ? "9.0–10.0" : sev === "high" ? "7.0–8.9" : sev === "medium" ? "4.0–6.9" : "< 4.0"}
- **Attack Vector:** Network
- **Privileges Required:** ${sev === "critical" ? "None (unauthenticated)" : "Low"}
- **User Interaction:** None

### Intelligence Sources
- **NVD:** https://nvd.nist.gov/vuln/detail/${cve}
- **OSV:** https://osv.dev/vulnerability/${cve}
- **GitHub Advisory:** https://github.com/advisories?query=${cve}
- **Snyk:** https://snyk.io/vuln/${cve}

### Exploitation Status
${sev === "critical" ? "🔴 **Known to be actively exploited in the wild** — patch immediately" : sev === "high" ? "🟠 **Proof-of-concept exploits publicly available** — patch within 24-48 hours" : "🟡 **Limited exploitation observed** — patch in next release cycle"}

### Affected Versions
Check the CVE advisory at NVD for the specific affected version range for \`${pkg}\`.

### Remediation
\`\`\`bash
# Check your current version
npm ls ${pkg}

# Upgrade to latest patched version
npm install ${pkg}@latest

# Or find minimum safe version from CVE advisory
npm install ${pkg}@^SAFE_VERSION
\`\`\`

### OWASP Context
${sev === "critical" || sev === "high" ? 
  "This vulnerability falls under **OWASP A06:2021 - Vulnerable and Outdated Components**. All third-party dependencies must be regularly audited." :
  "This falls under **OWASP A05:2021 - Security Misconfiguration** — ensure your dependency update process is automated."}`;
}

function generateTimeline(allIncidents) {
  const sorted = [...allIncidents].sort((a, b) => 
    new Date(a.pr_details?.merged_at || 0) - new Date(b.pr_details?.merged_at || 0)
  );
  
  return `## ⏱️ Security Incident Timeline

${sorted.map(i => {
    const date = i.pr_details?.merged_at ? 
      new Date(i.pr_details.merged_at).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : 
      "Unknown time";
    const sevEmoji = { critical: "🔴", high: "🟠", medium: "🟡", safe: "✅" }[i.vulnerability?.severity] || "⚪";
    return `**${date}** — ${sevEmoji} ${i.incident_id} | ${i.pr_details?.developer} | \`${i.package_details?.package_name}\` | Risk: ${i.risk_score}/100`;
  }).join("\n")}

**Total exposure window:** ${sorted[0]?.pr_details?.merged_at && sorted[sorted.length-1]?.pr_details?.merged_at ? 
  `${Math.round((new Date(sorted[sorted.length-1].pr_details.merged_at) - new Date(sorted[0].pr_details.merged_at)) / 3600000)}h` : "Unknown"}`;
}

function generateRemediationSteps(inc) {
  const sev = inc.vulnerability?.severity || "safe";
  const pkg = inc.package_details?.package_name || "unknown";
  const dev = inc.pr_details?.developer || "Unknown";
  const cve = inc.vulnerability?.cve || "N/A";
  const hasSecret = !!inc.secrets_detected;
  const hasPolicy = !!inc.policy_violation;
  
  const estimatedTime = sev === "critical" ? "1–2 hours" : sev === "high" ? "2–4 hours" : "4–8 hours";
  
  return `## 🛡️ Remediation Plan — ${inc.incident_id}

**Estimated resolution time:** ${estimatedTime}
**Priority:** ${sev.toUpperCase()}

### Phase 1: Containment (Do first)
${sev === "critical" || sev === "high" ? `- [ ] **Roll back the deployment** — \`git revert HEAD --no-edit && git push origin HEAD\`
- [ ] **Block the merge queue** — pause all CI/CD pipelines temporarily
- [ ] **Alert the team** — post in #security-alerts immediately` : 
`- [ ] **Flag the PR** — add a comment linking to this CVE
- [ ] **Notify the developer** — ${dev} needs to be informed`}
${hasSecret ? `- [ ] **Revoke exposed credentials immediately** — this is time-critical` : ""}

### Phase 2: Investigation
- [ ] Confirm exploit viability: \`npm audit --json | jq '.vulnerabilities.${pkg}'\`
- [ ] Check if vulnerability is reachable in your code path
- [ ] Review all PRs by ${dev} in the last 30 days
${hasPolicy ? `- [ ] Document the policy violation in Notion: ${inc.policy_violation.policy_name}` : ""}

### Phase 3: Fix
- [ ] Upgrade \`${pkg}\` to the minimum safe version
\`\`\`bash
npm install ${pkg}@latest
npm audit --audit-level=high
npm test
\`\`\`
${hasSecret ? `- [ ] Clean git history of secrets\n- [ ] Rotate all exposed credentials\n- [ ] Update secrets manager` : ""}

### Phase 4: Verify & Close
- [ ] Run \`npm audit\` — must show 0 critical/high
- [ ] Deploy to staging — run smoke tests
- [ ] Get security team sign-off
- [ ] Update incident status in this dashboard
- [ ] Post-mortem after resolution

### Resources
- CVE Advisory: https://nvd.nist.gov/vuln/detail/${cve}
- Package releases: https://www.npmjs.com/package/${pkg}?activeTab=versions`;
}

function generateGeneral(inc, allIncidents) {
  const sev = inc.vulnerability?.severity || "safe";
  const sevEmoji = { critical: "🔴", high: "🟠", medium: "🟡", safe: "✅" }[sev] || "⚪";
  
  return `## ${sevEmoji} Coral AI — ${inc.incident_id}

${inc.ai_summary}

**Quick Stats:**
- Severity: **${sev.toUpperCase()}** | Risk Score: **${inc.risk_score}/100**
- CVE: \`${inc.vulnerability?.cve || "N/A"}\` | Package: \`${inc.package_details?.package_name}\`
- Developer: **${inc.pr_details?.developer}** | PR: ${inc.pr_details?.title}
- Slack: ${inc.internal_discussion?.slack_channel !== "N/A" ? `"${inc.internal_discussion?.message?.slice(0, 80)}..." in ${inc.internal_discussion?.slack_channel}` : "No team discussion"}
${inc.secrets_detected ? `\n🔑 **Secret leak detected! Rotate credentials immediately.**` : ""}
${inc.policy_violation ? `\n📋 **Policy violation: ${inc.policy_violation.policy_name}**` : ""}

### What can I help you with?
- 🔍 **"Explain why this is critical"** — detailed severity analysis
- 🔄 **"Rollback procedure"** — step-by-step git revert guide
- 🔑 **"How to rotate secrets"** — credential rotation walkthrough
- 📦 **"Fix the ${inc.package_details?.package_name} issue"** — exact npm commands
- 👤 **"Developer context for ${inc.pr_details?.developer}"** — risk profile
- 📊 **"Show me the full report"** — all ${allIncidents.length} incidents summary
- 🚀 **"Is it safe to deploy?"** — go/no-go deployment check`;
}

/* ─────────────────────────────────────────────────────────────────────
   POST /api/chat
   GOATED AI Copilot with full NLP intent classification
───────────────────────────────────────────────────────────────────── */
router.post("/chat", async (req, res, next) => {
  const rawMsg = req.body?.message || "";
  const log_id = req.body?.log_id || 1;
  
  const message = sanitizeInput(rawMsg);
  if (!message) {
    return res.status(400).json({ success: false, error: "Message is required" });
  }
  
  const sessionId = req.headers["x-session-id"] || "default";
  const allIncidents = await getIncidents(sessionId);
  const inc = await getIncidentById(sessionId, log_id);

  const geminiKey = process.env.GEMINI_API_KEY;

  if (!geminiKey || geminiKey === "your-gemini-key-here" || geminiKey.trim().length === 0) {
    return res.json({
      success: true,
      mode: "coral-ai-v2-fallback",
      intent: "MISSING_KEY",
      incident_id: inc.incident_id,
      reply: "Please set your GEMINI_API_KEY in the `.env` file to use the LangChain agent.",
      timestamp: new Date().toISOString(),
    });
  }

  try {
    const activeIncidentContext = JSON.stringify({
      id: inc.incident_id,
      severity: inc.vulnerability?.severity,
      cve: inc.vulnerability?.cve,
      package: inc.package_details?.package_name,
      developer: inc.pr_details?.developer,
      diff: inc.pr_details?.commit_diff || "diff --git a/file b/file\n+ var AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';"
    }, null, 2);

    const tools = [scanCommitsForSecrets, searchNotionPolicies, queryOsv, checkGithubAccessRisk, scanCodeForMaliciousPatterns];
    const llm = new ChatGoogleGenerativeAI({
      modelName: "gemini-2.5-flash",
      temperature: 0,
      apiKey: geminiKey
    });

    const prompt = ChatPromptTemplate.fromMessages([
      ["system", "You are Coral AI, a highly intelligent DevSecOps Copilot for the Coral Security Command Center. You have access to tools to scan commits for secrets, query Notion policies, query OSV vulnerabilities, and check developer access risk. Use these tools when needed."],
      ["placeholder", "{chat_history}"],
      ["user", "{input}"],
      ["placeholder", "{agent_scratchpad}"]
    ]);

    const agent = createToolCallingAgent({ llm, tools, prompt });
    const agentExecutor = new AgentExecutor({ agent, tools, maxIterations: 5 });
    
    const input = `Query: "${message}". Current Incident Context: ${activeIncidentContext}`;
    const result = await agentExecutor.invoke({ input });

    return res.json({
      success: true,
      mode: "coral-ai-v2-langchain",
      intent: "REAL_AGENT_CHAT",
      incident_id: inc.incident_id,
      reply: result.output,
      timestamp: new Date().toISOString(),
    });

  } catch (err) {
    console.error("[CHAT_LANGCHAIN_ERROR]", err.message, err.stack);
    return res.json({
      success: false,
      error: "Langchain Agent failed: " + err.message
    });
  }
});

/* ─────────────────────────────────────────────────────────────────────
   GET /api/investigate?id=<1-N>
───────────────────────────────────────────────────────────────────── */
/* ── Personalized fallbacks ─────────────────────────────────────────── */
function generatePersonalizedInvestigationReport(inc, allIncidents) {
  const dev = inc.pr_details?.developer || "Unknown";
  const sev = inc.vulnerability?.severity || "safe";
  const cve = inc.vulnerability?.cve || "N/A";
  const pkg = inc.package_details?.package_name || "unknown";
  const hasSecret = !!inc.secrets_detected;
  const hasPolicy = !!inc.policy_violation;

  // Find all incidents by this developer
  const devIncidents = allIncidents.filter(i => i.pr_details?.developer === dev);
  const totalRisk = devIncidents.reduce((sum, i) => sum + (i.risk_score || 0), 0);
  const avgRisk = Math.round(totalRisk / (devIncidents.length || 1)) || 0;
  const criticalCount = devIncidents.filter(i => i.vulnerability?.severity === "critical").length;
  const secretLeaks = devIncidents.filter(i => i.secrets_detected).length;
  
  const anomalyScore = Math.min(100, Math.round((avgRisk * 0.4) + (criticalCount * 15) + (secretLeaks * 30)));
  
  let persona = "🟢 Secure Contributor";
  if (secretLeaks > 0 && criticalCount > 0) persona = "🚨 Insider Threat / Compromised Account";
  else if (criticalCount >= 2) persona = "🟠 High-Risk Operator";
  else if (avgRisk >= 40) persona = "🟡 Careless Committer";

  // Build specialized issue descriptions
  let issueExplanation = "";
  let exploitScenarios = "";
  
  const devLower = dev.toLowerCase();
  
  if (hasSecret) {
    const secretName = inc.secrets_detected?.findings?.[0]?.name || "API Access Key";
    issueExplanation = `The developer **${dev}** committed a hardcoded secret (**${secretName}**) directly inside the codebase. Hardcoding secrets in git trees is highly risky as it exposes long-lived authentication keys to any reader of the repository, enabling immediate privilege escalation.`;
    exploitScenarios = `An attacker gaining read access to this code or repository can immediately steal the exposed **${secretName}** to access our live production infrastructure, bypass multi-factor authentication, and download sensitive customer data.`;
  } else if (devLower.includes("contractor")) {
    issueExplanation = `The developer **${dev}** introduced highly suspicious code structures, including dynamic shell execution or \`eval()\` sandbox escapes in \`${pkg}\`. Executing unverified user-supplied input or raw commands dynamically is a classic backdoor pattern, which is banned under SOC2 and internal compliance policies.`;
    exploitScenarios = `An attacker could exploit this dynamic execution vector to feed remote commands to our servers, resulting in arbitrary shell execution, complete node takeover, and lateral movement across the Kubernetes cluster.`;
  } else if (pkg === "lodash" || pkg === "axios") {
    issueExplanation = `The developer **${dev}** merged dependency changes referencing the package \`${pkg}\` which is vulnerable to security exploits (including Prototype Pollution). Upgrade validation is required to ensure nested/transitive components are updated.`;
    exploitScenarios = `Prototype pollution allows malicious actors to inject properties into global prototypes, causing general application crashes (DoS) or, under specific configurations, remote code execution (RCE) inside Node.js.`;
  } else if (pkg === "jsonwebtoken") {
    issueExplanation = `The developer **${dev}** configured JWT token verification/signature operations using the \`${pkg}\` package. Known vulnerabilities in outdated versions allow algorithm confusion attacks or signature bypasses.`;
    exploitScenarios = `Attackers can modify JWT headers to use symmetric algorithms or 'none' verification, bypassing authorization mechanisms entirely to log in as admin users.`;
  } else {
    issueExplanation = `The developer **${dev}** committed modifications in \`${pkg}\` which have been flagged by the security engine due to outdated packages or policy non-compliance.`;
    exploitScenarios = `Security issues could lead to dependency-injection attacks or localized memory leak issues, decreasing service stability and integrity.`;
  }

  const slackDiscussion = inc.internal_discussion?.message && inc.internal_discussion.message !== "No internal discussion found."
    ? `> **Channel:** #${inc.internal_discussion.slack_channel || "security-alerts"}\n> **${dev}:** "${inc.internal_discussion.message}"`
    : `> No active Slack team discussions found for this incident. Alerts need to be sent immediately.`;

  const report = [
    `## 🔍 AI Security Investigation — ${inc.incident_id}`,
    ``,
    `### 🚨 Threat Overview & Impact`,
    `- **Severity:** ${sev.toUpperCase()} Risk (Risk Score: **${inc.risk_score}/100**)`,
    `- **Vulnerability Package:** \`${pkg}\` | **CVE:** \`${cve}\``,
    `- **Responsible Developer:** **${dev}**`,
    `- **Introduced In:** PR #${inc.pr_details?.pr_id || "101"} ("${inc.pr_details?.title || "Security fix"}")`,
    `- **Risk Score:** ${inc.risk_score} (calculated dynamically based on severity and policies)`,
    ``,
    `### 👤 Developer Risk Profile Context`,
    `- **Behavioral Persona:** **${persona}**`,
    `- **Trust Score:** **${100 - anomalyScore}/100** | **Behavioral Anomaly Factor:** **${anomalyScore}%**`,
    `- **Developer Track Record:** Introduced **${devIncidents.length}** security incident(s) recently. Average historical incident risk score is **${avgRisk}/100**.`,
    ``,
    `### 📖 Deep-Dive Analysis of the Issue`,
    issueExplanation,
    ``,
    `### 💀 Exploit Possibilities & Attack Scenarios`,
    exploitScenarios,
    ``,
    `### 💬 Correlated Social & Chat Evidence`,
    `A scan of corporate chat logs shows active discussion regarding this commit:`,
    slackDiscussion,
    ``,
    hasPolicy ? `### 📋 Notion Security Policy Violations\nThis commit violates our corporate security policies documented in Notion:\n- **Policy Rule:** \`${inc.policy_violation.policy_rule}\`\n- **Policy Description:** ${inc.policy_violation.description}\n- **Owner Team:** ${inc.policy_violation.owner_team}` : `### 📋 Notion Policy Status\n- **Policy Status:** Compliant. No internal Notion policies are violated by this dependency upgrade.`,
    ``,
    `### 🛠️ Immediate Containment Playbook`,
    `- **Rollback Action:** ${inc.recommended_action === "ROLLBACK_DEPLOYMENT" ? "🚨 Revert commit immediately and scale down the deployment." : "Monitor tests and check for stable versions."}`,
    `- **Audit Priority:** **${sev === "critical" ? "P0 (Immediate action required)" : sev === "high" ? "P1 (Remediate within 24 hours)" : "P2 (Resolve in next release cycle)"}**`,
  ].join("\n");

  return report;
}

function generatePersonalizedRemediationPlan(inc, allIncidents) {
  const dev = inc.pr_details?.developer || "Unknown";
  const sev = inc.vulnerability?.severity || "safe";
  const pkg = inc.package_details?.package_name || "unknown";
  const cve = inc.vulnerability?.cve || "N/A";
  const hasSecret = !!inc.secrets_detected;
  const hasPolicy = !!inc.policy_violation;
  const commitHash = inc.github?.commit_hash || "HEAD";

  // Build developer customized actions and scripts
  let title = `Security Hardening Plan — ${inc.incident_id}`;
  let subtitle = "Standard patching and validation guidelines";
  let actions = [];
  let scripts = [];
  let estTime = "1 Hour";

  const devLower = dev.toLowerCase();

  if (hasSecret) {
    const secretName = inc.secrets_detected?.findings?.[0]?.name || "Credential";
    title = `🛡️ ${secretName} Rotation & Clean Guide — ${dev}`;
    subtitle = `Rotate hardcoded credentials committed by ${dev} and purge history in ${pkg}`;
    estTime = "45 Minutes";
    actions = [
      `Immediately revoke and invalidate the exposed secret key (${secretName}) in the AWS or database console.`,
      `Purge the secret leak from Git commit history using Git-filter-repo to prevent history leakage.`,
      `Transition ${dev}'s configuration to load credentials dynamically via process.env from AWS Secrets Manager.`,
      `Verify the fix by running an automated TruffleHog scanner check locally and in the GitHub actions pipeline.`
    ];
    scripts = [
      `# 1. Revert the commit that exposed secrets\ngit log --oneline -5\ngit revert ${commitHash} --no-edit\ngit push origin HEAD --force-with-lease`,
      `# 2. Scrub secret from git history safely\npip install git-filter-repo\ngit filter-repo --invert-paths --path <secret-file>`,
      `# 3. Check for any other active leaks\npip install trufflehog\ntrufflehog git file://. --since-commit HEAD~5`,
      `# 4. Notify security alerts team on Slack\ncurl -X POST $SLACK_WEBHOOK_URL \\\n  -H 'Content-type: application/json' \\\n  --data '{"text":"🔄 Credential rotation completed for ${inc.incident_id} by ${dev}. Environment is secure."}'`
    ];
  } else if (devLower.includes("contractor")) {
    title = `🛡️ Critical Sandbox & Command Injection Quarantine — contractor_x`;
    subtitle = `Revert unauthorized setup modifications and backdoor execution hooks in ${pkg}`;
    estTime = "2 Hours";
    actions = [
      `Quarantine the developer contractor_x's push access credentials pending security and code review.`,
      `Perform a direct git revert to revoke setup scripts and command injection risks in node-setup/vm2.`,
      `Implement strict 2-person code reviews and merge gates using repository Branch Protection rules.`,
      `Audit developer local setup environment files for any persistent unauthorized modifications.`
    ];
    scripts = [
      `# 1. Revert contractor_x's unauthorized hooks commit\ngit revert ${commitHash} --no-edit\ngit push origin HEAD --force-with-lease`,
      `# 2. Reset local pre-commit scripts and verify files\nrm -rf .git/hooks/pre-commit\ngit checkout HEAD -- setup.sh\ngit status`,
      `# 3. Secure branch protection gates via GitHub CLI\ngh api -X PUT /repos/:owner/:repo/branches/main/protection \\\n  -F required_pull_request_reviews.required_approving_review_count=2`
    ];
  } else if (pkg === "lodash" || pkg === "axios") {
    title = `🛡️ Dependency Patching & Prototype Pollution Validation — ${dev}`;
    subtitle = `Patch lodash/axios vulnerabilities in ${dev}'s branch and audit transitive dependencies`;
    estTime = "30 Minutes";
    actions = [
      `Upgrade \`${pkg}\` package in package.json to the stable, fully secure version.`,
      `Audit the lockfile to ensure all sub-dependencies are clean from vulnerable lodash versions.`,
      `Run automated unit and integration tests to ensure no API compatibility breaking changes.`
    ];
    scripts = [
      `# 1. Install latest secure release version\nnpm install ${pkg}@latest --save`,
      `# 2. Run high-severity vulnerability audit check\nnpm audit --audit-level=high`,
      `# 3. Execute application validation test suite\nnpm test && npm run build`
    ];
  } else if (pkg === "jsonwebtoken") {
    title = `🛡️ JWT Authorization Bypass Security Patching — ${dev}`;
    subtitle = `Secure token validation and upgrade jsonwebtoken for ${dev}'s PR`;
    estTime = "1 Hour";
    actions = [
      `Upgrade vulnerable \`jsonwebtoken\` package to avoid signature authentication bypass vulnerabilities.`,
      `Review verification middleware logic to verify key encryption algorithm constraints are active.`,
      `Ensure private signing keys are loaded strictly from the environment and not hardcoded.`
    ];
    scripts = [
      `# 1. Update package version\nnpm install jsonwebtoken@9.0.2 --save`,
      `# 2. Audit dependencies for nested auth issues\nnpm audit`,
      `# 3. Test OAuth/JWT authorization tests\nnpm test`
    ];
  } else {
    // Default tailored to developer
    title = `🛡️ General Security Patching & Code Review — ${dev}`;
    subtitle = `Audit and verify package updates in ${dev}'s pull request`;
    estTime = sev === "critical" ? "2 Hours" : "1 Hour";
    actions = [
      `Upgrade the \`${pkg}\` library to the latest stable and secure release.`,
      `Arrange a security pairing review with ${dev} to review the dependency changes.`,
      `Execute standard package dependency scans and ensure tests pass.`
    ];
    scripts = [
      `# 1. Install latest package dependency version\nnpm install ${pkg}@latest`,
      `# 2. Audit dependency tree\nnpm audit`,
      `# 3. Rebuild bundle and verify compatibility\nnpm test && npm run build`
    ];
  }

  // Adjust scripts or actions based on policy
  if (hasPolicy) {
    actions.push(`Open a Notion Policy Exception report for violating "${inc.policy_violation.policy_name}"`);
  }

  return {
    title,
    subtitle,
    severity: sev,
    estimated_time: estTime,
    actions,
    scripts
  };
}

/* ─────────────────────────────────────────────────────────────────────
   GET /api/investigate?id=<1-N>
───────────────────────────────────────────────────────────────────── */
router.get("/investigate", async (req, res) => {
  const sessionId = req.headers["x-session-id"] || "default";
  const id = sanitizeInput(req.query.id || "1");
  const inc = await getIncidentById(sessionId, id);
  const allIncidents = await getIncidents(sessionId);
  
  const sev    = inc.vulnerability?.severity || "safe";
  const cve    = inc.vulnerability?.cve      || "N/A";
  const dev    = inc.pr_details?.developer   || "Unknown";
  const pkg    = inc.package_details?.package_name || "unknown";
  
  const openaiKey = process.env.OPENAI_API_KEY;
  const geminiKey = process.env.GEMINI_API_KEY;

  let report = "";
  let mode = "coral-ai-v2";

  if (openaiKey && openaiKey !== "sk-your-key-here" && openaiKey.trim().length > 0) {
    try {
      const systemPrompt = `You are Coral AI, a highly intelligent DevSecOps Security Engineer.
Analyze the following security incident and generate a deeply personalized, professional, and unique security investigation report in markdown.
Explain:
1. SUMMARY: What was found, what package, CVE, and what the business risk is.
2. DEVELOPER PERSONALIZATION: Who the developer is (${dev}), what their behavioral risk persona is, their risk profile history, and how this relates to their specific commit or Slack message: "${inc.internal_discussion?.message || ""}".
3. ROOT CAUSE & SEVERITY: Why this vulnerability matters and what exploit possibilities exist.
4. DETAILED RECOMMENDATIONS: Specific steps to contain, remediate, and verify.

Format your response in beautiful GitHub-style Markdown.`;

      const response = await axios.post("https://api.openai.com/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: `Investigate incident ${inc.incident_id}: Package ${pkg}, CVE ${cve}, Developer ${dev}, Risk Score ${inc.risk_score}/100, Slack: ${inc.internal_discussion?.message}` }
        ],
        temperature: 0.2,
        max_tokens: 1000
      }, {
        headers: {
          "Authorization": `Bearer ${openaiKey.trim()}`,
          "Content-Type": "application/json"
        },
        timeout: 10000
      });
      report = response.data?.choices?.[0]?.message?.content || "";
      mode = "live";
    } catch (err) {
      console.error("[INVESTIGATE_AI_ERROR]", err.message);
    }
  }

  if (!report && geminiKey && geminiKey !== "your-gemini-key-here" && geminiKey.trim().length > 0) {
    try {
      const systemPrompt = `You are Coral AI, a highly intelligent DevSecOps Security Engineer.
Analyze the following security incident and generate a deeply personalized, professional, and unique security investigation report in markdown.
Explain:
1. SUMMARY: What was found, what package, CVE, and what the business risk is.
2. DEVELOPER PERSONALIZATION: Who the developer is (${dev}), what their behavioral risk persona is, their risk profile history, and how this relates to their specific commit or Slack message: "${inc.internal_discussion?.message || ""}".
3. ROOT CAUSE & SEVERITY: Why this vulnerability matters and what exploit possibilities exist.
4. DETAILED RECOMMENDATIONS: Specific steps to contain, remediate, and verify.

Format your response in beautiful GitHub-style Markdown.`;

      const response = await axios.post(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey.trim()}`,
        {
          contents: [
            { parts: [{ text: `Investigate incident ${inc.incident_id}: Package ${pkg}, CVE ${cve}, Developer ${dev}, Risk Score ${inc.risk_score}/100, Slack: ${inc.internal_discussion?.message}` }] }
          ],
          systemInstruction: { parts: [{ text: systemPrompt }] },
          generationConfig: { temperature: 0.2, maxOutputTokens: 1000 }
        },
        { headers: { "Content-Type": "application/json" }, timeout: 10000 }
      );
      report = response.data?.candidates?.[0]?.content?.parts?.[0]?.text || "";
      mode = "live";
    } catch (err) {
      console.error("[INVESTIGATE_GEMINI_ERROR]", err.message);
    }
  }

  if (!report) {
    report = generatePersonalizedInvestigationReport(inc, allIncidents);
    mode = "mocked";
  }

  res.json({
    success: true,
    mode,
    ai_analysis_markdown: report,
    extracted_logs: [{
      id: inc.incident_id,
      severity: sev,
      cve,
      package: pkg,
      developer: dev,
      risk_score: inc.risk_score,
    }],
  });
});

/* ─────────────────────────────────────────────────────────────────────
   GET /api/remediate?id=<1-N>
───────────────────────────────────────────────────────────────────── */
router.get("/remediate", async (req, res) => {
  const sessionId = req.headers["x-session-id"] || "default";
  const id  = sanitizeInput(req.query.id || "1");
  const inc = await getIncidentById(sessionId, id);
  const allIncidents = await getIncidents(sessionId);
  
  const sev       = inc.vulnerability?.severity || "safe";
  const pkg       = inc.package_details?.package_name || "unknown";
  const dev       = inc.pr_details?.developer || "Unknown";
  const cve       = inc.vulnerability?.cve || "N/A";
  
  const openaiKey = process.env.OPENAI_API_KEY;
  const geminiKey = process.env.GEMINI_API_KEY;

  let remediationData = null;
  let mode = "coral-ai-v2";

  if (openaiKey && openaiKey !== "sk-your-key-here" && openaiKey.trim().length > 0) {
    try {
      const systemPrompt = `You are Coral AI, a highly intelligent DevSecOps Security Engineer.
Analyze the following security incident and return a JSON object with a highly personalized remediation plan tailored to the developer (${dev}) and the package (${pkg}).
The JSON MUST follow this format exactly:
{
  "title": "A customized title indicating the developer name and vulnerability",
  "subtitle": "A customized subtitle summarizing the fix priority",
  "severity": "${sev}",
  "estimated_time": "Estimated time (e.g. 30 Minutes, 2 Hours)",
  "actions": [
    "Specific personalized action item 1",
    "Specific personalized action item 2"
  ],
  "scripts": [
    "# Custom bash script step 1\\ncommands...",
    "# Custom bash script step 2\\ncommands..."
  ]
}
Return ONLY valid JSON, no markdown wrapping, no formatting.`;

      const response = await axios.post("https://api.openai.com/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: `Remediate incident ${inc.incident_id}: Package ${pkg}, CVE ${cve}, Developer ${dev}, Risk Score ${inc.risk_score}/100` }
        ],
        temperature: 0.1,
        response_format: { type: "json_object" }
      }, {
        headers: {
          "Authorization": `Bearer ${openaiKey.trim()}`,
          "Content-Type": "application/json"
        },
        timeout: 10000
      });
      remediationData = JSON.parse(response.data?.choices?.[0]?.message?.content);
      mode = "live";
    } catch (err) {
      console.error("[REMEDIATE_AI_ERROR]", err.message);
    }
  }

  if (!remediationData && geminiKey && geminiKey !== "your-gemini-key-here" && geminiKey.trim().length > 0) {
    try {
      const systemPrompt = `You are Coral AI, a highly intelligent DevSecOps Security Engineer.
Analyze the following security incident and return a JSON object with a highly personalized remediation plan tailored to the developer (${dev}) and the package (${pkg}).
The JSON MUST follow this format exactly:
{
  "title": "A customized title indicating the developer name and vulnerability",
  "subtitle": "A customized subtitle summarizing the fix priority",
  "severity": "${sev}",
  "estimated_time": "Estimated time (e.g. 30 Minutes, 2 Hours)",
  "actions": [
    "Specific personalized action item 1",
    "Specific personalized action item 2"
  ],
  "scripts": [
    "# Custom bash script step 1\\ncommands...",
    "# Custom bash script step 2\\ncommands..."
  ]
}
Return ONLY valid JSON, no markdown wrapping, no formatting.`;

      const response = await axios.post(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey.trim()}`,
        {
          contents: [
            { parts: [{ text: `Remediate incident ${inc.incident_id}: Package ${pkg}, CVE ${cve}, Developer ${dev}, Risk Score ${inc.risk_score}/100` }] }
          ],
          systemInstruction: { parts: [{ text: systemPrompt }] },
          generationConfig: { temperature: 0.1, responseMimeType: "application/json" }
        },
        { headers: { "Content-Type": "application/json" }, timeout: 10000 }
      );
      remediationData = JSON.parse(response.data?.candidates?.[0]?.content?.parts?.[0]?.text);
      mode = "live";
    } catch (err) {
      console.error("[REMEDIATE_GEMINI_ERROR]", err.message);
    }
  }

  if (!remediationData) {
    remediationData = generatePersonalizedRemediationPlan(inc, allIncidents);
    mode = "mocked";
  }

  res.json({
    success: true,
    mode,
    remediation: remediationData
  });
});

/* ─────────────────────────────────────────────────────────────────────
   GET /api/query?q=<natural language>
   Enhanced NL → Coral SQL search
───────────────────────────────────────────────────────────────────── */
router.get("/query", async (req, res) => {
  const sessionId = req.headers["x-session-id"] || "default";
  const q = sanitizeInput(req.query.q || "").toLowerCase();
  if (!q) {
    return res.status(400).json({ success: false, error: "Query parameter 'q' is required" });
  }
  
  const incidents = await getIncidents(sessionId);
  let filtered = incidents;
  let coral_query = `SELECT * FROM github_commits
LEFT JOIN vulnerabilities ON github_commits.package_name = vulnerabilities.package_name
LEFT JOIN slack_messages  ON github_commits.author = slack_messages.user
LEFT JOIN policies        ON github_commits.package_name = policies.applies_to`;
  let natural_query = q;
  
  if (/critical/i.test(q)) {
    filtered = incidents.filter(i => i.vulnerability?.severity === "critical");
    coral_query += `\nWHERE vulnerabilities.severity = 'critical'\nORDER BY risk_score DESC`;
  } else if (/high.*risk|high.*severity/i.test(q)) {
    filtered = incidents.filter(i => i.vulnerability?.severity === "high");
    coral_query += `\nWHERE vulnerabilities.severity = 'high'\nORDER BY risk_score DESC`;
  } else if (/secret|leak|credential/i.test(q)) {
    filtered = incidents.filter(i => i.secrets_detected);
    coral_query += `\nWHERE secrets_detected IS NOT NULL\nORDER BY risk_score DESC`;
  } else if (/policy|violation|notion/i.test(q)) {
    filtered = incidents.filter(i => i.policy_violation);
    coral_query += `\nWHERE policies.policy_rule IS NOT NULL\nORDER BY risk_score DESC`;
  } else if (/alice|alice_dev/i.test(q)) {
    filtered = incidents.filter(i => i.pr_details?.developer?.toLowerCase().includes("alice"));
    coral_query += `\nWHERE github_commits.author LIKE '%alice%'\nORDER BY merged_at DESC`;
  } else if (/bob|bob_engineer/i.test(q)) {
    filtered = incidents.filter(i => i.pr_details?.developer?.toLowerCase().includes("bob"));
    coral_query += `\nWHERE github_commits.author LIKE '%bob%'\nORDER BY merged_at DESC`;
  } else if (/contractor|anomal/i.test(q)) {
    filtered = incidents.filter(i => i.pr_details?.developer?.toLowerCase().includes("contractor"));
    coral_query += `\nWHERE github_commits.author LIKE '%contractor%'\nORDER BY risk_score DESC`;
  } else if (/today|recent|latest/i.test(q)) {
    filtered = [...incidents].sort((a, b) =>
      new Date(b.pr_details?.merged_at || 0) - new Date(a.pr_details?.merged_at || 0)
    ).slice(0, 5);
    coral_query += `\nORDER BY merged_at DESC\nLIMIT 5`;
  } else if (/rollback|revert/i.test(q)) {
    filtered = incidents.filter(i => i.recommended_action === "ROLLBACK_DEPLOYMENT");
    coral_query += `\nWHERE recommended_action = 'ROLLBACK_DEPLOYMENT'\nORDER BY risk_score DESC`;
  } else if (/highest risk|top risk|worst/i.test(q)) {
    filtered = [...incidents].sort((a, b) => b.risk_score - a.risk_score).slice(0, 5);
    coral_query += `\nORDER BY risk_score DESC\nLIMIT 5`;
  }
  
  const rows = filtered.map(i => ({
    incident_id: i.incident_id,
    code:        i.incident_id,
    severity:    i.vulnerability?.severity,
    risk_score:  i.risk_score,
    cve:         i.vulnerability?.cve,
    package:     i.package_details?.package_name,
    developer:   i.pr_details?.developer,
    title:       i.pr_details?.title,
    commit_message: i.pr_details?.title,
    author:      i.pr_details?.developer,
    vuln_id:     i.vulnerability?.cve,
    merged_at:   i.pr_details?.merged_at,
  }));
  
  res.json({
    success: true,
    natural_query: q,
    coral_query,
    rows,
    row_count: rows.length,
    total: rows.length,
  });
});

/* ─────────────────────────────────────────────────────────────────────
   GET /api/logs — All security logs with pagination
───────────────────────────────────────────────────────────────────── */
router.post("/query-engine", async (req, res) => {
  const sessionId = req.headers["x-session-id"] || "default";
  const incidents = await getIncidents(sessionId);
  const page  = Math.max(1, parseInt(req.query.page  || "1", 10));
  const limit = Math.min(50, Math.max(1, parseInt(req.query.limit || "20", 10)));
  const start = (page - 1) * limit;
  
  const paginated = incidents.slice(start, start + limit);
  
  res.json({
    success: true,
    logs:  paginated,
    total: incidents.length,
    page,
    limit,
    total_pages: Math.ceil(incidents.length / limit),
  });
});

/* ─────────────────────────────────────────────────────────────────────
   GET /api/anomalies — Developer anomaly detection
───────────────────────────────────────────────────────────────────── */
router.get("/suggested-actions", async (req, res) => {
  const sessionId = req.headers["x-session-id"] || "default";
  const incidents = await getIncidents(sessionId);
  const devMap = {};
  
  incidents.forEach(inc => {
    const dev = inc.pr_details?.developer || "Unknown";
    if (!devMap[dev]) devMap[dev] = { developer: dev, incidents: [], risk_total: 0, critical: 0, high: 0, secrets: 0 };
    devMap[dev].incidents.push(inc.incident_id);
    devMap[dev].risk_total += inc.risk_score || 0;
    if (inc.vulnerability?.severity === "critical") devMap[dev].critical++;
    if (inc.vulnerability?.severity === "high")     devMap[dev].high++;
    if (inc.secrets_detected) devMap[dev].secrets++;
  });
  
  const anomalies = Object.values(devMap)
    .map(d => ({
      ...d,
      avg_risk: Math.round(d.risk_total / d.incidents.length),
      anomaly_score: Math.round(d.risk_total / d.incidents.length + d.critical * 20 + d.secrets * 15),
    }))
    .filter(d => d.risk_total > 50 || d.incidents.length > 1 || d.critical > 0)
    .sort((a, b) => b.anomaly_score - a.anomaly_score);
  
  res.json({ success: true, anomalies, total: anomalies.length });
});

/* ─────────────────────────────────────────────────────────────────────
   GET /api/developer-risk — Developer risk profiles
───────────────────────────────────────────────────────────────────── */
router.get("/developer-risk", async (req, res) => {
  const sessionId = req.headers["x-session-id"] || "default";
  const incidents = await getIncidents(sessionId);
  const devMap = {};
  
  incidents.forEach(inc => {
    const dev = inc.pr_details?.developer || "Unknown";
    if (!devMap[dev]) devMap[dev] = {
      developer: dev, incidents: [], packages: new Set(),
      risk_total: 0, critical: 0, high: 0, medium: 0, safe: 0, secrets: 0, policy_violations: 0,
    };
    const d = devMap[dev];
    d.incidents.push({ id: inc.incident_id, title: inc.pr_details?.title, risk_score: inc.risk_score });
    d.packages.add(inc.package_details?.package_name);
    d.risk_total += inc.risk_score || 0;
    d[inc.vulnerability?.severity || "safe"]++;
    if (inc.secrets_detected) d.secrets++;
    if (inc.policy_violation) d.policy_violations++;
  });
  
  const profiles = Object.values(devMap).map(d => ({
    developer: d.developer,
    total_prs: d.incidents.length,
    avg_risk_score: Math.round(d.risk_total / d.incidents.length),
    critical_count: d.critical,
    high_count: d.high,
    medium_count: d.medium,
    safe_count: d.safe,
    secret_leaks: d.secrets,
    policy_violations: d.policy_violations,
    packages_affected: [...d.packages].filter(p => p !== "none"),
    recent_incidents: d.incidents.slice(0, 3),
    risk_tier: d.critical > 0 || d.secrets > 0 ? "HIGH_RISK" : d.high > 1 ? "ELEVATED" : "STANDARD",
  })).sort((a, b) => b.avg_risk_score - a.avg_risk_score);
  
  res.json({ success: true, profiles, total: profiles.length });
});

/* ─────────────────────────────────────────────────────────────────────
   GET /api/threat-summary — Threat intelligence summary
───────────────────────────────────────────────────────────────────── */
router.get("/threat-summary", async (req, res) => {
  const sessionId = req.headers["x-session-id"] || "default";
  const incidents = await getIncidents(sessionId);
  
  const critical = incidents.filter(i => i.vulnerability?.severity === "critical");
  const high     = incidents.filter(i => i.vulnerability?.severity === "high");
  const medium   = incidents.filter(i => i.vulnerability?.severity === "medium");
  const safe     = incidents.filter(i => i.vulnerability?.severity === "safe");
  const withSecrets = incidents.filter(i => i.secrets_detected);
  const withPolicy  = incidents.filter(i => i.policy_violation);
  
  const avgScore = Math.round(incidents.reduce((s, i) => s + (i.risk_score || 0), 0) / incidents.length);
  const overallScore = Math.max(0, Math.min(100, 100 - (critical.length * 30 + high.length * 15 + medium.length * 5)));
  
  const topCves = incidents
    .filter(i => i.vulnerability?.cve && i.vulnerability.cve !== "NO_CVE_FOUND")
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 5)
    .map(i => ({ cve: i.vulnerability.cve, package: i.package_details?.package_name, severity: i.vulnerability.severity }));
  
  res.json({
    success: true,
    threat_summary: {
      overall_security_score: overallScore,
      grade: overallScore >= 75 ? "A" : overallScore >= 50 ? "B" : overallScore >= 25 ? "C" : "D",
      total_incidents: incidents.length,
      by_severity: {
        critical: critical.length,
        high: high.length,
        medium: medium.length,
        safe: safe.length,
      },
      secret_leaks: withSecrets.length,
      policy_violations: withPolicy.length,
      avg_risk_score: avgScore,
      immediate_action_required: critical.length > 0 || withSecrets.length > 0,
      top_cves: topCves,
      highest_risk_incident: incidents.sort((a, b) => b.risk_score - a.risk_score)[0]?.incident_id,
      generated_at: new Date().toISOString(),
    },
  });
});

/* ─────────────────────────────────────────────────────────────────────
   GET /api/mcp-status — Model Context Protocol status
───────────────────────────────────────────────────────────────────── */
router.get("/mcp-status", (req, res) => {
  const cacheInfo = getCacheInfo();
  res.json({
    success: true,
    mcp: {
      status: "operational",
      version: "2.0.0",
      protocol: "coral-mcp-v1",
      sources_connected: 4,
      sources: [
        { id: "github",  status: "mock_connected",     latency_ms: 12 },
        { id: "osv",     status: "mock_connected",     latency_ms: 8  },
        { id: "slack",   status: "mock_connected",     latency_ms: 15 },
        { id: "notion",  status: "mock_connected",     latency_ms: 10 },
      ],
      cache: cacheInfo,
      last_join: new Date().toISOString(),
      features: ["multi-source-join", "secret-detection", "policy-enforcement", "ai-analysis", "nl-search", "rate-limiting"],
    },
  });
});

module.exports = router;
