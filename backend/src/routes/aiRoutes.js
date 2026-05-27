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

const { joinSecurityData, getCacheInfo } = require("../coral/joinData");
const { runSecurityAnalysis }            = require("../coral/queryEngine");

/* ── Helpers ─────────────────────────────────────────────────────────── */
function getIncidents() {
  const result = joinSecurityData();
  return runSecurityAnalysis(result.data);
}

function getIncidentById(id) {
  const incidents = getIncidents();
  const num = parseInt(id, 10);
  if (isNaN(num) || num < 1) return incidents[0];
  return incidents[Math.min(num - 1, incidents.length - 1)] || incidents[0];
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
  const avgRisk = Math.round(totalRisk / devIncidents.length);
  const criticalCount = devIncidents.filter(i => i.vulnerability?.severity === "critical").length;
  const highCount = devIncidents.filter(i => i.vulnerability?.severity === "high").length;
  const secretLeaks = devIncidents.filter(i => i.secrets_detected).length;
  
  const riskLevel = avgRisk >= 80 ? "🔴 HIGH RISK" : avgRisk >= 50 ? "🟠 MODERATE" : "🟢 LOW RISK";

  return `## 👤 Developer Risk Profile — ${dev}

**Overall Risk Rating:** ${riskLevel} (avg score: ${avgRisk}/100)

### Activity Summary
| Metric | Value |
|--------|-------|
| Total PRs merged | ${devIncidents.length} |
| Critical incidents | ${criticalCount} |
| High-risk incidents | ${highCount} |
| Secret leaks | ${secretLeaks} |
| Average risk score | ${avgRisk}/100 |

### Recent Incidents by ${dev}
${devIncidents.map((i, idx) => `${idx + 1}. **${i.incident_id}** — ${i.pr_details?.title || "Unknown PR"}
   - Severity: **${i.vulnerability?.severity?.toUpperCase()}** | Risk: ${i.risk_score}/100
   - Package: \`${i.package_details?.package_name}\` | CVE: \`${i.vulnerability?.cve}\`
   - Slack: "${i.internal_discussion?.message?.slice(0, 80)}..."`
).join("\n\n")}

### Current Incident
**${inc.incident_id}:** ${inc.ai_summary}

### Recommendation
${criticalCount > 0 || secretLeaks > 0 ? 
  `⚠️ **${dev} has ${criticalCount} critical incident(s) and ${secretLeaks} secret leak(s). Consider:**
- Temporarily restricting merge permissions pending security review
- Mandatory security training session
- Code review requirement from senior engineer for next 30 days
- Security onboarding refresher` :
  `✅ **${dev}'s risk profile is acceptable.** Continue standard monitoring and ensure they complete the CVE awareness training.`}`;
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
  
  const allIncidents = getIncidents();
  const inc = getIncidentById(log_id);

  // Check if OpenAI Key is configured
  const apiKey = process.env.OPENAI_API_KEY;
  if (apiKey && apiKey !== "sk-your-key-here" && apiKey.trim().length > 0) {
    try {
      // 1. Format the database context for prompt injection
      const incidentSummaryList = allIncidents.map(i => {
        return `- ID: ${i.incident_id}, Severity: ${i.vulnerability?.severity}, Score: ${i.risk_score}, Package: ${i.package_details?.package_name || "none"}, Developer: ${i.pr_details?.developer || "unknown"}, Title: ${i.pr_details?.title || "none"}, Action: ${i.recommended_action || "none"}`;
      }).join("\n");

      const activeIncidentContext = JSON.stringify({
        id: inc.incident_id,
        severity: inc.vulnerability?.severity,
        cve: inc.vulnerability?.cve,
        cvss: inc.vulnerability?.cvss,
        package: inc.package_details?.package_name,
        developer: inc.pr_details?.developer,
        pr_title: inc.pr_details?.title,
        merged_at: inc.pr_details?.merged_at,
        slack_discussion: inc.internal_discussion,
        policy_violation: inc.policy_violation,
        summary: inc.ai_summary
      }, null, 2);

      const systemPrompt = `You are Coral AI, a highly intelligent DevSecOps Copilot for the Coral Security Command Center.
Your role is to analyze threat logs, dependency audits, Slack messages, Notion policy databases, and assist the user (security manager or developer) with security evaluations, rollbacks, and remediations.

Here is the complete security state of the company:
[Security Incidents Log]
${incidentSummaryList}

[Currently Selected Incident context for investigation]
${activeIncidentContext}

Guidelines for responding:
1. Always base your replies on the provided context where applicable.
2. Provide technical, step-by-step guidance.
3. Be professional, direct, and concise. Do not write filler.
4. Format your output using clean GitHub-style Markdown (including headings, tables, code blocks, or alert block quotes where helpful).
5. If the user asks about general security, explain how Coral Virtual SQL engine compiles tables or how branch status gates prevent vulnerable merges.`;

      // 2. Perform OpenAI Completions Call
      const response = await axios.post("https://api.openai.com/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: message }
        ],
        temperature: 0.2,
        max_tokens: 1000
      }, {
        headers: {
          "Authorization": `Bearer ${apiKey.trim()}`,
          "Content-Type": "application/json"
        },
        timeout: 10000
      });

      const reply = response.data?.choices?.[0]?.message?.content || "No reply from AI service";
      
      return res.json({
        success: true,
        mode: "coral-ai-v2-openai",
        intent: "REAL_LLM_CHAT",
        incident_id: inc.incident_id,
        reply,
        timestamp: new Date().toISOString(),
      });
      
    } catch (err) {
      console.error("[CHAT_AI_ERROR]", err.message, err.response?.data || "");
      // If the API call fails, log it and fall back to local rule-based responses
    }
  }

  // ── FALLBACK MODE (Classify intent and generate template-based response) ──
  const intent = classifyIntent(message);
  let reply = "";
  
  switch (intent) {
    case "EXPLAIN_SEVERITY":
      reply = generateExplainSeverity(inc, message);
      break;
    case "ROLLBACK":
      reply = generateRollback(inc);
      break;
    case "SECRETS":
      reply = generateSecretsResponse(inc);
      break;
    case "FIX_PACKAGE":
      reply = generateFixPackage(inc, message);
      break;
    case "DEVELOPER_CONTEXT":
      reply = generateDeveloperContext(inc, allIncidents, message);
      break;
    case "POLICY":
      reply = generatePolicyResponse(inc);
      break;
    case "DEPLOY_SAFETY":
      reply = generateDeploySafety(inc);
      break;
    case "REPORT":
      reply = generateReport(allIncidents);
      break;
    case "THREAT_INTEL":
      reply = generateThreatIntel(inc);
      break;
    case "TIMELINE":
      reply = generateTimeline(allIncidents);
      break;
    case "REMEDIATION_STEPS":
      reply = generateRemediationSteps(inc);
      break;
    default:
      reply = generateGeneral(inc, allIncidents);
  }
  
  res.json({
    success: true,
    mode: "coral-ai-v2-fallback",
    intent,
    incident_id: inc.incident_id,
    reply,
    timestamp: new Date().toISOString(),
  });
});

/* ─────────────────────────────────────────────────────────────────────
   GET /api/investigate?id=<1-N>
───────────────────────────────────────────────────────────────────── */
router.get("/investigate", (req, res) => {
  const id = sanitizeInput(req.query.id || "1");
  const inc = getIncidentById(id);
  
  const sev    = inc.vulnerability?.severity || "safe";
  const cve    = inc.vulnerability?.cve      || "N/A";
  const dev    = inc.pr_details?.developer   || "Unknown";
  const pkg    = inc.package_details?.package_name || "unknown";
  const hasSecret = !!inc.secrets_detected;
  const hasPolicy = !!inc.policy_violation;
  
  const report = [
    `## 🔍 AI Security Investigation — ${inc.incident_id}`,
    ``,
    `### Incident Overview`,
    `- **Severity:** ${sev.toUpperCase()}`,
    `- **Risk Score:** ${inc.risk_score}/100`,
    `- **CVE:** \`${cve}\``,
    `- **Package:** \`${pkg}\``,
    `- **Developer:** ${dev}`,
    `- **PR:** ${inc.pr_details?.title || "Unknown PR"}`,
    `- **Merged:** ${inc.pr_details?.merged_at ? new Date(inc.pr_details.merged_at).toLocaleString() : "N/A"}`,
    ``,
    `### AI Analysis`,
    inc.ai_summary || "No AI summary available.",
    ``,
    `### Threat Assessment`,
    sev === "critical"
      ? `🚨 **CRITICAL THREAT** — Immediate action required. This vulnerability has a CVSS score in the 9.0–10.0 range. Active exploitation is possible. Every minute of delay increases your exposure window.`
      : sev === "high"
      ? `🟠 **HIGH RISK** — Security review mandatory before next deployment. This vulnerability could be exploited under specific conditions. Patch within 24–48 hours.`
      : sev === "medium"
      ? `🟡 **MODERATE RISK** — Monitor and test. Patch in the next release cycle. Limited exploitation risk.`
      : `✅ **LOW RISK** — No immediate action required. Continue standard monitoring and patch in the next routine update.`,
    ``,
    hasSecret ? `### 🔑 Secret Exposure\n- **${inc.secrets_detected.count} secret(s)** found in commit or message\n- Highest severity: **${inc.secrets_detected.highest_severity}**\n- **Rotate all exposed credentials immediately**` : null,
    hasPolicy ? `### 📋 Policy Violation\n- **Policy:** ${inc.policy_violation.policy_name}\n- **Rule:** \`${inc.policy_violation.policy_rule}\`\n- **Owner Team:** ${inc.policy_violation.owner_team}\n- ${inc.policy_violation.description}` : null,
    ``,
    `### Recommended Action`,
    `> **${(inc.recommended_action || "SAFE_TO_DEPLOY").replace(/_/g, " ")}**`,
    ``,
    `### Internal Intelligence`,
    `- **Slack Channel:** ${inc.internal_discussion?.slack_channel || "N/A"}`,
    `- **Discussion:** "${inc.internal_discussion?.message || "No discussion found."}"`,
  ].filter(l => l !== null).join("\n");
  
  res.json({
    success: true,
    mode: "coral-ai-v2",
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
router.get("/remediate", (req, res) => {
  const id  = sanitizeInput(req.query.id || "1");
  const inc = getIncidentById(id);
  
  const sev       = inc.vulnerability?.severity || "safe";
  const pkg       = inc.package_details?.package_name || "unknown";
  const dev       = inc.pr_details?.developer || "Unknown";
  const cve       = inc.vulnerability?.cve || "N/A";
  const hasSecret = !!inc.secrets_detected;
  const hasPolicy = !!inc.policy_violation;
  
  const actions = [
    `Perform a git revert to revoke code modifications introduced by ${dev}: \`git revert HEAD --no-edit\``,
    hasSecret ? `Rotate all exposed credentials — revoke on platform dashboard then update secrets manager` : null,
    hasPolicy ? `Open a Policy Exception in Notion for "${inc.policy_violation?.policy_name}" — link incident ${inc.incident_id}` : null,
    `Upgrade \`${pkg}\` to the latest patched version: \`npm install ${pkg}@latest\``,
    `Run \`npm audit --audit-level=high\` to verify no remaining vulnerabilities`,
    `Run your full test suite before redeploying: \`npm test\``,
    `Notify the security team and document the incident timeline`,
  ].filter(Boolean);
  
  const scripts = [
    `# Phase 1: Revert the vulnerable commit\ngit log --oneline -5\ngit revert HEAD --no-edit\ngit push origin HEAD --force-with-lease`,
    hasSecret ? `# Phase 2: Scan and clean secrets\npip install trufflehog\ntrufflehog git file://. --only-verified\n\n# Remove secret file from git history\ngit filter-repo --path <secret-file> --invert-paths --force` : null,
    `# Phase 3: Patch the vulnerable package\nnpm install ${pkg}@latest\nnpm audit --audit-level=high\nnpm test`,
    `# Phase 4: Verify and notify\necho "Audit exit code: $?"\ncurl -X POST $SLACK_WEBHOOK_URL \\\n  -H 'Content-type: application/json' \\\n  --data '{"text":"✅ ${inc.incident_id} remediated — ${pkg} patched, ${cve} resolved."}'`,
  ].filter(Boolean);
  
  res.json({
    success: true,
    mode: "coral-ai-v2",
    remediation: {
      title: `Remediation Plan — ${inc.incident_id}`,
      subtitle: sev === "critical"
        ? "Immediate rollback, credential rotation, and patch required"
        : "Security review and patch required",
      severity: sev,
      estimated_time: sev === "critical" ? "1–2 hours" : sev === "high" ? "2–4 hours" : "4–8 hours",
      actions,
      scripts,
    },
  });
});

/* ─────────────────────────────────────────────────────────────────────
   GET /api/query?q=<natural language>
   Enhanced NL → Coral SQL search
───────────────────────────────────────────────────────────────────── */
router.get("/query", (req, res) => {
  const q = sanitizeInput(req.query.q || "").toLowerCase();
  if (!q) {
    return res.status(400).json({ success: false, error: "Query parameter 'q' is required" });
  }
  
  const incidents = getIncidents();
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
router.get("/logs", (req, res) => {
  const incidents = getIncidents();
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
router.get("/anomalies", (req, res) => {
  const incidents = getIncidents();
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
router.get("/developer-risk", (req, res) => {
  const incidents = getIncidents();
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
router.get("/threat-summary", (req, res) => {
  const incidents = getIncidents();
  
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
