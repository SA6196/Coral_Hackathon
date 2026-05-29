/**
 * responseGenerators.js — Modular visual response templates for Coral AI Threat Agent
 * ─────────────────────────────────────────────────────────────────────────────
 * Organizes the visual presentation (remediation playbooks, charts, timelines)
 * away from the routing and LLM agent orchestration logic.
 * ─────────────────────────────────────────────────────────────────────────────
 */

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
  
  const devIncidents = allIncidents.filter(i => i.pr_details?.developer === dev);
  const totalRisk = devIncidents.reduce((sum, i) => sum + (i.risk_score || 0), 0);
  const avgRisk = Math.round(totalRisk / devIncidents.length) || 0;
  const criticalCount = devIncidents.filter(i => i.vulnerability?.severity === "critical").length;
  const highCount = devIncidents.filter(i => i.vulnerability?.severity === "high").length;
  const safeCount = devIncidents.filter(i => i.vulnerability?.severity === "safe" || i.vulnerability?.severity === "medium").length;
  const secretLeaks = devIncidents.filter(i => i.secrets_detected).length;
  
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
  `` + `` + `✅ **${dev}'s behavioral anomaly score is low.** No immediate containment necessary. Continue automated monitoring.`}`;
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
  
  const avgScore = Math.round(allIncidents.reduce((s, i) => s + (i.risk_score || 0), 0) / allIncidents.length) || 0;
  const overallScore = Math.max(0, 100 - (critical * 30 + high * 15 + medium * 5));
  const grade = overallScore >= 75 ? "A" : overallScore >= 50 ? "B" : overallScore >= 25 ? "C" : "D";
  
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

module.exports = {
  generateExplainSeverity,
  generateRollback,
  generateSecretsResponse,
  generateFixPackage,
  generateDeveloperContext,
  generatePolicyResponse,
  generateDeploySafety,
  generateReport,
  generateThreatIntel,
  generateTimeline,
  generateRemediationSteps,
  generateGeneral
};
