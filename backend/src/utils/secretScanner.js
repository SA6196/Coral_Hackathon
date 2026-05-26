/**
 * secretScanner.js
 * ─────────────────────────────────────────────────────────────
 * Scans commit titles and messages for leaked secrets / credentials.
 * Used by the Coral Security Agent as part of the threat pipeline.
 */

const SECRET_PATTERNS = [
  {
    name: "AWS Access Key",
    pattern: /AKIA[0-9A-Z]{16}/i,
    severity: "critical",
    recommendation: "Rotate AWS access key immediately via IAM console."
  },
  {
    name: "AWS Secret Key",
    pattern: /aws[_\-]?secret[_\-]?key/i,
    severity: "critical",
    recommendation: "Remove secret from codebase and rotate credentials."
  },
  {
    name: "Generic API Key",
    pattern: /api[_\-]?key\s*[:=]\s*['"][^'"]{8,}/i,
    severity: "high",
    recommendation: "Move API key to environment variables or secrets manager."
  },
  {
    name: "Generic Password",
    pattern: /password\s*[:=]\s*['"][^'"]{4,}/i,
    severity: "critical",
    recommendation: "Never commit passwords. Use env vars or vault."
  },
  {
    name: "Private Key Block",
    pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE KEY-----/,
    severity: "critical",
    recommendation: "Revoke and regenerate the private key immediately."
  },
  {
    name: "GitHub Token",
    pattern: /gh[ps]_[A-Za-z0-9]{36}/,
    severity: "critical",
    recommendation: "Revoke the GitHub token immediately in GitHub settings."
  },
  {
    name: "Slack Token",
    pattern: /xox[baprs]-[0-9A-Za-z\-]{10,}/,
    severity: "high",
    recommendation: "Revoke Slack token and regenerate in Slack app settings."
  },
  {
    name: "Database Credentials",
    pattern: /(?:db|database|postgres|mysql)[_\-]?(?:pass|password|pwd)\s*[:=]/i,
    severity: "critical",
    recommendation: "Rotate DB credentials immediately and audit access logs."
  },
  {
    name: "AWS Keyword in Title",
    pattern: /\baws\b.*(?:key|secret|credential)/i,
    severity: "critical",
    recommendation: "Audit commit for hardcoded AWS credentials."
  },
  {
    name: "Secret Keyword in Title",
    pattern: /\b(?:secret|credential|password|passwd|pwd)\b/i,
    severity: "high",
    recommendation: "Review commit for exposed sensitive values."
  },
  {
    name: "Token Keyword in Title",
    pattern: /\btoken\b/i,
    severity: "medium",
    recommendation: "Verify no tokens are hardcoded in this commit."
  }
];

/**
 * Scan a commit title + any message text for secret patterns.
 * Returns an array of detected secrets (empty = clean).
 *
 * @param {string} title   - PR/commit title
 * @param {string} message - Slack / commit message body (optional)
 * @returns {{ name, severity, recommendation, matched }[]}
 */
function scanForSecrets(title = "", message = "") {
  const haystack = `${title} ${message}`.trim();
  const findings = [];

  for (const pattern of SECRET_PATTERNS) {
    if (pattern.pattern.test(haystack)) {
      findings.push({
        name: pattern.name,
        severity: pattern.severity,
        recommendation: pattern.recommendation,
        matched: true
      });
    }
  }

  // De-duplicate by name (highest severity wins)
  const unique = {};
  for (const f of findings) {
    if (!unique[f.name] || severityRank(f.severity) < severityRank(unique[f.name].severity)) {
      unique[f.name] = f;
    }
  }

  return Object.values(unique);
}

function severityRank(s) {
  return { critical: 0, high: 1, medium: 2, low: 3 }[s] ?? 4;
}

/**
 * Returns true if any critical or high secret was detected.
 */
function hasSecretLeak(title, message) {
  return scanForSecrets(title, message).some(
    (f) => f.severity === "critical" || f.severity === "high"
  );
}

module.exports = { scanForSecrets, hasSecretLeak };
