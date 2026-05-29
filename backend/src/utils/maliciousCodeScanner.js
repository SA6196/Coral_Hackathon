/**
 * maliciousCodeScanner.js — Static Analysis Scanner
 * ─────────────────────────────────────────────────────────────────────
 * Scans code text / Git diffs for security backdoors, dynamic executions,
 * exfiltration routes, and base64-obfuscated malware payloads.
 * ─────────────────────────────────────────────────────────────────────
 */

const SUSPICIOUS_RULES = [
  {
    id: "backdoor_eval",
    description: "Dynamic code execution (eval backdoor)",
    severity: "critical",
    pattern: /\beval\s*\(/i,
    recommendation: "Never use eval() with untrusted inputs; refactor to static analysis or safe parsers."
  },
  {
    id: "backdoor_function",
    description: "Dynamic Function constructor backdoor",
    severity: "critical",
    pattern: /\bnew\s+Function\s*\(/i,
    recommendation: "Avoid dynamic code generation via the Function constructor."
  },
  {
    id: "backdoor_shell",
    description: "Unauthorized system shell execution",
    severity: "critical",
    pattern: /\b(exec|spawn|execSync|fork|execFile)\s*\(/i,
    recommendation: "Ensure shell command injection is impossible. Sanitize arguments or avoid executing sub-processes."
  },
  {
    id: "child_process_import",
    description: "Import of system child_process execution module",
    severity: "high",
    pattern: /require\s*\(\s*['"]child_process['"]\s*\)|import\s+.*?\s+from\s+['"]child_process['"]/i,
    recommendation: "Verify why this package requires OS level child_process invocation."
  },
  {
    id: "base64_obfuscation",
    description: "Obfuscated Base64 malware payload decode",
    severity: "critical",
    pattern: /\bBuffer\s*\.from\s*\(\s*['"`][A-Za-z0-9+/=]{20,}['"`]\s*,\s*['"`]base64['"`]\)/i,
    recommendation: "Examine decoded payload content for dynamic actions. Do not commit base64-obfuscated script files."
  },
  {
    id: "hex_obfuscation",
    description: "Obfuscated Hex malware payload decode",
    severity: "high",
    pattern: /\bBuffer\s*\.from\s*\(\s*['"`][a-fA-F0-9]{20,}['"`]\s*,\s*['"`]hex['"`]\)/i,
    recommendation: "Examine hex strings for encoded malicious instructions."
  },
  {
    id: "exfiltration_route",
    description: "Exfiltration webhook / pastebin endpoint",
    severity: "critical",
    pattern: /https?:\/\/(?:www\.)?(?:pastebin\.com|webhook\.site|temp-uri\.org|ipify\.org|requestbin\.net)/i,
    recommendation: "Investigate if this hook leaks credentials, environment variables, or code payloads externally."
  },
  {
    id: "persistence_hook",
    description: "Persistence write to Git hooks / environment configurations",
    severity: "critical",
    pattern: /\.git\/hooks|\.env|\.bashrc|\.profile/i,
    recommendation: "Verify file write access scopes. Prevent scripts from modifying internal Git hooks or user environments."
  }
];

function scanTextForMaliciousCode(text) {
  const findings = [];
  if (!text) return findings;

  const lines = text.split(/\r?\n/);
  SUSPICIOUS_RULES.forEach(rule => {
    lines.forEach((line, index) => {
      // Create local regex to find all matches per line
      const regex = new RegExp(rule.pattern.source, rule.pattern.flags + "g");
      let match;
      while ((match = regex.exec(line)) !== null) {
        findings.push({
          rule_id: rule.id,
          description: rule.description,
          severity: rule.severity,
          line: index + 1,
          preview: match[0],
          recommendation: rule.recommendation
        });
      }
    });
  });

  return findings;
}

module.exports = { scanTextForMaliciousCode, SUSPICIOUS_RULES };
