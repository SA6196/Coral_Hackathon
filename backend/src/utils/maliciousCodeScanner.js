/**
 * maliciousCodeScanner.js — Enterprise-Grade Heuristic & AST Static Analysis Scanner (SAST)
 * ─────────────────────────────────────────────────────────────────────
 * Scans files, scripts, and Git commit diffs for:
 *   - AST Analysis: Parses JS into an Abstract Syntax Tree (AST) using Acorn.
 *   - Constant Folding & String Expression Resolution: Resolves concats, reversed strings, etc.
 *   - Recursive Deobfuscation: Decodes base64/hex and scans nested content.
 *   - Variable Alias & Taint Tracking: Tracks variable reassignments to dangerous functions.
 *   - Supply-Chain Threat Audit: Typosquatting, env harvesting, malicious lifecycle hooks, homoglyphs.
 *   - Heuristic Fallback: Uses token regexes if syntax parsing fails.
 * ─────────────────────────────────────────────────────────────────────
 */

const acorn = require("acorn");

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

const POPULAR_PACKAGES = [
  "lodash", "express", "react", "react-dom", "chalk", "request", "axios", 
  "uuid", "dotenv", "async", "commander", "sequelize", "mongoose", 
  "jsonwebtoken", "bcrypt", "sqlite3", "pg", "mysql2", "redis", "helmet", 
  "stripe", "postgresql-client", "node-setup"
];

// Helper to calculate Levenshtein distance
function getLevenshteinDistance(a, b) {
  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

// Check for package typosquatting
function checkTyposquatting(pkgName) {
  if (!pkgName || typeof pkgName !== "string") return null;
  if (pkgName.startsWith(".") || pkgName.startsWith("/") || pkgName.startsWith("@")) return null;
  const builtins = ["fs", "path", "child_process", "crypto", "http", "https", "net", "tls", "dns", "os", "util", "zlib", "url", "querystring", "events", "stream"];
  if (builtins.includes(pkgName)) return null;

  for (const pop of POPULAR_PACKAGES) {
    if (pkgName === pop) return null;
    const dist = getLevenshteinDistance(pkgName, pop);
    if (dist > 0 && dist <= 2) {
      return { target: pop, distance: dist };
    }
  }
  return null;
}

// Helper to strip git diff metadata and return clean code for parsing
function extractCodeFromDiff(text) {
  if (!text) return "";
  if (!text.includes("diff --git") && !text.includes("@@")) {
    return text;
  }
  const lines = text.split(/\r?\n/);
  const cleanLines = [];
  for (const line of lines) {
    if (line.startsWith("+") && !line.startsWith("+++")) {
      cleanLines.push(line.substring(1));
    }
  }
  return cleanLines.join("\n");
}

// Parses Javascript string into an AST, wrapping fragments in IIFE if required
function parseToAST(code) {
  try {
    return acorn.parse(code, { ecmaVersion: 2020, sourceType: "module", locations: true });
  } catch (e) {
    try {
      return acorn.parse(code, { ecmaVersion: 2020, sourceType: "script", locations: true });
    } catch (err) {
      try {
        return acorn.parse(`(async () => {\n${code}\n})()`, { ecmaVersion: 2020, sourceType: "script", locations: true });
      } catch (finalErr) {
        return null;
      }
    }
  }
}

// Traverses AST nodes recursively
function walkAST(node, callback) {
  if (!node) return;
  callback(node);
  for (const key in node) {
    const child = node[key];
    if (child && typeof child === "object") {
      if (Array.isArray(child)) {
        child.forEach(c => c && walkAST(c, callback));
      } else if (child.type) {
        walkAST(child, callback);
      }
    }
  }
}

// AST-based SAST Scanner
function scanAST(code) {
  const findings = [];
  const ast = parseToAST(code);
  if (!ast) return null; // Signal fallback to regex rules

  const aliases = {};
  const variables = {};

  // Constant Expression String Resolver (Constant Folding, String.fromCharCode, string reverse)
  function resolveStringExpression(node) {
    if (!node) return null;
    if (node.type === "Literal" && typeof node.value === "string") {
      return node.value;
    }
    if (node.type === "Identifier" && typeof variables[node.name] === "string") {
      return variables[node.name];
    }
    if (node.type === "BinaryExpression" && node.operator === "+") {
      const left = resolveStringExpression(node.left);
      const right = resolveStringExpression(node.right);
      if (left !== null && right !== null) {
        return left + right;
      }
    }
    if (node.type === "CallExpression" && node.callee.type === "MemberExpression") {
      const obj = node.callee.object;
      const prop = node.callee.property;
      if (obj && obj.type === "Identifier" && obj.name === "String" && prop && prop.type === "Identifier" && prop.name === "fromCharCode") {
        const chars = [];
        for (const arg of node.arguments) {
          if (arg.type === "Literal" && typeof arg.value === "number") {
            chars.push(String.fromCharCode(arg.value));
          } else {
            return null;
          }
        }
        return chars.join("");
      }
    }
    // Reverse string resolver: "lave".split("").reverse().join("")
    if (node.type === "CallExpression" &&
        node.callee.type === "MemberExpression" &&
        node.callee.property.type === "Identifier" && node.callee.property.name === "join") {
      const splitCall = node.callee.object;
      if (splitCall && splitCall.type === "CallExpression" &&
          splitCall.callee.type === "MemberExpression" &&
          splitCall.callee.property.type === "Identifier" && splitCall.callee.property.name === "reverse") {
        const splitCallObj = splitCall.callee.object;
        if (splitCallObj && splitCallObj.type === "CallExpression" &&
            splitCallObj.callee.type === "MemberExpression" &&
            splitCallObj.callee.property.type === "Identifier" && splitCallObj.callee.property.name === "split") {
          const strNode = splitCallObj.callee.object;
          const baseStr = resolveStringExpression(strNode);
          if (baseStr) {
            return baseStr.split("").reverse().join("");
          }
        }
      }
    }
    return null;
  }

  let hasEnvAccess = false;
  let hasSecretEnvAccess = false;
  let hasNetworkCall = false;
  let envAccessNode = null;
  let networkCallNode = null;
  let secretKeyName = "";

  walkAST(ast, node => {
    // 1. Track variable values and aliases
    if (node.type === "VariableDeclarator" && node.id.type === "Identifier") {
      const varName = node.id.name;
      if (node.init) {
        // Resolve value if string
        const resolved = resolveStringExpression(node.init);
        if (resolved !== null) {
          variables[varName] = resolved;
        }

        // Track aliases to dangerous functions
        if (node.init.type === "Identifier") {
          const initName = node.init.name;
          if (["eval", "Function", "exec", "spawn", "execSync", "fork", "execFile"].includes(initName)) {
            aliases[varName] = initName;
          } else if (aliases[initName]) {
            aliases[varName] = aliases[initName];
          }
        } else if (node.init.type === "CallExpression" &&
                   node.init.callee.type === "Identifier" && node.init.callee.name === "require") {
          const arg = node.init.arguments[0];
          const resolvedArg = resolveStringExpression(arg);
          if (resolvedArg === "child_process") {
            aliases[varName] = "child_process";
          }
        } else if (node.init.type === "MemberExpression" && node.init.object.type === "Identifier") {
          const objName = node.init.object.name;
          const propName = node.init.computed
            ? resolveStringExpression(node.init.property)
            : (node.init.property.type === "Identifier" ? node.init.property.name : resolveStringExpression(node.init.property));
          if (aliases[objName] === "child_process" && ["exec", "spawn", "execSync", "fork", "execFile"].includes(propName)) {
            aliases[varName] = `child_process.${propName}`;
          }
        }
      }
    }

    // 2. Check for eval CallExpression
    if (node.type === "CallExpression" && node.callee.type === "Identifier") {
      const fnName = node.callee.name;
      if (fnName === "eval" || aliases[fnName] === "eval") {
        findings.push({
          rule_id: "backdoor_eval",
          description: `AST: Dynamic code execution (eval backdoor${aliases[fnName] === "eval" ? " via alias " + fnName : ""})`,
          severity: "critical",
          line: node.loc?.start.line || 1,
          preview: `${fnName}(...)`,
          recommendation: "Never use eval() with untrusted inputs; refactor to static analysis or safe parsers."
        });
      }
    }

    // 3. Check for Function Constructor NewExpression
    if (node.type === "NewExpression" && node.callee.type === "Identifier") {
      const fnName = node.callee.name;
      if (fnName === "Function" || aliases[fnName] === "Function") {
        findings.push({
          rule_id: "backdoor_function",
          description: `AST: Dynamic Function constructor backdoor${aliases[fnName] === "Function" ? " via alias " + fnName : ""}`,
          severity: "critical",
          line: node.loc?.start.line || 1,
          preview: `new ${fnName}(...)`,
          recommendation: "Avoid dynamic code generation via the Function constructor."
        });
      }
    }

    // 4. Check for OS Shell Command Spawns (exec, spawn, fork)
    if (node.type === "CallExpression") {
      let isShell = false;
      let fnName = "";
      if (node.callee.type === "Identifier") {
        const calleeName = node.callee.name;
        if (["exec", "spawn", "execSync", "fork", "execFile"].includes(calleeName) || 
            (aliases[calleeName] && aliases[calleeName].startsWith("child_process"))) {
          isShell = true;
          fnName = calleeName;
        }
      } else if (node.callee.type === "MemberExpression") {
        const obj = node.callee.object;
        const prop = node.callee.property;
        const objName = obj.type === "Identifier" ? obj.name : null;
        const propName = node.callee.computed 
          ? resolveStringExpression(prop)
          : (prop.type === "Identifier" ? prop.name : resolveStringExpression(prop));

        if (aliases[objName] === "child_process" && ["exec", "spawn", "execSync", "fork", "execFile"].includes(propName)) {
          isShell = true;
          fnName = `${objName}.${propName}`;
        } else if (objName === "child_process" && ["exec", "spawn", "execSync", "fork", "execFile"].includes(propName)) {
          isShell = true;
          fnName = `child_process.${propName}`;
        }
      }

      if (isShell) {
        findings.push({
          rule_id: "backdoor_shell",
          description: `AST: System shell execution backdoor (${fnName})`,
          severity: "critical",
          line: node.loc?.start.line || 1,
          preview: `${fnName}(...)`,
          recommendation: "Ensure shell command injection is impossible. Sanitize arguments or avoid executing sub-processes."
        });
      }
    }

    // 5. Check for child_process require/import
    if (node.type === "CallExpression" && node.callee.type === "Identifier" && node.callee.name === "require") {
      const arg = node.arguments[0];
      const resolvedArg = resolveStringExpression(arg);
      if (resolvedArg === "child_process") {
        findings.push({
          rule_id: "child_process_import",
          description: "AST: Import of system child_process execution module",
          severity: "high",
          line: node.loc?.start.line || 1,
          preview: `require('${resolvedArg}')`,
          recommendation: "Verify why this package requires OS level child_process invocation."
        });
      }
    }

    // 6. Typosquatting check for imports
    if (node.type === "CallExpression" && node.callee.type === "Identifier" && node.callee.name === "require") {
      const arg = node.arguments[0];
      const resolvedArg = resolveStringExpression(arg);
      if (resolvedArg) {
        const typo = checkTyposquatting(resolvedArg);
        if (typo) {
          findings.push({
            rule_id: "typosquatting_import",
            description: `Supply Chain: Potential Typosquatting import '${resolvedArg}' (similar to '${typo.target}')`,
            severity: "high",
            line: node.loc?.start.line || 1,
            preview: `require('${resolvedArg}')`,
            recommendation: `Check for spelling errors in package name. Verify if you intended to import '${typo.target}' instead of '${resolvedArg}'.`
          });
        }
      }
    }
    if (node.type === "ImportDeclaration") {
      const sourceVal = node.source ? node.source.value : null;
      if (sourceVal) {
        const typo = checkTyposquatting(sourceVal);
        if (typo) {
          findings.push({
            rule_id: "typosquatting_import",
            description: `Supply Chain: Potential Typosquatting import '${sourceVal}' (similar to '${typo.target}')`,
            severity: "high",
            line: node.loc?.start.line || 1,
            preview: `import ... from '${sourceVal}'`,
            recommendation: `Check for spelling errors in package name. Verify if you intended to import '${typo.target}' instead of '${sourceVal}'.`
          });
        }
      }
    }

    // 7. Base64/Hex/atob decodes (Recursive Scanner!)
    if (node.type === "CallExpression" &&
        node.callee.type === "MemberExpression" &&
        node.callee.object.type === "Identifier" && node.callee.object.name === "Buffer" &&
        node.callee.property.type === "Identifier" && node.callee.property.name === "from") {
      const encodingArg = node.arguments[1];
      if (encodingArg && encodingArg.type === "Literal" && ["base64", "hex"].includes(encodingArg.value)) {
        const payloadArg = node.arguments[0];
        const payloadVal = resolveStringExpression(payloadArg);
        if (payloadVal && payloadVal.length >= 16) {
          const type = encodingArg.value;
          try {
            const decoded = Buffer.from(payloadVal, type).toString("utf-8");
            const innerFindings = scanTextForMaliciousCode(decoded);
            if (innerFindings.length > 0) {
              findings.push({
                rule_id: `${type}_obfuscation_malicious`,
                description: `AST: Obfuscated ${type.toUpperCase()} payload contains malicious code: ${innerFindings[0].description}`,
                severity: "critical",
                line: node.loc?.start.line || 1,
                preview: `Buffer.from(..., '${type}')`,
                recommendation: "Examine decoded payload content for dynamic actions. Do not commit base64/hex obfuscated scripts containing dangerous operations."
              });
            }
          } catch (e) {
            findings.push({
              rule_id: `${type}_obfuscation`,
              description: `AST: Obfuscated ${type.toUpperCase()} payload decode`,
              severity: "high",
              line: node.loc?.start.line || 1,
              preview: `Buffer.from(..., '${type}')`,
              recommendation: "Verify that this hex/base64 payload doesn't hide malicious scripts."
            });
          }
        }
      }
    }
    if (node.type === "CallExpression" && node.callee.type === "Identifier" && node.callee.name === "atob") {
      const payloadArg = node.arguments[0];
      const payloadVal = resolveStringExpression(payloadArg);
      if (payloadVal && payloadVal.length >= 8) {
        try {
          const decoded = Buffer.from(payloadVal, "base64").toString("utf-8");
          const innerFindings = scanTextForMaliciousCode(decoded);
          if (innerFindings.length > 0) {
            findings.push({
              rule_id: "atob_obfuscation_malicious",
              description: `AST: Obfuscated atob payload contains malicious code: ${innerFindings[0].description}`,
              severity: "critical",
              line: node.loc?.start.line || 1,
              preview: `atob('${payloadVal.substring(0, 15)}...')`,
              recommendation: "Review the base64-decoded content of the atob call. Avoid dynamic script evaluations."
            });
          }
        } catch (e) {
          // ignore
        }
      }
    }

    // 8. Dynamic property access: global['eval'], globalThis['eval'], window['eval'], process['mainModule']['require']
    if (node.type === "MemberExpression") {
      const obj = node.object;
      const objName = obj.type === "Identifier" ? obj.name : null;
      if (objName && ["global", "globalThis", "window", "process"].includes(objName)) {
        const propVal = node.computed 
          ? resolveStringExpression(node.property) 
          : (node.property.type === "Identifier" ? node.property.name : resolveStringExpression(node.property));
        if (propVal === "eval" || propVal === "Function") {
          findings.push({
            rule_id: "backdoor_dynamic_property",
            description: `AST: Sneaky dynamic execution via ${objName}['${propVal}']`,
            severity: "critical",
            line: node.loc?.start.line || 1,
            preview: `${objName}['${propVal}']`,
            recommendation: "Avoid resolving and executing critical global methods dynamically."
          });
        }
      }
    }

    // 9. Environment variable secret harvesting detection
    if (node.type === "MemberExpression" && node.object.type === "Identifier" && node.object.name === "process") {
      const propVal = node.property.type === "Identifier" ? node.property.name : resolveStringExpression(node.property);
      if (propVal === "env") {
        hasEnvAccess = true;
        envAccessNode = node;
      }
    }
    if (node.type === "MemberExpression" && node.object.type === "MemberExpression" &&
        node.object.object.type === "Identifier" && node.object.object.name === "process" &&
        node.object.property.type === "Identifier" && node.object.property.name === "env") {
      const propVal = node.property.type === "Identifier" ? node.property.name : resolveStringExpression(node.property);
      if (propVal) {
        hasEnvAccess = true;
        envAccessNode = node;
        const secretPattern = /AWS|GITHUB|TOKEN|PASSWORD|SECRET|STRIPE|KEY|AUTH|DB/i;
        if (secretPattern.test(propVal)) {
          hasSecretEnvAccess = true;
          secretKeyName = propVal;
        }
      }
    }

    // 10. Detect network calls in AST
    if (node.type === "CallExpression") {
      let isNetwork = false;
      let netLib = "";
      if (node.callee.type === "Identifier") {
        const calleeName = node.callee.name;
        if (["fetch", "axios", "request", "WebSocket", "XMLHttpRequest"].includes(calleeName)) {
          isNetwork = true;
          netLib = calleeName;
        }
      } else if (node.callee.type === "MemberExpression") {
        const obj = node.callee.object;
        const prop = node.callee.property;
        const objName = obj.type === "Identifier" ? obj.name : null;
        const propName = prop.type === "Identifier" ? prop.name : resolveStringExpression(prop);

        if (["http", "https", "net", "tls", "axios"].includes(objName)) {
          isNetwork = true;
          netLib = `${objName}.${propName}`;
        }
      }

      if (isNetwork) {
        hasNetworkCall = true;
        networkCallNode = node;
      }
    }

    // 11. Literal value checks (for webhooks, exfiltrations, files, unicode)
    if (node.type === "Literal" && typeof node.value === "string") {
      const strVal = node.value;
      const webhookPattern = /https?:\/\/(?:www\.)?(?:pastebin\.com|webhook\.site|temp-uri\.org|ipify\.org|requestbin\.net)/i;
      if (webhookPattern.test(strVal)) {
        findings.push({
          rule_id: "exfiltration_route",
          description: "AST: Exfiltration webhook / pastebin endpoint",
          severity: "critical",
          line: node.loc?.start.line || 1,
          preview: strVal.length > 50 ? strVal.substring(0, 50) + "..." : strVal,
          recommendation: "Investigate if this hook leaks credentials, environment variables, or code payloads externally."
        });
      }

      const persistencePattern = /\.git\/hooks|\.env|\.bashrc|\.profile/i;
      if (persistencePattern.test(strVal)) {
        findings.push({
          rule_id: "persistence_hook",
          description: "AST: Persistence write to Git hooks or env configs",
          severity: "critical",
          line: node.loc?.start.line || 1,
          preview: strVal,
          recommendation: "Verify file write access scopes. Prevent scripts from modifying internal Git hooks or user environments."
        });
      }
    }
  });

  if (hasEnvAccess && hasNetworkCall) {
    const isCritical = hasSecretEnvAccess;
    findings.push({
      rule_id: "environment_harvesting",
      description: isCritical 
        ? `Supply Chain: High risk of Environment Secret Harvesting! Detected secret access to process.env.${secretKeyName} alongside outbound network call.`
        : "Supply Chain: Suspicious Environment variable access alongside outbound network call.",
      severity: isCritical ? "critical" : "high",
      line: networkCallNode?.loc?.start.line || envAccessNode?.loc?.start.line || 1,
      preview: `process.env + network request`,
      recommendation: "Examine if environment variables are being exfiltrated to an external server. Avoid passing system secrets directly to outbound network calls."
    });
  }

  return findings;
}

// Package.json scan helper
function scanPackageJson(text) {
  const findings = [];
  const cleanCode = extractCodeFromDiff(text);
  
  if (cleanCode.includes('"dependencies"') || cleanCode.includes('"devDependencies"') || cleanCode.includes('"scripts"')) {
    try {
      const pkg = JSON.parse(cleanCode);
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      for (const depName in deps) {
        const typo = checkTyposquatting(depName);
        if (typo) {
          findings.push({
            rule_id: "typosquatting_dependency",
            description: `Supply Chain: Typosquatting dependency '${depName}' in package.json (similar to '${typo.target}')`,
            severity: "critical",
            line: 1,
            preview: `"${depName}": "${deps[depName]}"`,
            recommendation: `Remove the suspicious dependency '${depName}' and use '${typo.target}' instead.`
          });
        }
      }

      if (pkg.scripts) {
        const suspiciousCommands = ["curl", "wget", "fetch", "powershell", "certutil", "sh", "bash", "cmd.exe"];
        for (const scriptName of ["preinstall", "postinstall", "prepublish", "prepare"]) {
          const cmd = pkg.scripts[scriptName];
          if (cmd && typeof cmd === "string") {
            const hasSuspicious = suspiciousCommands.some(sc => new RegExp(`\\b${sc}\\b`, "i").test(cmd));
            if (hasSuspicious) {
              findings.push({
                rule_id: "malicious_lifecycle_script",
                description: `Supply Chain: Suspicious command in lifecycle script '${scriptName}': "${cmd}"`,
                severity: "critical",
                line: 1,
                preview: `"${scriptName}": "${cmd}"`,
                recommendation: "Avoid executing network downloads or third-party binaries during package installation lifecycle hooks."
              });
            }
          }
        }
      }
    } catch (e) {
      const lines = text.split(/\r?\n/);
      lines.forEach((line, index) => {
        const scriptMatch = /"(preinstall|postinstall|prepublish)"\s*:\s*"([^"]+)"/.exec(line);
        if (scriptMatch) {
          const cmd = scriptMatch[2];
          if (/curl|wget|fetch|powershell|certutil|bash|\.sh|node\s+/i.test(cmd)) {
            findings.push({
              rule_id: "malicious_lifecycle_script",
              description: `Supply Chain: Suspicious command in lifecycle script '${scriptMatch[1]}': "${cmd}"`,
              severity: "critical",
              line: index + 1,
              preview: line.trim(),
              recommendation: "Avoid executing network downloads or third-party binaries during package installation lifecycle hooks."
            });
          }
        }

        const depMatch = /"([^"]+)"\s*:\s*"[^"]+"/.exec(line);
        if (depMatch && line.trim().startsWith("+")) {
          const depName = depMatch[1];
          const typo = checkTyposquatting(depName);
          if (typo) {
            findings.push({
              rule_id: "typosquatting_dependency",
              description: `Supply Chain: Typosquatting dependency '${depName}' in package.json (similar to '${typo.target}')`,
              severity: "critical",
              line: index + 1,
              preview: line.trim(),
              recommendation: `Remove the suspicious dependency '${depName}' and use '${typo.target}' instead.`
            });
          }
        }
      });
    }
  }
  return findings;
}

// Unicode Homoglyph scanner
function scanUnicodeHomoglyphs(text) {
  const findings = [];
  const lines = text.split(/\r?\n/);
  const homoglyphPattern = /[\u200B-\u200D\uFEFF\u202A-\u202E]/g;
  
  lines.forEach((line, index) => {
    if (homoglyphPattern.test(line)) {
      findings.push({
        rule_id: "unicode_homoglyph_attack",
        description: "Supply Chain: Invisible Unicode or bidirectional override character detected (Potential Homoglyph backdoor)",
        severity: "high",
        line: index + 1,
        preview: line.replace(homoglyphPattern, "[HIDDEN_CHAR]"),
        recommendation: "Remove any zero-width spaces, bidirectional text override characters, or invisible markers from the file."
      });
    }
  });
  
  return findings;
}

// Regex Heuristics (Heuristic Fallback)
function scanRegex(text) {
  const findings = [];
  const lines = text.split(/\r?\n/);
  SUSPICIOUS_RULES.forEach(rule => {
    lines.forEach((line, index) => {
      rule.pattern.lastIndex = 0;
      const regex = new RegExp(rule.pattern.source, rule.pattern.flags + "g");
      let match;
      while ((match = regex.exec(line)) !== null) {
        findings.push({
          rule_id: rule.id,
          description: "Regex: " + rule.description,
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

// Orchestrator: AST Scan first, Fallback to Regex Heuristics
function scanTextForMaliciousCode(text) {
  if (!text) return [];
  
  const findings = [];
  
  // 1. Scan for package.json issues
  const pkgJsonFindings = scanPackageJson(text);
  findings.push(...pkgJsonFindings);

  // 2. Scan for Unicode Homoglyph Backdoors
  const homoglyphFindings = scanUnicodeHomoglyphs(text);
  findings.push(...homoglyphFindings);

  const cleanCode = extractCodeFromDiff(text);
  
  // 3. Try AST static analysis scan
  const astFindings = scanAST(cleanCode);
  if (astFindings !== null) {
    findings.push(...astFindings);
    return findings;
  }
  
  // 4. Fallback to Regex heuristics if syntax errors prevented AST building
  const regexFindings = scanRegex(text);
  findings.push(...regexFindings);
  
  return findings;
}

module.exports = { scanTextForMaliciousCode, SUSPICIOUS_RULES };
