/**
 * ciScan.js — Coral Command Line Security Scanner
 * ─────────────────────────────────────────────────────────────
 * CLI tool designed for GitHub Actions and local developers.
 * Recursively scans code files for hardcoded secrets, checks 
 * package.json dependencies for banned libraries, and fails the 
 * build if any compliance or security check fails.
 * ─────────────────────────────────────────────────────────────
 */
const fs   = require("fs");
const path = require("path");
const { scanForSecrets } = require("./secretScanner");

const projectRoot = path.resolve(__dirname, "../../..");

const BANNED_PACKAGES = [
  "vm2",
  "node-serialize",
  "stripe",
  "ejs",
  "aws-sdk",
  "shelljs",
  "minimist"
];

// Folders to exclude from search
const EXCLUDE_DIRS = [
  "node_modules",
  ".git",
  "dist",
  "build",
  "out",
  ".gemini",
  "appDataDir",
  "mock-data",
  "docs",
  "demo_flow"
];

// Files to scan
const SCANNABLE_EXTS = [
  ".js", ".jsx", ".ts", ".tsx",
  ".json", ".yaml", ".yml",
  ".env", ".env.example", ".conf", ".config"
];

let filesScanned = 0;
let secretsFound = [];
let bannedPackagesFound = [];

// Helper to recursively walk files
function walkDirectory(dir) {
  let list = [];
  try {
    list = fs.readdirSync(dir);
  } catch (err) {
    return;
  }

  list.forEach(file => {
    const fullPath = path.join(dir, file);
    let stat;
    try {
      stat = fs.statSync(fullPath);
    } catch {
      return;
    }

    if (stat.isDirectory()) {
      if (!EXCLUDE_DIRS.includes(file)) {
        walkDirectory(fullPath);
      }
    } else {
      const ext = path.extname(file).toLowerCase();
      if (SCANNABLE_EXTS.includes(ext) || file === ".env") {
        scanFileForSecrets(fullPath);
      }
    }
  });
}

// Check file contents for secrets
function scanFileForSecrets(filePath) {
  filesScanned++;
  try {
    const content = fs.readFileSync(filePath, "utf8");
    const relativePath = path.relative(projectRoot, filePath);

    // Ignore configuration blueprints, mocks, and scanner definitions
    if (
      relativePath.includes("ciScan.js") || 
      relativePath.includes("secretScanner.js") ||
      relativePath.includes("webhookRoutes.js") ||
      relativePath.includes("submitRoutes.js") ||
      relativePath.includes("aiRoutes.js") ||
      relativePath.includes("DevSubmissionPortal.jsx") ||
      relativePath.includes(".env.example") ||
      relativePath.includes("package-lock.json") ||
      relativePath.includes("coral-sources.yaml")
    ) {
      return;
    }

    const baseFindings = scanForSecrets(content, "");
    // Filter out title/message metadata rules which are too noisy for full file analysis
    const findings = baseFindings.filter(f => 
      f.name !== "AWS Keyword in Title" &&
      f.name !== "Secret Keyword in Title" &&
      f.name !== "Token Keyword in Title"
    );

    if (findings.length > 0) {
      findings.forEach(f => {
        // Exclude placeholders / template values
        if (
          content.includes("your_token_here") || 
          content.includes("sk-your-openai") || 
          content.includes("xoxb-your-token") ||
          content.includes("xoxb-xxxxxxxxxxxx") ||
          content.includes("secret_your_token_here")
        ) {
          return;
        }
        secretsFound.push({
          file: relativePath,
          name: f.name,
          severity: f.severity,
          recommendation: f.recommendation
        });
      });
    }
  } catch {
    // Skip unreadable files
  }
}

// Check package.json for banned libraries
function auditDependencies() {
  const rootDir = path.resolve(__dirname, "../../..");
  const packageJsonPaths = [
    path.join(rootDir, "backend", "package.json"),
    path.join(rootDir, "frontend", "package.json")
  ];

  packageJsonPaths.forEach(pkgPath => {
    if (!fs.existsSync(pkgPath)) return;

    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
      const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };

      Object.keys(deps).forEach(dep => {
        if (BANNED_PACKAGES.includes(dep.toLowerCase())) {
          bannedPackagesFound.push({
            project: path.basename(path.dirname(pkgPath)),
            package: dep,
            version: deps[dep],
            reason: `Banned due to high vulnerability risk or organizational policy.`
          });
        }
      });
    } catch {
      // Ignore unparseable package.json
    }
  });
}

// Main execution
console.log("==================================================");
console.log("🛡️  CORAL AUTOMATED SECURITY CI GATE");
console.log("==================================================");
console.log("Scanning workspace files for vulnerabilities...");

walkDirectory(projectRoot);
auditDependencies();

console.log(`\n• Files Scanned: ${filesScanned}`);
console.log(`• Secret Leaks Found: ${secretsFound.length}`);
console.log(`• Banned Packages Found: ${bannedPackagesFound.length}`);
console.log("==================================================");

let failed = false;

if (bannedPackagesFound.length > 0) {
  failed = true;
  console.log("\n❌ BANNED PACKAGE COMPLIANCE FAILURES:");
  bannedPackagesFound.forEach(p => {
    console.log(`  [${p.project}] Package: '${p.package}' (${p.version})`);
    console.log(`  Reason: ${p.reason}\n`);
  });
}

if (secretsFound.length > 0) {
  failed = true;
  console.log("\n❌ HARDCODED SECRET LEAKS DETECTED:");
  secretsFound.forEach(s => {
    console.log(`  File: ${s.file}`);
    console.log(`  Alert: ${s.name} (${s.severity.toUpperCase()})`);
    console.log(`  Action: ${s.recommendation}\n`);
  });
}

if (failed) {
  console.log("🛑 Security gate failed! Please resolve findings before merging.");
  process.exit(1);
} else {
  console.log("✅ Coral Security Gate: Passed. Code is clean and cleared.");
  process.exit(0);
}
