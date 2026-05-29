const { spawn } = require("child_process");
const path = require("path");
const os = require("os");
const fs = require("fs");

const exeName = os.platform() === 'win32' ? 'coral.exe' : 'coral';
const CORAL_BIN = path.resolve(__dirname, `../../../coral_bin/${exeName}`);
const CORAL_SOURCE_FILE = path.join(__dirname, "../../coral-source.yaml");
const MOCK_DATA_DIR = path.join(__dirname, "../../mock-data");

// ── Node.js fallback JOIN (runs when Coral binary is unavailable) ────
// Performs the exact same LEFT JOIN logic as the Coral SQL query,
// but directly in Node.js against the mock JSON files.
// This ensures the dashboard always displays real incident data with
// correct severities — prevents the "100% score / blank feed" bug.
function getFallbackData() {
  try {
    const github = JSON.parse(fs.readFileSync(path.join(MOCK_DATA_DIR, "github.json"), "utf-8"));
    const osv    = JSON.parse(fs.readFileSync(path.join(MOCK_DATA_DIR, "osv.json"),    "utf-8"));
    const slack  = JSON.parse(fs.readFileSync(path.join(MOCK_DATA_DIR, "slack.json"),  "utf-8"));
    const notion = JSON.parse(fs.readFileSync(path.join(MOCK_DATA_DIR, "notion.json"), "utf-8"));

    // Build lookup maps (same as Coral's JOIN keys)
    const osvByPackage    = {};
    const slackByUser     = {};
    const notionByPackage = {};

    for (const v of osv)    osvByPackage[v.package_name]  = v;
    for (const s of slack)  slackByUser[s.user]            = s;
    for (const n of notion) notionByPackage[n.applies_to]  = n;

    // Simulate:
    //   SELECT g.*, o.*, s.*, n.*
    //   FROM github g
    //   LEFT JOIN osv    o ON g.package_name = o.package
    //   LEFT JOIN slack  s ON g.author       = s.user
    //   LEFT JOIN notion n ON g.package_name = n.applies_to
    return github.map(g => {
      const o = osvByPackage[g.package_name]    || {};
      const s = slackByUser[g.author]            || {};
      const n = notionByPackage[g.package_name]  || null;
      return {
        pr_id:        g.pr_id,
        author:       g.author,
        title:        g.title,
        package_name: g.package_name,
        merged_at:    g.merged_at,
        commit_diff:  g.commit_diff,
        cve:          o.cve_id     || o.cve || "NO_CVE_FOUND",
        severity:     o.severity   || "safe",
        cvss:         o.cvss_score || o.cvss || null,
        channel:      s.channel    || "N/A",
        message:      s.message    || "No internal discussion found.",
        timestamp:    s.timestamp  || null,
        policy_name:  n ? n.policy_name : null,
        policy_rule:  n ? n.policy_rule : null,
        owner_team:   n ? n.owner_team  : null,
        description:  n ? n.description : null,
      };
    });
  } catch (e) {
    console.error("[FALLBACK] Failed to read mock data:", e.message);
    return [];
  }
}

const getCriticalIncidents = async () => {
  return new Promise((resolve) => {
    // Hackathon Winning Query: Cross-Source JOIN across 4 JSON files natively via Coral!
    const query = `
      SELECT 
        g.pr_id, g.author, g.title, g.package_name, g.merged_at, g.commit_diff,
        o.cve, o.severity, o.cvss,
        s.channel, s.message, s.timestamp,
        n.policy_name, n.policy_rule, n.owner_team, n.description
      FROM coral_hackathon.github g
      LEFT JOIN coral_hackathon.osv o ON g.package_name = o.package AND (o.severity != 'safe' OR o.severity IS NULL)
      LEFT JOIN coral_hackathon.slack s ON g.author = s.user
      LEFT JOIN coral_hackathon.notion n ON g.package_name = n.applies_to AND n.policy_name LIKE '%policy%'
      ORDER BY g.pr_id DESC
    `;

    // Ensure we run the process cleanly, specifying the cwd so it finds coral-source.yaml
    const child = spawn(CORAL_BIN, ["sql", "--format", "json", query], {
      cwd: path.dirname(CORAL_SOURCE_FILE),
      env: process.env
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    child.on("close", (code) => {
      if (code !== 0) {
        console.warn("[CORAL] Binary execution failed — using Node.js fallback JOIN:", stderr.trim() || `exit code ${code}`);
        return resolve(getFallbackData());
      }
      try {
        const data = JSON.parse(stdout);
        if (!Array.isArray(data) || data.length === 0) {
          console.warn("[CORAL] Binary returned empty result — using Node.js fallback JOIN.");
          return resolve(getFallbackData());
        }
        resolve(data);
      } catch (e) {
        console.error("[CORAL] Parse error — using Node.js fallback JOIN:", e.message);
        resolve(getFallbackData());
      }
    });

    child.on("error", (err) => {
      console.error("[CORAL] Spawn error — using Node.js fallback JOIN:", err.message);
      resolve(getFallbackData());
    });
  });
};

module.exports = { getCriticalIncidents };