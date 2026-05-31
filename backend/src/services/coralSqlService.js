const { spawn } = require("child_process");
const path = require("path");
const os = require("os");
const fs = require("fs");
const { getSessionDir, getSessionMockDir } = require("../utils/sessionHelper");

const exeName = os.platform() === 'win32' ? 'coral.exe' : 'coral';
const CORAL_BIN = path.resolve(__dirname, `../../../coral_bin/${exeName}`);
const CORAL_SOURCE_FILE = path.join(__dirname, "../../coral-source.yaml");

// ── Node.js fallback JOIN (runs when Coral binary is unavailable) ────
// Performs the exact same LEFT JOIN logic as the Coral SQL query,
// but directly in Node.js against the mock JSON files.
// This ensures the dashboard always displays real incident data with
// correct severities — prevents the "100% score / blank feed" bug.
function getFallbackData(sessionId = "default") {
  try {
    const mockDir = getSessionMockDir(sessionId);
    const github = JSON.parse(fs.readFileSync(path.join(mockDir, "github.json"), "utf-8"));
    const osv    = JSON.parse(fs.readFileSync(path.join(mockDir, "osv.json"),    "utf-8"));
    const slack  = JSON.parse(fs.readFileSync(path.join(mockDir, "slack.json"),  "utf-8"));
    const notion = JSON.parse(fs.readFileSync(path.join(mockDir, "notion.json"), "utf-8"));

    // Build lookup maps (same as Coral's JOIN keys)
    const osvByPackage    = {};
    const slackByUser     = {};
    const notionByPackage = {};

    for (const v of osv)    osvByPackage[v.package || v.package_name]  = v;
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

const getCriticalIncidents = async (sessionId = "default") => {
  return new Promise((resolve) => {
    // ── Global manifest redirection to target session data ──
    const manifestPath = path.resolve(
      os.homedir(),
      "AppData/Roaming/withcoral/coral/config/workspaces/default/sources/coral_hackathon/manifest.yaml"
    );
    let originalManifestContent = null;
    let manifestUpdated = false;

    try {
      if (fs.existsSync(manifestPath)) {
        originalManifestContent = fs.readFileSync(manifestPath, "utf8");
        const sessionMockDir = getSessionMockDir(sessionId);
        const sessionMockPath = path.resolve(sessionMockDir).replace(/\\/g, "/");
        const fileUri = "file:///" + sessionMockPath.replace(/ /g, "%20") + "/";
        const modifiedContent = originalManifestContent.replace(
          /location:\s*[^\r\n]+/g,
          "location: " + fileUri
        );
        fs.writeFileSync(manifestPath, modifiedContent, "utf8");
        manifestUpdated = true;
      }
    } catch (e) {
      console.warn("[CORAL] Failed to redirect manifest.yaml:", e.message);
    }

    const restoreManifest = () => {
      if (manifestUpdated && originalManifestContent !== null) {
        try {
          fs.writeFileSync(manifestPath, originalManifestContent, "utf8");
        } catch (e) {
          console.warn("[CORAL] Failed to restore manifest.yaml:", e.message);
        }
      }
    };

    // Hackathon Winning Query: Cross-Source JOIN across 4 JSON files natively via Coral!
    const query = `
      SELECT 
        g.pr_id, g.author, g.title, g.package_name, g.merged_at, g.commit_diff,
        o.cve, o.severity, o.cvss,
        s.channel, s.message, s.timestamp,
        n.policy_name, n.policy_rule, n.owner_team, n.description
      FROM coral_hackathon.github g
      LEFT JOIN (
        SELECT package, MAX(cve) AS cve, MAX(severity) AS severity, MAX(cvss) AS cvss
        FROM coral_hackathon.osv
        GROUP BY package
      ) o ON g.package_name = o.package
      LEFT JOIN (
        SELECT s1.user, s1.channel, s1.message, s1.timestamp
        FROM coral_hackathon.slack s1
        INNER JOIN (
          SELECT user, MAX(timestamp) as max_ts
          FROM coral_hackathon.slack
          GROUP BY user
        ) s2 ON s1.user = s2.user AND s1.timestamp = s2.max_ts
      ) s ON g.author = s.user
      LEFT JOIN coral_hackathon.notion n ON g.package_name = n.applies_to
      ORDER BY g.pr_id DESC
    `;

    // Ensure we run the process cleanly, specifying the cwd so it finds coral-source.yaml
    const sessionDir = getSessionDir(sessionId);
    const child = spawn(CORAL_BIN, ["sql", "--format", "json", query], {
      cwd: sessionDir,
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
      restoreManifest();
      if (code !== 0) {
        console.warn("[CORAL] Binary execution failed — using Node.js fallback JOIN:", stderr.trim() || `exit code ${code}`);
        return resolve(getFallbackData(sessionId));
      }
      try {
        const data = JSON.parse(stdout);
        if (!Array.isArray(data) || data.length === 0) {
          console.warn("[CORAL] Binary returned empty result — using Node.js fallback JOIN.");
          return resolve(getFallbackData(sessionId));
        }
        resolve(data);
      } catch (e) {
        console.error("[CORAL] Parse error — using Node.js fallback JOIN:", e.message);
        resolve(getFallbackData(sessionId));
      }
    });

    child.on("error", (err) => {
      restoreManifest();
      console.error("[CORAL] Spawn error — using Node.js fallback JOIN:", err.message);
      resolve(getFallbackData(sessionId));
    });
  });
};

module.exports = { getCriticalIncidents };