const { exec } = require("child_process");
const path = require("path");
const os = require("os");

const exeName = os.platform() === 'win32' ? 'coral.exe' : 'coral';
const CORAL_BIN = path.resolve(__dirname, `../../../coral_bin/${exeName}`);
const CORAL_SOURCE_FILE = path.join(__dirname, "../../coral-source.yaml");

const getCriticalIncidents = async () => {
  return new Promise((resolve, reject) => {
    // Hackathon Winning Query: Cross-Source JOIN across 4 JSON files natively via Coral!
    const query = `
      SELECT 
        g.pr_id, g.author, g.title, g.package_name, g.merged_at, g.commit_diff,
        o.cve, o.severity, o.cvss,
        s.channel, s.message, s.timestamp,
        n.policy_name, n.policy_rule, n.owner_team, n.description
      FROM coral_hackathon.github g
      LEFT JOIN coral_hackathon.osv o ON g.package_name = o.package
      LEFT JOIN coral_hackathon.slack s ON g.author = s.user
      LEFT JOIN coral_hackathon.notion n ON g.package_name = n.applies_to
      ORDER BY g.pr_id DESC
    `;

    // Make sure quotes are escaped for PowerShell execution
    const cmd = `"${CORAL_BIN}" sql --format json "${query.replace(/\n/g, ' ')}"`;
    
    exec(cmd, { maxBuffer: 1024 * 1024 * 10 }, (error, stdout, stderr) => {
      if (error) {
        console.error("Coral SQL Error:", stderr || error.message);
        // Fallback to empty array on error so UI doesn't crash
        return resolve([]);
      }
      try {
        const data = JSON.parse(stdout);
        resolve(data);
      } catch (e) {
        console.error("Coral Parse Error:", e.message, "\nStdout:", stdout);
        resolve([]);
      }
    });
  });
};

module.exports = {
  getCriticalIncidents
};