const db = require("../config/database");

const githubData = require("../../mock-data/github.json");
const osvData    = require("../../mock-data/osv.json");
const slackData  = require("../../mock-data/slack.json");

/**
 * seedDatabase() — Idempotent seed (DELETE then INSERT)
 * Using DELETE + INSERT prevents duplicate rows on every restart.
 */
const seedDatabase = () => {
  // Clear existing data first to prevent duplicates
  db.serialize(() => {
    db.run("DELETE FROM github",  (err) => { if (err) console.error("[seed] clear github:", err.message); });
    db.run("DELETE FROM osv",     (err) => { if (err) console.error("[seed] clear osv:", err.message); });
    db.run("DELETE FROM slack",   (err) => { if (err) console.error("[seed] clear slack:", err.message); });

    // Seed GitHub data
    const githubStmt = db.prepare(
      `INSERT INTO github (author, title, package_name, merged_at) VALUES (?, ?, ?, ?)`
    );
    githubData.forEach((item) => {
      githubStmt.run(
        [item.author, item.title, item.package_name, item.merged_at],
        (err) => { if (err) console.error("[seed] github:", err.message); }
      );
    });
    githubStmt.finalize();

    // Seed OSV data
    const osvStmt = db.prepare(
      `INSERT INTO osv (package_name, cve, severity) VALUES (?, ?, ?)`
    );
    osvData.forEach((item) => {
      osvStmt.run(
        [item.package_name, item.cve_id || item.cve, item.severity],
        (err) => { if (err) console.error("[seed] osv:", err.message); }
      );
    });
    osvStmt.finalize();

    // Seed Slack data
    const slackStmt = db.prepare(
      `INSERT INTO slack (channel, message) VALUES (?, ?)`
    );
    slackData.forEach((item) => {
      slackStmt.run(
        [item.channel, item.message],
        (err) => { if (err) console.error("[seed] slack:", err.message); }
      );
    });
    slackStmt.finalize();

    console.log(`✅ Database seeded: ${githubData.length} GitHub | ${osvData.length} OSV | ${slackData.length} Slack`);
  });
};

module.exports = seedDatabase;