const db = require("../config/database");

const githubData = require("../../mock-data/github.json");
const osvData = require("../../mock-data/osv.json");
const slackData = require("../../mock-data/slack.json");

const seedDatabase = () => {

  /*
  |--------------------------------------------------------------------------
  | INSERT GITHUB DATA
  |--------------------------------------------------------------------------
  */

  githubData.forEach((item) => {

    db.run(
      `
      INSERT INTO github
      (author, title, package_name, merged_at)
      VALUES (?, ?, ?, ?)
      `,
      [
        item.author,
        item.title,
        item.package_name,
        item.merged_at
      ],
      (err) => {
        if (err) {
          console.log("GitHub Seed Error:", err.message);
        }
      }
    );

  });

  /*
  |--------------------------------------------------------------------------
  | INSERT OSV DATA
  |--------------------------------------------------------------------------
  */

  osvData.forEach((item) => {

    db.run(
      `
      INSERT INTO osv
      (package_name, cve, severity)
      VALUES (?, ?, ?)
      `,
      [
        item.package_name,
        item.cve,
        item.severity
      ],
      (err) => {
        if (err) {
          console.log("OSV Seed Error:", err.message);
        }
      }
    );

  });

  /*
  |--------------------------------------------------------------------------
  | INSERT SLACK DATA
  |--------------------------------------------------------------------------
  */

  slackData.forEach((item) => {

    db.run(
      `
      INSERT INTO slack
      (channel, message)
      VALUES (?, ?)
      `,
      [
        item.channel,
        item.message
      ],
      (err) => {
        if (err) {
          console.log("Slack Seed Error:", err.message);
        }
      }
    );

  });

  console.log("✅ Mock Data Seeded");

};

module.exports = seedDatabase;