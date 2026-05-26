const githubData = require("../../mock-data/github.json");
const osvData = require("../../mock-data/osv.json");
const slackData = require("../../mock-data/slack.json");

const joinSecurityData = () => {

  return githubData.map((commit, index) => {

    const vuln = osvData[index] || {};
    const slack = slackData[index] || {};

    return {

      github: {
        title: commit.title,
        author: commit.author,
        package_name: commit.package_name,
        merged_at: commit.merged_at,
      },

      vulnerability: {
        cve_id: vuln.cve,
        severity: vuln.severity || "safe",
      },

      slack: {
        channel: slack.channel,
        message: slack.message,
      },

    };

  });

};

module.exports = {
  joinSecurityData,
};