const fs = require("fs");
const path = require("path");

const BASELINE_PATH = path.join(__dirname, "../../.baseline/collaborators.json");

function getBaseline() {
  if (!fs.existsSync(BASELINE_PATH)) {
    return {};
  }
  return JSON.parse(fs.readFileSync(BASELINE_PATH, "utf-8"));
}

function checkAccessRisk(developer) {
  const baseline = getBaseline();
  if (!baseline[developer]) {
    return { risk: false, reason: "Developer not found in baseline. Assuming standard access." };
  }
  if (baseline[developer] === "admin") {
    return { risk: true, reason: "Developer has admin access." };
  }
  return { risk: false, reason: "Standard access." };
}

module.exports = { getBaseline, checkAccessRisk };
