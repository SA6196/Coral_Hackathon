const fs = require("fs");
const path = require("path");

const BASELINE_PATH = path.join(__dirname, "../../.baseline/collaborators.json");

function getBaseline() {
  try {
    if (!fs.existsSync(BASELINE_PATH)) {
      return { collaborators: [] };
    }
    return JSON.parse(fs.readFileSync(BASELINE_PATH, "utf-8"));
  } catch (e) {
    console.error("[BASELINE] Failed to read baseline:", e.message);
    return { collaborators: [] };
  }
}

function saveBaseline(data) {
  try {
    const dir = path.dirname(BASELINE_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(BASELINE_PATH, JSON.stringify(data, null, 2), "utf-8");
    console.log(`[BASELINE] Baseline saved to ${BASELINE_PATH}`);
  } catch (e) {
    console.error("[BASELINE] Failed to save baseline:", e.message);
  }
}

function diffAccessBaseline(currentCollaborators) {
  const findings = [];
  const baseline = getBaseline();
  
  const prev = {};
  if (Array.isArray(baseline.collaborators)) {
    baseline.collaborators.forEach(c => {
      prev[c.login] = c;
    });
  }

  const currentByLogin = {};
  currentCollaborators.forEach(c => {
    currentByLogin[c.login] = c;
  });

  // Check for new collaborators or privilege escalations
  currentCollaborators.forEach(c => {
    const login = c.login;
    const isCurrentAdmin = c.role && (c.role.admin === true || c.role.name === "admin");
    
    if (!prev[login]) {
      findings.push({
        type: "new_collaborator",
        login: login,
        admin: isCurrentAdmin,
        severity: isCurrentAdmin ? "high" : "medium",
      });
    } else {
      const prevCollab = prev[login];
      const wasPrevAdmin = prevCollab.role && (prevCollab.role.admin === true || prevCollab.role.name === "admin");
      
      if (isCurrentAdmin && !wasPrevAdmin) {
        findings.push({
          type: "privilege_escalation",
          login: login,
          severity: "critical",
        });
      }
    }
  });

  // Check for removed collaborators
  Object.keys(prev).forEach(login => {
    if (!currentByLogin[login]) {
      findings.push({
        type: "collaborator_removed",
        login: login,
        severity: "low",
      });
    }
  });

  return findings;
}

function checkAccessRisk(developer) {
  const baseline = getBaseline();
  const list = baseline.collaborators || [];
  const found = list.find(c => c.login === developer);
  
  if (!found) {
    return { risk: false, reason: "Developer not found in baseline. Assuming standard access." };
  }
  const isAdmin = found.role && (found.role.admin === true || found.role.name === "admin");
  if (isAdmin) {
    return { risk: true, reason: "Developer has admin access." };
  }
  return { risk: false, reason: "Standard access." };
}

module.exports = { getBaseline, saveBaseline, diffAccessBaseline, checkAccessRisk };
