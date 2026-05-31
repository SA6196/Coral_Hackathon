const path = require("path");
const fs = require("fs");

const MOCK_DATA_DIR = path.join(__dirname, "../../mock-data");
const CORAL_SOURCE_FILE = path.join(__dirname, "../../coral-source.yaml");

function getSessionDir(sessionId) {
  if (!sessionId || sessionId === "default" || sessionId === "coral-default") {
    return path.dirname(CORAL_SOURCE_FILE);
  }
  
  // Sanitize sessionId to prevent directory traversal
  const safeSessionId = sessionId.replace(/[^a-zA-Z0-9_-]/g, "");
  const sessionDir = path.join(__dirname, "../../sessions", safeSessionId);
  
  if (!fs.existsSync(sessionDir)) {
    fs.mkdirSync(sessionDir, { recursive: true });
  }

  // Ensure coral-source.yaml is inside sessionDir
  const destYaml = path.join(sessionDir, "coral-source.yaml");
  if (!fs.existsSync(destYaml)) {
    fs.copyFileSync(CORAL_SOURCE_FILE, destYaml);
  }

  // Ensure mock-data directory exists inside sessionDir
  const sessionMockDir = path.join(sessionDir, "mock-data");
  if (!fs.existsSync(sessionMockDir)) {
    fs.mkdirSync(sessionMockDir, { recursive: true });
    
    // Copy all files from original mock-data to session mock-data
    if (fs.existsSync(MOCK_DATA_DIR)) {
      const files = fs.readdirSync(MOCK_DATA_DIR);
      for (const file of files) {
        const srcPath = path.join(MOCK_DATA_DIR, file);
        const destPath = path.join(sessionMockDir, file);
        if (fs.statSync(srcPath).isFile()) {
          fs.copyFileSync(srcPath, destPath);
        }
      }
    }
  }

  return sessionDir;
}

function getSessionMockDir(sessionId) {
  const sessionDir = getSessionDir(sessionId);
  if (sessionId && sessionId !== "default" && sessionId !== "coral-default") {
    return path.join(sessionDir, "mock-data");
  }
  return MOCK_DATA_DIR;
}

module.exports = { getSessionDir, getSessionMockDir };
