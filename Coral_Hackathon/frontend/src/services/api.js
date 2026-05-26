import axios from "axios";

// ─── Node.js backend (port 5000) ────────────────────────────────────────────
const API = axios.create({ baseURL: "http://localhost:5000/api" });

export const getSummary    = () => API.get("/security-summary");
export const getHighRisk   = () => API.get("/high-risk-incidents");

// ─── Flask AI backend (port 5001) ────────────────────────────────────────────
const FLASK = axios.create({ baseURL: "http://localhost:5001/api" });

/** Natural Language → SQL search
 * @param {string} q  e.g. "show all critical incidents from today"
 */
export const nlSearch = (q) => FLASK.get("/query", { params: { q } });

/** AI full incident investigation report
 * @param {number} id  log id (1-based)
 */
export const investigateIncident = (id) =>
  FLASK.get("/investigate", { params: { id } });

/** AI Copilot chat
 * @param {string} message user message
 * @param {number} logId   active incident id
 */
export const chatWithCopilot = (message, logId = 1) =>
  FLASK.post("/chat", { message, log_id: logId });

/** Remediation scripts for an incident
 * @param {number} id log id
 */
export const getRemediation = (id) =>
  FLASK.get("/remediate", { params: { id } });

/** Anomaly detection sweep */
export const getAnomalies = () => FLASK.get("/anomalies");

/** All raw security logs from Flask/YAML */
export const getAllLogs = () => FLASK.get("/logs");