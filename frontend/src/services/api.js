import axios from "axios";

// ─── Single backend (Node.js port 5000) — all endpoints ─────────────────────
const API = axios.create({ baseURL: "http://localhost:5000/api" });

export const getSummary    = () => API.get("/security-summary");
export const getHighRisk   = () => API.get("/high-risk-incidents");

/** Natural Language → SQL search
 * @param {string} q  e.g. "show all critical incidents from today"
 */
export const nlSearch = (q) => API.get("/query", { params: { q } });

/** AI full incident investigation report
 * @param {number} id  log id (1-based)
 */
export const investigateIncident = (id) =>
  API.get("/investigate", { params: { id } });

/** AI Copilot chat
 * @param {string} message user message
 * @param {number} logId   active incident id
 */
export const chatWithCopilot = (message, logId = 1) =>
  API.post("/chat", { message, log_id: logId });

/** Remediation scripts for an incident
 * @param {number} id log id
 */
export const getRemediation = (id) =>
  API.get("/remediate", { params: { id } });

/** Anomaly detection sweep */
export const getAnomalies = () => API.get("/anomalies");

/** All raw security logs */
export const getAllLogs = () => API.get("/logs");