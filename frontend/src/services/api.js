import axios from "axios";

const API = axios.create({ baseURL: "http://localhost:5000/api" });

export const getSummary           = () => API.get("/security-summary");
export const getHighRisk          = () => API.get("/high-risk-incidents");
export const nlSearch             = (q) => API.get("/query", { params: { q } });
export const investigateIncident  = (id) => API.get("/investigate", { params: { id } });
export const chatWithCopilot      = (msg, logId = 1) => API.post("/chat", { message: msg, log_id: logId });
export const getRemediation       = (id) => API.get("/remediate", { params: { id } });
export const getAnomalies         = () => API.get("/anomalies");
export const getAllLogs            = () => API.get("/logs");
export const getDeveloperRisk     = () => API.get("/developer-risk");
export const getMcpStatus         = () => API.get("/mcp-status");
export const getThreatSummary     = () => API.get("/threat-summary");

// ── New endpoints ──────────────────────────────────────────────────────────
export const getSourceStatus      = () => API.get("/source-status");
export const configSources        = (cfg) => API.post("/config-sources", cfg);
export const refreshCache         = () => API.post("/refresh-cache");
export const getPolicyViolations  = () => API.get("/policy-violations");
export const getExportReport      = () => API.get("/export-report");