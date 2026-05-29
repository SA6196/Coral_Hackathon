import axios from "axios";

/* ── API base URL — always relative; Vite proxy handles dev forwarding ── */
const BASE_URL = import.meta.env.VITE_API_URL || "/api";

/* ── Multi-Tenant Session Management ──────────────────────────────── */
let sessionId = localStorage.getItem("coral_session_id");
if (!sessionId) {
  sessionId = "coral-" + Math.random().toString(36).substring(2, 15);
  localStorage.setItem("coral_session_id", sessionId);
}

const API = axios.create({
  baseURL: BASE_URL,
  timeout: 15000,
  headers: { 
    "Content-Type": "application/json",
    "Bypass-Tunnel-Reminder": "true",
    "X-Session-ID": sessionId
  },
});

API.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("coral_jwt_token");
    if (token) {
      config.headers["Authorization"] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

export const loginUser = (username, password) => API.post("/auth/login", { username, password });

/* ── Response interceptor — normalize errors ────────────────────────── */
API.interceptors.response.use(
  (response) => response,
  (error) => {
    const message =
      error?.response?.data?.error ||
      error?.response?.data?.message ||
      error.message ||
      "Request failed";
    error.userMessage = message;
    return Promise.reject(error);
  }
);

/* ── Core endpoints ─────────────────────────────────────────────────── */
export const getSummary          = ()          => API.get("/security-summary");
export const getHighRisk         = ()          => API.get("/high-risk-incidents");
export const nlSearch            = (q)         => API.get("/query",           { params: { q } });
export const investigateIncident = (id)        => API.get("/investigate",     { params: { id } });
export const chatWithCopilot     = (msg, logId = 1) => API.post("/chat",      { message: msg, log_id: logId });
export const getRemediation      = (id)        => API.get("/remediate",       { params: { id } });
export const getAnomalies        = ()          => API.get("/anomalies");
export const getAllLogs           = (page = 1, limit = 20) => API.get("/logs", { params: { page, limit } });
export const getDeveloperRisk    = ()          => API.get("/developer-risk");
export const getMcpStatus        = ()          => API.get("/mcp-status");
export const getThreatSummary    = ()          => API.get("/threat-summary");

/* ── Source & config endpoints ──────────────────────────────────────── */
export const getSourceStatus     = ()          => API.get("/source-status");
export const configSources       = (cfg)       => API.post("/config-sources", cfg);
export const syncRealData        = ()          => API.post("/sync-real-data");
export const refreshCache        = ()          => API.post("/refresh-cache");
export const getPolicyViolations = ()          => API.get("/policy-violations");
export const getExportReport     = ()          => API.get("/export-report");

/* ── Developer Submission endpoints ─────────────────────────────────── */
export const submitCommit        = (data)       => API.post("/submit-commit",     data);
export const getSubmissions      = (params)     => API.get("/submissions",        { params });
export const getSubmissionStats  = ()           => API.get("/submissions/stats");
export const getSubmission       = (id)         => API.get(`/submissions/${id}`);
export const deleteSubmission    = (id)         => API.delete(`/submissions/${id}`);

/* ── GitHub Webhook endpoints ────────────────────────────────────────── */
export const getWebhookEvents    = (params)     => API.get("/webhook/events",     { params });
export const getWebhookStats     = ()           => API.get("/webhook/stats");
export const getWebhookConfig    = ()           => API.get("/webhook/config");
export const postWebhookEvent    = (payload, event = "push") => API.post("/webhook/github", payload, {
  headers: { "X-GitHub-Event": event }
});


export const getHealth           = ()          => axios.get(`${BASE_URL.replace("/api", "")}/health`);

export default API;