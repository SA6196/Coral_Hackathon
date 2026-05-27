/**
 * DevSubmissionPortal.jsx
 * ─────────────────────────────────────────────────────────────────────
 * Rebuilt Developer Security Ingestion dashboard for Security Managers.
 * Displays real-time GitHub webhook data, developer risk leaderboards,
 * and a Webhook API sandbox to simulate commit alerts during demos.
 * ─────────────────────────────────────────────────────────────────────
 */
import { useState, useEffect, useCallback, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  FiAlertOctagon, FiAlertTriangle, FiAlertCircle, FiCheckCircle,
  FiKey, FiShield, FiRefreshCw, FiGitPullRequest, FiBarChart2,
  FiGitMerge, FiCode, FiChevronDown, FiChevronUp, FiCopy, FiCheck,
  FiCpu, FiActivity, FiTerminal, FiTerminal as FiBox, FiBookOpen, FiUser
} from "react-icons/fi";
import {
  getWebhookEvents,
  getWebhookStats,
  getWebhookConfig,
  postWebhookEvent
} from "../services/api";
import { useToast } from "./Toast";

/* ── Severity Configurations ───────────────────────────────────────── */
const SEV = {
  critical: { color: "#ef4444", bg: "rgba(239,68,68,0.05)", border: "rgba(239,68,68,0.2)", icon: FiAlertOctagon,  label: "CRITICAL" },
  high:     { color: "#f97316", bg: "rgba(249,115,22,0.05)", border: "rgba(249,115,22,0.2)", icon: FiAlertTriangle, label: "HIGH" },
  medium:   { color: "#fbbf24", bg: "rgba(251,191,36,0.05)", border: "rgba(251,191,36,0.2)", icon: FiAlertCircle,   label: "MEDIUM" },
  safe:     { color: "#00ff9d", bg: "rgba(0,255,157,0.03)", border: "rgba(0,255,157,0.15)",   icon: FiCheckCircle,   label: "SAFE" },
};

const ACTION_LABELS = {
  BLOCK_DEPLOYMENT:          "🔴 Block Deployment",
  ROTATE_SECRETS:            "🔑 Rotate Exposed Secrets",
  SECURITY_REVIEW:           "🟠 Security Review Required",
  SECURITY_AUDIT:            "🔍 Security Audit Required",
  MONITOR:                   "🟡 Monitor Package",
  SAFE_TO_DEPLOY:            "✅ Safe to Deploy",
};

/* ── API Webhook Sandbox templates ──────────────────────────────────── */
const SANDBOX_TEMPLATES = [
  {
    name: "🔴 Critical RCE: vm2 package in auth-service",
    event: "push",
    payload: {
      ref: "refs/heads/main",
      pusher: { name: "sarah_dev", email: "sarah@company.com" },
      repository: { full_name: "company/auth-service" },
      commits: [
        {
          id: "a7d9f2c3b4a5e6f7",
          message: "npm install vm2\n\nAdd sandbox runner for untrusted user scripts",
          package_name: "vm2",
          modified: ["package.json", "src/runner.js"]
        }
      ]
    }
  },
  {
    name: "🔑 Secret Leak: AWS Credentials in payment-gateway",
    event: "push",
    payload: {
      ref: "refs/heads/feature-s3-upload",
      pusher: { name: "alex_ops", email: "alex@company.com" },
      repository: { full_name: "company/payment-gateway" },
      commits: [
        {
          id: "f2c3d4e5a6b7c8d9",
          message: "Set credentials for upload\n\nexport const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
          package_name: "none",
          modified: ["src/config/s3.js"]
        }
      ]
    }
  },
  {
    name: "📋 Banned Package Policy: node-serialize in billing",
    event: "push",
    payload: {
      ref: "refs/heads/main",
      pusher: { name: "sarah_dev", email: "sarah@company.com" },
      repository: { full_name: "company/billing-service" },
      commits: [
        {
          id: "b1c2d3e4f5a6b7c8",
          message: "npm i node-serialize\n\nImplement process communication serializer",
          package_name: "node-serialize",
          modified: ["package.json"]
        }
      ]
    }
  },
  {
    name: "✅ Clean PR: Standard UI code in dashboard",
    event: "pull_request",
    action: "opened",
    payload: {
      action: "opened",
      repository: { full_name: "company/dashboard" },
      pull_request: {
        number: 45,
        html_url: "https://github.com/company/dashboard/pull/45",
        title: "Clean dashboard layout and widgets",
        body: "Refactored UI widgets for metrics panel",
        user: { login: "john_backend" },
        head: { ref: "feature-metrics", sha: "e8f9a0b1c2d3e4f5" }
      }
    }
  }
];

/* ── Webhook Event Detail Card ─────────────────────────────────────── */
function EventCard({ event, index }) {
  const [expanded, setExpanded] = useState(false);
  const sev = event.vulnerability?.severity || "safe";
  const cfg = SEV[sev] || SEV.safe;
  const SevIcon = cfg.icon;

  const getRelativeTime = (isoString) => {
    try {
      const ms = Date.now() - new Date(isoString).getTime();
      const mins = Math.round(ms / 60000);
      if (mins < 1) return "Just now";
      if (mins < 60) return `${mins}m ago`;
      const hrs = Math.round(mins / 60);
      if (hrs < 24) return `${hrs}h ago`;
      return new Date(isoString).toLocaleDateString();
    } catch {
      return "recently";
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: Math.min(index * 0.04, 0.4), duration: 0.3 }}
      style={{
        background: cfg.bg,
        border: `1px solid ${cfg.border}`,
        borderRadius: 12,
        overflow: "hidden",
        marginBottom: 10,
        boxShadow: "0 2px 8px rgba(0,0,0,0.15)",
        transition: "border-color 0.2s, background-color 0.2s",
      }}
      className="webhook-event-card"
    >
      {/* Header clickable summary */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          padding: "14px 16px",
          cursor: "pointer",
        }}
        onClick={() => setExpanded(prev => !prev)}
      >
        <SevIcon size={18} style={{ color: cfg.color, flexShrink: 0 }} />

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap", marginBottom: 3 }}>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: cfg.color, fontWeight: 700 }}>
              {event.id}
            </span>
            <span style={{
              fontSize: 8, padding: "1px 6px", borderRadius: 4, fontWeight: 800,
              background: `${cfg.color}15`, border: `1px solid ${cfg.color}25`, color: cfg.color,
              textTransform: "uppercase", letterSpacing: "0.05em",
            }}>
              {cfg.label}
            </span>
            {event.secrets_detected && (
              <span style={{
                fontSize: 8, padding: "1px 6px", borderRadius: 4, fontWeight: 700,
                background: "rgba(168,85,247,0.1)", border: "1px solid rgba(168,85,247,0.25)", color: "#c084fc",
              }}>
                🔑 SECRET LEAK
              </span>
            )}
            {event.policy_violation && (
              <span style={{
                fontSize: 8, padding: "1px 6px", borderRadius: 4, fontWeight: 700,
                background: "rgba(251,191,36,0.1)", border: "1px solid rgba(251,191,36,0.25)", color: "#fbbf24",
              }}>
                🛡️ POLICY ALERT
              </span>
            )}
          </div>

          <div style={{ fontSize: 12, color: "#fff", fontWeight: 600, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
            {event.pr_title}
          </div>

          <div style={{ fontSize: 10, color: "rgba(255,255,255,0.45)", marginTop: 2, display: "flex", flexWrap: "wrap", gap: 8 }}>
            <span>By <strong style={{ color: "rgba(255,255,255,0.7)" }}>{event.developer}</strong></span>
            <span>·</span>
            <code style={{ color: "#00d4ff" }}>{event.repo}:{event.branch}</code>
            <span>·</span>
            <span>{getRelativeTime(event.received_at)}</span>
          </div>
        </div>

        {/* Risk Score indicator */}
        <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", flexShrink: 0, paddingRight: 6 }}>
          <div style={{ fontSize: 16, fontWeight: 800, color: cfg.color }}>{event.risk_score}</div>
          <div style={{ fontSize: 7, color: "rgba(255,255,255,0.3)", letterSpacing: "0.05em", textTransform: "uppercase" }}>Risk Score</div>
        </div>

        {/* Expansion trigger */}
        <div style={{ color: "rgba(255,255,255,0.3)", flexShrink: 0 }}>
          {expanded ? <FiChevronUp size={14} /> : <FiChevronDown size={14} />}
        </div>
      </div>

      {/* Expandable details */}
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            style={{ overflow: "hidden", borderTop: `1px solid ${cfg.border}` }}
          >
            <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 12, background: "rgba(0,0,0,0.15)" }}>
              
              {/* Threat Summary banner */}
              <div style={{
                padding: 12,
                background: "rgba(0,0,0,0.25)",
                borderRadius: 8,
                borderLeft: `3px solid ${cfg.color}`,
                fontSize: 11,
                lineHeight: 1.5,
                color: "rgba(255,255,255,0.8)",
              }}>
                <div style={{ fontSize: 9, color: cfg.color, fontWeight: 700, letterSpacing: "0.05em", marginBottom: 3 }}>
                  🤖 AUTOMATED SEC REPORT
                </div>
                {event.ai_summary}
              </div>

              {/* Technical details grid */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: 12 }}>
                <DetailTile label="Vulnerability / CVE" value={event.vulnerability?.cve === "NO_CVE_FOUND" ? "No Vulnerabilities" : event.vulnerability?.cve} highlight={event.vulnerability?.cve !== "NO_CVE_FOUND" ? cfg.color : null} />
                <DetailTile label="Vulnerability Severity" value={event.vulnerability?.severity?.toUpperCase()} highlight={event.vulnerability?.severity !== "safe" ? cfg.color : null} />
                <DetailTile label="CVSS Score" value={event.vulnerability?.cvss > 0 ? `${event.vulnerability.cvss} / 10` : "N/A"} highlight={event.vulnerability?.cvss > 7.5 ? "#ef4444" : null} />
                <DetailTile label="Dependency Package" value={event.package_name || "none"} mono />
                <DetailTile label="Git Commit SHA" value={event.commit_sha} mono />
                <DetailTile label="Delivery ID" value={event.delivery_id?.slice(0, 16)} mono />
              </div>

              {/* Secrets Detection Details */}
              {event.secrets_detected && (
                <div style={{
                  padding: 10,
                  background: "rgba(168,85,247,0.06)",
                  border: "1px solid rgba(168,85,247,0.18)",
                  borderRadius: 8,
                  fontSize: 11,
                }}>
                  <div style={{ color: "#c084fc", fontWeight: 700, marginBottom: 4, display: "flex", alignItems: "center", gap: 5 }}>
                    <FiKey size={12} /> {event.secrets_detected.count} secret leak(s) intercepted in diff:
                  </div>
                  {event.secrets_detected.findings?.map((f, idx) => (
                    <div key={idx} style={{ color: "rgba(255,255,255,0.7)", marginLeft: 6, margin: "2px 0" }}>
                      • <strong style={{ color: "#fff" }}>{f.name}</strong> — {f.recommendation}
                    </div>
                  ))}
                </div>
              )}

              {/* Policy Violations details */}
              {event.policy_violation && (
                <div style={{
                  padding: 10,
                  background: "rgba(251,191,36,0.05)",
                  border: "1px solid rgba(251,191,36,0.18)",
                  borderRadius: 8,
                  fontSize: 11,
                }}>
                  <div style={{ color: "#fbbf24", fontWeight: 700, marginBottom: 4, display: "flex", alignItems: "center", gap: 5 }}>
                    <FiShield size={12} /> Policy Infraction: {event.policy_violation.rule}
                  </div>
                  <div style={{ color: "rgba(255,255,255,0.7)" }}>{event.policy_violation.reason}</div>
                  <div style={{ color: "rgba(255,255,255,0.4)", fontSize: 9, marginTop: 4 }}>
                    Escalated Team: <span style={{ color: "rgba(255,255,255,0.6)" }}>{event.policy_violation.team}</span>
                  </div>
                </div>
              )}

              {/* Action Banner */}
              <div style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                padding: "8px 12px",
                borderRadius: 6,
                background: `${cfg.color}10`,
                border: `1px solid ${cfg.color}25`,
                fontSize: 11,
                fontWeight: 700,
                color: cfg.color,
                alignSelf: "flex-start",
              }}>
                {ACTION_LABELS[event.recommended_action] || event.recommended_action}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

function DetailTile({ label, value, highlight, mono }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
      <span style={{ fontSize: 9, color: "rgba(255,255,255,0.35)", textTransform: "uppercase" }}>{label}</span>
      <span style={{
        fontSize: 11,
        color: highlight || "rgba(255,255,255,0.8)",
        fontWeight: highlight ? 700 : 500,
        fontFamily: mono ? "var(--font-mono)" : "inherit"
      }}>
        {value || "none"}
      </span>
    </div>
  );
}

/* ── Main Dashboard Portal ─────────────────────────────────────────── */
export default function DevSubmissionPortal() {
  const toast = useToast();
  const [panelOpen, setPanelOpen] = useState(true);
  const [activeTab, setActiveTab] = useState("stream"); // stream | registry | setup | sandbox
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState(null);
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  /* Sandbox State */
  const [selectedTemplateIdx, setSelectedTemplateIdx] = useState(0);
  const [sandboxPayload, setSandboxPayload] = useState("");
  const [sandboxSending, setSandboxSending] = useState(false);
  const [sandboxResponse, setSandboxResponse] = useState(null);

  const statsInterval = useRef(null);

  /* Fetch event listing, stats, and configurations */
  const loadData = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const [eventsRes, statsRes, configRes] = await Promise.all([
        getWebhookEvents({ limit: 40 }),
        getWebhookStats(),
        getWebhookConfig()
      ]);

      if (eventsRes.data?.success) {
        setEvents(eventsRes.data.events);
      }
      if (statsRes.data?.success) {
        setStats(statsRes.data.stats);
      }
      if (configRes.data?.success) {
        setConfig(configRes.data.config);
      }
    } catch (err) {
      console.warn("Failed to fetch webhook metadata:", err);
    } finally {
      if (!silent) setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    // Poll stats silently to show dynamic sandbox outcomes
    statsInterval.current = setInterval(() => loadData(true), 15000);
    return () => clearInterval(statsInterval.current);
  }, [loadData]);

  /* Synchronize sandbox payload when template is selected */
  useEffect(() => {
    const tmpl = SANDBOX_TEMPLATES[selectedTemplateIdx];
    if (tmpl) {
      setSandboxPayload(JSON.stringify(tmpl.payload, null, 2));
      setSandboxResponse(null);
    }
  }, [selectedTemplateIdx]);

  /* Copy Webhook URL to clipboard */
  const handleCopyUrl = () => {
    if (!config?.webhook_url) return;
    navigator.clipboard.writeText(config.webhook_url);
    setCopied(true);
    toast.success("Webhook endpoint copied to clipboard!");
    setTimeout(() => setCopied(false), 2000);
  };

  /* Sandbox webhook dispatcher */
  const handleDispatchSandbox = async () => {
    setSandboxSending(true);
    setSandboxResponse(null);
    try {
      let parsed = null;
      try {
        parsed = JSON.parse(sandboxPayload);
      } catch {
        toast.error("Malformed JSON payload in editor");
        setSandboxSending(false);
        return;
      }

      const template = SANDBOX_TEMPLATES[selectedTemplateIdx];
      const eventType = template?.event || "push";

      toast.info(`Dispatching simulated '${eventType}' webhook event...`);

      const res = await postWebhookEvent(parsed, eventType);

      setSandboxResponse({
        status: res.status,
        statusText: res.statusText,
        data: res.data
      });

      if (res.data?.success) {
        toast.success(`Webhook received. Ingested ${res.data.processed} event logs.`);
        // Reload list immediately
        await loadData(true);
      } else {
        toast.error("Endpoint rejected webhook payload");
      }
    } catch (err) {
      toast.error(err.userMessage || "Failed to dispatch webhook event");
      setSandboxResponse({
        status: err.response?.status || 500,
        statusText: err.response?.statusText || "Internal Error",
        data: err.response?.data || { error: err.message }
      });
    } finally {
      setSandboxSending(false);
    }
  };

  return (
    <section
      aria-label="Developer Ingestion Dashboard"
      style={{ marginBottom: 24 }}
    >
      {/* ── Dashboard Header ──────────────────────────────────────────── */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          background: "rgba(0, 212, 255, 0.05)",
          border: "1px solid rgba(0, 212, 255, 0.2)",
          borderRadius: panelOpen ? "14px 14px 0 0" : 14,
          padding: "14px 20px",
          cursor: "pointer",
          transition: "border-radius 0.2s",
        }}
        onClick={() => setPanelOpen(prev => !prev)}
        role="button"
        aria-expanded={panelOpen}
        id="dev-portal-toggle"
      >
        <FiGitMerge size={16} style={{ color: "#ff4d6d" }} />
        <span style={{ fontSize: 13, fontWeight: 700, color: "#fff", flex: 1, display: "flex", alignItems: "center", gap: 8 }}>
          Developer Webhook Ingestion & Gates
          <span style={{
            fontSize: 9, padding: "2px 8px", borderRadius: 10, fontWeight: 700,
            background: "rgba(0,255,157,0.1)", border: "1px solid rgba(0,255,157,0.25)", color: "#00ff9d",
            display: "flex", alignItems: "center", gap: 5,
          }}>
            <span style={{
              width: 5, height: 5, borderRadius: "50%", background: "#00ff9d",
              display: "inline-block", boxShadow: "0 0 5px #00ff9d",
              animation: "pulse 2s infinite"
            }} />
            ACTIVE LISTENER
          </span>
        </span>

        {events.length > 0 && (
          <span style={{
            fontSize: 10, padding: "2px 8px", borderRadius: 8,
            background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", color: "rgba(255,255,255,0.6)",
            fontFamily: "var(--font-mono)", fontWeight: 600, marginRight: 8
          }}>
            {events.length} events
          </span>
        )}

        <span style={{ color: "rgba(255,255,255,0.3)" }}>
          {panelOpen ? <FiChevronUp size={14} /> : <FiChevronDown size={14} />}
        </span>
      </div>

      {/* ── Dashboard Body ────────────────────────────────────────────── */}
      <AnimatePresence>
        {panelOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25 }}
            style={{
              overflow: "hidden",
              background: "rgba(10, 15, 30, 0.65)",
              backdropFilter: "blur(12px)",
              border: "1px solid rgba(0, 212, 255, 0.15)",
              borderTop: "none",
              borderRadius: "0 0 14px 14px",
              boxShadow: "var(--shadow-card)"
            }}
          >
            {/* Tab navigation */}
            <div style={{
              display: "flex",
              borderBottom: "1px solid rgba(255,255,255,0.08)",
              background: "rgba(0,0,0,0.2)",
              padding: "0 10px",
              gap: 4
            }}>
              <TabButton active={activeTab === "stream"} onClick={() => setActiveTab("stream")}>
                <FiActivity size={12} /> Webhook Ingest Stream
                <span className="live-pill" />
              </TabButton>
              <TabButton active={activeTab === "registry"} onClick={() => setActiveTab("registry")}>
                <FiBarChart2 size={12} /> Developer Risk Registry
              </TabButton>
              <TabButton active={activeTab === "setup"} onClick={() => setActiveTab("setup")}>
                <FiBookOpen size={12} /> GitHub Integration Setup
              </TabButton>
              <TabButton active={activeTab === "sandbox"} onClick={() => setActiveTab("sandbox")}>
                <FiTerminal size={12} /> Webhook API Sandbox
              </TabButton>
            </div>

            <div style={{ padding: 20 }}>
              {/* ── TAB 1: WEBHOOK INGEST STREAM ─────────────────────────────── */}
              {activeTab === "stream" && (
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
                    <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)" }}>
                      Passive commit scanners intercepting push logs from configured webhooks
                    </div>
                    <button
                      onClick={() => loadData(false)}
                      disabled={loading}
                      style={{
                        background: "transparent", border: "none", cursor: "pointer",
                        color: "rgba(0,212,255,0.6)", fontSize: 11, display: "flex", alignItems: "center", gap: 6,
                      }}
                    >
                      <FiRefreshCw size={11} className={loading ? "spin-animation" : ""} />
                      Refresh Logs
                    </button>
                  </div>

                  {events.length > 0 ? (
                    <div style={{ maxHeight: 500, overflowY: "auto", paddingRight: 6 }}>
                      {events.map((e, idx) => (
                        <EventCard key={e.id} event={e} index={idx} />
                      ))}
                    </div>
                  ) : (
                    <div style={{ textAlign: "center", padding: "40px 0", color: "rgba(255,255,255,0.3)", fontSize: 12 }}>
                      No webhook logs captured yet. Use the Webhook API Sandbox tab to dispatch simulated commits.
                    </div>
                  )}
                </div>
              )}

              {/* ── TAB 2: DEVELOPER RISK REGISTRY ──────────────────────────── */}
              {activeTab === "registry" && (
                <div>
                  <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)", marginBottom: 16 }}>
                    Aggregated developer risk grading compiled from automated webhook analysis
                  </div>

                  {stats?.developers?.length > 0 ? (
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))", gap: 14 }}>
                      {stats.developers.map((d, idx) => {
                        const tier = d.risk_tier || "STANDARD";
                        const conf = {
                          HIGH_RISK: { color: "#ef4444", bg: "rgba(239,68,68,0.05)", label: "HIGH RISK" },
                          ELEVATED:  { color: "#f97316", bg: "rgba(249,115,22,0.05)", label: "ELEVATED RISK" },
                          STANDARD:  { color: "#00ff9d", bg: "rgba(0,255,157,0.03)", label: "STANDARD" }
                        }[tier] || { color: "#fff", bg: "rgba(255,255,255,0.05)", label: "UNKNOWN" };

                        return (
                          <motion.div
                            key={d.developer}
                            initial={{ opacity: 0, scale: 0.97 }}
                            animate={{ opacity: 1, scale: 1 }}
                            transition={{ delay: idx * 0.05 }}
                            style={{
                              background: conf.bg,
                              border: `1px solid ${conf.color}25`,
                              borderRadius: 12,
                              padding: 16,
                              display: "flex",
                              flexDirection: "column",
                              justifyContent: "space-between",
                              boxShadow: "0 2px 10px rgba(0,0,0,0.1)"
                            }}
                          >
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
                              <div>
                                <h4 style={{ color: "#fff", fontSize: 13, fontWeight: 700, margin: 0, display: "flex", alignItems: "center", gap: 6 }}>
                                  <FiUser size={12} style={{ color: "rgba(255,255,255,0.4)" }} /> {d.developer}
                                </h4>
                                <span style={{
                                  fontSize: 8, padding: "1px 6px", borderRadius: 4, fontWeight: 700,
                                  background: `${conf.color}15`, color: conf.color, border: `1px solid ${conf.color}25`,
                                  display: "inline-block", marginTop: 4, letterSpacing: "0.05em"
                                }}>
                                  {conf.label}
                                </span>
                              </div>
                              <div style={{ textAlign: "right" }}>
                                <span style={{ fontSize: 18, fontWeight: 800, color: conf.color }}>{d.avg_risk}</span>
                                <div style={{ fontSize: 7, color: "rgba(255,255,255,0.3)", textTransform: "uppercase" }}>Avg Risk</div>
                              </div>
                            </div>

                            <div style={{ gap: 6, display: "flex", flexDirection: "column", marginTop: 6 }}>
                              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "rgba(255,255,255,0.4)" }}>
                                <span>Checked Commits: <strong style={{ color: "#fff" }}>{d.submissions || d.commits}</strong></span>
                                {d.critical > 0 && <span style={{ color: "#ef4444" }}>{d.critical} Critical CVEs</span>}
                                {d.secrets > 0 && <span style={{ color: "#a855f7" }}>{d.secrets} Secret Leaks</span>}
                              </div>

                              {/* Progress bar */}
                              <div style={{ height: 4, width: "100%", background: "rgba(255,255,255,0.06)", borderRadius: 2, overflow: "hidden" }}>
                                <div style={{
                                  height: "100%",
                                  width: `${d.avg_risk}%`,
                                  background: conf.color,
                                  boxShadow: `0 0 8px ${conf.color}`
                                }} />
                              </div>
                            </div>
                          </motion.div>
                        );
                      })}
                    </div>
                  ) : (
                    <div style={{ textAlign: "center", padding: "40px 0", color: "rgba(255,255,255,0.3)", fontSize: 12 }}>
                      No developer grades available yet. Capture webhook events to build the risk ledger.
                    </div>
                  )}
                </div>
              )}

              {/* ── TAB 3: WEBHOOK INTEGRATION SETUP ─────────────────────────── */}
              {activeTab === "setup" && (
                <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 24, alignItems: "start" }}>
                  <div>
                    <h3 style={{ fontSize: 13, fontWeight: 700, color: "#fff", marginBottom: 12 }}>
                      Automated Pipeline Configuration
                    </h3>
                    <p style={{ fontSize: 11, color: "rgba(255,255,255,0.45)", lineHeight: 1.6, marginBottom: 16 }}>
                      In production, the security manager copies the webhook listener URL and configures it inside GitHub settings.
                      Any code commit pushed by any developer instantly triggers the scanning pipeline passively.
                    </p>

                    {/* Copy URL widget */}
                    <div style={{ marginBottom: 18 }}>
                      <label style={{ fontSize: 9, color: "rgba(255,255,255,0.4)", display: "block", marginBottom: 5, uppercase: "true" }}>
                        Payload URL (Webhook Receiver)
                      </label>
                      <div style={{
                        display: "flex",
                        alignItems: "center",
                        background: "rgba(0,0,0,0.3)",
                        border: "1px solid rgba(0,212,255,0.2)",
                        borderRadius: 8,
                        padding: "8px 12px",
                        gap: 10
                      }}>
                        <code style={{
                          flex: 1, color: "#00d4ff", fontSize: 11, overflowX: "auto", whiteSpace: "nowrap",
                          fontFamily: "var(--font-mono)"
                        }}>
                          {config?.webhook_url || "http://localhost:5000/api/webhook/github"}
                        </code>
                        <button
                          onClick={handleCopyUrl}
                          style={{
                            background: "transparent", border: "none", cursor: "pointer",
                            color: copied ? "#00ff9d" : "rgba(255,255,255,0.4)", padding: 4, display: "flex"
                          }}
                          title="Copy payload URL"
                        >
                          {copied ? <FiCheck size={14} /> : <FiCopy size={14} />}
                        </button>
                      </div>
                    </div>

                    {/* Step list */}
                    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                      {config?.instructions?.map((inst, idx) => (
                        <div key={idx} style={{
                          display: "flex", gap: 10, padding: "8px 12px",
                          background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.04)",
                          borderRadius: 6, fontSize: 10.5, color: "rgba(255,255,255,0.7)"
                        }}>
                          <span style={{ color: "#ff4d6d", fontWeight: 700 }}>0{idx + 1}</span>
                          <span>{inst}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Flow graphic */}
                  <div style={{
                    background: "rgba(0,0,0,0.15)",
                    border: "1px solid rgba(255,255,255,0.05)",
                    borderRadius: 10,
                    padding: 16,
                  }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: "rgba(255,255,255,0.4)", marginBottom: 12, display: "flex", alignItems: "center", gap: 5 }}>
                      <FiCpu size={12} /> SECURE INGESTION FLOW PIPELINE
                    </div>

                    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                      <FlowBlock title="Developer Commit" subtitle="Git Push / PR Opened" detail="Triggers Webhook Event" color="#58a6ff" />
                      <FlowConnector />
                      <FlowBlock title="Coral Webhook Gateway" subtitle="Express /api/webhook/github" detail="Ingests event JSON payload" color="#ff4d6d" />
                      <FlowConnector />
                      <FlowBlock title="Sec Scanners (Static & Policy)" subtitle="SecretScanner.js & Notion Sync" detail="Exposes CVEs, keys, banned rules" color="#fbbf24" />
                      <FlowConnector />
                      <FlowBlock title="Real-Time Alerts" subtitle="Dashboard Feed & Slack Bot" detail="Blocks bad builds, notifies team" color="#00ff9d" />
                    </div>
                  </div>
                </div>
              )}

              {/* ── TAB 4: WEBHOOK API SANDBOX ──────────────────────────────── */}
              {activeTab === "sandbox" && (
                <div style={{ display: "grid", gridTemplateColumns: "1.1fr 1fr", gap: 20 }}>
                  
                  {/* Left Side: Payload selection and Dispatch */}
                  <div>
                    <div style={{ display: "flex", gap: 10, flexDirection: "column", marginBottom: 14 }}>
                      <label style={{ fontSize: 11, color: "rgba(255,255,255,0.4)" }}>
                        Select Commit Payload template to dispatch:
                      </label>
                      <select
                        value={selectedTemplateIdx}
                        onChange={e => setSelectedTemplateIdx(parseInt(e.target.value))}
                        style={{
                          width: "100%",
                          background: "#080c14",
                          border: "1px solid rgba(0,212,255,0.25)",
                          borderRadius: 8,
                          padding: "8px 12px",
                          color: "#fff",
                          fontSize: 12,
                          outline: "none"
                        }}
                      >
                        {SANDBOX_TEMPLATES.map((tmpl, idx) => (
                          <option key={idx} value={idx}>{tmpl.name}</option>
                        ))}
                      </select>
                    </div>

                    {/* Payload JSON Editor */}
                    <div style={{ marginBottom: 14 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                        <span style={{ fontSize: 9, color: "rgba(255,255,255,0.4)", textTransform: "uppercase", display: "flex", alignItems: "center", gap: 4 }}>
                          <FiCode size={11} /> Webhook Body JSON (Edit payload parameters as needed)
                        </span>
                        <span style={{ fontSize: 8.5, color: "#a855f7", fontWeight: 700 }}>
                          EVENT: {SANDBOX_TEMPLATES[selectedTemplateIdx]?.event?.toUpperCase()}
                        </span>
                      </div>
                      <textarea
                        value={sandboxPayload}
                        onChange={e => setSandboxPayload(e.target.value)}
                        disabled={sandboxSending}
                        rows={12}
                        style={{
                          width: "100%",
                          background: "rgba(0,0,0,0.3)",
                          border: "1px solid rgba(0,212,255,0.15)",
                          borderRadius: 8,
                          padding: 12,
                          color: "#00d4ff",
                          fontSize: 10.5,
                          fontFamily: "var(--font-mono)",
                          outline: "none",
                          resize: "none",
                          lineHeight: 1.4
                        }}
                      />
                    </div>

                    <button
                      onClick={handleDispatchSandbox}
                      disabled={sandboxSending}
                      style={{
                        width: "100%",
                        padding: "11px 0",
                        background: sandboxSending ? "rgba(0,212,255,0.05)" : "linear-gradient(135deg, rgba(255, 77, 109, 0.25), rgba(255, 77, 109, 0.1))",
                        border: `1px solid ${sandboxSending ? "rgba(255,255,255,0.05)" : "rgba(255, 77, 109, 0.4)"}`,
                        borderRadius: 8,
                        cursor: sandboxSending ? "not-allowed" : "pointer",
                        color: sandboxSending ? "rgba(255,255,255,0.3)" : "#fff",
                        fontSize: 12,
                        fontWeight: 700,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        gap: 8,
                        boxShadow: "0 4px 12px rgba(255, 77, 109, 0.15)"
                      }}
                    >
                      {sandboxSending ? (
                        <>
                          <FiRefreshCw size={13} style={{ animation: "spin 0.8s linear infinite" }} />
                          Ingesting Webhook Event Payload...
                        </>
                      ) : (
                        <>
                          <FiTerminal size={12} />
                          Dispatch Webhook Event
                        </>
                      )}
                    </button>
                  </div>

                  {/* Right Side: Response Inspector */}
                  <div style={{
                    background: "rgba(0,0,0,0.25)",
                    border: "1px solid rgba(255,255,255,0.05)",
                    borderRadius: 10,
                    padding: 16,
                    display: "flex",
                    flexDirection: "column",
                  }}>
                    <div style={{ fontSize: 9, fontWeight: 700, color: "rgba(255,255,255,0.4)", marginBottom: 10, display: "flex", alignItems: "center", gap: 5 }}>
                      <FiActivity size={12} /> API RESPONSE INSPECTOR
                    </div>

                    {sandboxResponse ? (
                      <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
                        <div style={{
                          display: "flex", justifyContent: "space-between", alignItems: "center",
                          padding: "6px 10px", background: sandboxResponse.status < 300 ? "rgba(0,255,157,0.08)" : "rgba(239,68,68,0.08)",
                          border: `1px solid ${sandboxResponse.status < 300 ? "rgba(0,255,157,0.2)" : "rgba(239,68,68,0.2)"}`,
                          borderRadius: 6, marginBottom: 12
                        }}>
                          <span style={{ fontSize: 10, color: "rgba(255,255,255,0.5)" }}>HTTP Status Code</span>
                          <span style={{ fontSize: 11, fontWeight: 700, color: sandboxResponse.status < 300 ? "#00ff9d" : "#ef4444" }}>
                            {sandboxResponse.status} {sandboxResponse.statusText}
                          </span>
                        </div>

                        <div style={{ flex: 1, minHeight: 180, position: "relative" }}>
                          <pre style={{
                            position: "absolute", top: 0, bottom: 0, left: 0, right: 0,
                            background: "#080c14", padding: 12, borderRadius: 6,
                            color: "rgba(255,255,255,0.75)", fontSize: 9.5, overflow: "auto",
                            border: "1px solid rgba(255,255,255,0.05)", margin: 0,
                            fontFamily: "var(--font-mono)"
                          }}>
                            {JSON.stringify(sandboxResponse.data, null, 2)}
                          </pre>
                        </div>
                      </div>
                    ) : (
                      <div style={{
                        flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
                        color: "rgba(255,255,255,0.25)", fontSize: 11, textAlign: "center", gap: 10, padding: "40px 0"
                      }}>
                        <FiTerminal size={24} style={{ opacity: 0.3 }} />
                        <span>Dispatch a simulated commit payload to inspect the live API response.</span>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Inject custom CSS keyframes dynamically for animations */}
      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        .spin-animation {
          animation: spin 1s linear infinite;
        }
        @keyframes pulse {
          0% { opacity: 0.4; }
          50% { opacity: 1; }
          100% { opacity: 0.4; }
        }
        .live-pill {
          width: 5px;
          height: 5px;
          border-radius: 50%;
          background: #00ff9d;
          box-shadow: 0 0 5px #00ff9d;
          animation: pulse 1.5s infinite;
        }
      `}</style>
    </section>
  );
}

/* ── UI Flow diagram blocks ────────────────────────────────────────── */
function FlowBlock({ title, subtitle, detail, color }) {
  return (
    <div style={{
      background: "rgba(0,0,0,0.25)",
      border: `1px solid ${color}25`,
      borderRadius: 8,
      padding: "10px 12px",
      borderLeft: `4px solid ${color}`
    }}>
      <h5 style={{ color: "#fff", fontSize: 11, margin: 0, fontWeight: 700 }}>{title}</h5>
      <div style={{ fontSize: 9, color: "rgba(255,255,255,0.5)", marginTop: 2 }}>{subtitle}</div>
      <div style={{ fontSize: 8.5, color: color, fontWeight: 600, marginTop: 4 }}>{detail}</div>
    </div>
  );
}

function FlowConnector() {
  return (
    <div style={{ display: "flex", justifyContent: "center", margin: "-6px 0", color: "rgba(255,255,255,0.2)" }}>
      │
    </div>
  );
}

/* ── Custom Tab Nav Button ─────────────────────────────────────────── */
function TabButton({ active, onClick, children }) {
  return (
    <button
      onClick={onClick}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 6,
        padding: "12px 16px",
        background: active ? "rgba(0,212,255,0.06)" : "transparent",
        border: "none",
        borderBottom: `2px solid ${active ? "#ff4d6d" : "transparent"}`,
        color: active ? "#fff" : "rgba(255,255,255,0.45)",
        cursor: "pointer",
        fontSize: 11.5,
        fontWeight: active ? 700 : 500,
        transition: "all 0.2s ease",
        outline: "none"
      }}
      className="tab-nav-btn"
      onMouseEnter={e => {
        if (!active) e.currentTarget.style.color = "rgba(255,255,255,0.85)";
      }}
      onMouseLeave={e => {
        if (!active) e.currentTarget.style.color = "rgba(255,255,255,0.45)";
      }}
    >
      {children}
    </button>
  );
}
