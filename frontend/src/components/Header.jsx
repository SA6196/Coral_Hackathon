/**
 * Header.jsx
 * ─────────────────────────────────────────────────────────────────────
 * Features:
 *   • Clickable source badges → opens token input modal for that source
 *   • Live Refresh Indicator — 30s countdown, auto-invalidates Coral cache
 *   • Export Report button — JSON download + Print/PDF
 * ─────────────────────────────────────────────────────────────────────
 */
import { useEffect, useState, useCallback, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { FaShieldAlt, FaGithub, FaSlack } from "react-icons/fa";
import { MdSecurity } from "react-icons/md";
import {
  FiRefreshCw, FiDownload, FiX, FiEye, FiEyeOff,
  FiCheck, FiExternalLink, FiPrinter, FiFileText,
  FiAlertTriangle, FiChevronDown,
} from "react-icons/fi";
import { refreshCache, configSources, getExportReport, syncRealData } from "../services/api";

/* ── Live clock ──────────────────────────────────────────────────────── */
function LiveClock() {
  const [time, setTime] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return (
    <span className="header-time">
      {time.toLocaleTimeString("en-US", { hour12: false })} UTC
    </span>
  );
}

/* ── Token Input Modal ──────────────────────────────────────────────── */
const SOURCE_META = {
  github: {
    label: "GitHub",
    color: "#58a6ff",
    icon: <FaGithub size={18} />,
    fields: [
      { key: "repo", label: "Repository", placeholder: "owner/repo-name", type: "text", help: "e.g. acme-corp/backend-api" },
      { key: "token", label: "Personal Access Token", placeholder: "ghp_xxxxxxxxxxxx", type: "password", help: "Needs repo + read:org scopes" },
    ],
    docsUrl: "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token",
    envVar: "GITHUB_TOKEN",
  },
  slack: {
    label: "Slack",
    color: "#e01e5a",
    icon: <FaSlack size={18} />,
    fields: [
      { key: "channel", label: "Channel Name", placeholder: "#security-alerts", type: "text", help: "Channel to monitor" },
      { key: "token", label: "Bot OAuth Token", placeholder: "xoxb-xxxxxxxxxxxx", type: "password", help: "From Slack App settings" },
    ],
    docsUrl: "https://api.slack.com/authentication/basics",
    envVar: "SLACK_BOT_TOKEN",
  },
  osv: {
    label: "OSV Database",
    color: "#f59e0b",
    icon: <span style={{ fontSize: 18 }}>⚡</span>,
    fields: [],
    note: "OSV is a public API — no credentials required. Coral queries it automatically at https://api.osv.dev/v1",
    envVar: null,
    isPublic: true,
  },
  notion: {
    label: "Notion",
    color: "#e2e8f0",
    icon: <span style={{ fontSize: 18 }}>📄</span>,
    fields: [
      { key: "db", label: "Policy Database ID", placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", type: "text", help: "From the Notion database URL" },
      { key: "token", label: "Integration Token", placeholder: "secret_xxxxxxxxxxxx", type: "password", help: "Notion → Settings → Integrations" },
    ],
    docsUrl: "https://developers.notion.com/docs/create-a-notion-integration",
    envVar: "NOTION_TOKEN",
  },
};

function PasswordInput({ value, onChange, placeholder, id }) {
  const [show, setShow] = useState(false);
  return (
    <div style={{ position: "relative" }}>
      <input
        id={id}
        type={show ? "text" : "password"}
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        style={{
          width: "100%", boxSizing: "border-box",
          background: "rgba(0,0,0,0.4)", border: "1px solid rgba(255,255,255,0.12)",
          borderRadius: 8, padding: "9px 36px 9px 12px", fontSize: 13,
          color: "rgba(255,255,255,0.85)", outline: "none", fontFamily: "monospace",
        }}
      />
      <button
        type="button"
        onClick={() => setShow(s => !s)}
        style={{
          position: "absolute", right: 10, top: "50%", transform: "translateY(-50%)",
          background: "transparent", border: "none", cursor: "pointer",
          color: "rgba(255,255,255,0.35)", padding: 0,
        }}
        aria-label={show ? "Hide" : "Show"}
      >
        {show ? <FiEyeOff size={13} /> : <FiEye size={13} />}
      </button>
    </div>
  );
}

function TokenModal({ sourceId, onClose, onSaved }) {
  const meta = SOURCE_META[sourceId];
  // Pre-fill with any values already saved in localStorage
  const stored = JSON.parse(localStorage.getItem(`coral_tokens_${sourceId}`) || "null") || {};
  const [values, setValues] = useState(stored);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  const handleSave = async () => {
    if (meta.isPublic) { onClose(); return; }
    setSaving(true);
    try {
      // Persist to localStorage first for reload persistence
      localStorage.setItem(`coral_tokens_${sourceId}`, JSON.stringify(values));
      await configSources({ [sourceId]: values });
      setSaved(true);
      if (onSaved) onSaved();
      setTimeout(onClose, 1200);
    } catch {
      // Still save to localStorage even if backend is temporarily down
      localStorage.setItem(`coral_tokens_${sourceId}`, JSON.stringify(values));
      setSaved(true);
      if (onSaved) onSaved();
      setTimeout(onClose, 1200);
    } finally {
      setSaving(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      style={{
        position: "fixed", inset: 0, zIndex: 9999,
        background: "rgba(0,0,0,0.75)", backdropFilter: "blur(8px)",
        display: "flex", alignItems: "center", justifyContent: "center",
        padding: 20,
      }}
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.92, y: 20 }}
        animate={{ scale: 1, y: 0 }}
        exit={{ scale: 0.92, y: 20 }}
        transition={{ duration: 0.22 }}
        onClick={e => e.stopPropagation()}
        style={{
          background: "rgba(8,12,28,0.98)",
          border: `1px solid ${meta.color}40`,
          borderRadius: 16, padding: 28,
          maxWidth: 460, width: "100%",
          boxShadow: `0 24px 64px rgba(0,0,0,0.7), 0 0 0 1px ${meta.color}20`,
        }}
        role="dialog"
        aria-label={`Configure ${meta.label}`}
      >
        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
          <div style={{
            width: 44, height: 44, borderRadius: 12, flexShrink: 0,
            background: `${meta.color}15`, border: `1px solid ${meta.color}30`,
            display: "flex", alignItems: "center", justifyContent: "center",
            color: meta.color,
          }}>
            {meta.icon}
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 16, fontWeight: 700, color: "rgba(255,255,255,0.9)" }}>
              Configure {meta.label}
            </div>
            <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)", marginTop: 2 }}>
              {meta.envVar ? `Env var: ${meta.envVar}` : "Public API — no credentials needed"}
            </div>
          </div>
          <button
            onClick={onClose}
            style={{ background: "transparent", border: "none", cursor: "pointer", color: "rgba(255,255,255,0.4)", padding: 4 }}
            aria-label="Close"
          >
            <FiX size={18} />
          </button>
        </div>

        {/* Public source note */}
        {meta.isPublic && (
          <div style={{
            background: "rgba(16,185,129,0.06)", border: "1px solid rgba(16,185,129,0.2)",
            borderRadius: 10, padding: "14px 16px", fontSize: 13, color: "#10b981",
            lineHeight: 1.6, marginBottom: 20,
          }}>
            ✅ {meta.note}
          </div>
        )}

        {/* YAML env preview */}
        {meta.envVar && (
          <div style={{
            background: "rgba(0,0,0,0.4)", border: "1px solid rgba(14,165,233,0.15)",
            borderRadius: 8, padding: "8px 14px", marginBottom: 18,
            fontFamily: "monospace", fontSize: 11, color: "#8b5cf6",
          }}>
            <span style={{ color: "rgba(255,255,255,0.3)" }}># coral-sources.yaml</span><br />
            {"  auth:\n    type: bearer_token\n    env_var: "}<span style={{ color: "#f59e0b" }}>{meta.envVar}</span>
          </div>
        )}

        {/* Fields */}
        {meta.fields.map(f => (
          <div key={f.key} style={{ marginBottom: 16 }}>
            <label style={{ display: "block", fontSize: 11, color: "rgba(255,255,255,0.5)", marginBottom: 6 }}>
              {f.label}
              <span style={{ color: "rgba(255,255,255,0.25)", marginLeft: 8 }}>— {f.help}</span>
            </label>
            {f.type === "password" ? (
              <PasswordInput
                id={`modal-${sourceId}-${f.key}`}
                value={values[f.key] || ""}
                onChange={v => setValues(prev => ({ ...prev, [f.key]: v }))}
                placeholder={f.placeholder}
              />
            ) : (
              <input
                id={`modal-${sourceId}-${f.key}`}
                type="text"
                value={values[f.key] || ""}
                onChange={e => setValues(prev => ({ ...prev, [f.key]: e.target.value }))}
                placeholder={f.placeholder}
                style={{
                  width: "100%", boxSizing: "border-box",
                  background: "rgba(0,0,0,0.4)", border: "1px solid rgba(255,255,255,0.12)",
                  borderRadius: 8, padding: "9px 12px", fontSize: 13,
                  color: "rgba(255,255,255,0.85)", outline: "none",
                }}
              />
            )}
          </div>
        ))}

        {/* Docs link */}
        {meta.docsUrl && (
          <a href={meta.docsUrl} target="_blank" rel="noopener noreferrer"
            style={{ fontSize: 11, color: meta.color, textDecoration: "none", display: "inline-flex", alignItems: "center", gap: 4, marginBottom: 20 }}>
            <FiExternalLink size={10} /> How to get credentials
          </a>
        )}

        {/* Buttons */}
        <div style={{ display: "flex", gap: 10, marginTop: meta.docsUrl ? 8 : 0 }}>
          {!meta.isPublic && (
            <button
              onClick={handleSave}
              disabled={saving}
              id={`save-token-${sourceId}`}
              style={{
                flex: 1, background: `linear-gradient(135deg, ${meta.color}cc, ${meta.color}88)`,
                border: "none", borderRadius: 9, padding: "10px 20px",
                color: "#000", fontWeight: 700, fontSize: 13, cursor: "pointer",
                display: "flex", alignItems: "center", justifyContent: "center", gap: 6,
              }}
            >
              {saved ? <><FiCheck size={13} /> Saved!</> : saving ? "Saving…" : <><FiCheck size={13} /> Save & Connect</>}
            </button>
          )}
          <button
            onClick={onClose}
            style={{
              flex: meta.isPublic ? 1 : 0, padding: "10px 18px",
              background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.1)",
              borderRadius: 9, color: "rgba(255,255,255,0.6)", fontSize: 13, cursor: "pointer",
            }}
          >
            {meta.isPublic ? "Got it" : "Cancel"}
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
}

/* ── Live Refresh Indicator ─────────────────────────────────────────── */
const REFRESH_INTERVAL = 30;

function LiveRefreshIndicator({ onRefreshed }) {
  const [countdown,  setCountdown]  = useState(REFRESH_INTERVAL);
  const [refreshing, setRefreshing] = useState(false);
  const [lastTime,   setLastTime]   = useState(null);
  const doRefreshRef = useRef(null);

  const doRefresh = useCallback(async () => {
    setRefreshing(true);
    try {
      await refreshCache();
      if (onRefreshed) onRefreshed();
    } catch { /* backend may be off */ }
    setRefreshing(false);
    setLastTime(new Date());
    setCountdown(REFRESH_INTERVAL);
  }, [onRefreshed]);

  doRefreshRef.current = doRefresh;

  useEffect(() => {
    const t = setInterval(() => {
      setCountdown(c => {
        if (c <= 1) { doRefreshRef.current(); return REFRESH_INTERVAL; }
        return c - 1;
      });
    }, 1000);
    return () => clearInterval(t);
  }, []);

  const pct = ((REFRESH_INTERVAL - countdown) / REFRESH_INTERVAL) * 100;

  return (
    <div
      style={{
        display: "flex", alignItems: "center", gap: 8,
        background: "rgba(14,165,233,0.06)",
        border: "1px solid rgba(14,165,233,0.2)",
        borderRadius: 8, padding: "5px 10px",
      }}
      title={lastTime ? `Last refreshed: ${lastTime.toLocaleTimeString()}` : "Auto-refreshes Coral cache every 30s"}
    >
      {/* Pulsing status dot */}
      <div style={{ position: "relative", width: 8, height: 8, flexShrink: 0 }}>
        <div style={{
          width: 8, height: 8, borderRadius: "50%",
          background: refreshing ? "#f59e0b" : "#10b981",
          boxShadow: `0 0 6px ${refreshing ? "#f59e0b" : "#10b981"}80`,
        }} />
        {!refreshing && (
          <motion.div
            animate={{ scale: [1, 1.9, 1], opacity: [0.7, 0, 0.7] }}
            transition={{ duration: 2, repeat: Infinity }}
            style={{
              position: "absolute", inset: -2, borderRadius: "50%",
              background: "#10b98130", pointerEvents: "none",
            }}
          />
        )}
      </div>

      <span style={{ fontSize: 10, color: "rgba(255,255,255,0.5)", whiteSpace: "nowrap" }}>
        {refreshing ? "Refreshing…" : `Refresh ${countdown}s`}
      </span>

      {/* Progress bar */}
      <div style={{ width: 36, height: 2.5, background: "rgba(14,165,233,0.15)", borderRadius: 2, overflow: "hidden" }}>
        <div style={{
          height: "100%", width: `${pct}%`,
          background: "linear-gradient(90deg,#0ea5e9,#10b981)",
          borderRadius: 2, transition: "width 1s linear",
        }} />
      </div>

      {/* Manual trigger */}
      <button
        onClick={() => doRefreshRef.current()}
        disabled={refreshing}
        style={{
          background: "transparent", border: "none", cursor: "pointer",
          color: "#0ea5e9", padding: 0, display: "flex", alignItems: "center",
        }}
        title="Refresh now"
        id="header-manual-refresh"
        aria-label="Refresh Coral cache now"
      >
        <FiRefreshCw size={11} style={{ animation: refreshing ? "spin 0.8s linear infinite" : "none" }} />
      </button>
    </div>
  );
}

/* ── Sync Live Data Button ────────────────────────────────────────────── */
function SyncLiveDataButton() {
  const [syncing, setSyncing] = useState(false);
  const [done, setDone] = useState(false);

  const handleSync = async () => {
    setSyncing(true);
    try {
      await syncRealData();
      setDone(true);
      setTimeout(() => {
        setDone(false);
        window.location.reload(); // Reload to pick up all the new live data seamlessly
      }, 1500);
    } catch (err) {
      alert("Failed to sync live data. Please check backend connection and keys.");
      setSyncing(false);
    }
  };

  return (
    <motion.button
      whileHover={{ scale: 1.04 }}
      whileTap={{ scale: 0.97 }}
      onClick={handleSync}
      disabled={syncing}
      style={{
        display: "flex", alignItems: "center", gap: 6,
        background: done 
          ? "linear-gradient(135deg,rgba(16,185,129,0.15),rgba(16,185,129,0.08))"
          : "linear-gradient(135deg,rgba(245,158,11,0.15),rgba(245,158,11,0.05))",
        border: done ? "1px solid rgba(16,185,129,0.4)" : "1px solid rgba(245,158,11,0.4)",
        borderRadius: 8, padding: "6px 12px",
        color: done ? "#10b981" : "#f59e0b",
        fontSize: 11, fontWeight: 600, cursor: syncing ? "wait" : "pointer",
        whiteSpace: "nowrap",
      }}
    >
      {done ? (
        <><FiCheck size={12} /> Synced & Reloading!</>
      ) : syncing ? (
        <><FiRefreshCw size={12} style={{ animation: "spin 1s linear infinite" }} /> Fetching APIs…</>
      ) : (
        <><span>⚡</span> Sync Live Data</>
      )}
    </motion.button>
  );
}

/* ── Export Report Button ─────────────────────────────────────────────── */
function ExportReportButton() {
  const [open,        setOpen]       = useState(false);
  const [downloading, setDownloading]= useState(false);
  const [done,        setDone]       = useState(false);

  const downloadJson = async () => {
    setOpen(false);
    setDownloading(true);
    try {
      const res  = await getExportReport();
      const blob = new Blob([JSON.stringify(res.data.report, null, 2)], { type: "application/json" });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href     = url;
      a.download = `coral-security-report-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setDone(true);
      setTimeout(() => setDone(false), 2500);
    } catch {
      alert("Export failed — is the backend running on port 5000?");
    }
    setDownloading(false);
  };

  const printPdf = async () => {
    setOpen(false);
    setDownloading(true);
    try {
      const res = await getExportReport();
      const report = res.data?.report;
      const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Coral Security Report — ${new Date().toLocaleDateString()}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: #0f172a; background: #fff; margin: 0; padding: 24px 32px; }
    h1 { font-size: 24px; font-weight: 800; color: #0f172a; margin-bottom: 4px; }
    .subtitle { font-size: 12px; color: #64748b; margin-bottom: 24px; }
    .section { margin-bottom: 28px; }
    .section h2 { font-size: 14px; font-weight: 700; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; margin-bottom: 12px; color: #0f172a; }
    .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
    .stat-card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; }
    .stat-label { font-size: 10px; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }
    .stat-val { font-size: 26px; font-weight: 800; color: #0f172a; margin-top: 4px; }
    .incident { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px 16px; margin-bottom: 10px; page-break-inside: avoid; border-left: 4px solid #e11d48; }
    .incident.high { border-left-color: #ea580c; }
    .incident.medium { border-left-color: #f59e0b; }
    .incident-id { font-size: 10px; font-weight: 700; color: #e11d48; }
    .incident-title { font-size: 13px; font-weight: 600; margin: 4px 0; }
    .incident-meta { font-size: 11px; color: #64748b; display: flex; gap: 16px; margin-top: 6px; }
    .score { font-weight: 700; color: #0f172a; }
    .ai-summary { font-size: 11px; color: #334155; background: #f1f5f9; border-radius: 6px; padding: 8px 10px; margin-top: 8px; line-height: 1.6; }
    .footer { font-size: 10px; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 12px; margin-top: 24px; display: flex; justify-content: space-between; }
    @page { size: A4; margin: 15mm; }
    @media print { body { padding: 0; } }
  </style>
</head>
<body>
  <h1>🛡 Coral Security Report</h1>
  <div class="subtitle">Generated: ${new Date().toLocaleString()} · Multi-Source Enterprise Threat Intelligence</div>
  <div class="stat-grid">
    <div class="stat-card"><div class="stat-label">Critical CVEs</div><div class="stat-val" style="color:#e11d48">${report?.critical_cves ?? 0}</div></div>
    <div class="stat-card"><div class="stat-label">High Severity</div><div class="stat-val" style="color:#ea580c">${report?.high_severity ?? 0}</div></div>
    <div class="stat-card"><div class="stat-label">Secret Leaks</div><div class="stat-val" style="color:#8b5cf6">${report?.secrets_found ?? 0}</div></div>
    <div class="stat-card"><div class="stat-label">Policy Violations</div><div class="stat-val" style="color:#f59e0b">${report?.policy_violations ?? 0}</div></div>
  </div>
  ${report?.top_risk_incident ? `
  <div class="section">
    <h2>⚠ Top Risk Incident</h2>
    <div class="incident">
      <div class="incident-id">${report.top_risk_incident.incident_id}</div>
      <div class="incident-title">${report.top_risk_incident.pr_details?.title || "Unknown PR"}</div>
      <div class="incident-meta">
        <span>Developer: <b>${report.top_risk_incident.pr_details?.developer || "Unknown"}</b></span>
        <span>Package: <b>${report.top_risk_incident.package_details?.package_name || "N/A"}</b></span>
        <span>Risk Score: <b class="score">${report.top_risk_incident.risk_score}</b></span>
      </div>
      ${report.top_risk_incident.ai_summary ? `<div class="ai-summary">${report.top_risk_incident.ai_summary}</div>` : ""}
    </div>
  </div>` : ""}
  <div class="footer">
    <span>Coral Security Command Center · Enterprise Threat Intelligence</span>
    <span>Printed: ${new Date().toLocaleString()}</span>
  </div>
</body>
</html>`;
      const iframe = document.createElement("iframe");
      iframe.style.position = "fixed";
      iframe.style.right = "0";
      iframe.style.bottom = "0";
      iframe.style.width = "0";
      iframe.style.height = "0";
      iframe.style.border = "0";
      document.body.appendChild(iframe);
      
      iframe.contentWindow.document.open();
      iframe.contentWindow.document.write(html);
      iframe.contentWindow.document.close();
      iframe.contentWindow.focus();
      
      setTimeout(() => {
        iframe.contentWindow.print();
        setTimeout(() => document.body.removeChild(iframe), 2000);
      }, 500);
    } catch {
      alert("Print failed — is the backend running on port 5000?");
    }
    setDownloading(false);
  };

  return (
    <div style={{ position: "relative" }}>
      <motion.button
        id="export-report-btn"
        whileHover={{ scale: 1.04 }}
        whileTap={{ scale: 0.97 }}
        onClick={() => setOpen(o => !o)}
        disabled={downloading}
        aria-label="Export report"
        aria-expanded={open}
        style={{
          display: "flex", alignItems: "center", gap: 6,
          background: done
            ? "linear-gradient(135deg,rgba(16,185,129,0.15),rgba(16,185,129,0.08))"
            : "linear-gradient(135deg,rgba(14,165,233,0.1),rgba(139,92,246,0.1))",
          border: done ? "1px solid rgba(16,185,129,0.4)" : "1px solid rgba(14,165,233,0.3)",
          borderRadius: 8, padding: "6px 12px",
          color: done ? "#10b981" : "#0ea5e9",
          fontSize: 11, fontWeight: 600, cursor: downloading ? "wait" : "pointer",
          whiteSpace: "nowrap",
        }}
      >
        {done ? (
          <><FiCheck size={12} /> Downloaded!</>
        ) : downloading ? (
          <><FiDownload size={12} style={{ animation: "pulse 0.6s ease-in-out infinite" }} /> Exporting…</>
        ) : (
          <><FiDownload size={12} /> Export <FiChevronDown size={9} style={{ opacity: 0.6 }} /></>
        )}
      </motion.button>

      <AnimatePresence>
        {open && (
          <>
            <div style={{ position: "fixed", inset: 0, zIndex: 98 }} onClick={() => setOpen(false)} />
            <motion.div
              initial={{ opacity: 0, y: -6, scale: 0.96 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -6, scale: 0.96 }}
              transition={{ duration: 0.15 }}
              style={{
                position: "absolute", top: "calc(100% + 6px)", right: 0,
                background: "rgba(8,12,28,0.98)", border: "1px solid rgba(14,165,233,0.2)",
                borderRadius: 10, padding: 6, zIndex: 99, minWidth: 180,
                boxShadow: "0 8px 32px rgba(0,0,0,0.6)",
              }}
            >
              <ExportOption icon={FiFileText} label="JSON Report" sub="Full structured data" color="#0ea5e9" onClick={downloadJson} />
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
}

function ExportOption({ icon: Icon, label, sub, color, onClick }) {
  return (
    <button
      onClick={onClick}
      style={{
        width: "100%", display: "flex", alignItems: "center", gap: 10,
        background: "transparent", border: "none", padding: "8px 10px",
        borderRadius: 7, cursor: "pointer", textAlign: "left",
        color: "rgba(255,255,255,0.8)", transition: "background 0.15s",
      }}
      onMouseEnter={e => e.currentTarget.style.background = `${color}12`}
      onMouseLeave={e => e.currentTarget.style.background = "transparent"}
    >
      <div style={{
        width: 28, height: 28, borderRadius: 7, flexShrink: 0,
        background: `${color}15`, border: `1px solid ${color}25`,
        display: "flex", alignItems: "center", justifyContent: "center",
      }}>
        <Icon size={13} style={{ color }} />
      </div>
      <div>
        <div style={{ fontSize: 12, fontWeight: 600 }}>{label}</div>
        <div style={{ fontSize: 9.5, color: "rgba(255,255,255,0.35)", marginTop: 1 }}>{sub}</div>
      </div>
    </button>
  );
}

/* ── Clickable Source Badge ──────────────────────────────────────────── */
function SourceBadge({ id, className, children, onConfigure }) {
  const meta = SOURCE_META[id];
  return (
    <motion.button
      className={`source-badge ${className}`}
      onClick={() => onConfigure(id)}
      whileHover={{ scale: 1.06, y: -1 }}
      whileTap={{ scale: 0.97 }}
      title={`Click to configure ${meta.label} ${meta.isPublic ? "(public — no auth)" : "token"}`}
      style={{
        cursor: "pointer", border: "none",
        outline: "none", position: "relative",
      }}
      aria-label={`Configure ${meta.label}`}
      id={`badge-${id}`}
    >
      {children}
      {/* Small "click to configure" hint */}
      {!meta.isPublic && (
        <span style={{
          position: "absolute", top: -6, right: -4,
          width: 8, height: 8, borderRadius: "50%",
          background: "#f59e0b",
          boxShadow: "0 0 6px #f59e0b",
          border: "1px solid rgba(0,0,0,0.5)",
        }} title="Token required" />
      )}
      {meta.isPublic && (
        <span style={{
          position: "absolute", top: -6, right: -4,
          width: 8, height: 8, borderRadius: "50%",
          background: "#10b981",
          boxShadow: "0 0 6px #10b981",
          border: "1px solid rgba(0,0,0,0.5)",
        }} title="Public — connected" />
      )}
    </motion.button>
  );
}

/* ── Main Header ──────────────────────────────────────────────────────── */
function Header({ onRefreshed, onLogout }) {
  const [modalSource, setModalSource] = useState(null);

  // On mount: re-hydrate backend with any tokens saved in localStorage
  useEffect(() => {
    const sourcesToRestore = ["github", "slack", "notion"];
    const toSend = {};
    let hasAny = false;
    sourcesToRestore.forEach(id => {
      const stored = JSON.parse(localStorage.getItem(`coral_tokens_${id}`) || "null");
      if (stored && Object.values(stored).some(v => v)) {
        toSend[id] = stored;
        hasAny = true;
      }
    });
    if (hasAny) {
      configSources(toSend).catch(() => {}); // Best-effort restore
    }
  }, []);

  return (
    <>
      <header className="header">
        <div className="header-bg-glow" aria-hidden="true" />

        {/* Top status bar */}
        <div className="header-top-bar" style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <div className="header-brand">
            <MdSecurity size={16} />
            CORAL ENTERPRISE AGENT · TRACK 1
          </div>

          {/* Centre: live refresh indicator */}
          <LiveRefreshIndicator onRefreshed={onRefreshed} />

          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 10 }}>
            {/* Sync Live button */}
            <SyncLiveDataButton />
            {/* Export button */}
            <ExportReportButton />
            {/* Logout button */}
            {onLogout && (
              <button 
                className="logout-btn" 
                onClick={onLogout}
                style={{
                  background: "rgba(255, 77, 109, 0.1)",
                  border: "1px solid rgba(255, 77, 109, 0.3)",
                  color: "#ff4d6d",
                  padding: "5px 10px",
                  borderRadius: "6px",
                  cursor: "pointer",
                  fontSize: "11px",
                  fontWeight: "600",
                  display: "flex",
                  alignItems: "center",
                  gap: "4px",
                  transition: "background 0.2s"
                }}
                onMouseEnter={e => e.currentTarget.style.background = "rgba(255, 77, 109, 0.2)"}
                onMouseLeave={e => e.currentTarget.style.background = "rgba(255, 77, 109, 0.1)"}
              >
                Log Out
              </button>
            )}
            <div className="header-status">
              <div className="status-dot" />
              LIVE
            </div>
            <LiveClock />
          </div>
        </div>

        {/* Central hero */}
        <div className="header-center">
          <div className="header-icon-wrap">
            <div className="header-shield-ring" aria-hidden="true" />
            <FaShieldAlt className="header-shield-icon" aria-label="Security Shield" />
          </div>

          <h1 className="header-title">
            Coral Security<br />Command Center
          </h1>

          <p className="header-subtitle">
            Multi-Source Enterprise Threat Intelligence Platform
          </p>

          {/* Hint text */}
          <p style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", marginBottom: 12, marginTop: -4 }}>
            Click any source badge below to configure your token ↓
          </p>

          {/* Clickable source badges */}
          <div className="header-badges">
            <SourceBadge id="github" className="badge-github" onConfigure={setModalSource}>
              <FaGithub size={12} /> GitHub
            </SourceBadge>
            <SourceBadge id="slack" className="badge-slack" onConfigure={setModalSource}>
              <FaSlack size={12} /> Slack
            </SourceBadge>
            <SourceBadge id="osv" className="badge-osv" onConfigure={setModalSource}>
              <span>⚡</span> OSV Database
            </SourceBadge>
            <SourceBadge id="notion" className="badge-notion" onConfigure={setModalSource}>
              <span>📄</span> Notion Policies
            </SourceBadge>
            <div className="source-badge badge-coral">
              <span>◈</span> Powered by Coral
            </div>
          </div>
        </div>

        {/* Animated scan line */}
        <div className="scan-bar" aria-hidden="true">
          <div className="scan-bar-fill" />
        </div>
      </header>

      {/* Token modal */}
      <AnimatePresence>
        {modalSource && (
          <TokenModal
            sourceId={modalSource}
            onClose={() => setModalSource(null)}
            onSaved={() => { if (onRefreshed) onRefreshed(); }}
          />
        )}
      </AnimatePresence>
    </>
  );
}

export default Header;