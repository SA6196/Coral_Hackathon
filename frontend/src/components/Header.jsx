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
import { createPortal } from "react-dom";
import { motion, AnimatePresence } from "framer-motion";
import { FaShieldAlt, FaGithub, FaSlack } from "react-icons/fa";
import { MdSecurity } from "react-icons/md";
import {
  FiRefreshCw, FiDownload, FiX, FiEye, FiEyeOff,
  FiCheck, FiExternalLink, FiPrinter, FiFileText,
  FiAlertTriangle, FiChevronDown,
} from "react-icons/fi";
import { refreshCache, configSources, getExportReport, syncRealData, getDeveloperRisk } from "../services/api";

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
function SyncLiveDataButton({ onRefreshed }) {
  const [syncing, setSyncing] = useState(false);
  const [done, setDone] = useState(false);
  const [syncError, setSyncError] = useState(false);

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
      title={syncError ? "Sync failed — check backend connection & keys" : "Pull live data from all connected sources"}
      style={{
        display: "flex", alignItems: "center", gap: 6,
        background: syncError
          ? "linear-gradient(135deg,rgba(239,68,68,0.15),rgba(239,68,68,0.08))"
          : done
          ? "linear-gradient(135deg,rgba(16,185,129,0.15),rgba(16,185,129,0.08))"
          : "linear-gradient(135deg,rgba(245,158,11,0.15),rgba(245,158,11,0.05))",
        border: syncError
          ? "1px solid rgba(239,68,68,0.4)"
          : done ? "1px solid rgba(16,185,129,0.4)" : "1px solid rgba(245,158,11,0.4)",
        borderRadius: 8, padding: "6px 12px",
        color: syncError ? "#ef4444" : done ? "#10b981" : "#f59e0b",
        fontSize: 11, fontWeight: 600, cursor: syncing ? "wait" : "pointer",
        whiteSpace: "nowrap",
        transition: "all 0.3s",
      }}
    >
      {syncError ? (
        <>⚠️ Sync failed — check keys</>
      ) : done ? (
        <><FiCheck size={12} /> Synced!</>
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
  const [dropPos,     setDropPos]    = useState({ top: 0, right: 0 });
  const btnRef = useRef(null);

  /* ── JSON download (unchanged from original) ── */
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

  /* ── PDF download — all users / vulnerabilities / risk scores ── */
  const downloadPdf = async () => {
    setOpen(false);
    setDownloading(true);
    try {
      const [reportRes, devRiskRes] = await Promise.allSettled([
        getExportReport(),
        getDeveloperRisk(),
      ]);
      /* ── API data — fix field names to match actual backend response ── */
      // /api/export-report → res.data.report.executive_summary.{critical, high, secrets_leaked, policy_violations}
      // /api/developer-risk → res.data.profiles[].{avg_risk_score, total_prs, high_count, secret_leaks, ...}
      const report  = reportRes.status  === "fulfilled" ? reportRes.value.data?.report   : null;
      const devRisk = devRiskRes.status === "fulfilled" ? (devRiskRes.value.data?.profiles ?? devRiskRes.value.data?.data ?? []) : [];
      const execSum = report?.executive_summary ?? {};

      const scoreColor = (s) => {
        if (!s && s !== 0) return "#64748b";
        if (s >= 80) return "#e11d48";
        if (s >= 60) return "#ea580c";
        if (s >= 40) return "#f59e0b";
        return "#10b981";
      };
      const scoreLabel = (s) => {
        if (!s && s !== 0) return "Unknown";
        if (s >= 80) return "CRITICAL";
        if (s >= 60) return "HIGH";
        if (s >= 40) return "MEDIUM";
        return "LOW";
      };
      const esc = (str) => String(str || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");

      /* ── Developer rows — using correct field names from /api/developer-risk ── */
      const userRows = (Array.isArray(devRisk) ? devRisk : [])
        .sort((a, b) => (b.avg_risk_score || b.risk_score || 0) - (a.avg_risk_score || a.risk_score || 0))
        .map((u, i) => {
          const sc  = u.avg_risk_score ?? u.risk_score ?? u.score ?? 0;
          const col = scoreColor(sc);
          const lbl = scoreLabel(sc);
          // packages_affected is an array of strings
          const pkgs = Array.isArray(u.packages_affected) ? u.packages_affected.join(", ") : (u.packages || "—");
          // recent_incidents is [{id, title, risk_score}]
          const incidents = Array.isArray(u.recent_incidents) ? u.recent_incidents : [];
          const incHtml = incidents.length
            ? incidents.map(inc => `<div class="vuln-item"><span class="vuln-id">${esc(inc.id)}</span><span class="vuln-pkg">${esc(inc.title)}</span><span class="vuln-sev" style="color:${scoreColor(inc.risk_score)}">Score: ${esc(inc.risk_score)}</span></div>`).join("")
            : `<div class="vuln-none">No recent incidents on record</div>`;
          return `<tr class="user-row">
            <td class="rank">${i+1}</td>
            <td class="dev-name">${esc(u.developer||u.author||u.name||"Unknown")}</td>
            <td><span class="score-badge" style="background:${col}22;color:${col};border-color:${col}55">${sc} — ${lbl}</span></td>
            <td class="num">${esc(u.total_prs ?? u.total_incidents ?? u.incident_count ?? 0)}</td>
            <td class="num">${esc(u.high_count ?? u.high_risk_prs ?? 0)}</td>
            <td class="num">${esc(u.secret_leaks ?? u.secrets_found ?? 0)}</td>
            <td class="num">${esc(u.critical_count ?? u.vuln_count ?? 0)}</td>
          </tr>
          <tr class="vuln-row"><td colspan="7"><div class="vuln-detail">
            <strong style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.06em">
              Recent Incidents &nbsp;|&nbsp; Packages: ${esc(pkgs)}
            </strong>
            ${incHtml}
          </div></td></tr>`;
        }).join("");

      /* ── Incident rows — using correct field names from /api/export-report ── */
      const incidentRows = (Array.isArray(report?.incidents) ? report.incidents : [])
        .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
        .slice(0, 50)
        .map(inc => {
          const sc  = inc.risk_score ?? 0;
          const col = scoreColor(sc);
          const sev = inc.vulnerability?.severity || scoreLabel(sc);
          return `<tr>
            <td class="inc-id">${esc(inc.incident_id||inc.id)}</td>
            <td>${esc(inc.pr_details?.title||inc.title||"—")}</td>
            <td>${esc(inc.pr_details?.developer||inc.developer||"—")}</td>
            <td>${esc(inc.package_details?.package_name||inc.package||"—")}</td>
            <td><span class="score-badge" style="background:${col}22;color:${col};border-color:${col}55">${sc}</span></td>
            <td style="color:${col};font-weight:700">${esc(sev).toUpperCase()}</td>
          </tr>`;
        }).join("");

      /* ── Stat strip — correct paths into executive_summary ── */
      const statCritical  = execSum.critical         ?? 0;
      const statHigh      = execSum.high              ?? 0;
      const statSecrets   = execSum.secrets_leaked    ?? 0;
      const statPolicies  = execSum.policy_violations ?? 0;
      const statDevs      = (Array.isArray(devRisk) ? devRisk : []).length;

      const html = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Coral Security — Full Vulnerability Report ${new Date().toLocaleDateString()}</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;color:#0f172a;background:#fff;padding:28px 36px;font-size:13px}h1{font-size:22px;font-weight:800;margin-bottom:2px}.subtitle{font-size:11px;color:#64748b;margin-bottom:20px}.stat-strip{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}.stat-box{flex:1;min-width:100px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 14px}.stat-lbl{font-size:9px;color:#94a3b8;text-transform:uppercase;letter-spacing:.07em}.stat-val{font-size:24px;font-weight:800;margin-top:3px}.section-title{font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:#0f172a;border-bottom:2px solid #e2e8f0;padding-bottom:6px;margin:24px 0 12px}table{width:100%;border-collapse:collapse;font-size:11.5px}th{background:#f1f5f9;text-align:left;padding:8px 10px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#64748b;border-bottom:1px solid #e2e8f0}td{padding:7px 10px;border-bottom:1px solid #f1f5f9;vertical-align:top}.user-row td{background:#fff;font-weight:500}.vuln-row td{background:#fafafa;padding:0 10px 10px 10px}.vuln-detail{padding:8px 10px;border-left:3px solid #e2e8f0;margin-left:16px}.vuln-item{display:flex;gap:10px;align-items:center;padding:3px 0;border-bottom:1px dashed #f1f5f9;flex-wrap:wrap}.vuln-item:last-child{border-bottom:none}.vuln-id{font-family:monospace;font-size:10px;font-weight:700;color:#6366f1;min-width:90px}.vuln-pkg{font-size:10px;color:#334155;flex:1}.vuln-sev{font-size:10px;font-weight:700;min-width:60px}.vuln-cvss{font-size:9.5px;color:#94a3b8}.vuln-none{font-size:10px;color:#94a3b8;font-style:italic}.score-badge{display:inline-block;padding:2px 9px;border-radius:30px;font-size:10px;font-weight:700;border:1px solid}.rank{font-weight:800;color:#94a3b8;width:28px}.dev-name{font-weight:700}.num{text-align:center;color:#334155}.inc-id{font-family:monospace;font-size:10px;font-weight:700;color:#6366f1}.footer{font-size:9.5px;color:#94a3b8;border-top:1px solid #e2e8f0;padding-top:10px;margin-top:28px;display:flex;justify-content:space-between}@page{size:A4;margin:14mm}@media print{body{padding:0}}</style></head><body>
<h1>🛡 Coral Security — Vulnerability &amp; Risk Report</h1>
<div class="subtitle">Generated: ${new Date().toLocaleString()} &nbsp;&middot;&nbsp; Multi-Source Enterprise Threat Intelligence &nbsp;&middot;&nbsp; Coral Security Command Center</div>
<div class="stat-strip">
  <div class="stat-box"><div class="stat-lbl">Critical CVEs</div><div class="stat-val" style="color:#e11d48">${statCritical}</div></div>
  <div class="stat-box"><div class="stat-lbl">High Severity</div><div class="stat-val" style="color:#ea580c">${statHigh}</div></div>
  <div class="stat-box"><div class="stat-lbl">Secret Leaks</div><div class="stat-val" style="color:#8b5cf6">${statSecrets}</div></div>
  <div class="stat-box"><div class="stat-lbl">Policy Violations</div><div class="stat-val" style="color:#f59e0b">${statPolicies}</div></div>
  <div class="stat-box"><div class="stat-lbl">Developers Tracked</div><div class="stat-val" style="color:#0ea5e9">${statDevs}</div></div>
</div>
<div class="section-title">👤 Developer Risk Scores &amp; Vulnerabilities</div>
${userRows ? `<table><thead><tr><th>#</th><th>Developer</th><th>Avg Risk Score</th><th>Total PRs</th><th>High Severity</th><th>Secret Leaks</th><th>Critical</th></tr></thead><tbody>${userRows}</tbody></table>` : '<p style="color:#94a3b8;font-size:11px">No developer risk data available.</p>'}
${incidentRows ? `<div class="section-title">⚠ All Incidents (top 50 by risk)</div><table><thead><tr><th>ID</th><th>Title</th><th>Developer</th><th>Package</th><th>Risk Score</th><th>Severity</th></tr></thead><tbody>${incidentRows}</tbody></table>` : ''}
<div class="footer">
  <span>Coral Security Command Center &middot; Enterprise Threat Intelligence &middot; Coral Hackathon 2026</span>
  <span>Printed: ${new Date().toLocaleString()}</span>
</div></body></html>`;

      const iframe = document.createElement("iframe");
      iframe.style.cssText = "position:fixed;right:0;bottom:0;width:0;height:0;border:0;";
      document.body.appendChild(iframe);
      iframe.contentWindow.document.open();
      iframe.contentWindow.document.write(html);
      iframe.contentWindow.document.close();
      iframe.contentWindow.focus();
      setTimeout(() => { iframe.contentWindow.print(); setTimeout(() => document.body.removeChild(iframe), 2500); }, 600);
    } catch (err) {
      console.error(err);
      alert("PDF generation failed — is the backend running?");
    }
    setDownloading(false);
  };

  /* open the dropdown and record button position for portal placement */
  const handleOpen = () => {
    if (btnRef.current) {
      const r = btnRef.current.getBoundingClientRect();
      setDropPos({ top: r.bottom + 6, right: window.innerWidth - r.right });
    }
    setOpen(o => !o);
  };

  return (
    <div style={{ position: "relative" }}>
      <motion.button
        ref={btnRef}
        id="export-report-btn"
        whileHover={{ scale: 1.04 }}
        whileTap={{ scale: 0.97 }}
        onClick={handleOpen}
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

      {/*
        ★ Portal: renders backdrop + dropdown directly into document.body
          This breaks out of ANY stacking context (backdrop-filter, transform, etc.)
          so z-index is always global. Both options are guaranteed clickable.
      */}
      {open && createPortal(
        <>
          {/* invisible backdrop — click to close */}
          <div
            style={{ position: "fixed", inset: 0, zIndex: 99990, cursor: "default" }}
            onClick={() => setOpen(false)}
          />
          {/* dropdown panel */}
          <div
            style={{
              position: "fixed",
              top: dropPos.top,
              right: dropPos.right,
              zIndex: 99999,
              background: "rgba(8,12,28,0.98)",
              border: "1px solid rgba(139,92,246,0.35)",
              borderRadius: 10,
              padding: 6,
              minWidth: 220,
              boxShadow: "0 12px 40px rgba(0,0,0,0.85), 0 0 0 1px rgba(139,92,246,0.1)",
            }}
          >
            <ExportOption
              icon={FiFileText}
              label="JSON Report"
              sub="Full structured data"
              color="#0ea5e9"
              onClick={downloadJson}
            />
            <ExportOption
              icon={FiPrinter}
              label="PDF Report"
              sub="All users · vulnerabilities · risk scores"
              color="#a855f7"
              onClick={downloadPdf}
            />
          </div>
        </>,
        document.body
      )}
    </div>
  );
}

function ExportOption({ icon: Icon, label, sub, color, onClick }) {
  return (
    <button
      onClick={onClick}
      style={{
        width: "100%", display: "flex", alignItems: "center", gap: 10,
        background: "transparent", border: "none", padding: "10px 12px",
        borderRadius: 7, cursor: "pointer", textAlign: "left",
        color: "rgba(255,255,255,0.88)", transition: "background 0.15s",
      }}
      onMouseEnter={e => e.currentTarget.style.background = `${color}18`}
      onMouseLeave={e => e.currentTarget.style.background = "transparent"}
    >
      <div style={{
        width: 30, height: 30, borderRadius: 8, flexShrink: 0,
        background: `${color}15`, border: `1px solid ${color}30`,
        display: "flex", alignItems: "center", justifyContent: "center",
      }}>
        <Icon size={14} style={{ color }} />
      </div>
      <div>
        <div style={{ fontSize: 12.5, fontWeight: 600 }}>{label}</div>
        <div style={{ fontSize: 10, color: "rgba(255,255,255,0.38)", marginTop: 2 }}>{sub}</div>
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

/* ── How To Use Modal ───────────────────────────────────────────────── */
function HowToModal({ onClose }) {
  const steps = [
    { icon: "🔑", title: "Configure Sources", desc: "Click the GitHub, Slack, or Notion badges to enter your API tokens. OSV is public — no token needed." },
    { icon: "⚡", title: "Sync Live Data", desc: "Hit 'Sync Live Data' to pull real-time events from all connected sources into Coral's cache." },
    { icon: "🔍", title: "Search Threats", desc: "Use the NL → SQL search bar to ask questions in plain English — Coral translates them to queries instantly." },
    { icon: "🛡", title: "Review Incidents", desc: "Browse the Incident Feed, click any card to investigate with AI, and follow the remediation steps." },
  ];

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      style={{
        position: "fixed", inset: 0, zIndex: 9999,
        background: "rgba(0,0,0,0.85)", backdropFilter: "blur(12px)",
        display: "flex", alignItems: "flex-start", justifyContent: "center",
        padding: "20px", overflowY: "auto",
      }}
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.91, y: 24 }}
        animate={{ scale: 1, y: 0 }}
        exit={{ scale: 0.91, y: 24 }}
        transition={{ duration: 0.24, type: "spring", stiffness: 260, damping: 22 }}
        onClick={e => e.stopPropagation()}
        style={{
          background: "rgba(8,12,28,0.98)",
          border: "1px solid rgba(16,185,129,0.25)",
          borderRadius: 20, padding: 36,
          maxWidth: 720, width: "100%",
          marginTop: "auto", marginBottom: "auto",
          boxShadow: "0 32px 80px rgba(0,0,0,0.8), 0 0 0 1px rgba(16,185,129,0.08), 0 0 60px rgba(16,185,129,0.06)",
          position: "relative",
        }}
        role="dialog"
        aria-label="How to use Coral Security"
      >
        {/* Close button */}
        <button
          onClick={onClose}
          aria-label="Close"
          style={{
            position: "absolute", top: 16, right: 16,
            background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.1)",
            borderRadius: 8, cursor: "pointer", color: "rgba(255,255,255,0.5)",
            padding: "4px 8px", display: "flex", alignItems: "center",
          }}
        >
          <FiX size={16} />
        </button>

        {/* Header */}
        <div style={{ textAlign: "center", marginBottom: 24 }}>
          <div style={{
            display: "inline-flex", alignItems: "center", justifyContent: "center",
            width: 64, height: 64, borderRadius: 20,
            background: "linear-gradient(135deg,rgba(16,185,129,0.15),rgba(0,212,255,0.15))",
            border: "1px solid rgba(16,185,129,0.25)",
            fontSize: 32, marginBottom: 14,
          }}>▶</div>
          <div style={{
            fontSize: 22, fontWeight: 800,
            background: "linear-gradient(135deg,#fff 0%,#10b981 50%,#00d4ff 100%)",
            WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
            backgroundClip: "text", marginBottom: 6,
          }}>How to Use</div>
          <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)", letterSpacing: "0.12em", textTransform: "uppercase" }}>
            Coral Security Command Center — Demo Walkthrough
          </div>
        </div>

        {/* Video Player */}
        <div style={{
          position: "relative", borderRadius: 14, overflow: "hidden",
          border: "1px solid rgba(16,185,129,0.2)",
          background: "#000", marginBottom: 28,
          boxShadow: "0 8px 32px rgba(0,0,0,0.6), 0 0 20px rgba(16,185,129,0.08)",
        }}>
          <video
            controls
            style={{ width: "100%", display: "block", maxHeight: 400, background: "#000" }}
            preload="metadata"
          >
            <source src="/Coral_video.mp4" type="video/mp4" />
            Your browser does not support the video tag.
          </video>
        </div>

        {/* Step guide */}
        <div style={{ fontSize: 11, fontWeight: 700, color: "rgba(255,255,255,0.35)", textTransform: "uppercase", letterSpacing: "0.14em", marginBottom: 14, textAlign: "center" }}>
          QUICK START GUIDE
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 20 }}>
          {steps.map((step, i) => (
            <div key={i} style={{
              background: "rgba(16,185,129,0.05)",
              border: "1px solid rgba(16,185,129,0.15)",
              borderRadius: 12, padding: "14px 16px",
              display: "flex", gap: 12, alignItems: "flex-start",
            }}>
              <div style={{
                fontSize: 22, flexShrink: 0, lineHeight: 1,
                marginTop: 2,
              }}>{step.icon}</div>
              <div>
                <div style={{ fontSize: 12.5, fontWeight: 700, color: "#10b981", marginBottom: 4 }}>
                  {i + 1}. {step.title}
                </div>
                <div style={{ fontSize: 11, color: "rgba(255,255,255,0.5)", lineHeight: 1.6 }}>
                  {step.desc}
                </div>
              </div>
            </div>
          ))}
        </div>

        <div style={{ textAlign: "center", fontSize: 11, color: "rgba(255,255,255,0.2)" }}>
          Built for Coral Hackathon 2026 · Track 1: Enterprise Agent
        </div>
      </motion.div>
    </motion.div>
  );
}

/* ── About Modal ─────────────────────────────────────────────────────── */
const DEVELOPERS = [
  {
    name: "S. Sohan Kumar",
    role: "Frontend & UI/UX",
    description: "Designed the user interface · Created smooth user journeys · Built responsive frontend screens",
    github: "https://github.com/Sohan-2025",
    linkedin: "https://www.linkedin.com/in/s-sohan-kumar-0377b136a/",
    avatar: "SK",
    color: "#0ea5e9",
  },
  {
    name: "Shivansh Agarwal",
    role: "Backend & API",
    description: "Developed backend services · Handled APIs and database integration · Ensured secure and scalable architecture",
    github: "https://github.com/SA6196",
    linkedin: "https://www.linkedin.com/in/shivansh-agarwal-a76756375",
    avatar: "SA",
    color: "#a855f7",
  },
  {
    name: "Tanmay Shukla",
    role: "Coral Integration, DevOps & QA",
    description: "Integrated Coral features and data sources · Managed deployment and infrastructure · Conducted testing and performance optimization",
    github: "https://github.com/tanmayshukla60-netizen",
    linkedin: "https://www.linkedin.com/in/tanmay-shukla-3703052b7?trk=contact-info",
    avatar: "TS",
    color: "#f59e0b",
  },
  {
    name: "Ramsrivathsan R",
    role: "AI / LLM",
    description: "Designed AI workflows and prompts · Integrated LLMs and AI agents · Built intelligent decision-making capabilities",
    github: "https://github.com/Ramsri12",
    linkedin: "https://www.linkedin.com/in/ramsrivathsan-ramasubramanian-954a38375?utm_source=share_via&utm_content=profile&utm_medium=member_android",
    avatar: "RR",
    color: "#10b981",
  },
];

function AboutModal({ onClose }) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      style={{
        position: "fixed", inset: 0, zIndex: 9999,
        background: "rgba(0,0,0,0.8)", backdropFilter: "blur(10px)",
        display: "flex", alignItems: "flex-start", justifyContent: "center",
        padding: "20px 20px", overflowY: "auto",
      }}
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.91, y: 24 }}
        animate={{ scale: 1, y: 0 }}
        exit={{ scale: 0.91, y: 24 }}
        transition={{ duration: 0.24, type: "spring", stiffness: 260, damping: 22 }}
        onClick={e => e.stopPropagation()}
        style={{
          background: "rgba(8,12,28,0.98)",
          border: "1px solid rgba(0,212,255,0.2)",
          borderRadius: 20, padding: 36,
          maxWidth: 620, width: "100%",
          marginTop: "auto", marginBottom: "auto",
          boxShadow: "0 32px 80px rgba(0,0,0,0.8), 0 0 0 1px rgba(0,212,255,0.08), 0 0 60px rgba(0,212,255,0.06)",
          position: "relative",
        }}
        role="dialog"
        aria-label="About Coral Security"
      >
        {/* Close button */}
        <button
          onClick={onClose}
          aria-label="Close"
          style={{
            position: "absolute", top: 16, right: 16,
            background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.1)",
            borderRadius: 8, cursor: "pointer", color: "rgba(255,255,255,0.5)",
            padding: "4px 8px", display: "flex", alignItems: "center",
          }}
        >
          <FiX size={16} />
        </button>

        {/* Logo & title */}
        <div style={{ textAlign: "center", marginBottom: 28 }}>
          <div style={{
            display: "inline-flex", alignItems: "center", justifyContent: "center",
            width: 64, height: 64, borderRadius: 20,
            background: "linear-gradient(135deg,rgba(0,212,255,0.15),rgba(168,85,247,0.15))",
            border: "1px solid rgba(0,212,255,0.25)",
            fontSize: 32, marginBottom: 14,
          }}>🛡</div>
          <div style={{
            fontSize: 22, fontWeight: 800,
            background: "linear-gradient(135deg,#fff 0%,#00d4ff 50%,#a855f7 100%)",
            WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
            backgroundClip: "text", marginBottom: 6,
          }}>Coral Security Command Center</div>
          <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)", letterSpacing: "0.12em", textTransform: "uppercase" }}>
            Enterprise Threat Intelligence Platform
          </div>
        </div>

        {/* About text */}
        <div style={{
          background: "rgba(0,212,255,0.04)",
          border: "1px solid rgba(0,212,255,0.12)",
          borderRadius: 14, padding: "20px 22px",
          marginBottom: 28, lineHeight: 1.75,
          fontSize: 13.5, color: "rgba(255,255,255,0.78)",
        }}>
          <p style={{ marginBottom: 12 }}>
            Security threats don't announce themselves — they hide in a merged pull request, a Slack
            message with a leaked key, a CVE quietly matching a dependency you shipped three months ago.
            Most teams only find out when it's too late, because the signals were always there, just
            scattered across too many tools for any human to connect in time.
          </p>
          <p style={{ marginBottom: 12 }}>
            <strong style={{ color: "#00d4ff" }}>Coral Security Command Center</strong> was built not
            just as a concept, but as a direct answer to this real-world crisis. Instead of forcing
            teams to dig through messy, disconnected logs, our platform instantly connects the dots to
            show you exactly where your system is vulnerable.
          </p>
          <p>
            <strong style={{ color: "#00d4ff" }}>Coral Security Command Centre</strong> is an
            enterprise-grade threat monitor that connects your GitHub repos, Slack channels, OSV
            vulnerability database, and Notion policies into a single intelligent layer. Built on the
            <strong> Coral agentic platform</strong>, it continuously cross-references signals across
            all four sources — surfacing vulnerabilities, policy violations, and leaked secrets in real
            time, with clear context on what went wrong and exactly what to do next.
          </p>
        </div>

        {/* Feature pills */}
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 28, justifyContent: "center" }}>
          {["4-Source SQL JOIN","AI Copilot","Secret Detection","Policy Enforcement",
            "NL → SQL Search","Developer Risk Scoring","MCP Integration","Live Caching"].map(f => (
            <span key={f} style={{
              padding: "4px 12px", borderRadius: 30,
              background: "rgba(168,85,247,0.08)", border: "1px solid rgba(168,85,247,0.2)",
              fontSize: 11, fontWeight: 600, color: "#a855f7",
            }}>{f}</span>
          ))}
        </div>

        {/* Divider */}
        <div style={{ height: 1, background: "linear-gradient(90deg,transparent,rgba(255,255,255,0.1),transparent)", marginBottom: 24 }} />

        {/* Developers */}
        <div style={{ fontSize: 11, fontWeight: 700, color: "rgba(255,255,255,0.35)", textTransform: "uppercase", letterSpacing: "0.14em", marginBottom: 16, textAlign: "center" }}>
          DEVELOPERS
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          {DEVELOPERS.map(dev => (
            <div key={dev.name} style={{
              background: `${dev.color}08`,
              border: `1px solid ${dev.color}22`,
              borderRadius: 14, padding: "16px 18px",
              display: "flex", flexDirection: "column", gap: 10,
            }}>
              {/* Avatar + name + role */}
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <div style={{
                  width: 44, height: 44, borderRadius: 14, flexShrink: 0,
                  background: `linear-gradient(135deg,${dev.color}30,${dev.color}10)`,
                  border: `1px solid ${dev.color}35`,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 14, fontWeight: 800, color: dev.color,
                }}>{dev.avatar}</div>
                <div>
                  <div style={{ fontSize: 13.5, fontWeight: 700, color: "rgba(255,255,255,0.9)" }}>{dev.name}</div>
                  <div style={{ fontSize: 10.5, color: dev.color, fontWeight: 600, marginTop: 1 }}>{dev.role}</div>
                </div>
              </div>
              {/* Description */}
              {dev.description && (
                <div style={{ fontSize: 10.5, color: "rgba(255,255,255,0.42)", lineHeight: 1.55 }}>
                  {dev.description.split(" · ").map((line, i) => (
                    <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 5 }}>
                      <span style={{ color: dev.color, marginTop: 1 }}>›</span>
                      <span>{line}</span>
                    </div>
                  ))}
                </div>
              )}
              {/* Links */}
              <div style={{ display: "flex", gap: 8 }}>
                <a
                  href={dev.github} target="_blank" rel="noopener noreferrer"
                  style={{
                    flex: 1, display: "flex", alignItems: "center", justifyContent: "center", gap: 5,
                    padding: "6px 0", borderRadius: 8,
                    background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)",
                    fontSize: 11, fontWeight: 600, color: "rgba(255,255,255,0.65)",
                    textDecoration: "none", transition: "background 0.15s",
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.1)"}
                  onMouseLeave={e => e.currentTarget.style.background = "rgba(255,255,255,0.05)"}
                >
                  <FaGithub size={12} /> GitHub
                </a>
                <a
                  href={dev.linkedin} target="_blank" rel="noopener noreferrer"
                  style={{
                    flex: 1, display: "flex", alignItems: "center", justifyContent: "center", gap: 5,
                    padding: "6px 0", borderRadius: 8,
                    background: `${dev.color}12`, border: `1px solid ${dev.color}30`,
                    fontSize: 11, fontWeight: 600, color: dev.color,
                    textDecoration: "none", transition: "background 0.15s",
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = `${dev.color}22`}
                  onMouseLeave={e => e.currentTarget.style.background = `${dev.color}12`}
                >
                  <FiExternalLink size={11} /> LinkedIn
                </a>
              </div>
            </div>
          ))}
        </div>

        {/* Footer note */}
        <div style={{ textAlign: "center", marginTop: 24, fontSize: 11, color: "rgba(255,255,255,0.2)" }}>
          Built for Coral Hackathon 2026 · Track 1: Enterprise Agent
        </div>
      </motion.div>
    </motion.div>
  );
}

/* ── Main Header ──────────────────────────────────────────────────────── */
function Header({ onRefreshed, onLogout }) {
  const [modalSource, setModalSource] = useState(null);
  const [showAbout,   setShowAbout]   = useState(false);
  const [showHowTo,   setShowHowTo]   = useState(false);

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
            <SyncLiveDataButton onRefreshed={onRefreshed} />
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
            <motion.button
              className="source-badge badge-about"
              onClick={() => setShowAbout(true)}
              whileHover={{ scale: 1.06, y: -1 }}
              whileTap={{ scale: 0.97 }}
              title="About this project"
              aria-label="About Coral Security Command Center"
              id="badge-about"
              style={{ cursor: "pointer", border: "none", outline: "none", position: "relative" }}
            >
              <span>ℹ</span> About
            </motion.button>
            <motion.button
              className="source-badge badge-howto"
              onClick={() => setShowHowTo(true)}
              whileHover={{ scale: 1.06, y: -1 }}
              whileTap={{ scale: 0.97 }}
              title="How to use Coral Security"
              aria-label="How to use Coral Security Command Center"
              id="badge-howto"
              style={{ cursor: "pointer", border: "none", outline: "none", position: "relative" }}
            >
              <span>▶</span> How to Use
            </motion.button>
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

      {/* About modal */}
      <AnimatePresence>
        {showAbout && <AboutModal onClose={() => setShowAbout(false)} />}
      </AnimatePresence>

      {/* How to Use modal */}
      <AnimatePresence>
        {showHowTo && <HowToModal onClose={() => setShowHowTo(false)} />}
      </AnimatePresence>
    </>
  );
}

export default Header;