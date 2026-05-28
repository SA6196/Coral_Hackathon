/**
 * SourceStatusPanel.jsx — compact collapsible panel showing live health of all 4 Coral sources
 */
import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { FiRefreshCw, FiChevronDown, FiChevronUp, FiCode, FiCheckCircle, FiXCircle, FiAlertTriangle } from "react-icons/fi";
import { FaGithub, FaSlack } from "react-icons/fa";
import { getSourceStatus, refreshCache } from "../services/api";

function SourceIcon({ id, size = 12 }) {
  if (id === "github") return <FaGithub size={size} />;
  if (id === "slack")  return <FaSlack  size={size} />;
  if (id === "osv")    return <span style={{ fontSize: size }}>⚡</span>;
  if (id === "notion") return <span style={{ fontSize: size }}>📄</span>;
  return null;
}

function StatusDot({ status }) {
  const c = status === "connected" ? "#10b981" : status === "not_configured" ? "#f59e0b" : "#e11d48";
  return <div style={{ width: 7, height: 7, borderRadius: "50%", background: c, boxShadow: `0 0 5px ${c}`, flexShrink: 0 }} />;
}

function rel(iso) {
  if (!iso) return "N/A";
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  return `${Math.floor(s/3600)}h ago`;
}

export default function SourceStatusPanel({ onRefreshed }) {
  const [sources,   setSources]   = useState([]);
  const [cache,     setCache]     = useState(null);
  const [sql,       setSql]       = useState("");
  const [loading,   setLoading]   = useState(true);
  const [refreshing,setRefreshing]= useState(false);
  const [expanded,  setExpanded]  = useState(false);
  const [sqlVis,    setSqlVis]    = useState(false);

  const fetchStatus = async () => {
    try {
      const res = await getSourceStatus();
      setSources(res.data.sources || []);
      setCache(res.data.cache || null);
      setSql(res.data.coral_sql || "");
    } catch { /* backend may be off */ }
    finally { setLoading(false); setRefreshing(false); }
  };

  useEffect(() => { fetchStatus(); }, []);

  const handleRefresh = async () => {
    setRefreshing(true);
    try { await refreshCache(); if (onRefreshed) onRefreshed(); } catch {}
    await fetchStatus();
  };

  const connected  = sources.filter(s => s.status === "connected").length;
  const needsToken = sources.filter(s => s.status === "not_configured").length;
  const allGood    = connected === sources.length && sources.length > 0;

  return (
    <section style={{ marginBottom: 20 }} aria-label="Source Status Panel">
      {/* Compact bar */}
      <div
        onClick={() => setExpanded(e => !e)}
        style={{
          display: "flex", alignItems: "center", gap: 10,
          background: "rgba(14,165,233,0.04)", border: "1px solid rgba(14,165,233,0.18)",
          borderRadius: expanded ? "12px 12px 0 0" : 12,
          padding: "9px 14px", cursor: "pointer", userSelect: "none",
          transition: "border-radius 0.2s",
        }}
        role="button"
        aria-expanded={expanded}
        id="source-status-toggle"
      >
        <StatusDot status={allGood ? "connected" : needsToken > 0 ? "not_configured" : "error"} />
        <span style={{ fontSize: 11, fontWeight: 700, color: "#0ea5e9" }}>Coral Data Sources</span>
        <span style={{ fontSize: 10, color: "rgba(255,255,255,0.3)" }}>
          {connected}/{sources.length} connected{needsToken > 0 ? ` · ${needsToken} need token` : ""}
        </span>

        {/* Source icons */}
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {sources.map(s => {
            const c = s.status === "connected" ? s.color : s.status === "not_configured" ? "#f59e0b" : "#e11d48";
            return <span key={s.id} style={{ color: c, opacity: 0.85 }} title={`${s.name}: ${s.status}`}><SourceIcon id={s.id} size={11} /></span>;
          })}
        </div>

        {/* Cache pill */}
        {cache && (
          <span style={{
            fontSize: 9, padding: "2px 8px", borderRadius: 6,
            background: "rgba(14,165,233,0.08)", border: "1px solid rgba(14,165,233,0.15)",
            color: "rgba(14,165,233,0.6)", whiteSpace: "nowrap",
          }}>
            {cache.is_cached ? `Cache ✓ · ${cache.expires_in_seconds}s` : "No cache"}
          </span>
        )}

        <button
          onClick={e => { e.stopPropagation(); handleRefresh(); }}
          disabled={refreshing || loading}
          style={{
            background: "transparent", border: "1px solid rgba(14,165,233,0.18)",
            borderRadius: 6, padding: "3px 8px", cursor: "pointer",
            color: "#0ea5e9", fontSize: 10, display: "flex", alignItems: "center", gap: 3,
          }}
          id="source-status-refresh"
          aria-label="Refresh sources"
        >
          <FiRefreshCw size={9} style={{ animation: refreshing ? "spin 0.8s linear infinite" : "none" }} />
          {refreshing ? "…" : "Refresh"}
        </button>
        {expanded ? <FiChevronUp size={11} style={{ color: "rgba(255,255,255,0.25)" }} /> : <FiChevronDown size={11} style={{ color: "rgba(255,255,255,0.25)" }} />}
      </div>

      {/* Expanded body */}
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25 }}
            style={{
              overflow: "hidden",
              background: "rgba(0,0,0,0.2)", border: "1px solid rgba(14,165,233,0.1)",
              borderTop: "none", borderRadius: "0 0 12px 12px",
            }}
          >
            <div style={{ padding: 14 }}>
              {loading ? (
                <div style={{ textAlign: "center", color: "rgba(255,255,255,0.3)", fontSize: 12, padding: "10px 0" }}>
                  <FiRefreshCw size={13} style={{ animation: "spin 1s linear infinite", display: "inline" }} />
                  <span style={{ marginLeft: 8 }}>Loading source status…</span>
                </div>
              ) : (
                <>
                  {/* Source cards */}
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(190px,1fr))", gap: 10, marginBottom: 12 }}>
                    {sources.map((s, i) => {
                      const c = s.status === "connected" ? "#10b981" : s.status === "not_configured" ? "#f59e0b" : "#e11d48";
                      const statusText = s.status === "connected" ? "Connected" : s.status === "not_configured" ? "Needs Token" : "Error";
                      return (
                        <motion.div key={s.id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.06 }}
                          style={{ background: `${s.color}06`, border: `1px solid ${c}20`, borderRadius: 10, padding: "10px 12px" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
                            <FiCheckCircle size={9} style={{ color: c }} />
                            <span style={{ color: s.color }}><SourceIcon id={s.id} size={11} /></span>
                            <span style={{ fontSize: 11, fontWeight: 700, color: "rgba(255,255,255,0.85)" }}>{s.name}</span>
                            {s.is_public && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: "rgba(16,185,129,0.1)", border: "1px solid rgba(16,185,129,0.2)", color: "#10b981" }}>PUBLIC</span>}
                          </div>
                          <div style={{ fontSize: 9, padding: "2px 8px", borderRadius: 6, display: "inline-flex", alignItems: "center", gap: 4, background: `${c}12`, border: `1px solid ${c}25`, color: c, marginBottom: 6 }}>
                            {statusText}
                          </div>
                          <div style={{ fontSize: 9.5, color: "rgba(255,255,255,0.35)", lineHeight: 1.8 }}>
                            <div>Table: <code style={{ color: "#0ea5e9" }}>{s.coral_table}</code></div>
                            <div>Join: <code style={{ color: "#8b5cf6", fontSize: 9 }}>{s.join_key}</code></div>
                            <div>Synced: {rel(s.last_synced)}</div>
                            {s.env_var && <div>Env: <code style={{ color: "#f59e0b" }}>{s.env_var}</code></div>}
                          </div>
                        </motion.div>
                      );
                    })}
                  </div>

                  {/* SQL toggle */}
                  <button onClick={() => setSqlVis(v => !v)} style={{
                    background: "transparent", border: "none", cursor: "pointer",
                    fontSize: 10, color: "rgba(14,165,233,0.5)", display: "flex", alignItems: "center", gap: 4, padding: "2px 0",
                  }}>
                    <FiCode size={9} /> {sqlVis ? "Hide" : "Show"} Coral JOIN query
                  </button>
                  <AnimatePresence>
                    {sqlVis && sql && (
                      <motion.pre initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                        style={{ fontSize: 9.5, background: "rgba(0,0,0,0.4)", border: "1px solid rgba(14,165,233,0.15)", borderRadius: 8, padding: "10px 14px", marginTop: 8, color: "#0ea5e9", overflow: "hidden" }}>
                        {sql}
                      </motion.pre>
                    )}
                  </AnimatePresence>
                </>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </section>
  );
}
