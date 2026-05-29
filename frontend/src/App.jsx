import { useEffect, useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";

import Header              from "./components/Header";
import SummaryCards        from "./components/SummaryCards";
import SeverityChart       from "./components/SeverityChart";
import IncidentFeed        from "./components/IncidentFeed";
import SecurityScore       from "./components/SecurityScore";
import ParticleBackground  from "./components/ParticleBackground";
import NLSearchBar         from "./components/NLSearchBar";
import AICopilot           from "./components/AICopilot";
import CoralQueryViewer    from "./components/CoralQueryViewer";
import SchemaViewer        from "./components/SchemaViewer";
import NotionPoliciesPanel from "./components/NotionPoliciesPanel";
import SourceStatusPanel   from "./components/SourceStatusPanel";
import ErrorBoundary       from "./components/ErrorBoundary";
import DevSubmissionPortal from "./components/DevSubmissionPortal";
import Login               from "./components/Login";
import { useToast }        from "./components/Toast";

import { getSummary, getHighRisk, getExportReport } from "./services/api";

import "./App.css";

/* ── Loading screen ────────────────────────────────────────────────── */
const LOAD_LOGS = [
  "Initializing Coral agent…",
  "Reading coral-sources.yaml…",
  "Connecting to GitHub source…",
  "Connecting to Slack source…",
  "Querying OSV vulnerability database…",
  "Joining Notion policy documents…",
  "Building hash indexes for JOINs…",
  "Running cross-source SQL query…",
  "Scanning commits for secrets…",
  "Generating threat intelligence report…",
];

function LoadingScreen() {
  const [logIndex, setLogIndex] = useState(0);
  useEffect(() => {
    if (logIndex >= LOAD_LOGS.length - 1) return;
    const t = setTimeout(() => setLogIndex(i => i + 1), 300);
    return () => clearTimeout(t);
  }, [logIndex]);
  return (
    <div className="loading-screen">
      <ParticleBackground />
      <div className="grid-bg" aria-hidden="true" />
      <div className="loading-spinner" aria-label="Loading" />
      <div className="loading-title">CORAL SECURITY AGENT</div>
      <AnimatePresence mode="wait">
        <motion.div
          key={logIndex}
          className="loading-log"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          transition={{ duration: 0.25 }}
        >
          &gt; {LOAD_LOGS[logIndex]}
        </motion.div>
      </AnimatePresence>
    </div>
  );
}

function ErrorScreen({ message, onRetry }) {
  return (
    <div className="error-screen">
      <ParticleBackground />
      <div className="error-icon">⚠️</div>
      <div className="error-title">Connection Failed</div>
      <div className="error-msg">{message}</div>
      <div className="error-msg" style={{ opacity: 0.5, fontSize: 12 }}>
        Make sure the backend is running: <code style={{ color: "#00d4ff" }}>cd backend &amp;&amp; npm start</code>
      </div>
      <button className="retry-btn" onClick={onRetry}>↻ Retry Connection</button>
    </div>
  );
}

function App() {
  const toast = useToast();
  const [token,      setToken]      = useState(localStorage.getItem("coral_jwt_token"));
  const [summary,    setSummary]    = useState(null);
  const [incidents,  setIncidents]  = useState([]);
  const [coralMeta,  setCoralMeta]  = useState(null);
  const [loading,    setLoading]    = useState(true);
  const [error,      setError]      = useState(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [exporting,  setExporting]  = useState(false);

  const handleLogout = useCallback(() => {
    localStorage.removeItem("coral_jwt_token");
    setToken(null);
    toast.success("Logged out successfully");
  }, [toast]);

  const loadData = useCallback(async () => {
    setError(null);
    try {
      const [summaryRes, incidentsRes] = await Promise.all([
        getSummary(),
        getHighRisk(),
        new Promise(r => setTimeout(r, loading ? 2800 : 0)),
      ]);
      setSummary(summaryRes.data.data);
      setIncidents(incidentsRes.data.data);
      setCoralMeta(incidentsRes.data.coral_meta || summaryRes.data.coral_meta || null);
    } catch (err) {
      setError(err.userMessage || err.message || "Failed to connect to backend");
    } finally {
      setLoading(false);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refreshKey]);

  useEffect(() => { 
    if (token) {
      loadData(); 
    } else {
      setLoading(false);
    }
  }, [loadData, token]);

  const handleRefreshed = useCallback(() => {
    setRefreshKey(k => k + 1);
    toast.info("Dashboard refreshed");
  }, [toast]);

  /* ── Export report as JSON download ─────────────────────────────── */
  const handleExport = useCallback(async () => {
    if (exporting) return;
    setExporting(true);
    toast.info("Generating report…");
    try {
      const res = await getExportReport();
      const blob = new Blob(
        [JSON.stringify(res.data.report, null, 2)],
        { type: "application/json" }
      );
      const url  = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `coral-security-report-${new Date().toISOString().slice(0,10)}.json`;
      link.click();
      URL.revokeObjectURL(url);
      toast.success(`Report exported: ${res.data.report.executive_summary.total_incidents} incidents`);
    } catch (e) {
      toast.error("Export failed — is the backend running?");
    } finally {
      setExporting(false);
    }
  }, [exporting, toast]);

  if (!token) {
    return (
      <Login 
        onLoginSuccess={(newToken) => {
          localStorage.setItem("coral_jwt_token", newToken);
          setToken(newToken);
          setLoading(true);
        }} 
      />
    );
  }

  if (loading) return <LoadingScreen />;
  if (error)   return <ErrorScreen message={error} onRetry={loadData} />;

  return (
    <div className="app">
      <ParticleBackground />
      <div className="grid-bg" aria-hidden="true" />

      <div className="app-content">

        {/* ── Header: clickable badges + live refresh + export ───────── */}
        <Header onRefreshed={handleRefreshed} onExport={handleExport} exporting={exporting} onLogout={handleLogout} />

        {/* ── Coral powered banner ───────────────────────────────────── */}
        <div className="coral-powered">
          <div className="coral-powered-dot" />
          <span>
            Powered by <strong style={{ color: "#ff4d6d" }}>Coral</strong>
            {" "}— 4-source SQL JOIN · Schema learning · Caching · Secret detection · Policy enforcement · MCP
          </span>
          {coralMeta?.cache_hit && (
            <span className="coral-powered-cache">⚡ Cache hit · {coralMeta.expires_in_seconds}s TTL</span>
          )}
        </div>

        {/* ── Source Status Panel ────────────────────────────────────── */}
        <ErrorBoundary>
          <SourceStatusPanel onRefreshed={handleRefreshed} />
        </ErrorBoundary>

        {/* ── NL → SQL Search ────────────────────────────────────────── */}
        <ErrorBoundary>
          <NLSearchBar />
        </ErrorBoundary>

        {/* ── Coral SQL Query Viewer ─────────────────────────────────── */}
        <ErrorBoundary>
          <CoralQueryViewer coralMeta={coralMeta} />
        </ErrorBoundary>

        {/* ── Schema Learning Viewer ─────────────────────────────────── */}
        <ErrorBoundary>
          <SchemaViewer />
        </ErrorBoundary>

        {/* ── Summary cards ──────────────────────────────────────────── */}
        <ErrorBoundary>
          <SummaryCards summary={summary} />
        </ErrorBoundary>

        {/* ── Analytics row ──────────────────────────────────────────── */}
        <div className="section-label">
          <span className="section-label-text">Analytics</span>
          <div className="section-label-line" />
        </div>
        <div className="dashboard-row">
          <ErrorBoundary>
            <SecurityScore summary={summary} />
          </ErrorBoundary>
          <ErrorBoundary>
            <SeverityChart summary={summary} />
          </ErrorBoundary>
        </div>

        {/* ── Notion Policy Violations Panel ─────────────────────────── */}
        <ErrorBoundary>
          <NotionPoliciesPanel />
        </ErrorBoundary>

        {/* ── Developer Submission Portal ─────────────────────────────── */}
        <ErrorBoundary>
          <DevSubmissionPortal />
        </ErrorBoundary>

        {/* ── Incident Feed (each card has Remediation + AI Invest) ──── */}
        <ErrorBoundary>
          <IncidentFeed incidents={incidents} />
        </ErrorBoundary>

        {/* ── Footer ─────────────────────────────────────────────────── */}
        <footer className="footer">
          <span>◈ Coral</span> Security Command Center &nbsp;·&nbsp;
          GitHub + Slack + OSV + Notion &nbsp;·&nbsp;
          Track 1: Enterprise Agent &nbsp;·&nbsp;
          Built for Coral Hackathon 2026
        </footer>
      </div>

      {/* ── Floating AI Copilot ────────────────────────────────────── */}
      <ErrorBoundary>
        <AICopilot activeIncidentId={1} />
      </ErrorBoundary>
    </div>
  );
}

export default App;