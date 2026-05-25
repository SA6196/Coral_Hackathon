import { useEffect, useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";

import Header from "./components/Header";
import SummaryCards from "./components/SummaryCards";
import SeverityChart from "./components/SeverityChart";
import IncidentFeed from "./components/IncidentFeed";
import SecurityScore from "./components/SecurityScore";
import ParticleBackground from "./components/ParticleBackground";

import {
  getSummary,
  getHighRisk,
} from "./services/api";

import "./App.css";

const LOAD_LOGS = [
  "Initializing Coral agent...",
  "Connecting to GitHub source...",
  "Connecting to Slack source...",
  "Querying OSV vulnerability database...",
  "Cross-referencing policy documents...",
  "Running SQL joins across data sources...",
  "Analyzing threat patterns with AI...",
  "Generating security report...",
];

function LoadingScreen() {
  const [logIndex, setLogIndex] = useState(0);

  useEffect(() => {
    if (logIndex >= LOAD_LOGS.length - 1) return;
    const t = setTimeout(() => setLogIndex((i) => i + 1), 400);
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
        Make sure the backend is running on port 5000
      </div>
      <button className="retry-btn" onClick={onRetry}>
        ↻ Retry Connection
      </button>
    </div>
  );
}

function App() {
  const [summary, setSummary] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // Give loading screen at least 2.4s for dramatic effect
      const [summaryRes, incidentsRes] = await Promise.all([
        getSummary(),
        getHighRisk(),
        new Promise((r) => setTimeout(r, 2400)),
      ]);

      setSummary(summaryRes.data.data);
      setIncidents(incidentsRes.data.data);
    } catch (err) {
      setError(err.message || "Failed to connect to backend");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  if (loading) return <LoadingScreen />;
  if (error) return <ErrorScreen message={error} onRetry={loadData} />;

  return (
    <div className="app">
      <ParticleBackground />
      <div className="grid-bg" aria-hidden="true" />

      <div className="app-content">
        <Header />

        {/* Coral powered banner */}
        <div className="coral-powered">
          <div className="coral-powered-dot" />
          <span>
            Powered by <strong style={{ color: "#ff4d6d" }}>Coral</strong>
            {" "}— Multi-source SQL joins · Schema learning · Caching · MCP integration
          </span>
        </div>

        {/* Summary stats */}
        <SummaryCards summary={summary} />

        {/* Score + Chart row */}
        <div className="section-label">
          <span className="section-label-text">// analytics</span>
          <div className="section-label-line" />
        </div>

        <div className="dashboard-row">
          <SecurityScore summary={summary} />
          <SeverityChart summary={summary} />
        </div>

        {/* Incident feed */}
        <IncidentFeed incidents={incidents} />

        {/* Footer */}
        <footer className="footer">
          <span>◈ Coral</span> Security Command Center &nbsp;·&nbsp;
          GitHub + Slack + OSV + Notion &nbsp;·&nbsp;
          Track 1: Enterprise Agent &nbsp;·&nbsp;
          Built for Coral Hackathon 2026
        </footer>
      </div>
    </div>
  );
}

export default App;