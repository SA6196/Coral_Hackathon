import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  FiAlertOctagon,
  FiAlertTriangle,
  FiAlertCircle,
  FiCheckCircle,
  FiChevronDown,
  FiChevronUp,
  FiUser,
  FiPackage,
  FiGitPullRequest,
  FiMessageSquare,
  FiClock,
  FiCpu,
} from "react-icons/fi";
import { FaSlack } from "react-icons/fa";

const SEVERITY_MAP = {
  critical: {
    badge: "badge-critical",
    cardClass: "severity-critical",
    icon: FiAlertOctagon,
    iconColor: "#ef4444",
    scoreColor: "#ef4444",
    actionClass: "action-rollback",
  },
  high: {
    badge: "badge-high",
    cardClass: "severity-high",
    icon: FiAlertTriangle,
    iconColor: "#f97316",
    scoreColor: "#f97316",
    actionClass: "action-review",
  },
  medium: {
    badge: "badge-medium",
    cardClass: "severity-medium",
    icon: FiAlertCircle,
    iconColor: "#fbbf24",
    scoreColor: "#fbbf24",
    actionClass: "action-safe",
  },
  safe: {
    badge: "badge-safe",
    cardClass: "severity-safe",
    icon: FiCheckCircle,
    iconColor: "#00ff9d",
    scoreColor: "#00ff9d",
    actionClass: "action-safe",
  },
};



function getActionLabel(action) {
  switch (action) {
    case "ROLLBACK_DEPLOYMENT": return "⚠ Rollback Deployment";
    case "SECURITY_REVIEW_REQUIRED": return "🔍 Security Review Required";
    case "SAFE_TO_DEPLOY": return "✓ Safe to Deploy";
    default: return action;
  }
}

function IncidentCard({ item, index }) {
  const [expanded, setExpanded] = useState(false);
  const severity = item.vulnerability?.severity || "safe";
  const cfg = SEVERITY_MAP[severity] || SEVERITY_MAP.safe;
  const SeverityIcon = cfg.icon;

  const prTitle = item.pr_details?.title || "Unknown PR";
  const developer = item.pr_details?.developer || "Unknown";
  const mergedAt = item.pr_details?.merged_at
    ? new Date(item.pr_details.merged_at).toLocaleString("en-US", {
        month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
      })
    : "N/A";
  const packageName = item.package_details?.package_name || "Unknown";
  const cve = item.vulnerability?.cve || "NO_CVE_FOUND";
  const riskScore = item.risk_score ?? 0;
  const aiSummary = item.ai_summary || "";
  const action = item.recommended_action || "";
  const slackChannel = item.internal_discussion?.slack_channel || "N/A";
  const slackMsg = item.internal_discussion?.message || "";

  return (
    <motion.div
      className={`incident-card ${cfg.cardClass}`}
      initial={{ opacity: 0, y: 24 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.1, duration: 0.5, ease: "easeOut" }}
      layout
    >
      <div className="incident-severity-bar" aria-hidden="true" />

      <div className="incident-card-inner">
        {/* Top row */}
        <div className="incident-top-row">
          <div className="incident-id-group">
            <SeverityIcon
              size={18}
              style={{ color: cfg.iconColor, flexShrink: 0 }}
              aria-hidden="true"
            />
            <span className="incident-id">{item.incident_id}</span>
            <span className={`incident-severity-badge ${cfg.badge}`}>
              {severity}
            </span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div
              className="incident-risk-score"
              style={{ color: cfg.scoreColor }}
              aria-label={`Risk score: ${riskScore}`}
            >
              {riskScore}
            </div>
            <button
              className="expand-toggle"
              onClick={() => setExpanded((p) => !p)}
              aria-expanded={expanded}
              aria-label={expanded ? "Collapse details" : "Expand details"}
            >
              {expanded ? <FiChevronUp size={14} /> : <FiChevronDown size={14} />}
              {expanded ? "less" : "more"}
            </button>
          </div>
        </div>

        {/* PR title */}
        <div
          style={{
            fontWeight: 600,
            fontSize: 14,
            color: "rgba(255,255,255,0.85)",
            marginBottom: 14,
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          <FiGitPullRequest size={14} style={{ color: "#58a6ff", flexShrink: 0 }} />
          {prTitle}
        </div>

        {/* Meta grid */}
        <div className="incident-meta-grid">
          <div className="incident-meta-item">
            <div className="incident-meta-key">
              <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
                <FiUser size={10} /> Developer
              </span>
            </div>
            <div className="incident-meta-val">{developer}</div>
          </div>

          <div className="incident-meta-item">
            <div className="incident-meta-key">
              <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
                <FiPackage size={10} /> Package
              </span>
            </div>
            <div className="incident-meta-val">{packageName}</div>
          </div>

          <div className="incident-meta-item">
            <div className="incident-meta-key">CVE ID</div>
            <div
              className="incident-meta-val incident-cve"
              style={{ color: cfg.scoreColor, fontSize: 12 }}
            >
              {cve}
            </div>
          </div>
        </div>

        {/* AI Summary */}
        <div className="incident-ai-summary">
          <div className="ai-summary-label">
            <FiCpu size={10} />
            AI Analysis
          </div>
          <div className="ai-summary-text">{aiSummary}</div>
        </div>

        {/* Action row */}
        <div className="incident-action-row">
          <button className={`action-btn ${cfg.actionClass}`}>
            {getActionLabel(action)}
          </button>

          {/* Slack info */}
          {slackMsg && (
            <div className="incident-slack-msg">
              <FaSlack size={12} />
              <span className="slack-channel">{slackChannel}</span>
            </div>
          )}
        </div>

        {/* Expanded details */}
        <AnimatePresence>
          {expanded && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.3, ease: "easeInOut" }}
              style={{ overflow: "hidden" }}
            >
              <div
                style={{
                  marginTop: 16,
                  paddingTop: 16,
                  borderTop: "1px solid rgba(255,255,255,0.07)",
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr",
                  gap: 12,
                }}
              >
                <div className="incident-meta-item">
                  <div className="incident-meta-key">
                    <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
                      <FiClock size={10} /> Merged At
                    </span>
                  </div>
                  <div className="incident-meta-val" style={{ fontSize: 12 }}>
                    {mergedAt}
                  </div>
                </div>

                <div className="incident-meta-item">
                  <div className="incident-meta-key">
                    <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
                      <FiMessageSquare size={10} /> Slack Discussion
                    </span>
                  </div>
                  <div className="incident-meta-val" style={{ fontSize: 12 }}>
                    {slackMsg || "No discussion"}
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}

function IncidentFeed({ incidents }) {
  const criticalCount = incidents.filter(
    (i) => i.vulnerability?.severity === "critical"
  ).length;

  return (
    <section className="incident-feed-section" aria-label="High Risk Incidents">
      <div className="feed-header">
        <div className="section-label" style={{ marginBottom: 0, flex: 1 }}>
          <span className="section-label-text">High Risk Incidents</span>
          <div className="section-label-line" />
        </div>

        {criticalCount > 0 && (
          <div className="feed-alert-badge">
            <div className="feed-alert-dot" />
            {criticalCount} CRITICAL
          </div>
        )}
      </div>

      <div style={{ marginBottom: 16 }} />

      {incidents.length === 0 ? (
        <div
          style={{
            textAlign: "center",
            padding: "60px 20px",
            background: "rgba(0,255,157,0.04)",
            border: "1px solid rgba(0,255,157,0.1)",
            borderRadius: 16,
            color: "#00ff9d",
            fontFamily: "var(--font-mono)",
            fontSize: 14,
          }}
        >
          ✓ No high-risk incidents detected
        </div>
      ) : (
        <div className="incident-grid">
          {incidents.map((item, i) => (
            <IncidentCard key={item.incident_id} item={item} index={i} />
          ))}
        </div>
      )}
    </section>
  );
}

export default IncidentFeed;