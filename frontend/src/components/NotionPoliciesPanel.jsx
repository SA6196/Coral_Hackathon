/**
 * NotionPoliciesPanel.jsx
 * ─────────────────────────────────────────────────────────────────────
 * A dedicated dashboard panel showing ALL Notion policy violations
 * detected by Coral's cross-source SQL JOIN.
 * Fetches from GET /api/policy-violations on mount.
 * ─────────────────────────────────────────────────────────────────────
 */
import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  FiShield, FiRefreshCw, FiChevronDown, FiChevronUp,
  FiAlertTriangle, FiAlertOctagon, FiAlertCircle,
  FiCode, FiUser, FiPackage,
} from "react-icons/fi";
import { getPolicyViolations } from "../services/api";

const RULE_CONFIG = {
  BANNED_PACKAGE: {
    label: "Banned Package",
    color: "#ef4444",
    icon: FiAlertOctagon,
    description: "Package is on the organization's banned dependency list. Must be removed before any deployment.",
  },
  SECRETS_RISK: {
    label: "Secrets Risk",
    color: "#a855f7",
    icon: FiAlertTriangle,
    description: "Package handles sensitive credentials — poses secret exposure risk. Security audit mandatory.",
  },
  AUDIT_REQUIRED: {
    label: "Audit Required",
    color: "#f97316",
    icon: FiAlertCircle,
    description: "A full security audit must be completed before this change can be merged to production.",
  },
  REVIEW_REQUIRED: {
    label: "Review Required",
    color: "#fbbf24",
    icon: FiAlertCircle,
    description: "A senior security engineer must sign off on this change before deployment.",
  },
};

const SEVERITY_COLOR = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#fbbf24",
  low:      "#00ff9d",
};

function ViolationCard({ v, index }) {
  const [expanded, setExpanded] = useState(false);
  const ruleCfg = RULE_CONFIG[v.policy_rule] || {
    label: v.policy_rule, color: "#fbbf24", icon: FiAlertTriangle, description: ""
  };
  const RuleIcon = ruleCfg.icon;
  const sevColor = SEVERITY_COLOR[v.severity] || "#fbbf24";

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.07, duration: 0.35 }}
      style={{
        background: `${ruleCfg.color}08`,
        border: `1px solid ${ruleCfg.color}25`,
        borderRadius: 12,
        overflow: "hidden",
      }}
    >
      {/* Card header */}
      <div
        style={{
          display: "flex", alignItems: "center", gap: 12,
          padding: "12px 16px", cursor: "pointer",
        }}
        onClick={() => setExpanded(e => !e)}
        role="button"
        aria-expanded={expanded}
      >
        {/* Rule icon */}
        <div style={{
          width: 32, height: 32, borderRadius: 8, flexShrink: 0,
          background: `${ruleCfg.color}18`, border: `1px solid ${ruleCfg.color}30`,
          display: "flex", alignItems: "center", justifyContent: "center",
        }}>
          <RuleIcon size={14} style={{ color: ruleCfg.color }} />
        </div>

        {/* Main info */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            <span style={{ fontSize: 13, fontWeight: 700, color: "rgba(255,255,255,0.88)" }}>
              {v.incident_id}
            </span>
            {/* Rule badge */}
            <span style={{
              fontSize: 9, fontWeight: 800, padding: "2px 8px", borderRadius: 10,
              background: `${ruleCfg.color}18`, border: `1px solid ${ruleCfg.color}35`,
              color: ruleCfg.color, textTransform: "uppercase", letterSpacing: "0.05em",
            }}>
              {ruleCfg.label}
            </span>
            {/* Severity */}
            <span style={{
              fontSize: 9, fontWeight: 700, padding: "2px 8px", borderRadius: 10,
              background: `${sevColor}12`, border: `1px solid ${sevColor}30`,
              color: sevColor, textTransform: "uppercase", letterSpacing: "0.05em",
            }}>
              {v.severity}
            </span>
          </div>
          <div style={{ fontSize: 11.5, color: "rgba(255,255,255,0.45)", marginTop: 3 }}>
            <span style={{ color: "#a855f7" }}>{v.policy_name}</span>
            {v.owner_team && <span style={{ color: "rgba(255,255,255,0.25)" }}> · {v.owner_team}</span>}
          </div>
        </div>

        {/* Risk score */}
        <div style={{
          fontSize: 16, fontWeight: 800, color: SEVERITY_COLOR[v.severity] || sevColor,
          flexShrink: 0, minWidth: 30, textAlign: "right",
        }}>
          {v.risk_score}
        </div>

        <div style={{ color: "rgba(255,255,255,0.25)", flexShrink: 0 }}>
          {expanded ? <FiChevronUp size={13} /> : <FiChevronDown size={13} />}
        </div>
      </div>

      {/* Expanded detail */}
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25 }}
            style={{ overflow: "hidden" }}
          >
            <div style={{
              borderTop: `1px solid ${ruleCfg.color}18`,
              padding: "14px 16px",
              display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10,
            }}>
              {/* Package */}
              <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)" }}>
                <span style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 3 }}>
                  <FiPackage size={10} /> Package
                </span>
                <code style={{ color: "#58a6ff", fontSize: 12 }}>{v.package}</code>
              </div>
              {/* Developer */}
              <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)" }}>
                <span style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 3 }}>
                  <FiUser size={10} /> Developer
                </span>
                <span style={{ color: "rgba(255,255,255,0.75)", fontSize: 12 }}>{v.developer}</span>
              </div>
              {/* CVE */}
              {v.cve && v.cve !== "NO_CVE_FOUND" && (
                <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)" }}>
                  <span style={{ marginBottom: 3, display: "block" }}>CVE</span>
                  <code style={{ color: sevColor, fontSize: 11 }}>{v.cve}</code>
                </div>
              )}
              {/* Owner */}
              <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)" }}>
                <span style={{ marginBottom: 3, display: "block" }}>Owning Team</span>
                <span style={{ color: "rgba(255,255,255,0.7)", fontSize: 12 }}>{v.owner_team}</span>
              </div>
              {/* Policy description */}
              <div style={{ gridColumn: "1 / -1", fontSize: 11.5, color: "rgba(255,255,255,0.45)", lineHeight: 1.6 }}>
                <span style={{ color: ruleCfg.color, fontWeight: 600 }}>Policy Rule: </span>
                {ruleCfg.description}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

export default function NotionPoliciesPanel() {
  const [data,     setData]     = useState(null);
  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState(null);
  const [expanded, setExpanded] = useState(true);
  const [sqlVis,   setSqlVis]   = useState(false);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getPolicyViolations();
      setData(res.data);
    } catch (e) {
      setError(e.message || "Failed to fetch");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, []);

  const byRule = data?.by_rule || {};
  const violations = data?.violations || [];

  return (
    <section aria-label="Notion Policy Violations" style={{ marginBottom: 24 }}>
      {/* Section header */}
      <div
        style={{
          display: "flex", alignItems: "center", gap: 10,
          background: "rgba(168,85,247,0.06)",
          border: "1px solid rgba(168,85,247,0.2)",
          borderRadius: expanded ? "14px 14px 0 0" : 14,
          padding: "12px 18px",
          cursor: "pointer",
          transition: "border-radius 0.2s",
        }}
        onClick={() => setExpanded(e => !e)}
        role="button"
        aria-expanded={expanded}
        id="notion-policies-toggle"
      >
        <FiShield size={15} style={{ color: "#a855f7" }} />
        <span style={{ fontSize: 13, fontWeight: 700, color: "#a855f7", flex: 1 }}>
          Notion Policy Violations
        </span>

        {/* Rule counts */}
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {Object.entries(byRule).map(([rule, count]) => {
            const cfg = RULE_CONFIG[rule] || { color: "#fbbf24", label: rule };
            return (
              <span key={rule} style={{
                fontSize: 9, padding: "2px 9px", borderRadius: 10, fontWeight: 700,
                background: `${cfg.color}15`, border: `1px solid ${cfg.color}30`,
                color: cfg.color, textTransform: "uppercase", letterSpacing: "0.04em",
              }}>
                {count}× {cfg.label}
              </span>
            );
          })}
          {violations.length > 0 && (
            <span style={{
              fontSize: 9, padding: "2px 9px", borderRadius: 10, fontWeight: 800,
              background: "rgba(239,68,68,0.15)", border: "1px solid rgba(239,68,68,0.3)",
              color: "#ef4444",
            }}>
              {violations.length} Total
            </span>
          )}
        </div>

        {/* Refresh */}
        <button
          onClick={e => { e.stopPropagation(); fetchData(); }}
          disabled={loading}
          style={{
            background: "transparent", border: "none", cursor: "pointer",
            color: "#a855f7", padding: 0, display: "flex", alignItems: "center",
          }}
          title="Refresh"
          aria-label="Refresh policy violations"
        >
          <FiRefreshCw size={12} style={{ animation: loading ? "spin 0.8s linear infinite" : "none" }} />
        </button>
        <span style={{ color: "rgba(255,255,255,0.25)" }}>
          {expanded ? <FiChevronUp size={12} /> : <FiChevronDown size={12} />}
        </span>
      </div>

      {/* Body */}
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.28 }}
            style={{
              overflow: "hidden",
              background: "rgba(0,0,0,0.2)",
              border: "1px solid rgba(168,85,247,0.12)",
              borderTop: "none",
              borderRadius: "0 0 14px 14px",
            }}
          >
            <div style={{ padding: 16 }}>
              {loading && (
                <div style={{ textAlign: "center", padding: "20px 0", color: "rgba(255,255,255,0.3)", fontSize: 12 }}>
                  <FiRefreshCw size={14} style={{ animation: "spin 1s linear infinite", display: "inline" }} />
                  <span style={{ marginLeft: 8 }}>Querying Coral JOIN — policies × github_commits…</span>
                </div>
              )}

              {error && !loading && (
                <div style={{
                  padding: "12px 16px", background: "rgba(239,68,68,0.08)",
                  border: "1px solid rgba(239,68,68,0.2)", borderRadius: 10,
                  fontSize: 12, color: "#ef4444", marginBottom: 12,
                }}>
                  ⚠ {error} — is the backend running on port 5000?
                </div>
              )}

              {!loading && !error && violations.length === 0 && (
                <div style={{
                  textAlign: "center", padding: "24px 0",
                  fontSize: 13, color: "#00ff9d",
                  fontFamily: "monospace",
                }}>
                  ✅ No policy violations detected — all packages compliant
                </div>
              )}

              {!loading && violations.length > 0 && (
                <>
                  {/* Summary strip */}
                  <div style={{
                    display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap",
                    padding: "10px 14px", marginBottom: 14,
                    background: "rgba(168,85,247,0.05)", border: "1px solid rgba(168,85,247,0.12)",
                    borderRadius: 10, fontSize: 11, color: "rgba(255,255,255,0.5)",
                  }}>
                    <span style={{ color: "#a855f7", fontWeight: 700 }}>◈ Coral SQL Result</span>
                    <span>{violations.length} violation(s) from JOIN: github_commits ⋈ policies (on <code style={{ color: "#00d4ff" }}>package_name = applies_to</code>)</span>
                    <button
                      onClick={() => setSqlVis(v => !v)}
                      style={{
                        marginLeft: "auto", background: "transparent", border: "none",
                        cursor: "pointer", fontSize: 10, color: "rgba(0,212,255,0.6)",
                        display: "flex", alignItems: "center", gap: 4, padding: 0,
                      }}
                    >
                      <FiCode size={9} /> {sqlVis ? "Hide" : "View"} SQL
                    </button>
                  </div>

                  {/* SQL viewer */}
                  <AnimatePresence>
                    {sqlVis && (
                      <motion.pre
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: "auto", opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        style={{
                          fontSize: 11, background: "rgba(0,0,0,0.45)",
                          border: "1px solid rgba(0,212,255,0.15)", borderRadius: 8,
                          padding: "10px 14px", marginBottom: 14, color: "#00d4ff",
                          overflowX: "auto", overflow: "hidden",
                        }}
                      >
                        {data?.coral_sql || "SELECT ... FROM github_commits JOIN policies ON package_name = applies_to"}
                      </motion.pre>
                    )}
                  </AnimatePresence>

                  {/* Violation cards */}
                  <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                    {violations.map((v, i) => (
                      <ViolationCard key={v.incident_id} v={v} index={i} />
                    ))}
                  </div>

                  {/* What to do next */}
                  <div style={{
                    marginTop: 14, padding: "12px 16px",
                    background: "rgba(168,85,247,0.05)", border: "1px solid rgba(168,85,247,0.12)",
                    borderRadius: 10,
                  }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: "#a855f7", marginBottom: 8 }}>
                      📋 What to do next
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                      {[
                        "Open a Policy Exception in Notion — link the Coral incident ID",
                        "Get sign-off from the owning team listed above",
                        "Run `npm audit` after replacing any banned packages",
                        "Update .npmrc to block banned packages at install time",
                      ].map((tip, i) => (
                        <div key={i} style={{ fontSize: 11, color: "rgba(255,255,255,0.5)", display: "flex", gap: 8 }}>
                          <span style={{ color: "#a855f7", flexShrink: 0 }}>→</span> {tip}
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </section>
  );
}
