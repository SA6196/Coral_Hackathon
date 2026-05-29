import { useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  FiShield,
  FiTerminal,
  FiCheckCircle,
  FiCopy,
  FiChevronDown,
  FiChevronUp,
  FiAlertTriangle,
  FiRotateCcw,
  FiKey,
  FiFileText,
  FiMessageSquare,
  FiZap,
  FiLoader,
  FiTool
} from "react-icons/fi";
import { getRemediation } from "../services/api";

/* ─── Utilities ───────────────────────────────────────────────────────────── */
function toLogId(incidentId) {
  return incidentId || "1";
}

/* ─── Copy button ─────────────────────────────────────────────────────────── */
function CopyBtn({ text, small }) {
  const [copied, setCopied] = useState(false);
  const copy = useCallback(() => {
    navigator.clipboard.writeText(text).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  }, [text]);
  return (
    <button
      className="gemini-copy-btn"
      onClick={copy}
      aria-label="Copy command"
      style={small ? { padding: "3px 7px", fontSize: 10 } : {}}
    >
      {copied ? <FiCheckCircle size={12} style={{ color: "#10b981" }} /> : <FiCopy size={12} />}
      {!small && <span>{copied ? "Copied" : "Copy"}</span>}
    </button>
  );
}

/* ─── Playbook Step Component ─────────────────────────────────────────────── */
function PlaybookStep({ step, index }) {
  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.1 }}
      className="gemini-playbook-step"
    >
      <div className="gemini-step-header">
        <div className="gemini-step-icon">
          {index + 1}
        </div>
        <div className="gemini-step-title">{step.title || "Remediation Action"}</div>
      </div>
      <div className="gemini-step-content">
        <p className="gemini-p">{step.description || step}</p>
        {step.commands && step.commands.map((cmd, i) => (
          <div key={i} className="gemini-code-block">
            <div className="gemini-code-header">
              <span>BASH</span>
              <CopyBtn text={cmd} small />
            </div>
            <pre className="gemini-code-pre">{cmd}</pre>
          </div>
        ))}
      </div>
    </motion.div>
  );
}

export default function RemediationCenter({ item }) {
  const [expanded, setExpanded] = useState(false);
  const [loading, setLoading] = useState(false);
  const [remediation, setRemed] = useState(null);
  const [error, setError] = useState(null);

  const toggle = async () => {
    if (expanded) {
      setExpanded(false);
      return;
    }
    
    setExpanded(true);
    if (remediation) return;

    setLoading(true);
    setError(null);
    try {
      const res = await getRemediation(toLogId(item.incident_id));
      setRemed(res.data.remediation);
    } catch {
      setError("AI Engine unreachable. Check backend connection.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="ai-invest-premium-wrap" style={{ borderTop: 'none', paddingTop: 8 }}>
      <button 
        onClick={toggle} 
        className={`gemini-trigger-btn ${expanded ? "active" : ""}`}
        style={{ background: expanded ? "linear-gradient(135deg, rgba(16, 185, 129, 0.15), rgba(0, 212, 255, 0.15))" : "linear-gradient(135deg, rgba(16, 185, 129, 0.05), rgba(0, 212, 255, 0.05))", borderColor: expanded ? "rgba(16, 185, 129, 0.5)" : "rgba(16, 185, 129, 0.2)" }}
      >
        <span className="gemini-sparkle-icon" style={{ color: "#10b981", background: "rgba(16, 185, 129, 0.15)" }}>
          <FiTool size={14} />
        </span>
        <span className="gemini-btn-text">AI Remediation Playbook</span>
        {expanded ? <FiChevronUp size={14} /> : <FiChevronDown size={14} />}
      </button>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
            className="gemini-panel-wrapper"
          >
            <div className="gemini-panel-inner" style={{ borderColor: "rgba(16, 185, 129, 0.3)", boxShadow: "inset 0 0 40px rgba(16, 185, 129, 0.05)" }}>
              {loading ? (
                <div className="gemini-loading-state">
                  <FiLoader className="nl-icon-spin" size={24} style={{ color: "#10b981" }} />
                  <p>Security Engine is generating a tailored remediation playbook...</p>
                </div>
              ) : error ? (
                <div className="gemini-error-state">
                  <FiAlertTriangle size={18} /> {error}
                </div>
              ) : remediation ? (
                <>
                  <div className="gemini-report-header" style={{ borderColor: "rgba(16, 185, 129, 0.15)" }}>
                    <div className="gemini-report-title">
                      <FiShield size={16} style={{ color: "#10b981" }} />
                      {remediation.title || "Remediation Playbook"}
                    </div>
                  </div>
                  
                  <div className="gemini-report-body">
                    {remediation.subtitle && (
                      <p className="gemini-p" style={{ color: "rgba(255,255,255,0.6)", fontStyle: "italic", marginBottom: 20 }}>
                        {remediation.subtitle}
                      </p>
                    )}
                    
                    {remediation.estimated_time && (
                      <div style={{ display: "inline-flex", background: "rgba(16, 185, 129, 0.1)", color: "#10b981", padding: "4px 10px", borderRadius: 20, fontSize: 11, fontFamily: "var(--font-mono)", marginBottom: 24 }}>
                        ⏱ Estimated Time: {remediation.estimated_time}
                      </div>
                    )}

                    <h2 className="gemini-h2" style={{ color: "#10b981" }}>Required Actions</h2>
                    <div className="gemini-playbook-steps" style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                      {remediation.actions && remediation.actions.map((act, i) => (
                        <PlaybookStep 
                          key={i} 
                          index={i} 
                          step={{
                            title: `Step ${i + 1}`,
                            description: act,
                            commands: remediation.scripts ? [remediation.scripts[i]].filter(Boolean) : []
                          }} 
                        />
                      ))}
                    </div>
                  </div>
                </>
              ) : null}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
