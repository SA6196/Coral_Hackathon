import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  FiCpu,
  FiTool,
  FiZap,
  FiLoader,
  FiChevronDown,
  FiChevronUp,
  FiCopy,
  FiCheckCircle,
} from "react-icons/fi";
import { investigateIncident, getRemediation } from "../services/api";

/* ─── tiny markdown renderer (same as copilot) ─────────────────────────────── */
function MiniMarkdown({ text }) {
  if (!text) return null;
  const lines = text.split("\n");
  return (
    <div className="copilot-md" style={{ fontSize: 13 }}>
      {lines.map((line, i) => {
        if (line.startsWith("### "))
          return <h3 key={i} className="copilot-md-h3">{line.slice(4)}</h3>;
        if (line.startsWith("## ") || line.startsWith("# "))
          return <h2 key={i} className="copilot-md-h2">{line.replace(/^#{1,2} /, "")}</h2>;
        if (line.startsWith("* ") || line.startsWith("- "))
          return (
            <div key={i} className="copilot-md-bullet">
              <span className="copilot-md-bullet-dot">▸</span>
              <span dangerouslySetInnerHTML={{ __html: fmt(line.slice(2)) }} />
            </div>
          );
        if (line.trim() === "") return <div key={i} style={{ height: 6 }} />;
        return <p key={i} className="copilot-md-p" dangerouslySetInnerHTML={{ __html: fmt(line) }} />;
      })}
    </div>
  );
}
function fmt(t) {
  return t
    .replace(/`([^`]+)`/g, '<code class="copilot-inline-code">$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\*([^*]+)\*/g, "<em>$1</em>");
}

/* ─── Copy button ────────────────────────────────────────────────────────── */
function CopyBtn({ text }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };
  return (
    <button className="remediate-copy-btn" onClick={copy} aria-label="Copy script">
      {copied ? <FiCheckCircle size={12} style={{ color: "#00ff9d" }} /> : <FiCopy size={12} />}
    </button>
  );
}

/* ─── Script block ───────────────────────────────────────────────────────── */
function ScriptBlock({ code }) {
  return (
    <div className="remediate-script-block">
      <div className="remediate-script-toolbar">
        <span className="remediate-script-lang">bash</span>
        <CopyBtn text={code} />
      </div>
      <pre className="remediate-script-pre">{code}</pre>
    </div>
  );
}

/* ─── Main Component ──────────────────────────────────────────────────────── */
export default function AIInvestigation({ logId = 1 }) {
  const [tab, setTab]           = useState(null); // "investigate" | "remediate" | null
  const [loading, setLoading]   = useState(false);
  const [aiReport, setAiReport] = useState(null);
  const [remediation, setRemed] = useState(null);
  const [error, setError]       = useState(null);

  const openTab = async (t) => {
    // toggle off
    if (tab === t) { setTab(null); return; }
    setTab(t);
    setError(null);

    // already loaded
    if (t === "investigate" && aiReport) return;
    if (t === "remediate"   && remediation) return;

    setLoading(true);
    try {
      if (t === "investigate") {
        const res = await investigateIncident(logId);
        setAiReport({
          report: res.data.ai_analysis_markdown,
          mode:   res.data.mode,
          logs:   res.data.extracted_logs,
        });
      } else {
        const res = await getRemediation(logId);
        setRemed(res.data.remediation);
      }
    } catch {
      setError("Flask backend unreachable (port 5001). Make sure `python app.py` is running.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="ai-invest-wrap">
      {/* ── Tab buttons ── */}
      <div className="ai-invest-tabs" role="tablist">
        <button
          role="tab"
          id={`investigate-tab-${logId}`}
          aria-selected={tab === "investigate"}
          className={`ai-invest-tab ${tab === "investigate" ? "ai-invest-tab-active" : ""}`}
          onClick={() => openTab("investigate")}
        >
          <FiCpu size={12} />
          AI Investigation
          {tab === "investigate"
            ? <FiChevronUp size={11} />
            : <FiChevronDown size={11} />}
        </button>
        <button
          role="tab"
          id={`remediate-tab-${logId}`}
          aria-selected={tab === "remediate"}
          className={`ai-invest-tab ${tab === "remediate" ? "ai-invest-tab-active ai-invest-tab-green" : ""}`}
          onClick={() => openTab("remediate")}
        >
          <FiTool size={12} />
          Remediation Scripts
          {tab === "remediate"
            ? <FiChevronUp size={11} />
            : <FiChevronDown size={11} />}
        </button>
      </div>

      {/* ── Panel body ── */}
      <AnimatePresence>
        {tab && (
          <motion.div
            className="ai-invest-panel"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.3, ease: "easeInOut" }}
            style={{ overflow: "hidden" }}
          >
            <div style={{ padding: "16px 0 4px" }}>
              {/* Loading */}
              {loading && (
                <div className="ai-invest-loading">
                  <FiLoader className="nl-icon-spin" size={16} />
                  <span>
                    {tab === "investigate"
                      ? "Running Coral AI investigation…"
                      : "Generating remediation scripts…"}
                  </span>
                </div>
              )}

              {/* Error */}
              {!loading && error && (
                <div className="ai-invest-error">{error}</div>
              )}

              {/* ── Investigate panel ── */}
              {!loading && !error && tab === "investigate" && aiReport && (
                <div className="ai-invest-content">
                  {aiReport.mode === "live" && (
                    <div className="ai-invest-live-badge">
                      <FiZap size={10} /> Live GPT-4o-mini Response
                    </div>
                  )}
                  {aiReport.mode === "mocked" && (
                    <div className="ai-invest-mock-badge">
                      ⚡ Expert Template (no OpenAI key — add OPENAI_API_KEY to env)
                    </div>
                  )}
                  <MiniMarkdown text={aiReport.report} />
                </div>
              )}

              {/* ── Remediation panel ── */}
              {!loading && !error && tab === "remediate" && remediation && (
                <div className="ai-invest-content">
                  <div className="remediate-title">{remediation.title}</div>

                  {/* Action checklist */}
                  <div className="remediate-actions">
                    {remediation.actions?.map((action, i) => (
                      <div key={i} className="remediate-action-item">
                        <span className="remediate-action-num">{i + 1}</span>
                        {action}
                      </div>
                    ))}
                  </div>

                  {/* Scripts */}
                  {remediation.scripts?.length > 0 && (
                    <div className="remediate-scripts">
                      <div className="remediate-scripts-label">
                        <FiTool size={11} /> Shell Scripts
                      </div>
                      {remediation.scripts.map((script, i) => (
                        <ScriptBlock key={i} code={script} />
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
