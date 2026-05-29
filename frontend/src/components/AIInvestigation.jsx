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

/* ─── Premium Gemini-style Markdown Renderer ─────────────────────────────── */
function GeminiMarkdown({ text }) {
  if (!text) return null;
  const lines = text.split("\n");
  
  let inCodeBlock = false;
  let codeLines = [];
  let rendered = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    
    if (line.startsWith("```")) {
      if (inCodeBlock) {
        // flush code block
        rendered.push(
          <div key={`code-${i}`} className="gemini-code-block">
            <div className="gemini-code-header">
              <span>{codeLines.lang || "code"}</span>
              <CopyBtn text={codeLines.join("\n")} small />
            </div>
            <pre className="gemini-code-pre">{codeLines.join("\n")}</pre>
          </div>
        );
        inCodeBlock = false;
        codeLines = [];
      } else {
        inCodeBlock = true;
        codeLines.lang = line.replace("```", "").trim();
      }
      continue;
    }

    if (inCodeBlock) {
      codeLines.push(line);
      continue;
    }

    if (line.startsWith("### ")) {
      rendered.push(<h3 key={i} className="gemini-h3">{line.slice(4)}</h3>);
      continue;
    }
    if (line.startsWith("## ") || line.startsWith("# ")) {
      rendered.push(<h2 key={i} className="gemini-h2">{line.replace(/^#{1,2} /, "")}</h2>);
      continue;
    }
    if (line.startsWith("> ")) {
      rendered.push(<blockquote key={i} className="gemini-blockquote" dangerouslySetInnerHTML={{ __html: fmt(line.slice(2)) }} />);
      continue;
    }
    if (line.startsWith("* ") || line.startsWith("- ")) {
      rendered.push(
        <div key={i} className="gemini-list-item">
          <span className="gemini-bullet">•</span>
          <span dangerouslySetInnerHTML={{ __html: fmt(line.slice(2)) }} />
        </div>
      );
      continue;
    }
    if (line.trim() === "") {
      rendered.push(<div key={i} className="gemini-spacer" />);
      continue;
    }
    rendered.push(<p key={i} className="gemini-p" dangerouslySetInnerHTML={{ __html: fmt(line) }} />);
  }

  return (
    <div className="gemini-markdown-container">
      {rendered}
    </div>
  );
}

function fmt(t) {
  return t
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/`([^`]+)`/g, '<code class="gemini-inline-code">$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\*([^*]+)\*/g, "<em>$1</em>");
}

/* ─── Copy button ────────────────────────────────────────────────────────── */
function CopyBtn({ text, small }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };
  return (
    <button className="gemini-copy-btn" onClick={copy} aria-label="Copy code">
      {copied ? <FiCheckCircle size={small ? 12 : 14} style={{ color: "#10b981" }} /> : <FiCopy size={small ? 12 : 14} />}
      {!small && <span>{copied ? "Copied" : "Copy"}</span>}
    </button>
  );
}

/* ─── Main Component ──────────────────────────────────────────────────────── */
export default function AIInvestigation({ logId = 1 }) {
  const [expanded, setExpanded] = useState(false);
  const [loading, setLoading]   = useState(false);
  const [aiReport, setAiReport] = useState(null);
  const [error, setError]       = useState(null);

  const toggle = async () => {
    if (expanded) {
      setExpanded(false);
      return;
    }
    
    setExpanded(true);
    if (aiReport) return;

    setLoading(true);
    setError(null);
    try {
      const res = await investigateIncident(logId);
      setAiReport({
        report: res.data.ai_analysis_markdown,
        mode:   res.data.mode,
      });
    } catch {
      setError("AI Engine unreachable. Check backend connection.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="ai-invest-premium-wrap">
      <button 
        onClick={toggle} 
        className={`gemini-trigger-btn ${expanded ? "active" : ""}`}
      >
        <span className="gemini-sparkle-icon">
          <FiZap size={14} />
        </span>
        <span className="gemini-btn-text">Deep AI Investigation</span>
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
            <div className="gemini-panel-inner">
              {loading ? (
                <div className="gemini-loading-state">
                  <FiLoader className="nl-icon-spin" size={24} style={{ color: "#a855f7" }} />
                  <p>Coral AI is synthesizing incident forensics...</p>
                </div>
              ) : error ? (
                <div className="gemini-error-state">
                  <FiTool size={18} /> {error}
                </div>
              ) : aiReport ? (
                <>
                  <div className="gemini-report-header">
                    <div className="gemini-report-title">
                      <FiCpu size={16} style={{ color: "#c084fc" }} />
                      Security Intelligence Report
                    </div>
                    <div className={`gemini-badge ${aiReport.mode === 'live' ? 'live' : 'mocked'}`}>
                      {aiReport.mode === 'live' ? '✨ Live Generation (Gemini 2.5 Flash)' : '🔄 Cached Fallback'}
                    </div>
                  </div>
                  <div className="gemini-report-body">
                    <GeminiMarkdown text={aiReport.report} />
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
