import { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  FiSend, FiCpu, FiX, FiMessageCircle, FiZap, FiChevronDown,
  FiShield, FiRotateCcw, FiKey, FiUser, FiTerminal, FiAlertTriangle,
} from "react-icons/fi";
import { chatWithCopilot } from "../services/api";

/* ─── tiny markdown-to-JSX renderer ──────────────────────────────────────── */
function MiniMarkdown({ text }) {
  if (!text) return null;
  const lines = text.split("\n");
  return (
    <div className="copilot-md">
      {lines.map((line, i) => {
        if (line.startsWith("### "))
          return <h3 key={i} className="copilot-md-h3">{line.slice(4)}</h3>;
        if (line.startsWith("## "))
          return <h2 key={i} className="copilot-md-h2">{line.slice(3)}</h2>;
        if (line.startsWith("# "))
          return <h2 key={i} className="copilot-md-h2">{line.slice(2)}</h2>;
        if (line.startsWith("* ") || line.startsWith("- "))
          return (
            <div key={i} className="copilot-md-bullet">
              <span className="copilot-md-bullet-dot">▸</span>
              <span dangerouslySetInnerHTML={{ __html: inlineFormat(line.slice(2)) }} />
            </div>
          );
        if (line.trim() === "") return <div key={i} style={{ height: 8 }} />;
        return <p key={i} className="copilot-md-p" dangerouslySetInnerHTML={{ __html: inlineFormat(line) }} />;
      })}
    </div>
  );
}

function inlineFormat(text) {
  return text
    .replace(/`([^`]+)`/g, '<code class="copilot-inline-code">$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong style="color:rgba(255,255,255,0.92)">$1</strong>')
    .replace(/\*([^*]+)\*/g, '<em>$1</em>');
}

/* ─── Categorized suggestion chips ───────────────────────────────────────── */
const SUGGESTION_GROUPS = [
  {
    label: "Triage",
    icon: FiAlertTriangle,
    color: "#f97316",
    chips: [
      "Why is SEC-101 critical?",
      "What's the blast radius of this incident?",
      "Which developer introduced this vulnerability?",
    ],
  },
  {
    label: "Rollback",
    icon: FiRotateCcw,
    color: "#ef4444",
    chips: [
      "What's the rollback procedure?",
      "How do I revert the vulnerable commit safely?",
      "Is it safe to redeploy after the revert?",
    ],
  },
  {
    label: "Secrets",
    icon: FiKey,
    color: "#a855f7",
    chips: [
      "Show me the secrets detection findings",
      "How do I rotate the exposed API keys?",
      "How do I scrub secrets from git history?",
    ],
  },
  {
    label: "Fix",
    icon: FiShield,
    color: "#00d4ff",
    chips: [
      "How do I fix the lodash issue?",
      "What npm command patches this CVE?",
      "Show the remediation CLI commands",
    ],
  },
  {
    label: "Developer",
    icon: FiUser,
    color: "#00ff9d",
    chips: [
      "Explain the contractor_x anomaly",
      "What other PRs did this developer merge?",
      "Should I revoke developer access temporarily?",
    ],
  },
];

/* ─── Main Component ──────────────────────────────────────────────────────── */
export default function AICopilot({ activeIncidentId = 1 }) {
  const [open, setOpen]       = useState(false);
  const [activeGroup, setActiveGroup] = useState(0);
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      text: "👋 I'm your **SecOps AI Copilot** powered by Coral.\n\nI can help you:\n* 🔍 **Triage** — explain CVEs, blast radius, developer context\n* ⚡ **Rollback** — guide you through safe git reverts\n* 🔑 **Secrets** — rotate credentials & scrub git history\n* 🛡️ **Fix** — provide exact npm/pip patch commands\n\nSelect a category below or ask me anything.",
    },
  ]);
  const [input, setInput]     = useState("");
  const [loading, setLoading] = useState(false);
  const [logId, setLogId]     = useState(activeIncidentId);
  const bottomRef             = useRef(null);
  const inputRef              = useRef(null);

  // auto-scroll to latest message
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  // focus input when chat opens
  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 300);
  }, [open]);

  const send = async (text) => {
    const msg = text || input.trim();
    if (!msg || loading) return;
    setInput("");

    setMessages((prev) => [...prev, { role: "user", text: msg }]);
    setLoading(true);

    try {
      const res = await chatWithCopilot(msg, logId);
      const reply = res.data?.reply || "No response from AI.";
      const mode  = res.data?.mode || "mocked";
      setMessages((prev) => [
        ...prev,
        { role: "assistant", text: reply, mode },
      ]);
    } catch {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          text: "⚠️ Could not reach the AI backend. Make sure Flask is running on port 5001.",
          error: true,
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      {/* ── Floating toggle button ── */}
      <motion.button
        id="copilot-toggle-btn"
        className="copilot-fab"
        onClick={() => setOpen((o) => !o)}
        aria-label="Toggle AI Copilot"
        whileHover={{ scale: 1.08 }}
        whileTap={{ scale: 0.95 }}
        animate={open ? { rotate: 0 } : { rotate: 0 }}
      >
        {open ? <FiX size={22} /> : <FiMessageCircle size={22} />}
        {!open && <span className="copilot-fab-label">AI Copilot</span>}
        <span className="copilot-fab-pulse" />
      </motion.button>

      {/* ── Chat panel ── */}
      <AnimatePresence>
        {open && (
          <motion.div
            className="copilot-panel"
            initial={{ opacity: 0, y: 40, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 40, scale: 0.95 }}
            transition={{ duration: 0.28, ease: "easeOut" }}
            role="dialog"
            aria-label="AI Security Copilot"
          >
            {/* Header */}
            <div className="copilot-header">
              <div className="copilot-header-left">
                <div className="copilot-header-icon">
                  <FiCpu size={16} />
                  <span className="copilot-header-pulse" />
                </div>
                <div>
                  <div className="copilot-header-title">SecOps AI Copilot</div>
                  <div className="copilot-header-sub">Powered by Coral · GPT-4o-mini</div>
                </div>
              </div>

              {/* Incident selector */}
              <div className="copilot-incident-select">
                <select
                  value={logId}
                  onChange={(e) => setLogId(Number(e.target.value))}
                  className="copilot-select"
                  aria-label="Select active incident"
                >
                  <option value={1}>SEC-101</option>
                  <option value={2}>SEC-102</option>
                  <option value={3}>SEC-103</option>
                </select>
                <FiChevronDown size={12} className="copilot-select-arrow" />
              </div>

              <button
                className="copilot-close-btn"
                onClick={() => setOpen(false)}
                aria-label="Close chat"
              >
                <FiX size={16} />
              </button>
            </div>

            {/* Messages */}
            <div className="copilot-messages" role="log" aria-live="polite">
              {messages.map((m, i) => (
                <motion.div
                  key={i}
                  className={`copilot-msg copilot-msg-${m.role} ${m.error ? "copilot-msg-error" : ""}`}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.2 }}
                >
                  {m.role === "assistant" && (
                    <div className="copilot-msg-avatar">
                      <FiCpu size={12} />
                    </div>
                  )}
                  <div className="copilot-msg-bubble">
                    <MiniMarkdown text={m.text} />
                    {m.mode === "live" && (
                      <div className="copilot-live-badge">
                        <FiZap size={9} /> Live AI
                      </div>
                    )}
                  </div>
                </motion.div>
              ))}

              {/* Typing indicator */}
              {loading && (
                <motion.div
                  className="copilot-msg copilot-msg-assistant"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                >
                  <div className="copilot-msg-avatar"><FiCpu size={12} /></div>
                  <div className="copilot-msg-bubble copilot-typing">
                    <span /><span /><span />
                  </div>
                </motion.div>
              )}
              <div ref={bottomRef} />
            </div>

            {/* Categorized Suggestion chips */}
            {messages.length < 3 && (
              <div className="copilot-suggestions">
                {/* Category tabs */}
                <div className="copilot-suggestion-tabs">
                  {SUGGESTION_GROUPS.map((g, i) => {
                    const Icon = g.icon;
                    return (
                      <button
                        key={i}
                        className={`copilot-suggestion-tab ${activeGroup === i ? "copilot-suggestion-tab-active" : ""}`}
                        style={activeGroup === i ? { borderColor: g.color + "66", color: g.color, background: g.color + "18" } : {}}
                        onClick={() => setActiveGroup(i)}
                      >
                        <Icon size={10} />
                        {g.label}
                      </button>
                    );
                  })}
                </div>
                {/* Chips for active group */}
                <div className="copilot-chip-group">
                  {SUGGESTION_GROUPS[activeGroup].chips.map((s, i) => (
                    <button
                      key={i}
                      className="copilot-chip"
                      onClick={() => send(s)}
                      disabled={loading}
                      style={{ borderColor: SUGGESTION_GROUPS[activeGroup].color + "44" }}
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Input bar */}
            <form
              className="copilot-input-row"
              onSubmit={(e) => { e.preventDefault(); send(); }}
            >
              <input
                ref={inputRef}
                className="copilot-input"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Ask about any incident, CVE, or developer…"
                disabled={loading}
                aria-label="Chat message input"
                id="copilot-message-input"
              />
              <button
                type="submit"
                className="copilot-send-btn"
                disabled={!input.trim() || loading}
                aria-label="Send message"
                id="copilot-send-btn"
              >
                <FiSend size={16} />
              </button>
            </form>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
