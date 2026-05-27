import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { FiDatabase, FiZap, FiCheck, FiChevronDown, FiChevronUp } from "react-icons/fi";

/* ── The Coral SQL query that runs on every page load ─────────────── */
const CORAL_SQL = `SELECT
  g.author,
  g.title           AS commit_title,
  g.package_name,
  g.merged_at,
  o.cve_id,
  o.severity,
  s.channel         AS slack_channel,
  s.message         AS slack_message,
  n.policy_name,
  n.policy_rule,
  n.owner_team
FROM   github_commits  AS g
LEFT JOIN vulnerabilities AS o
       ON g.package_name = o.package_name
LEFT JOIN slack_messages  AS s
       ON g.author       = s.user
LEFT JOIN policies        AS n
       ON g.package_name = n.applies_to
ORDER BY
  CASE o.severity
    WHEN 'critical' THEN 1
    WHEN 'high'     THEN 2
    WHEN 'medium'   THEN 3
    ELSE 4
  END,
  g.merged_at DESC`;

/* ── Execution steps shown during animation ──────────────────────── */
const EXEC_STEPS = [
  { label: "Connecting to GitHub source…",      color: "#58a6ff", icon: "🐙" },
  { label: "Connecting to OSV database…",       color: "#fbbf24", icon: "⚡" },
  { label: "Connecting to Slack…",              color: "#e01e5a", icon: "💬" },
  { label: "Connecting to Notion policies…",    color: "#fff",    icon: "📄" },
  { label: "Building hash indexes for JOINs…", color: "#a855f7", icon: "🔗" },
  { label: "Executing cross-source JOIN…",      color: "#a855f7", icon: "⚙️" },
  { label: "Running secret detection scan…",   color: "#ef4444", icon: "🔑" },
  { label: "Applying policy violation check…", color: "#f97316", icon: "📋" },
  { label: "Coral handled auth, pagination, rate limits", color: "#00d4ff", icon: "🛡️" },
];

/* ── Typewriter effect for SQL ───────────────────────────────────── */
function useTypewriter(text, speed = 18, play = false) {
  const [displayed, setDisplayed] = useState("");
  const indexRef = useRef(0);

  useEffect(() => {
    if (!play) return;
    indexRef.current = 0;
    setDisplayed("");
    const interval = setInterval(() => {
      if (indexRef.current >= text.length) {
        clearInterval(interval);
        return;
      }
      setDisplayed(text.slice(0, indexRef.current + 1));
      indexRef.current += 1;
    }, speed);
    return () => clearInterval(interval);
  }, [text, play, speed]);

  return displayed;
}

export default function CoralQueryViewer({ coralMeta }) {
  const [expanded, setExpanded] = useState(false);
  const [playing,  setPlaying]  = useState(false);
  const [stepIdx,  setStepIdx]  = useState(-1);
  const [done,     setDone]     = useState(false);

  const typedSQL = useTypewriter(CORAL_SQL, 12, playing);

  /* Auto-play once on mount */
  useEffect(() => {
    const t = setTimeout(() => setPlaying(true), 800);
    return () => clearTimeout(t);
  }, []);

  /* Step ticker */
  useEffect(() => {
    if (!playing) return;
    if (stepIdx >= EXEC_STEPS.length - 1) { setDone(true); return; }
    const t = setTimeout(() => setStepIdx(i => i + 1), 420);
    return () => clearTimeout(t);
  }, [playing, stepIdx]);

  const replay = () => {
    setDone(false);
    setStepIdx(-1);
    setPlaying(false);
    setTimeout(() => setPlaying(true), 80);
  };

  return (
    <section className="cqv-wrap" aria-label="Coral Query Viewer">
      {/* ── Header bar ──────────────────────────────────────────── */}
      <div className="cqv-header">
        <div className="cqv-header-left">
          <div className="cqv-icon"><FiDatabase size={14} /></div>
          <span className="cqv-title">Coral SQL Engine</span>
          <span className="cqv-sources-pill">
            <FiZap size={9} /> 4 sources · 1 query
          </span>
          {done && (
            <motion.span
              className="cqv-done-pill"
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
            >
              <FiCheck size={9} /> Executed
            </motion.span>
          )}
          {coralMeta?.cache_hit && (
            <span className="cqv-cache-pill" title={`Cached at ${coralMeta.cached_at}`}>
              ⚡ Cache hit
            </span>
          )}
        </div>
        <div className="cqv-header-right">
          {done && (
            <button className="cqv-replay-btn" onClick={replay} aria-label="Replay animation">
              ↺ Replay
            </button>
          )}
          <button
            className="cqv-toggle-btn"
            onClick={() => setExpanded(e => !e)}
            aria-expanded={expanded}
          >
            {expanded ? <FiChevronUp size={14} /> : <FiChevronDown size={14} />}
          </button>
        </div>
      </div>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.28 }}
            style={{ overflow: "hidden" }}
          >
            <div className="cqv-body">
              {/* ── Left: SQL display ─────────────────────────── */}
              <div className="cqv-sql-panel">
                <div className="cqv-sql-toolbar">
                  <span className="cqv-sql-lang">coral sql</span>
                  <span className="cqv-sql-file">coral-sources.yaml</span>
                </div>
                <pre className="cqv-sql-code" aria-label="Coral SQL query">
                  <code>{typedSQL || " "}<span className="cqv-cursor" aria-hidden="true" /></code>
                </pre>
              </div>

              {/* ── Right: Execution log ─────────────────────── */}
              <div className="cqv-exec-panel">
                <div className="cqv-exec-title">Execution Log</div>
                <div className="cqv-exec-steps">
                  {EXEC_STEPS.map((step, i) => (
                    <AnimatePresence key={i}>
                      {i <= stepIdx && (
                        <motion.div
                          className="cqv-exec-step"
                          initial={{ opacity: 0, x: -12 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ duration: 0.22 }}
                        >
                          <span className="cqv-step-icon">{step.icon}</span>
                          <span className="cqv-step-label" style={{ color: step.color }}>
                            {step.label}
                          </span>
                          <FiCheck size={10} className="cqv-step-check" />
                        </motion.div>
                      )}
                    </AnimatePresence>
                  ))}
                </div>

                {/* ── Result stats ─────────────────────────── */}
                {done && (
                  <motion.div
                    className="cqv-result-stats"
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.2 }}
                  >
                    <div className="cqv-stat">
                      <div className="cqv-stat-val" style={{ color: "#00d4ff" }}>4</div>
                      <div className="cqv-stat-label">Sources Joined</div>
                    </div>
                    <div className="cqv-stat">
                      <div className="cqv-stat-val" style={{ color: "#00ff9d" }}>6</div>
                      <div className="cqv-stat-label">Rows Returned</div>
                    </div>
                    <div className="cqv-stat">
                      <div className="cqv-stat-val" style={{ color: "#a855f7" }}>
                        {coralMeta?.cache_hit ? "⚡ hit" : "~42ms"}
                      </div>
                      <div className="cqv-stat-label">
                        {coralMeta?.cache_hit ? "Cache Hit" : "Query Time"}
                      </div>
                    </div>
                    <div className="cqv-stat">
                      <div className="cqv-stat-val" style={{ color: "#ff4d6d" }}>✓</div>
                      <div className="cqv-stat-label">Auth Handled</div>
                    </div>
                  </motion.div>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </section>
  );
}
