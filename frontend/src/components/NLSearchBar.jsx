import { useState, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  FiSearch,
  FiZap,
  FiDatabase,
  FiAlertCircle,
  FiCheckCircle,
  FiLoader,
} from "react-icons/fi";
import { nlSearch } from "../services/api";

/* ─── Quick example queries ───────────────────────────────────────────────── */
const EXAMPLES = [
  "Show all critical incidents",
  "Find commits by alice today",
  "High severity vulnerabilities",
  "Who introduced the lodash bug?",
];

/* ─── Result severity color ──────────────────────────────────────────────── */
const sColor = {
  Critical: "#e11d48",
  High: "#ea580c",
  Medium: "#f59e0b",
  Low: "#10b981",
};

export default function NLSearchBar({ onResults }) {
  const [query, setQuery]       = useState("");
  const [loading, setLoading]   = useState(false);
  const [result, setResult]     = useState(null);   // { sql, rows, count }
  const [error, setError]       = useState(null);
  const [sqlExpanded, setSqlExp] = useState(true);
  const [rowsExpanded, setRowsExp] = useState(true);
  const inputRef = useRef(null);

  const search = async (q) => {
    const text = q || query.trim();
    if (!text) return;
    setQuery(text);
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await nlSearch(text);
      const d   = res.data;
      setResult({
        sql:   d.coral_query,
        rows:  d.rows || [],
        count: d.row_count,
        naturalQuery: d.natural_query,
      });
      onResults?.(d.rows || []);
    } catch (err) {
      setError(
        err?.response?.status === 404
          ? "Backend not running — start with: cd backend && npm start"
          : err.userMessage || err.message || "Search failed"
      );
    } finally {
      setLoading(false);
    }
  };

  const clear = () => {
    setQuery("");
    setResult(null);
    setError(null);
    onResults?.(null);
    inputRef.current?.focus();
  };

  return (
    <section className="nl-search-section" aria-label="Natural Language Search">
      {/* ── Section label ── */}
      <div className="section-label" style={{ marginBottom: 12 }}>
        <span className="section-label-text">Natural Language → SQL Search</span>
        <div className="section-label-line" />
        <span
          className="nl-badge"
          title="Translates your English question into a Coral SQL query"
        >
          <FiZap size={10} /> Coral Powered
        </span>
      </div>

      {/* ── Search input ── */}
      <form
        className="nl-form"
        onSubmit={(e) => { e.preventDefault(); search(); }}
        role="search"
      >
        <div className="nl-input-wrap">
          {loading
            ? <FiLoader className="nl-icon nl-icon-spin" aria-hidden="true" />
            : <FiSearch className="nl-icon" aria-hidden="true" />
          }
          <input
            ref={inputRef}
            id="nl-search-input"
            className="nl-input"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder='e.g. "Show all critical incidents from today"'
            disabled={loading}
            aria-label="Natural language security query"
            autoComplete="off"
          />
          {query && (
            <button
              type="button"
              className="nl-clear-btn"
              onClick={clear}
              aria-label="Clear search"
            >
              ×
            </button>
          )}
        </div>
        <button
          id="nl-search-submit"
          type="submit"
          className="nl-search-btn"
          disabled={!query.trim() || loading}
          aria-label="Run search"
        >
          {loading ? "Querying…" : "Run Query"}
        </button>
      </form>

      {/* ── Example chips ── */}
      <div className="nl-examples" role="list" aria-label="Example queries">
        {EXAMPLES.map((ex) => (
          <button
            key={ex}
            role="listitem"
            className="nl-example-chip"
            onClick={() => search(ex)}
            disabled={loading}
          >
            {ex}
          </button>
        ))}
      </div>

      {/* ── Error ── */}
      <AnimatePresence>
        {error && (
          <motion.div
            className="nl-error"
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
          >
            <FiAlertCircle size={14} /> {error}
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Results ── */}
      <AnimatePresence>
        {result && (
          <motion.div
            className="nl-results"
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.3 }}
          >
            {/* Generated SQL */}
            <div className="nl-sql-block">
              <button
                className="nl-sql-header"
                onClick={() => setSqlExp((x) => !x)}
                aria-expanded={sqlExpanded}
                id="nl-sql-toggle"
              >
                <span className="nl-sql-label">
                  <FiDatabase size={12} /> Generated Coral SQL
                </span>
                <span className="nl-sql-chevron">{sqlExpanded ? "▲" : "▼"}</span>
              </button>
              <AnimatePresence>
                {sqlExpanded && (
                  <motion.pre
                    className="nl-sql-code"
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.2 }}
                  >
                    {result.sql}
                  </motion.pre>
                )}
              </AnimatePresence>
            </div>

            {/* Row count */}
            <div className="nl-row-count">
              <FiCheckCircle size={13} style={{ color: "#10b981" }} />
              <span>
                <strong style={{ color: "#10b981" }}>{result.count}</strong>{" "}
                row{result.count !== 1 ? "s" : ""} returned
              </span>
            </div>

            {/* Result rows */}
            {result.rows.length > 0 && (
              <div className="nl-rows-wrap">
                <button
                  className="nl-rows-toggle"
                  onClick={() => setRowsExp((x) => !x)}
                  aria-expanded={rowsExpanded}
                >
                  {rowsExpanded ? "▲ Hide" : "▼ Show"} results
                </button>
                <AnimatePresence>
                  {rowsExpanded && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: "auto", opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                    >
                      {result.rows.map((row, i) => (
                        <div key={i} className="nl-row-card">
                          <div className="nl-row-top">
                            <span
                              className="nl-row-code"
                              style={{ color: sColor[row.severity] || "#fff" }}
                            >
                              {row.code || `ROW-${i + 1}`}
                            </span>
                            {row.severity && (
                              <span
                                className="nl-row-sev"
                                style={{
                                  color: sColor[row.severity],
                                  borderColor: (sColor[row.severity] || "#fff") + "44",
                                  background: (sColor[row.severity] || "#fff") + "14",
                                }}
                              >
                                {row.severity}
                              </span>
                            )}
                          </div>
                          <div className="nl-row-commit">{row.commit_message}</div>
                          <div className="nl-row-meta">
                            {row.author && <span>👤 {row.author}</span>}
                            {row.vuln_id && <span>🔒 {row.vuln_id}</span>}
                            {row.package && <span>📦 {row.package}</span>}
                          </div>
                        </div>
                      ))}
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </section>
  );
}
