import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { FiDatabase, FiChevronDown, FiChevronUp, FiLink } from "react-icons/fi";
import { FaGithub, FaSlack } from "react-icons/fa";

/* ── Schema definition (mirrors coral-sources.yaml) ─────────────── */
const SCHEMA = [
  {
    source: "github",
    table: "github_commits",
    icon: FaGithub,
    color: "#58a6ff",
    bg: "rgba(88,166,255,0.08)",
    border: "rgba(88,166,255,0.2)",
    learned_at: "2026-05-26T09:00:00Z",
    row_count: 6,
    columns: [
      { name: "pr_id",        type: "integer",   key: "PRIMARY" },
      { name: "author",       type: "string",    key: "JOIN → slack.user" },
      { name: "title",        type: "string",    key: null },
      { name: "package_name", type: "string",    key: "JOIN → osv.package_name, notion.applies_to" },
      { name: "merged_at",    type: "timestamp", key: null },
    ],
  },
  {
    source: "osv",
    table: "vulnerabilities",
    icon: () => <span style={{ fontSize: 14 }}>⚡</span>,
    color: "#fbbf24",
    bg: "rgba(251,191,36,0.08)",
    border: "rgba(251,191,36,0.2)",
    learned_at: "2026-05-26T09:01:00Z",
    row_count: 6,
    columns: [
      { name: "cve_id",       type: "string",  key: "PRIMARY" },
      { name: "package_name", type: "string",  key: "JOIN → github.package_name" },
      { name: "severity",     type: "enum",    key: null, values: "critical|high|medium|safe" },
      { name: "cvss_score",   type: "float",   key: null },
    ],
  },
  {
    source: "slack",
    table: "slack_messages",
    icon: FaSlack,
    color: "#e01e5a",
    bg: "rgba(224,30,90,0.08)",
    border: "rgba(224,30,90,0.2)",
    learned_at: "2026-05-26T09:01:30Z",
    row_count: 6,
    columns: [
      { name: "message_ts", type: "timestamp", key: "PRIMARY" },
      { name: "user",       type: "string",    key: "JOIN → github.author" },
      { name: "channel",    type: "string",    key: null },
      { name: "message",    type: "text",      key: null },
    ],
  },
  {
    source: "notion",
    table: "policies",
    icon: () => <span style={{ fontSize: 14 }}>📄</span>,
    color: "#e2e8f0",
    bg: "rgba(255,255,255,0.05)",
    border: "rgba(255,255,255,0.15)",
    learned_at: "2026-05-26T09:02:00Z",
    row_count: 4,
    columns: [
      { name: "policy_id",   type: "string", key: "PRIMARY" },
      { name: "applies_to",  type: "string", key: "JOIN → github.package_name" },
      { name: "policy_rule", type: "enum",   key: null, values: "BANNED|SECRETS_RISK|AUDIT|REVIEW" },
      { name: "owner_team",  type: "string", key: null },
      { name: "severity",    type: "enum",   key: null, values: "critical|high|medium" },
    ],
  },
];

function SchemaTable({ schema, open, onToggle }) {
  const Icon = schema.icon;
  return (
    <motion.div
      className="schema-card"
      style={{ borderColor: schema.border, background: schema.bg }}
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      <button className="schema-card-header" onClick={onToggle} aria-expanded={open}>
        <div className="schema-card-left">
          <div className="schema-card-icon" style={{ color: schema.color }}>
            <Icon size={14} />
          </div>
          <div>
            <div className="schema-card-source" style={{ color: schema.color }}>
              {schema.source}
            </div>
            <div className="schema-card-table">{schema.table}</div>
          </div>
        </div>
        <div className="schema-card-right">
          <span className="schema-rows-badge">{schema.row_count} rows</span>
          <span className="schema-learned-badge">✓ learned</span>
          {open ? <FiChevronUp size={12} /> : <FiChevronDown size={12} />}
        </div>
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            style={{ overflow: "hidden" }}
          >
            <div className="schema-columns">
              {schema.columns.map((col, i) => (
                <div key={i} className="schema-col-row">
                  <span className="schema-col-name">{col.name}</span>
                  <span className="schema-col-type">{col.type}</span>
                  {col.values && (
                    <span className="schema-col-values">{col.values}</span>
                  )}
                  {col.key && (
                    <span className="schema-col-key" title={col.key}>
                      <FiLink size={9} />
                      {col.key.startsWith("JOIN") ? col.key : col.key}
                    </span>
                  )}
                </div>
              ))}
            </div>
            <div className="schema-learned-at">
              Schema learned at {new Date(schema.learned_at).toLocaleTimeString()}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

export default function SchemaViewer() {
  const [open, setOpen]         = useState(false);
  const [openIdx, setOpenIdx]   = useState(null);

  const toggleSource = (i) => setOpenIdx(openIdx === i ? null : i);

  return (
    <section className="schema-section" aria-label="Coral Schema Viewer">
      <button className="schema-toggle-row" onClick={() => setOpen(o => !o)}>
        <div className="section-label" style={{ marginBottom: 0, flex: 1 }}>
          <FiDatabase size={12} style={{ color: "#a855f7" }} />
          <span className="section-label-text" style={{ color: "#a855f7" }}>
            Coral Schema Learning
          </span>
          <div className="section-label-line" />
        </div>
        <div className="schema-header-right">
          <span className="schema-header-pill">4 sources · 19 columns · auto-learned</span>
          {open ? <FiChevronUp size={14} /> : <FiChevronDown size={14} />}
        </div>
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3 }}
            style={{ overflow: "hidden" }}
          >
            <div className="schema-grid">
              {SCHEMA.map((s, i) => (
                <SchemaTable
                  key={s.source}
                  schema={s}
                  open={openIdx === i}
                  onToggle={() => toggleSource(i)}
                />
              ))}
            </div>
            <div className="schema-footer">
              <span>◈ Coral automatically learns schema from each source at startup</span>
              <span>·</span>
              <span>Join keys detected from <code>coral-sources.yaml</code></span>
              <span>·</span>
              <span>No manual mapping required</span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </section>
  );
}
