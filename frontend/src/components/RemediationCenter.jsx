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
} from "react-icons/fi";
import { getRemediation } from "../services/api";

/* ─── Utilities ───────────────────────────────────────────────────────────── */
function toLogId(incidentId) {
  return incidentId || "1";
}

/* ─── Static remediation data per severity ────────────────────────────────── */
function buildRemediationPlan(item) {
  const severity = item.vulnerability?.severity || "safe";
  const incidentId = item.incident_id || "CORAL-?";
  const developer = item.pr_details?.developer || "Unknown Developer";
  const packageName = item.package_details?.package_name || "unknown-package";
  const cve = item.vulnerability?.cve || "NO_CVE";
  const hasSecrets = !!item.secrets_detected;
  const hasPolicy = !!item.policy_violation;

  const steps = [];

  // Step 1: Always — immediate triage
  steps.push({
    id: "triage",
    icon: FiAlertTriangle,
    color: "#f97316",
    title: "Triage & Assess",
    description: `Review incident ${incidentId} triggered by ${developer}. Confirm vulnerability scope and blast radius.`,
    commands: [
      `# View incident details\ngit log --oneline -10`,
      `# Check affected files\ngit show HEAD --name-status`,
    ],
  });

  // Step 2: Critical/High — rollback
  if (severity === "critical" || severity === "high") {
    steps.push({
      id: "rollback",
      icon: FiRotateCcw,
      color: "#ef4444",
      title: "Immediate Rollback",
      description: `Revert the vulnerable branch change introduced by ${developer} to restore a safe deployment state.`,
      commands: [
        `# Revert the vulnerable branch change\ngit revert HEAD --no-edit`,
        `# Force push to block deployment (if needed)\ngit push origin HEAD --force-with-lease`,
      ],
    });
  }

  // Step 3: Secret leak
  if (hasSecrets) {
    steps.push({
      id: "secrets",
      icon: FiKey,
      color: "#a855f7",
      title: "Rotate Exposed Credentials",
      description: `Secret leak detected in commit. Immediately invalidate and rotate all exposed API keys or tokens.`,
      commands: [
        `# Scan for further leaks\npip install trufflehog\ntrufflehog git file://.`,
        `# Remove secret from git history\ngit filter-repo --path <secret-file> --invert-paths`,
        `# Rotate secrets on platform credentials dashboard`,
      ],
    });
  }

  // Step 4: Package vulnerability
  steps.push({
    id: "patch",
    icon: FiShield,
    color: "#00d4ff",
    title: `Patch Vulnerable Package`,
    description: `Update ${packageName} to its latest patched version to resolve ${cve}.`,
    commands: [
      `# Audit current dependencies\nnpm audit`,
      `# Upgrade the vulnerable package\nnpm install ${packageName}@latest`,
      `# Verify fix\nnpm audit --audit-level=high`,
    ],
  });

  // Step 5: Policy violation
  if (hasPolicy) {
    const rule = item.policy_violation?.policy_rule?.replace(/_/g, " ") || "policy rule";
    steps.push({
      id: "policy",
      icon: FiFileText,
      color: "#fbbf24",
      title: "Conduct Policy Review",
      description: `Violation of "${rule}" detected. Conduct a policy review in Notion to align branch guidelines and re-approve the PR workflow.`,
      commands: [
        `# Identify policy-violating commits\ngit log --all --grep="merge" --oneline`,
        `# Update branch protection rules\ngh api repos/:owner/:repo/branches/main/protection --method PUT`,
      ],
    });
  }

  // Step 6: Always — notify & document
  steps.push({
    id: "notify",
    icon: FiMessageSquare,
    color: "#00ff9d",
    title: "Notify & Document",
    description: `Alert the security team on Slack and document the incident in Notion with timeline, impact, and remediation steps.`,
    commands: [
      `# Post alert to Slack\ncurl -X POST $SLACK_WEBHOOK_URL \\\n  -H 'Content-type: application/json' \\\n  --data '{"text":"🚨 Security incident ${incidentId} remediated. CVE: ${cve}"}'`,
    ],
  });

  return {
    title: `Remediation CLI Center — ${incidentId}`,
    subtitle:
      severity === "critical"
        ? "Immediate Rollback & Credential Rotation Guidelines"
        : severity === "high"
        ? "Security Review & Patch Guidelines"
        : "Compliance & Patch Guidelines",
    severity,
    steps,
  };
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
      className="rc-copy-btn"
      onClick={copy}
      aria-label="Copy command"
      style={small ? { padding: "3px 7px", fontSize: 10 } : {}}
    >
      {copied ? (
        <><FiCheckCircle size={11} style={{ color: "#00ff9d" }} /> Copied</>
      ) : (
        <><FiCopy size={11} /> Copy</>
      )}
    </button>
  );
}

/* ─── CLI Command block ───────────────────────────────────────────────────── */
function CliBlock({ code }) {
  return (
    <div className="rc-cli-block">
      <div className="rc-cli-toolbar">
        <span className="rc-cli-lang">
          <FiTerminal size={10} /> bash terminal
        </span>
        <CopyBtn text={code} small />
      </div>
      <pre className="rc-cli-pre">{code}</pre>
    </div>
  );
}

/* ─── Single remediation step ────────────────────────────────────────────── */
function RemStep({ step, index, total }) {
  const [open, setOpen] = useState(false);
  const [done, setDone] = useState(false);
  const Icon = step.icon;

  return (
    <motion.div
      className={`rc-step ${done ? "rc-step-done" : ""}`}
      initial={{ opacity: 0, x: -12 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.07, duration: 0.35 }}
    >
      {/* connector line */}
      {index < total - 1 && <div className="rc-step-line" style={{ borderColor: step.color + "30" }} />}

      <div className="rc-step-header" onClick={() => setOpen((o) => !o)}>
        <div className="rc-step-left">
          <div className="rc-step-num" style={{ background: step.color + "22", border: `1px solid ${step.color}55`, color: step.color }}>
            {done ? <FiCheckCircle size={13} /> : index + 1}
          </div>
          <div className="rc-step-icon" style={{ color: step.color }}>
            <Icon size={14} />
          </div>
          <div className="rc-step-info">
            <div className="rc-step-title">{step.title}</div>
            <div className="rc-step-desc">{step.description}</div>
          </div>
        </div>
        <div className="rc-step-right">
          <button
            className="rc-mark-done"
            onClick={(e) => { e.stopPropagation(); setDone((d) => !d); }}
            style={{ color: done ? "#00ff9d" : "rgba(255,255,255,0.3)" }}
            aria-label={done ? "Mark as undone" : "Mark as done"}
          >
            <FiCheckCircle size={16} />
          </button>
          <button className="rc-expand-btn" aria-label="Toggle CLI commands">
            {open ? <FiChevronUp size={13} /> : <FiChevronDown size={13} />}
          </button>
        </div>
      </div>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.25, ease: "easeInOut" }}
            style={{ overflow: "hidden" }}
          >
            <div className="rc-step-cmds">
              {step.commands.map((cmd, i) => (
                <CliBlock key={i} code={cmd} />
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

/* ─── Progress bar ───────────────────────────────────────────────────────── */
function ProgressBar({ completed, total }) {
  const pct = total === 0 ? 0 : Math.round((completed / total) * 100);
  const color = pct === 100 ? "#00ff9d" : pct >= 50 ? "#fbbf24" : "#ef4444";
  return (
    <div className="rc-progress-wrap">
      <div className="rc-progress-label">
        <span style={{ color }}>
          {pct === 100 ? "✓ All steps completed" : `${completed} / ${total} steps completed`}
        </span>
        <span className="rc-progress-pct" style={{ color }}>{pct}%</span>
      </div>
      <div className="rc-progress-track">
        <motion.div
          className="rc-progress-fill"
          style={{ background: `linear-gradient(90deg, ${color}99, ${color})` }}
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.7, ease: "easeOut" }}
        />
      </div>
    </div>
  );
}

/* ─── Main component ─────────────────────────────────────────────────────── */
export default function RemediationCenter({ item }) {
  const [open, setOpen] = useState(false);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiScripts, setAiScripts] = useState(null);
  const [aiError, setAiError] = useState(null);
  const [doneMap, setDoneMap] = useState({});

  const plan = buildRemediationPlan(item);
  const severityColor =
    plan.severity === "critical"
      ? "#ef4444"
      : plan.severity === "high"
      ? "#f97316"
      : plan.severity === "medium"
      ? "#fbbf24"
      : "#00ff9d";

  const completedCount = plan.steps.filter((s) => doneMap[s.id]).length;

  const fetchAiScripts = useCallback(async () => {
    if (aiScripts) return;
    setAiLoading(true);
    setAiError(null);
    try {
      const res = await getRemediation(toLogId(item.incident_id));
      setAiScripts(res.data.remediation);
    } catch {
      setAiError("AI backend offline (port 5001). Showing static plan only.");
    } finally {
      setAiLoading(false);
    }
  }, [item.incident_id, aiScripts]);

  const handleOpen = useCallback(() => {
    setOpen((o) => {
      if (!o) fetchAiScripts();
      return !o;
    });
  }, [fetchAiScripts]);

  const toggleDone = useCallback((id) => {
    setDoneMap((prev) => ({ ...prev, [id]: !prev[id] }));
  }, []);

  return (
    <div className="rc-wrap">
      {/* Trigger button */}
      <button
        className={`rc-trigger-btn ${open ? "rc-trigger-btn-active" : ""}`}
        style={{ borderColor: severityColor + "55", color: severityColor }}
        onClick={handleOpen}
        id={`rc-btn-${item.incident_id}`}
      >
        <FiShield size={13} />
        Remediation Center
        {open ? <FiChevronUp size={12} /> : <FiChevronDown size={12} />}
        {completedCount > 0 && (
          <span className="rc-badge-count" style={{ background: severityColor + "22", color: severityColor }}>
            {completedCount}/{plan.steps.length}
          </span>
        )}
      </button>

      {/* Panel */}
      <AnimatePresence>
        {open && (
          <motion.div
            className="rc-panel"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.35, ease: "easeInOut" }}
            style={{ overflow: "hidden" }}
          >
            <div className="rc-panel-inner">
              {/* Header */}
              <div className="rc-panel-header">
                <div className="rc-panel-header-left">
                  <div className="rc-panel-icon" style={{ background: severityColor + "22", border: `1px solid ${severityColor}44` }}>
                    <FiShield size={16} style={{ color: severityColor }} />
                  </div>
                  <div>
                    <div className="rc-panel-title">{plan.title}</div>
                    <div className="rc-panel-subtitle">{plan.subtitle}</div>
                  </div>
                </div>
                {aiLoading && (
                  <div className="rc-ai-loading">
                    <FiLoader className="nl-icon-spin" size={13} />
                    <span>Loading AI scripts…</span>
                  </div>
                )}
                {aiScripts && !aiLoading && (
                  <div className="rc-ai-badge">
                    <FiZap size={10} /> AI Enhanced
                  </div>
                )}
              </div>

              {aiError && (
                <div className="rc-ai-error">{aiError}</div>
              )}

              {/* Progress */}
              <ProgressBar
                completed={Object.values(doneMap).filter(Boolean).length}
                total={plan.steps.length}
              />

              {/* Required Steps label */}
              <div className="rc-section-label">
                <FiCheckCircle size={11} />
                📋 Required Remediation Steps
              </div>

              {/* Steps */}
              <div className="rc-steps-list">
                {plan.steps.map((step, i) => (
                  <div key={step.id} onClick={() => {}} >
                    <RemStepControlled
                      step={step}
                      index={i}
                      total={plan.steps.length}
                      done={!!doneMap[step.id]}
                      onToggleDone={() => toggleDone(step.id)}
                    />
                  </div>
                ))}
              </div>

              {/* AI-enhanced scripts section */}
              {aiScripts && (
                <div className="rc-ai-scripts-section">
                  <div className="rc-section-label">
                    <FiZap size={11} />
                    💻 AI-Generated Actionable CLI Commands
                  </div>
                  {aiScripts.scripts?.map((script, i) => (
                    <CliBlock key={i} code={script} />
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

/* Controlled version with external done state */
function RemStepControlled({ step, index, total, done, onToggleDone }) {
  const [open, setOpen] = useState(false);
  const Icon = step.icon;

  return (
    <motion.div
      className={`rc-step ${done ? "rc-step-done" : ""}`}
      initial={{ opacity: 0, x: -12 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.07, duration: 0.35 }}
    >
      {index < total - 1 && (
        <div className="rc-step-line" style={{ borderColor: step.color + "30" }} />
      )}

      <div className="rc-step-header" onClick={() => setOpen((o) => !o)}>
        <div className="rc-step-left">
          <div
            className="rc-step-num"
            style={{
              background: done ? "#00ff9d22" : step.color + "22",
              border: `1px solid ${done ? "#00ff9d55" : step.color + "55"}`,
              color: done ? "#00ff9d" : step.color,
            }}
          >
            {done ? <FiCheckCircle size={13} /> : index + 1}
          </div>
          <div className="rc-step-icon" style={{ color: done ? "#00ff9d" : step.color }}>
            <Icon size={14} />
          </div>
          <div className="rc-step-info">
            <div className="rc-step-title" style={{ textDecoration: done ? "line-through" : "none", opacity: done ? 0.6 : 1 }}>
              {step.title}
            </div>
            <div className="rc-step-desc">{step.description}</div>
          </div>
        </div>
        <div className="rc-step-right">
          <button
            className="rc-mark-done"
            onClick={(e) => { e.stopPropagation(); onToggleDone(); }}
            style={{ color: done ? "#00ff9d" : "rgba(255,255,255,0.3)" }}
            title={done ? "Mark as undone" : "Mark as done"}
          >
            <FiCheckCircle size={16} />
          </button>
          <button className="rc-expand-btn" aria-label="Show CLI commands">
            {open ? <FiChevronUp size={13} /> : <FiChevronDown size={13} />}
          </button>
        </div>
      </div>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.25, ease: "easeInOut" }}
            style={{ overflow: "hidden" }}
          >
            <div className="rc-step-cmds">
              {step.commands.map((cmd, i) => (
                <CliBlock key={i} code={cmd} />
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
