import { useEffect, useRef } from "react";
import { motion } from "framer-motion";
import {
  FiAlertOctagon,
  FiAlertTriangle,
  FiAlertCircle,
  FiCheckCircle,
  FiActivity,
  FiKey,
  FiShield,
} from "react-icons/fi";

const cardConfigs = [
  {
    key: "total",
    label: "Total Incidents",
    dataKey: "total_incidents",
    icon: FiActivity,
    className: "card-total",
    trend: "Monitoring",
    corner: "#00d4ff",
  },
  {
    key: "critical",
    label: "Critical",
    dataKey: "critical",
    icon: FiAlertOctagon,
    className: "card-critical",
    trend: "Immediate action",
    corner: "#ef4444",
  },
  {
    key: "high",
    label: "High Risk",
    dataKey: "high",
    icon: FiAlertTriangle,
    className: "card-high",
    trend: "Review required",
    corner: "#f97316",
  },
  {
    key: "medium",
    label: "Medium",
    dataKey: "medium",
    icon: FiAlertCircle,
    className: "card-medium",
    trend: "Monitoring",
    corner: "#fbbf24",
  },
  {
    key: "safe",
    label: "Safe",
    dataKey: "safe",
    icon: FiCheckCircle,
    className: "card-safe",
    trend: "Clear to deploy",
    corner: "#00ff9d",
  },
  {
    key: "secrets",
    label: "Secrets Detected",
    dataKey: "secrets_detected",
    icon: FiKey,
    className: "card-critical",
    trend: "Rotate immediately",
    corner: "#ef4444",
  },
  {
    key: "policy",
    label: "Policy Violations",
    dataKey: "policy_violations",
    icon: FiShield,
    className: "card-high",
    trend: "Notion policy breach",
    corner: "#f97316",
  },
];

function AnimatedNumber({ value }) {
  const ref = useRef(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const start = 0;
    const end = Number(value);
    const duration = 1200;
    const startTime = performance.now();

    const update = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      el.textContent = Math.round(start + (end - start) * eased);
      if (progress < 1) requestAnimationFrame(update);
    };

    requestAnimationFrame(update);
  }, [value]);

  return <span ref={ref}>0</span>;
}

function SummaryCards({ summary }) {
  return (
    <section aria-label="Security Summary">
      <div className="section-label">
        <span className="section-label-text">Threat Overview</span>
        <div className="section-label-line" />
      </div>

      <div className="cards-grid">
        {cardConfigs.map((cfg, i) => {
          const Icon = cfg.icon;
          const value = summary[cfg.dataKey] ?? 0;

          return (
            <motion.div
              key={cfg.key}
              className={`stat-card ${cfg.className}`}
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.08, duration: 0.5, ease: "easeOut" }}
              whileHover={{ scale: 1.03, y: -6 }}
              role="article"
              aria-label={`${cfg.label}: ${value}`}
            >
              <div className="stat-card-glow" aria-hidden="true" />

              <Icon className="card-icon" aria-hidden="true" />

              <div className="card-label">{cfg.label}</div>

              <div className="card-value">
                <AnimatedNumber value={value} />
              </div>

              <div className="card-trend">{cfg.trend}</div>

              {/* Corner decoration */}
              <svg
                className="card-corner-accent"
                viewBox="0 0 40 40"
                aria-hidden="true"
              >
                <path
                  d="M40 0 L40 40 L0 40 Z"
                  fill={cfg.corner}
                />
              </svg>
            </motion.div>
          );
        })}
      </div>
    </section>
  );
}

export default SummaryCards;