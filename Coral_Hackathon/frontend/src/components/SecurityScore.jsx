import { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";

const RADIUS = 80;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

function getScoreConfig(score) {
  if (score >= 75) {
    return {
      color: "#00ff9d",
      glow: "rgba(0,255,157,0.4)",
      grade: "A",
      gradeColor: "#00ff9d",
      label: "Excellent",
      borderColor: "rgba(0,255,157,0.3)",
      bg: "rgba(0,255,157,0.08)",
    };
  } else if (score >= 50) {
    return {
      color: "#fbbf24",
      glow: "rgba(251,191,36,0.4)",
      grade: "B",
      gradeColor: "#fbbf24",
      label: "Moderate Risk",
      borderColor: "rgba(251,191,36,0.3)",
      bg: "rgba(251,191,36,0.08)",
    };
  } else if (score >= 25) {
    return {
      color: "#f97316",
      glow: "rgba(249,115,22,0.4)",
      grade: "C",
      gradeColor: "#f97316",
      label: "High Risk",
      borderColor: "rgba(249,115,22,0.3)",
      bg: "rgba(249,115,22,0.08)",
    };
  } else {
    return {
      color: "#ef4444",
      glow: "rgba(239,68,68,0.4)",
      grade: "D",
      gradeColor: "#ef4444",
      label: "Critical Risk",
      borderColor: "rgba(239,68,68,0.3)",
      bg: "rgba(239,68,68,0.08)",
    };
  }
}

function SecurityScore({ summary }) {
  const danger =
    (summary.critical ?? 0) * 30 +
    (summary.high ?? 0) * 15 +
    (summary.medium ?? 0) * 5;
  const score = Math.max(0, Math.min(100, 100 - danger));

  const [displayScore, setDisplayScore] = useState(0);
  const [dashOffset, setDashOffset] = useState(CIRCUMFERENCE);
  const cfg = getScoreConfig(score);

  useEffect(() => {
    const duration = 1500;
    const startTime = performance.now();

    const animate = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);

      setDisplayScore(Math.round(score * eased));
      setDashOffset(CIRCUMFERENCE - CIRCUMFERENCE * (score / 100) * eased);

      if (progress < 1) requestAnimationFrame(animate);
    };

    requestAnimationFrame(animate);
  }, [score]);

  return (
    <motion.section
      className="score-card"
      initial={{ opacity: 0, x: -30 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.6, ease: "easeOut", delay: 0.3 }}
      aria-label={`Security Score: ${score} out of 100`}
    >
      <div className="score-card-title">Security Score</div>

      {/* Grade badge */}
      <div
        className="score-grade-badge"
        style={{
          color: cfg.gradeColor,
          borderColor: cfg.borderColor,
          background: cfg.bg,
        }}
      >
        <span style={{ fontSize: "18px", fontFamily: "var(--font-display)", fontWeight: 900 }}>
          {cfg.grade}
        </span>
        <span style={{ fontSize: "12px" }}>{cfg.label}</span>
      </div>

      {/* SVG Gauge */}
      <div className="score-gauge-wrap">
        <svg
          className="score-gauge-svg"
          width="200"
          height="200"
          viewBox="0 0 200 200"
          aria-hidden="true"
        >
          {/* Track */}
          <circle
            className="score-gauge-track"
            cx="100"
            cy="100"
            r={RADIUS}
          />
          {/* Fill */}
          <circle
            className="score-gauge-fill"
            cx="100"
            cy="100"
            r={RADIUS}
            stroke={cfg.color}
            strokeDasharray={CIRCUMFERENCE}
            strokeDashoffset={dashOffset}
            style={{
              filter: `drop-shadow(0 0 8px ${cfg.glow}) drop-shadow(0 0 16px ${cfg.glow})`,
            }}
          />
          {/* Tick marks */}
          {Array.from({ length: 20 }).map((_, i) => {
            const angle = (i / 20) * 360;
            const rad = (angle * Math.PI) / 180;
            const inner = 66;
            const outer = 72;
            const x1 = 100 + inner * Math.cos(rad);
            const y1 = 100 + inner * Math.sin(rad);
            const x2 = 100 + outer * Math.cos(rad);
            const y2 = 100 + outer * Math.sin(rad);
            return (
              <line
                key={i}
                x1={x1} y1={y1}
                x2={x2} y2={y2}
                stroke="rgba(255,255,255,0.08)"
                strokeWidth="1"
              />
            );
          })}
        </svg>

        <div className="score-gauge-center">
          <div
            className="score-value"
            style={{ color: cfg.color }}
          >
            {displayScore}
          </div>
          <div className="score-label">/ 100</div>
        </div>
      </div>

      {/* Risk breakdown */}
      <div className="score-risk-breakdown">
        <div className="score-risk-item">
          <div className="score-risk-label">Critical</div>
          <div className="score-risk-value" style={{ color: "#ef4444" }}>
            {summary.critical ?? 0}
          </div>
        </div>
        <div className="score-risk-item">
          <div className="score-risk-label">High</div>
          <div className="score-risk-value" style={{ color: "#f97316" }}>
            {summary.high ?? 0}
          </div>
        </div>
        <div className="score-risk-item">
          <div className="score-risk-label">Medium</div>
          <div className="score-risk-value" style={{ color: "#fbbf24" }}>
            {summary.medium ?? 0}
          </div>
        </div>
        <div className="score-risk-item">
          <div className="score-risk-label">Safe</div>
          <div className="score-risk-value" style={{ color: "#00ff9d" }}>
            {summary.safe ?? 0}
          </div>
        </div>
      </div>
    </motion.section>
  );
}

export default SecurityScore;
