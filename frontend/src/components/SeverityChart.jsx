import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

const SEVERITY_CONFIG = {
  Critical: { color: "#ef4444", glow: "rgba(239,68,68,0.3)", bar: "#ef4444" },
  High: { color: "#f97316", glow: "rgba(249,115,22,0.3)", bar: "#f97316" },
  Medium: { color: "#fbbf24", glow: "rgba(251,191,36,0.3)", bar: "#fbbf24" },
  Safe: { color: "#00ff9d", glow: "rgba(0,255,157,0.3)", bar: "#00ff9d" },
};

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  const { name, value } = payload[0];
  const cfg = SEVERITY_CONFIG[name] || {};
  return (
    <div
      style={{
        background: "rgba(6,16,38,0.95)",
        border: `1px solid ${cfg.color || "#00d4ff"}40`,
        borderRadius: 10,
        padding: "10px 16px",
        fontFamily: "var(--font-mono)",
        fontSize: 13,
        boxShadow: `0 8px 32px rgba(0,0,0,0.5), 0 0 16px ${cfg.glow || "transparent"}`,
      }}
    >
      <div style={{ color: cfg.color || "#fff", fontWeight: 700, marginBottom: 4 }}>{name}</div>
      <div style={{ color: "rgba(255,255,255,0.7)" }}>
        Count: <strong style={{ color: "#fff" }}>{value}</strong>
      </div>
    </div>
  );
};

const CustomLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, name, percent }) => {
  if (percent < 0.05) return null;
  const RADIAN = Math.PI / 180;
  const r = innerRadius + (outerRadius - innerRadius) * 0.5;
  const x = cx + r * Math.cos(-midAngle * RADIAN);
  const y = cy + r * Math.sin(-midAngle * RADIAN);
  return (
    <text
      x={x} y={y}
      fill="rgba(255,255,255,0.9)"
      textAnchor="middle"
      dominantBaseline="central"
      style={{ fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 600 }}
    >
      {(percent * 100).toFixed(0)}%
    </text>
  );
};

function SeverityChart({ summary }) {
  const [animated, setAnimated] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setAnimated(true), 400);
    return () => clearTimeout(t);
  }, []);

  const data = [
    { name: "Critical", value: summary.critical ?? 0 },
    { name: "High",     value: summary.high ?? 0 },
    { name: "Medium",   value: summary.medium ?? 0 },
    { name: "Safe",     value: summary.safe ?? 0 },
  ];

  const total = data.reduce((s, d) => s + d.value, 0) || 1;

  return (
    <motion.section
      className="chart-card"
      initial={{ opacity: 0, x: 30 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.6, ease: "easeOut", delay: 0.4 }}
      aria-label="Severity Distribution Chart"
    >
      <div className="chart-card-header">
        <div className="chart-card-title">Severity Distribution</div>
        <div className="chart-legend">
          {data.map((d) => (
            <div key={d.name} className="legend-item">
              <div
                className="legend-dot"
                style={{ background: SEVERITY_CONFIG[d.name]?.color }}
              />
              {d.name}
            </div>
          ))}
        </div>
      </div>

      <div className="chart-inner">
        {/* Pie chart */}
        <ResponsiveContainer width={220} height={220}>
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={55}
              outerRadius={90}
              dataKey="value"
              startAngle={90}
              endAngle={-270}
              labelLine={false}
              label={<CustomLabel />}
              isAnimationActive={true}
              animationBegin={500}
              animationDuration={1200}
              animationEasing="ease-out"
            >
              {data.map((entry) => (
                <Cell
                  key={entry.name}
                  fill={SEVERITY_CONFIG[entry.name]?.color}
                  style={{
                    filter: `drop-shadow(0 0 6px ${SEVERITY_CONFIG[entry.name]?.glow})`,
                  }}
                />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
          </PieChart>
        </ResponsiveContainer>

        {/* Bar breakdown */}
        <div className="chart-bars-section">
          {data.map((d) => {
            const pct = (d.value / total) * 100;
            const cfg = SEVERITY_CONFIG[d.name];
            return (
              <div key={d.name} className="chart-bar-item">
                <div className="chart-bar-label">{d.name}</div>
                <div className="chart-bar-track">
                  <div
                    className="chart-bar-fill"
                    style={{
                      width: animated ? `${pct}%` : "0%",
                      background: `linear-gradient(90deg, ${cfg.color}aa, ${cfg.color})`,
                      boxShadow: `0 0 8px ${cfg.glow}`,
                      transition: "width 1.2s cubic-bezier(0.4, 0, 0.2, 1)",
                    }}
                  />
                </div>
                <div
                  className="chart-bar-count"
                  style={{ color: cfg.color }}
                >
                  {d.value}
                </div>
              </div>
            );
          })}

          {/* Total indicator */}
          <div
            style={{
              marginTop: 16,
              padding: "10px 14px",
              background: "rgba(0,212,255,0.05)",
              border: "1px solid rgba(0,212,255,0.12)",
              borderRadius: 10,
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              fontFamily: "var(--font-mono)",
              fontSize: 12,
            }}
          >
            <span style={{ color: "rgba(255,255,255,0.45)" }}>Total Incidents</span>
            <span style={{ color: "#00d4ff", fontWeight: 700, fontSize: 18, fontFamily: "var(--font-display)" }}>
              {summary.total_incidents ?? 0}
            </span>
          </div>
        </div>
      </div>
    </motion.section>
  );
}

export default SeverityChart;