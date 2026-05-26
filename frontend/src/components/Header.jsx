import { useEffect, useState } from "react";
import {
  FaShieldAlt,
  FaGithub,
  FaSlack,
} from "react-icons/fa";
import { MdSecurity } from "react-icons/md";

function LiveClock() {
  const [time, setTime] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return (
    <span className="header-time">
      {time.toLocaleTimeString("en-US", { hour12: false })} UTC
    </span>
  );
}

function Header() {
  return (
    <header className="header">
      <div className="header-bg-glow" aria-hidden="true" />

      {/* Top status bar */}
      <div className="header-top-bar">
        <div className="header-brand">
          <MdSecurity size={16} />
          CORAL ENTERPRISE AGENT · TRACK 1
        </div>
        <div className="header-status">
          <div className="status-dot" />
          LIVE MONITORING ACTIVE
        </div>
        <LiveClock />
      </div>

      {/* Central hero */}
      <div className="header-center">
        <div className="header-icon-wrap">
          <div className="header-shield-ring" aria-hidden="true" />
          <FaShieldAlt className="header-shield-icon" aria-label="Security Shield" />
        </div>

        <h1 className="header-title">
          Coral Security<br />Command Center
        </h1>

        <p className="header-subtitle">
          Multi-Source Enterprise Threat Intelligence Platform
        </p>

        {/* Data source badges */}
        <div className="header-badges">
          <div className="source-badge badge-github">
            <FaGithub size={12} />
            GitHub
          </div>
          <div className="source-badge badge-slack">
            <FaSlack size={12} />
            Slack
          </div>
          <div className="source-badge badge-osv">
            <span>⚡</span>
            OSV Database
          </div>
          <div className="source-badge badge-notion">
            <span>📄</span>
            Notion Policies
          </div>
          <div className="source-badge badge-coral">
            <span>◈</span>
            Powered by Coral
          </div>
        </div>
      </div>

      {/* Animated scan line */}
      <div className="scan-bar" aria-hidden="true">
        <div className="scan-bar-fill" />
      </div>
    </header>
  );
}

export default Header;