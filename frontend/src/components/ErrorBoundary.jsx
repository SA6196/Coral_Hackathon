/**
 * ErrorBoundary.jsx — Catches runtime errors in any component
 * Prevents the entire app from crashing if one component fails.
 */
import { Component } from "react";

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, info) {
    console.error("[ErrorBoundary] Component crashed:", error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div
          style={{
            padding: "20px 24px",
            background: "rgba(239,68,68,0.08)",
            border: "1px solid rgba(239,68,68,0.25)",
            borderRadius: 12,
            margin: "8px 0",
            fontFamily: "monospace",
            fontSize: 12,
          }}
        >
          <div style={{ color: "#ef4444", fontWeight: 700, marginBottom: 6 }}>
            ⚠ Component Error
          </div>
          <div style={{ color: "rgba(255,255,255,0.5)", marginBottom: 10 }}>
            {this.state.error?.message || "An unexpected error occurred"}
          </div>
          <button
            onClick={() => this.setState({ hasError: false, error: null })}
            style={{
              background: "rgba(239,68,68,0.15)",
              border: "1px solid rgba(239,68,68,0.3)",
              color: "#ef4444",
              padding: "4px 12px",
              borderRadius: 6,
              cursor: "pointer",
              fontSize: 11,
            }}
          >
            ↻ Retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
