/**
 * Toast.jsx — Lightweight toast notification system
 * Usage: import { useToast, ToastContainer } from "./Toast"
 *        const toast = useToast();
 *        toast.success("Saved!"); toast.error("Failed"); toast.info("Note");
 */
import { useState, useCallback, useEffect, createContext, useContext } from "react";
import { motion, AnimatePresence } from "framer-motion";

const ToastContext = createContext(null);

let _toastFn = null;

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const addToast = useCallback((message, type = "info", duration = 3500) => {
    const id = Date.now() + Math.random();
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, duration);
    return id;
  }, []);

  // Expose globally for use outside React tree
  _toastFn = addToast;

  const remove = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={addToast}>
      {children}
      <ToastContainer toasts={toasts} onRemove={remove} />
    </ToastContext.Provider>
  );
}

export function useToast() {
  const addToast = useContext(ToastContext);
  return {
    success: (msg, dur) => addToast(msg, "success", dur),
    error:   (msg, dur) => addToast(msg, "error",   dur),
    info:    (msg, dur) => addToast(msg, "info",     dur),
    warn:    (msg, dur) => addToast(msg, "warn",     dur),
  };
}

// Call outside of React components
export const toast = {
  success: (msg, dur) => _toastFn?.(msg, "success", dur),
  error:   (msg, dur) => _toastFn?.(msg, "error",   dur),
  info:    (msg, dur) => _toastFn?.(msg, "info",     dur),
  warn:    (msg, dur) => _toastFn?.(msg, "warn",     dur),
};

const TOAST_COLORS = {
  success: { bg: "rgba(0,255,157,0.12)", border: "rgba(0,255,157,0.3)", color: "#00ff9d", icon: "✅" },
  error:   { bg: "rgba(239,68,68,0.12)", border: "rgba(239,68,68,0.3)", color: "#ef4444", icon: "❌" },
  warn:    { bg: "rgba(251,191,36,0.12)", border: "rgba(251,191,36,0.3)", color: "#fbbf24", icon: "⚠️" },
  info:    { bg: "rgba(0,212,255,0.10)", border: "rgba(0,212,255,0.3)", color: "#00d4ff", icon: "ℹ️" },
};

function ToastContainer({ toasts, onRemove }) {
  return (
    <div
      style={{
        position: "fixed",
        bottom: 24,
        right: 24,
        zIndex: 9999,
        display: "flex",
        flexDirection: "column",
        gap: 8,
        pointerEvents: "none",
      }}
      aria-live="polite"
      aria-atomic="true"
    >
      <AnimatePresence>
        {toasts.map(t => {
          const cfg = TOAST_COLORS[t.type] || TOAST_COLORS.info;
          return (
            <motion.div
              key={t.id}
              initial={{ opacity: 0, y: 20, scale: 0.95 }}
              animate={{ opacity: 1, y: 0,  scale: 1    }}
              exit={{   opacity: 0, y: 10,  scale: 0.95 }}
              transition={{ duration: 0.22 }}
              onClick={() => onRemove(t.id)}
              style={{
                pointerEvents: "auto",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: 10,
                padding: "10px 16px",
                borderRadius: 10,
                background: cfg.bg,
                border: `1px solid ${cfg.border}`,
                boxShadow: `0 4px 20px rgba(0,0,0,0.4), 0 0 10px ${cfg.border}`,
                fontSize: 13,
                color: "rgba(255,255,255,0.9)",
                fontFamily: "var(--font-mono, monospace)",
                maxWidth: 340,
                backdropFilter: "blur(12px)",
              }}
              role="alert"
            >
              <span>{cfg.icon}</span>
              <span style={{ flex: 1 }}>{t.message}</span>
              <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 10 }}>×</span>
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
}
