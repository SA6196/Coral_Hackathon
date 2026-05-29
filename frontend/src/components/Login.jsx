import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { FiLock, FiUser, FiLoader, FiShield, FiEye, FiEyeOff, FiUserPlus, FiLogIn, FiCheck } from "react-icons/fi";
import { loginUser, registerUser } from "../services/api";

const LS_REMEMBER = "coral_remember_me";
const LS_SAVED_UN = "coral_saved_username";
const LS_SAVED_PW = "coral_saved_password";

/* ── Password visibility toggle input ──────────────────────────────── */
function PasswordField({ id, value, onChange, placeholder, disabled, label }) {
  const [show, setShow] = useState(false);
  return (
    <div className="login-input-group">
      <label htmlFor={id}>{label || "Password"}</label>
      <div className="login-input-wrapper" style={{ position: "relative" }}>
        <FiLock className="login-input-icon" />
        <input
          id={id}
          type={show ? "text" : "password"}
          value={value}
          onChange={onChange}
          placeholder={placeholder || "Enter password"}
          disabled={disabled}
          style={{ paddingRight: 36 }}
        />
        <button
          type="button"
          onClick={() => setShow(s => !s)}
          disabled={disabled}
          style={{
            position: "absolute", right: 10, top: "50%", transform: "translateY(-50%)",
            background: "transparent", border: "none", cursor: "pointer",
            color: "rgba(255,255,255,0.35)", padding: 0, lineHeight: 1
          }}
          aria-label={show ? "Hide password" : "Show password"}
        >
          {show ? <FiEyeOff size={14} /> : <FiEye size={14} />}
        </button>
      </div>
    </div>
  );
}

export default function Login({ onLoginSuccess }) {
  const [mode, setMode]           = useState("login"); // "login" | "signup"
  const [username, setUsername]   = useState("");
  const [password, setPassword]   = useState("");
  const [confirm, setConfirm]     = useState("");
  const [remember, setRemember]   = useState(false);
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState(null);
  const [success, setSuccess]     = useState(null);

  /* ── Auto-fill remembered credentials on mount ── */
  useEffect(() => {
    const saved = localStorage.getItem(LS_REMEMBER) === "true";
    if (saved) {
      setRemember(true);
      setUsername(localStorage.getItem(LS_SAVED_UN) || "");
      setPassword(localStorage.getItem(LS_SAVED_PW) || "");
    }
  }, []);

  /* ── Clear state when switching modes ── */
  const switchMode = (m) => {
    setMode(m);
    setError(null);
    setSuccess(null);
    setConfirm("");
    // Don't clear username/password so user doesn't retype
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username || !password) { setError("Please fill in all fields."); return; }
    if (mode === "signup") {
      if (password.length < 6) { setError("Password must be at least 6 characters."); return; }
      if (confirm !== password) { setError("Passwords do not match."); return; }
    }

    setLoading(true);
    setError(null);
    setSuccess(null);

    try {
      let res;
      if (mode === "login") {
        res = await loginUser(username, password);
      } else {
        res = await registerUser(username, password, confirm);
      }

      if (res.data?.token) {
        /* ── Persist credentials if remember me checked ── */
        if (remember) {
          localStorage.setItem(LS_REMEMBER, "true");
          localStorage.setItem(LS_SAVED_UN, username);
          localStorage.setItem(LS_SAVED_PW, password);
        } else {
          localStorage.removeItem(LS_REMEMBER);
          localStorage.removeItem(LS_SAVED_UN);
          localStorage.removeItem(LS_SAVED_PW);
        }

        if (mode === "signup") {
          setSuccess(`Account created! Welcome, ${res.data.user?.username || username} 🎉`);
          setTimeout(() => onLoginSuccess(res.data.token), 1200);
        } else {
          onLoginSuccess(res.data.token);
        }
      } else {
        setError("Failed to obtain session token.");
      }
    } catch (err) {
      setError(err.userMessage || err.message || (mode === "login" ? "Invalid credentials." : "Registration failed."));
    } finally {
      setLoading(false);
    }
  };

  const isLogin  = mode === "login";
  const tabColor = "#0ea5e9";

  return (
    <div className="login-screen">
      <div className="grid-bg" aria-hidden="true" />

      <motion.div
        className="login-card"
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: "easeOut" }}
        style={{ maxWidth: 420 }}
      >
        <div className="login-glow" />

        {/* Header */}
        <div className="login-header">
          <div className="login-shield-wrap">
            <div className="login-shield-ring" />
            <FiShield className="login-shield-icon" />
          </div>
          <h2 className="login-title">CORAL ENTERPRISE</h2>
          <p className="login-subtitle">SECURE COMMAND CENTER ACCESS</p>
        </div>

        {/* Mode tabs */}
        <div style={{
          display: "flex", gap: 0, marginBottom: 24,
          background: "rgba(255,255,255,0.04)",
          border: "1px solid rgba(255,255,255,0.08)",
          borderRadius: 10, overflow: "hidden",
        }}>
          {[
            { key: "login",  label: "Sign In",  Icon: FiLogIn    },
            { key: "signup", label: "Sign Up",  Icon: FiUserPlus },
          ].map(({ key, label, Icon }) => (
            <button
              key={key}
              type="button"
              onClick={() => switchMode(key)}
              style={{
                flex: 1, display: "flex", alignItems: "center", justifyContent: "center", gap: 6,
                padding: "10px 0",
                background: mode === key ? `linear-gradient(135deg, ${tabColor}22, ${tabColor}10)` : "transparent",
                border: "none",
                borderBottom: mode === key ? `2px solid ${tabColor}` : "2px solid transparent",
                color: mode === key ? tabColor : "rgba(255,255,255,0.4)",
                fontWeight: mode === key ? 700 : 500,
                fontSize: 12, letterSpacing: "0.06em", cursor: "pointer",
                transition: "all 0.2s",
              }}
              id={`tab-${key}`}
            >
              <Icon size={13} /> {label}
            </button>
          ))}
        </div>

        {/* Error / Success alerts */}
        <AnimatePresence mode="wait">
          {error && (
            <motion.div
              key="err"
              className="login-error-alert"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              transition={{ duration: 0.2 }}
            >
              ⚠️ {error}
            </motion.div>
          )}
          {success && (
            <motion.div
              key="ok"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
              style={{
                background: "rgba(16,185,129,0.1)", border: "1px solid rgba(16,185,129,0.3)",
                borderRadius: 8, padding: "10px 14px", fontSize: 13,
                color: "#10b981", marginBottom: 16, display: "flex", alignItems: "center", gap: 8
              }}
            >
              <FiCheck size={14} /> {success}
            </motion.div>
          )}
        </AnimatePresence>

        {/* Form */}
        <form onSubmit={handleSubmit} className="login-form">
          {/* Username */}
          <div className="login-input-group">
            <label htmlFor="login-username">Username</label>
            <div className="login-input-wrapper">
              <FiUser className="login-input-icon" />
              <input
                id="login-username"
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                placeholder={isLogin ? "Enter username" : "Choose a username (3–32 chars)"}
                disabled={loading}
                autoComplete="username"
                autoCapitalize="none"
              />
            </div>
          </div>

          {/* Password */}
          <PasswordField
            id="login-password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder={isLogin ? "Enter password" : "Create a password (min 6 chars)"}
            disabled={loading}
            label="Password"
          />

          {/* Confirm password — sign-up only */}
          <AnimatePresence>
            {!isLogin && (
              <motion.div
                key="confirm"
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.25 }}
                style={{ overflow: "hidden" }}
              >
                <PasswordField
                  id="login-confirm"
                  value={confirm}
                  onChange={e => setConfirm(e.target.value)}
                  placeholder="Confirm your password"
                  disabled={loading}
                  label="Confirm Password"
                />
              </motion.div>
            )}
          </AnimatePresence>

          {/* Remember Me */}
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 18, marginTop: 2 }}>
            <button
              type="button"
              id="remember-me-toggle"
              onClick={() => setRemember(r => !r)}
              disabled={loading}
              style={{
                width: 18, height: 18, borderRadius: 4, flexShrink: 0,
                background: remember ? `linear-gradient(135deg, ${tabColor}, ${tabColor}cc)` : "rgba(255,255,255,0.06)",
                border: `1px solid ${remember ? tabColor : "rgba(255,255,255,0.15)"}`,
                cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center",
                transition: "all 0.2s",
              }}
              aria-pressed={remember}
              aria-label="Remember me"
            >
              {remember && <FiCheck size={10} color="#fff" />}
            </button>
            <span
              onClick={() => !loading && setRemember(r => !r)}
              style={{ fontSize: 12, color: "rgba(255,255,255,0.5)", cursor: "pointer", userSelect: "none" }}
            >
              Remember me on this device
            </span>
          </div>

          {/* Submit */}
          <button type="submit" className="login-submit-btn" disabled={loading} id="login-submit-btn">
            {loading ? (
              <><FiLoader className="nl-icon-spin" size={16} /> {isLogin ? "Verifying..." : "Creating Account..."}</>
            ) : isLogin ? (
              <><FiLogIn size={14} /> Authorize Session</>
            ) : (
              <><FiUserPlus size={14} /> Create Account</>
            )}
          </button>
        </form>

        {/* Footer */}
        <div className="login-footer">
          <p>AUTHORIZED SECURITY PERSONNEL ONLY</p>
          {!isLogin && (
            <p className="login-hint">
              Already have an account?{" "}
              <span style={{ cursor: "pointer", textDecoration: "underline" }} onClick={() => switchMode("login")}>
                Sign in
              </span>
            </p>
          )}
        </div>
      </motion.div>
    </div>
  );
}
