import { useState } from "react";
import { motion } from "framer-motion";
import { FiLock, FiUser, FiLoader, FiShield } from "react-icons/fi";
import { loginUser } from "../services/api";

export default function Login({ onLoginSuccess }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username || !password) {
      setError("Please fill in all fields.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await loginUser(username, password);
      if (res.data && res.data.token) {
        onLoginSuccess(res.data.token);
      } else {
        setError("Failed to obtain session token.");
      }
    } catch (err) {
      setError(err.userMessage || err.message || "Invalid credentials.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-screen">
      <div className="grid-bg" aria-hidden="true" />
      
      <motion.div
        className="login-card"
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: "easeOut" }}
      >
        <div className="login-glow" />
        
        <div className="login-header">
          <div className="login-shield-wrap">
            <div className="login-shield-ring" />
            <FiShield className="login-shield-icon" />
          </div>
          <h2 className="login-title">CORAL ENTERPRISE</h2>
          <p className="login-subtitle">SECURE COMMAND CENTER ACCESS</p>
        </div>

        {error && (
          <motion.div
            className="login-error-alert"
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
          >
            ⚠️ {error}
          </motion.div>
        )}

        <form onSubmit={handleSubmit} className="login-form">
          <div className="login-input-group">
            <label htmlFor="username">Username</label>
            <div className="login-input-wrapper">
              <FiUser className="login-input-icon" />
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username"
                disabled={loading}
                autoComplete="off"
              />
            </div>
          </div>

          <div className="login-input-group">
            <label htmlFor="password">Password</label>
            <div className="login-input-wrapper">
              <FiLock className="login-input-icon" />
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                disabled={loading}
              />
            </div>
          </div>

          <button type="submit" className="login-submit-btn" disabled={loading}>
            {loading ? (
              <>
                <FiLoader className="nl-icon-spin" size={16} /> Verifying...
              </>
            ) : (
              "Authorize Session"
            )}
          </button>
        </form>

        <div className="login-footer">
          <p>AUTHORIZED SECURITY PERSONNEL ONLY</p>
          <p className="login-hint">Demo Access: <span>admin</span> / <span>admin123</span></p>
        </div>
      </motion.div>
    </div>
  );
}
