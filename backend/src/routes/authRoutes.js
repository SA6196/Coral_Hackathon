const express  = require("express");
const router   = express.Router();
const crypto   = require("crypto");
const db       = require("../config/database");
const { signToken, protect } = require("../middleware/authMiddleware");

function hashPass(plain) {
  return crypto.createHash("sha256").update(plain).digest("hex");
}

/* ── POST /api/auth/register ────────────────────────────────────────── */
router.post("/register", (req, res) => {
  const { username, password, confirmPassword } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, error: "Username and password are required." });
  }
  if (username.length < 3 || username.length > 32) {
    return res.status(400).json({ success: false, error: "Username must be 3–32 characters." });
  }
  if (password.length < 6) {
    return res.status(400).json({ success: false, error: "Password must be at least 6 characters." });
  }
  if (confirmPassword !== undefined && password !== confirmPassword) {
    return res.status(400).json({ success: false, error: "Passwords do not match." });
  }

  const hashed = hashPass(password);
  const now    = new Date().toISOString();

  db.run(
    "INSERT INTO users (username, password, role, team, created_at) VALUES (?, ?, 'analyst', 'security', ?)",
    [username.toLowerCase().trim(), hashed, now],
    function (err) {
      if (err) {
        if (err.message.includes("UNIQUE")) {
          return res.status(409).json({ success: false, error: "Username already taken. Please choose another." });
        }
        return res.status(500).json({ success: false, error: "Registration failed: " + err.message });
      }
      const token = signToken({ username: username.toLowerCase().trim(), role: "analyst", team: "security" });
      return res.status(201).json({
        success: true,
        message: "Account created successfully.",
        token,
        user: { username: username.toLowerCase().trim(), role: "analyst", team: "security" }
      });
    }
  );
});

/* ── POST /api/auth/login ───────────────────────────────────────────── */
router.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, error: "Username and password are required." });
  }

  const ADMIN_USER = process.env.ADMIN_USER || "admin";
  const ADMIN_PASS = process.env.ADMIN_PASS || "admin123";

  // Check built-in admin account first
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    const token = signToken({ username, role: "admin", team: "security" });
    return res.json({
      success: true,
      message: "Authentication successful",
      token,
      user: { username, role: "admin", team: "security" }
    });
  }

  // Check registered SQLite users
  const hashed = hashPass(password);
  db.get(
    "SELECT username, role, team FROM users WHERE username = ? AND password = ?",
    [username.toLowerCase().trim(), hashed],
    (err, row) => {
      if (err) return res.status(500).json({ success: false, error: "Auth check failed." });
      if (!row) return res.status(401).json({ success: false, error: "Invalid username or password." });

      const token = signToken({ username: row.username, role: row.role, team: row.team });
      return res.json({
        success: true,
        message: "Authentication successful",
        token,
        user: { username: row.username, role: row.role, team: row.team }
      });
    }
  );
});

/* ── GET /api/auth/me ───────────────────────────────────────────────── */
router.get("/me", protect, (req, res) => {
  res.json({ success: true, user: req.user });
});

module.exports = router;
