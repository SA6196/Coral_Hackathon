const express  = require("express");
const router   = express.Router();
const bcrypt   = require("bcryptjs");
const db       = require("../config/database");
const { signToken, protect } = require("../middleware/authMiddleware");

const BCRYPT_ROUNDS = 12;

/* ── POST /api/auth/register ────────────────────────────────────────── */
router.post("/register", async (req, res) => {
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

  try {
    const hashed = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const now    = new Date().toISOString();
    const user   = username.toLowerCase().trim();

    db.run(
      "INSERT INTO users (username, password, role, team, created_at) VALUES (?, ?, 'analyst', 'security', ?)",
      [user, hashed, now],
      function (err) {
        if (err) {
          if (err.message.includes("UNIQUE")) {
            return res.status(409).json({ success: false, error: "Username already taken. Please choose another." });
          }
          return res.status(500).json({ success: false, error: "Registration failed: " + err.message });
        }
        const token = signToken({ username: user, role: "analyst", team: "security" });
        return res.status(201).json({
          success: true,
          message: "Account created successfully.",
          token,
          user: { username: user, role: "analyst", team: "security" }
        });
      }
    );
  } catch (err) {
    return res.status(500).json({ success: false, error: "Server error during registration." });
  }
});

/* ── POST /api/auth/login ───────────────────────────────────────────── */
router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, error: "Username and password are required." });
  }

  const ADMIN_USER = process.env.ADMIN_USER || "admin";
  const ADMIN_PASS = process.env.ADMIN_PASS || "admin123";

  // Check built-in admin account first (env-controlled, not stored in DB)
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    const token = signToken({ username, role: "admin", team: "security" });
    return res.json({
      success: true,
      message: "Authentication successful",
      token,
      user: { username, role: "admin", team: "security" }
    });
  }

  // Check registered SQLite users — fetch hash then compare with bcrypt
  db.get(
    "SELECT username, password, role, team FROM users WHERE username = ?",
    [username.toLowerCase().trim()],
    async (err, row) => {
      if (err) return res.status(500).json({ success: false, error: "Auth check failed." });
      if (!row) return res.status(401).json({ success: false, error: "Invalid username or password." });

      try {
        const match = await bcrypt.compare(password, row.password);
        if (!match) return res.status(401).json({ success: false, error: "Invalid username or password." });

        const token = signToken({ username: row.username, role: row.role, team: row.team });
        return res.json({
          success: true,
          message: "Authentication successful",
          token,
          user: { username: row.username, role: row.role, team: row.team }
        });
      } catch (e) {
        return res.status(500).json({ success: false, error: "Auth verification failed." });
      }
    }
  );
});

/* ── GET /api/auth/me ───────────────────────────────────────────────── */
router.get("/me", protect, (req, res) => {
  res.json({ success: true, user: req.user });
});

module.exports = router;
