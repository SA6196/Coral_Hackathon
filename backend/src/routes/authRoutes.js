const express = require("express");
const router = express.Router();
const { signToken, protect } = require("../middleware/authMiddleware");

// POST /login
router.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, error: "Username and password are required." });
  }

  const ADMIN_USER = process.env.ADMIN_USER || "admin";
  const ADMIN_PASS = process.env.ADMIN_PASS || "admin123";

  if (username === ADMIN_USER && password === ADMIN_PASS) {
    const token = signToken({ username, role: "admin", team: "security" });
    return res.json({
      success: true,
      message: "Authentication successful",
      token,
      user: { username, role: "admin", team: "security" }
    });
  }

  return res.status(401).json({ success: false, error: "Invalid username or password." });
});

// GET /me
router.get("/me", protect, (req, res) => {
  res.json({
    success: true,
    user: req.user
  });
});

module.exports = router;
