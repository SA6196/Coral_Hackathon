const express = require("express");
const router = express.Router();
const { signToken, protect } = require("../middleware/authMiddleware");

// POST /login
router.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, error: "Username and password are required." });
  }

  if (username === "admin" && password === "admin123") {
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
