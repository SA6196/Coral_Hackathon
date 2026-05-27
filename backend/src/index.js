require("dotenv").config();

const express  = require("express");
const cors     = require("cors");
const morgan   = require("morgan");
const rateLimit = require("express-rate-limit");

const securityRoutes = require("./routes/securityRoutes");
const coralRoutes    = require("./routes/coralRoutes");
const aiRoutes       = require("./routes/aiRoutes");
const configRoutes   = require("./routes/configRoutes");
const submitRoutes   = require("./routes/submitRoutes");
const { router: webhookRoutes } = require("./routes/webhookRoutes");

const app = express();

/* ─── Security Middleware ─────────────────────────────────────────────── */
app.use(cors({
  origin: [
    "http://localhost:5173",
    "http://localhost:3000",
    "http://localhost:5174",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
  ],
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-GitHub-Event", "X-GitHub-Delivery", "X-Hub-Signature-256"],
  credentials: true,
}));

/* ─── Rate Limiting (100 users × burst) ──────────────────────────────── */
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 500,                  // 500 requests per window per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "Too many requests — please slow down." },
});

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,       // 1 minute
  max: 30,                   // 30 chat messages per minute per IP
  message: { success: false, error: "Chat rate limit exceeded — please wait." },
});

app.use(limiter);
app.use(express.json({ limit: "1mb" }));
app.use(morgan("dev"));

/* ─── Health check (monitoring tools, load balancers) ────────────────── */
app.get("/health", (req, res) => {
  res.json({
    status: "healthy",
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    version: "2.0.0",
    services: {
      coral_engine: "running",
      mock_data: "loaded",
    }
  });
});

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Coral Security Command Center API v2.0",
    endpoints: ["/health", "/api/security-summary", "/api/high-risk-incidents", "/api/chat", "/api/investigate", "/api/query"],
  });
});

/* ─── Routes ──────────────────────────────────────────────────────────── */
app.use("/api", securityRoutes);
app.use("/api", coralRoutes);
app.use("/api/chat", chatLimiter);
app.use("/api", aiRoutes);
app.use("/api", configRoutes);
app.use("/api", submitRoutes);
app.use("/api", webhookRoutes);

/* ─── Global error handler ────────────────────────────────────────────── */
app.use((err, req, res, next) => {
  console.error("[ERROR]", err.message, err.stack);
  const status = err.status || 500;
  res.status(status).json({
    success: false,
    error:   err.message || "Internal server error",
    ...(process.env.NODE_ENV !== "production" && { stack: err.stack }),
  });
});

/* ─── 404 handler ─────────────────────────────────────────────────────── */
app.use((req, res) => {
  res.status(404).json({ success: false, error: `Route not found: ${req.path}` });
});

/* ─── Graceful shutdown ───────────────────────────────────────────────── */
const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, () => {
  console.log(`🚀 Coral Security API v2.0 running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔒 CORS whitelist: localhost:5173, localhost:3000`);
  console.log(`🛡️  Rate limit: 500 req/15min global, 30 chat/min`);
});

process.on("SIGTERM", () => {
  console.log("SIGTERM received — gracefully shutting down...");
  server.close(() => {
    console.log("Server closed.");
    process.exit(0);
  });
});

process.on("SIGINT", () => {
  console.log("\nSIGINT received — shutting down...");
  server.close(() => process.exit(0));
});

module.exports = app;