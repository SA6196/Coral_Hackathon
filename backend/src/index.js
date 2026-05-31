require("dotenv").config();

const express  = require("express");
const cors     = require("cors");
const morgan   = require("morgan");
const rateLimit = require("express-rate-limit");
const path     = require("path");

const securityRoutes = require("./routes/securityRoutes");
const coralRoutes    = require("./routes/coralRoutes");
const aiRoutes       = require("./routes/aiRoutes");
const configRoutes   = require("./routes/configRoutes");
const submitRoutes   = require("./routes/submitRoutes");
const { router: webhookRoutes } = require("./routes/webhookRoutes");
const authRoutes     = require("./routes/authRoutes");
const { protect }    = require("./middleware/authMiddleware");

const app = express();

/* ─── Security Middleware ─────────────────────────────────────────────── */
// Build allowed origins list — always includes localhost + any deployed URLs from env
const allowedOrigins = [
  "http://localhost:5000",
  "http://127.0.0.1:5000",
  "http://localhost:5173",
  "http://localhost:3000",
  "http://localhost:5174",
  "http://127.0.0.1:5173",
  "http://127.0.0.1:5174",
  "http://192.168.29.47:5174",   // local network (phone access via Vite)
  "http://192.168.29.47:5173",
  "https://coral-production-cd18.up.railway.app",
];
if (process.env.FRONTEND_URL) allowedOrigins.push(process.env.FRONTEND_URL);
if (process.env.PUBLIC_URL)   allowedOrigins.push(process.env.PUBLIC_URL);

app.use(cors({
  origin: (origin, callback) => {
    // If request has no origin (like curl, postman, or same-origin), allow it
    if (!origin) return callback(null, true);
    
    // Check if origin matches allowed whitelist or is a deployment domain
    const isAllowed = allowedOrigins.some(o => origin.startsWith(o)) ||
                      origin.includes("railway.app") ||
                      origin.includes("vercel.app");
                      
    if (isAllowed || process.env.NODE_ENV === "development") {
      callback(null, true);
    } else {
      callback(new Error(`Blocked by CORS: ${origin}`));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-GitHub-Event", "X-GitHub-Delivery", "X-Hub-Signature-256"],
  credentials: true,
}));

/* ─── Rate Limiting (100 users × burst) ──────────────────────────────── */
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5000,                  // 5000 requests per window per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "Too many requests — please slow down." },
});

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,       // 1 minute
  max: 300,                   // 300 chat messages per minute per IP
  message: { success: false, error: "Chat rate limit exceeded — please wait." },
});

if (process.env.NODE_ENV !== "development") {
  app.use(limiter);
}
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

app.get("/api", (req, res) => {
  res.json({
    success: true,
    message: "Coral Security Command Center API v2.0",
    endpoints: ["/health", "/api/security-summary", "/api/high-risk-incidents", "/api/chat", "/api/investigate", "/api/query"],
  });
});

/* ─── Routes ──────────────────────────────────────────────────────────── */
app.use("/api/auth", authRoutes);
app.use("/api", submitRoutes);
app.use("/api", webhookRoutes);
app.use("/api", protect, securityRoutes);
app.use("/api", protect, coralRoutes);
app.use("/api", protect, aiRoutes);        // chat limiter applied inside aiRoutes
app.use("/api", protect, configRoutes);

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

/* ─── Serve Frontend (Single-Host Bundle) ─────────────────────────────── */
const frontendDistPath = path.join(__dirname, "../../frontend/dist");
app.use(express.static(frontendDistPath, {
  setHeaders: (res, filePath) => {
    if (path.basename(filePath) === "index.html") {
      res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
      res.setHeader("Pragma", "no-cache");
      res.setHeader("Expires", "0");
    }
  }
}));

app.use((req, res, next) => {
  if (req.method === "GET" && !req.path.startsWith("/api")) {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    return res.sendFile(path.join(frontendDistPath, "index.html"));
  }
  next();
});

/* ─── 404 handler (For API routes) ────────────────────────────────────── */
app.use((req, res) => {
  res.status(404).json({ success: false, error: `Route not found: ${req.path}` });
});

/* ─── Graceful shutdown ───────────────────────────────────────────────── */
const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, "0.0.0.0", () => {
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