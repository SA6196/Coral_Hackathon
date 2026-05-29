const crypto = require("crypto");

const SECRET = process.env.JWT_SECRET || "coral-super-secret-key-123456789";

function signToken(payload, expiresInHours = 8) {
  try {
    const now = Math.floor(Date.now() / 1000);
    const enriched = { ...payload, iat: now, exp: now + expiresInHours * 3600 };
    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
    const data = Buffer.from(JSON.stringify(enriched)).toString("base64url");
    const signature = crypto.createHmac("sha256", SECRET).update(`${header}.${data}`).digest("base64url");
    return `${header}.${data}.${signature}`;
  } catch (e) {
    return null;
  }
}

function verifyToken(token) {
  try {
    if (!token || typeof token !== "string") return null;
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [header, data, signature] = parts;
    const expectedSig = crypto.createHmac("sha256", SECRET).update(`${header}.${data}`).digest("base64url");
    if (signature !== expectedSig) return null;
    const payload = JSON.parse(Buffer.from(data, "base64url").toString("utf-8"));
    // Reject expired tokens
    if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

function protect(req, res, next) {
  if (req.method === "OPTIONS") return next();

  let token = null;
  if (req.headers.authorization && req.headers.authorization.startsWith("Bearer ")) {
    token = req.headers.authorization.split(" ")[1];
  }

  if (!token) {
    return res.status(401).json({ success: false, error: "Access denied. Authentication token missing." });
  }

  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ success: false, error: "Access denied. Invalid or expired token." });
  }

  req.user = decoded;
  next();
}

module.exports = { signToken, verifyToken, protect };
