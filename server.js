const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const { OAuth2Client } = require("google-auth-library");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const SESSION_SECRET = process.env.SESSION_SECRET;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN;
const COOKIE_SAME_SITE = (process.env.COOKIE_SAME_SITE || "none").toLowerCase();
const SESSION_DAYS = Math.min(Math.max(Number(process.env.SESSION_DAYS || 7), 1), 30);

if (!GOOGLE_CLIENT_ID || !SESSION_SECRET || !FRONTEND_ORIGIN) {
  console.error("Missing required env vars: GOOGLE_CLIENT_ID, SESSION_SECRET, FRONTEND_ORIGIN");
  process.exit(1);
}
if (SESSION_SECRET.length < 32) {
  console.error("SESSION_SECRET must be at least 32 characters.");
  process.exit(1);
}
if (!["none", "lax", "strict"].includes(COOKIE_SAME_SITE)) {
  console.error("COOKIE_SAME_SITE must be none, lax, or strict.");
  process.exit(1);
}

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);
const allowedOrigins = FRONTEND_ORIGIN.split(",").map(x => x.trim()).filter(Boolean);
const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: COOKIE_SAME_SITE,
  path: "/",
  maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000
};

app.set("trust proxy", 1);
app.use(helmet());
app.use(cors({
  origin(origin, callback) {
    // No-Origin requests are useful for health checks and server-to-server calls.
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("Origin not allowed"));
  },
  credentials: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"]
}));
app.use(express.json({ limit: "20kb" }));
app.use(cookieParser());

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

function requireAllowedOrigin(req, res, next) {
  const origin = req.get("origin");
  if (origin && !allowedOrigins.includes(origin)) {
    return res.status(403).json({ error: "Origin not allowed" });
  }
  next();
}

function setSession(res, user) {
  const token = jwt.sign(
    { sub: user.sub, email: user.email, name: user.name, picture: user.picture },
    SESSION_SECRET,
    { expiresIn: `${SESSION_DAYS}d`, issuer: "sylesstacks-auth" }
  );
  res.cookie("ss_session", token, cookieOptions);
}

function readSession(req) {
  const token = req.cookies?.ss_session;
  if (!token) return null;
  try {
    return jwt.verify(token, SESSION_SECRET, { issuer: "sylesstacks-auth" });
  } catch {
    return null;
  }
}

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "sylesstacks-auth", version: "1.0.0" });
});

app.post("/api/auth/google", authLimiter, requireAllowedOrigin, async (req, res) => {
  try {
    const credential = req.body?.credential;
    if (typeof credential !== "string" || credential.length > 10000) {
      return res.status(400).json({ error: "Missing or invalid Google credential" });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();

    if (!payload?.sub || !payload.email || payload.email_verified !== true) {
      return res.status(401).json({ error: "Google account email is not verified" });
    }

    const user = {
      sub: payload.sub,
      email: payload.email,
      name: payload.name || "",
      picture: payload.picture || ""
    };

    setSession(res, user);
    return res.json({ ok: true, user });
  } catch (error) {
    console.warn("Google sign-in rejected:", error.message);
    return res.status(401).json({ error: "Google sign-in could not be verified" });
  }
});

app.get("/api/me", (req, res) => {
  const session = readSession(req);
  if (!session) return res.status(401).json({ authenticated: false });
  return res.json({
    authenticated: true,
    user: {
      id: session.sub,
      email: session.email,
      name: session.name,
      picture: session.picture
    }
  });
});

app.post("/api/logout", requireAllowedOrigin, (_req, res) => {
  res.clearCookie("ss_session", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: COOKIE_SAME_SITE,
    path: "/"
  });
  res.json({ ok: true });
});

app.use((err, _req, res, _next) => {
  if (err.message === "Origin not allowed") {
    return res.status(403).json({ error: "Origin not allowed" });
  }
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, () => console.log(`SylesStacks auth server listening on ${PORT}`));
