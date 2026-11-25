
"use strict";

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
const APK_RELEASES_REPO = process.env.APK_RELEASES_REPO || "";
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || "";

const COOKIE_SAME_SITE = (process.env.COOKIE_SAME_SITE || "none").toLowerCase();

const SESSION_DAYS = Math.min(
  Math.max(Number(process.env.SESSION_DAYS || 7), 1),
  30
);

if (!GOOGLE_CLIENT_ID || !SESSION_SECRET || !FRONTEND_ORIGIN) {
  console.error("Missing required environment variables.");
  process.exit(1);
}

if (SESSION_SECRET.length < 32) {
  console.error("SESSION_SECRET must be at least 32 characters.");
  process.exit(1);
}

if (!["none", "lax", "strict"].includes(COOKIE_SAME_SITE)) {
  console.error("Invalid COOKIE_SAME_SITE.");
  process.exit(1);
}

if (
  APK_RELEASES_REPO &&
  !/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(APK_RELEASES_REPO)
) {
  console.error("Invalid APK_RELEASES_REPO.");
  process.exit(1);
}

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

const allowedOrigins = FRONTEND_ORIGIN
  .split(",")
  .map(x => x.trim())
  .filter(Boolean);

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
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

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

const catalogLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

function requireAllowedOrigin(req, res, next) {
  const origin = req.get("origin");

  if (origin && !allowedOrigins.includes(origin)) {
    return res.status(403).json({
      error: "Origin not allowed"
    });
  }

  next();
}

function setSession(res, user) {
  const token = jwt.sign(
    {
      sub: user.sub,
      email: user.email,
      name: user.name,
      picture: user.picture
    },
    SESSION_SECRET,
    {
      expiresIn: `${SESSION_DAYS}d`,
      issuer: "sylesstacks-auth"
    }
  );

  res.cookie("ss_session", token, cookieOptions);
}

function readSession(req) {
  const token = req.cookies?.ss_session;

  if (!token) return null;

  try {
    return jwt.verify(token, SESSION_SECRET, {
      issuer: "sylesstacks-auth"
    });
  } catch {
    return null;
  }
}

/* =========================
   APK CATALOG
========================= */

let catalogCache = {
  data: null,
  expiresAt: 0
};

const CATALOG_CACHE_MS = 60 * 1000;

async function loadApkCatalog() {
  if (!APK_RELEASES_REPO) {
    return [];
  }

  if (
    catalogCache.data &&
    Date.now() < catalogCache.expiresAt
  ) {
    return catalogCache.data;
  }

  const apiUrl =
    "https://api.github.com/repos/" +
    APK_RELEASES_REPO +
    "/releases?per_page=100";

  const headers = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "SylesStacks-Store"
  };

  if (GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${GITHUB_TOKEN}`;
  }

  const response = await fetch(apiUrl, {
    method: "GET",
    headers,
    signal: AbortSignal.timeout(15000)
  });

  if (!response.ok) {
    let message = "Unknown GitHub error";

    try {
      const errorData = await response.json();
      message = errorData.message || message;
    } catch {
      // Keep default message.
    }

    console.error("GitHub API diagnostic:", {
      status: response.status,
      message,
      tokenConfigured: Boolean(GITHUB_TOKEN),
      repository: APK_RELEASES_REPO
    });

    throw new Error(
      `GitHub Releases request failed: ${response.status} - ${message}`
    );
  }

  const releases = await response.json();

  if (!Array.isArray(releases)) {
    throw new Error("Invalid GitHub Releases response");
  }

  const apps = [];

  for (const release of releases) {
    if (release.draft || release.prerelease) continue;

    const assets = Array.isArray(release.assets)
      ? release.assets
      : [];

    for (const asset of assets) {
      if (
        !asset.name ||
        !asset.name.toLowerCase().endsWith(".apk")
      ) {
        continue;
      }

      if (
        !asset.browser_download_url ||
        !asset.browser_download_url.startsWith("https://github.com/")
      ) {
        continue;
      }

      apps.push({
        id: `${release.id}-${asset.id}`,
        name: release.name || asset.name.replace(/\.apk$/i, ""),
        version: release.tag_name || "latest",
        description: release.body || "",
        fileName: asset.name,
        size: asset.size,
        downloads: asset.download_count || 0,
        downloadUrl: asset.browser_download_url,
        publishedAt: release.published_at || null,
        repository: APK_RELEASES_REPO
      });
    }
  }

  catalogCache = {
    data: apps,
    expiresAt: Date.now() + CATALOG_CACHE_MS
  };

  return apps;
}

/* =========================
   HEALTH
========================= */

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "sylesstacks-auth",
    version: "1.2.1",
    catalogConfigured: Boolean(APK_RELEASES_REPO),
    githubTokenConfigured: Boolean(GITHUB_TOKEN)
  });
});

/* =========================
   GOOGLE AUTH
========================= */

app.post(
  "/api/auth/google",
  authLimiter,
  requireAllowedOrigin,
  async (req, res) => {
    try {
      const credential = req.body?.credential;

      if (
        typeof credential !== "string" ||
        credential.length > 10000
      ) {
        return res.status(400).json({
          error: "Missing or invalid Google credential"
        });
      }

      const ticket = await googleClient.verifyIdToken({
        idToken: credential,
        audience: GOOGLE_CLIENT_ID
      });

      const payload = ticket.getPayload();

      if (
        !payload?.sub ||
        !payload.email ||
        payload.email_verified !== true
      ) {
        return res.status(401).json({
          error: "Google account email is not verified"
        });
      }

      const user = {
        sub: payload.sub,
        email: payload.email,
        name: payload.name || "",
        picture: payload.picture || ""
      };

      setSession(res, user);

      return res.json({
        ok: true,
        user
      });
    } catch (error) {
      console.warn("Google sign-in rejected:", error.message);

      return res.status(401).json({
        error: "Google sign-in could not be verified"
      });
    }
  }
);

app.get("/api/me", (req, res) => {
  const session = readSession(req);

  if (!session) {
    return res.status(401).json({
      authenticated: false
    });
  }

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

app.post(
  "/api/logout",
  requireAllowedOrigin,
  (_req, res) => {
    res.clearCookie("ss_session", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: COOKIE_SAME_SITE,
      path: "/"
    });

    res.json({
      ok: true
    });
  }
);

/* =========================
   STORE API
========================= */

app.get(
  "/api/store/apps",
  catalogLimiter,
  async (_req, res) => {
    try {
      const apps = await loadApkCatalog();

      res.set("Cache-Control", "public, max-age=30");

      return res.json({
        ok: true,
        count: apps.length,
        apps
      });
    } catch (error) {
      console.error("Store catalog error:", error.message);

      return res.status(502).json({
        ok: false,
        error: "Could not load app catalog"
      });
    }
  }
);

app.get(
  "/api/store/apps/:id",
  catalogLimiter,
  async (req, res) => {
    try {
      const apps = await loadApkCatalog();

      const appItem = apps.find(
        item => item.id === req.params.id
      );

      if (!appItem) {
        return res.status(404).json({
          error: "Application not found"
        });
      }

      return res.json({
        ok: true,
        app: appItem
      });
    } catch (error) {
      console.error("Store app error:", error.message);

      return res.status(502).json({
        error: "Could not load application"
      });
    }
  }
);

/* =========================
   ERROR HANDLER
========================= */

app.use((err, _req, res, _next) => {
  if (err.message === "Origin not allowed") {
    return res.status(403).json({
      error: "Origin not allowed"
    });
  }

  console.error(err);

  return res.status(500).json({
    error: "Internal server error"
  });
});

/* =========================
   START
========================= */

app.listen(PORT, () => {
  console.log(`SylesStacks server listening on port ${PORT}`);

  console.log(
    APK_RELEASES_REPO
      ? `APK catalog repository: ${APK_RELEASES_REPO}`
      : "APK catalog is not configured"
  );

  console.log(
    `GitHub token configured: ${Boolean(GITHUB_TOKEN)}`
  );
});
