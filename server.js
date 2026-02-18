// server.js
require("dotenv").config();
const express = require("express");
const path = require("path");
const fs = require("fs");
const axios = require("axios");
const cookieSession = require("cookie-session");
const { Redis } = require("@upstash/redis");

const app = express();
const IS_PROD = process.env.NODE_ENV === "production";

/* ========= BASIC CONFIG (loader.json) ========= */

const loaderConfig = require("./config/loader.json");

/* ========= UPSTASH REDIS / VERCEL KV ========= */

const REDIS_REST_URL =
  process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const REDIS_REST_TOKEN =
  process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;

if (!REDIS_REST_URL || !REDIS_REST_TOKEN) {
  console.warn(
    "[WARN] Redis REST env not set. Set UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN atau KV_REST_API_URL + KV_REST_API_TOKEN."
  );
}

const redis = new Redis({
  url: REDIS_REST_URL,
  token: REDIS_REST_TOKEN,
});

/* ========= DISCORD CONFIG ========= */

const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI =
  process.env.DISCORD_REDIRECT_URI ||
  "https://exc-webs.vercel.app/auth/discord/callback";
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const DISCORD_GUILD_ID = process.env.DISCORD_GUILD_ID;

if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET) {
  console.warn(
    "[WARN] DISCORD_CLIENT_ID / DISCORD_CLIENT_SECRET belum di-set."
  );
}

/* ========= ADS PROVIDER CONFIG ========= */

const WORKINK_BASE_URL =
  process.env.WORKINK_BASE_URL || "https://work.ink/your-link";
const LINKVERTISE_BASE_URL =
  process.env.LINKVERTISE_BASE_URL || "https://linkvertise.com/your-link";

/* ========= KEY CONFIG ========= */

const KEY_PREFIX = "EXHUBFREE";
const KEY_TTL_MS = 3 * 60 * 60 * 1000; // 3 jam
const VERIFY_SESSION_TTL_SEC = 10 * 60; // 10 menit sekali pakai

/* ========= ADMIN USER/PASS (ENV) ========= */

const ADMIN_USER = process.env.ADMIN_USER || "";
const ADMIN_PASS = process.env.ADMIN_PASS || "";

/* ========= EXPRESS SETUP ========= */

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.set("trust proxy", 1);

app.use(
  cookieSession({
    name: "exhub_session",
    keys: [process.env.SESSION_SECRET || "dev-secret-change-this"],
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 hari
    httpOnly: true,
    sameSite: "lax",
    secure: IS_PROD,
  })
);

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use("/public", express.static(path.join(__dirname, "public")));

app.locals.siteName = loaderConfig.siteName;
app.locals.tagline = loaderConfig.tagline;
app.locals.loaderUrl = loaderConfig.loader;

app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  res.locals.adminUser = req.session.adminUser || null;
  next();
});

/* ========= HELPER FUNCTIONS ========= */

function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    const nextUrl = encodeURIComponent(req.originalUrl || "/dashboard");
    console.log("[AUTH] no session, redirect -> /login?next=" + nextUrl);
    return res.redirect(`/login?next=${nextUrl}`);
  }
  next();
}

function isAdmin(req) {
  if (req.session && req.session.adminUser) return true;

  const adminIds = (process.env.ADMIN_DISCORD_IDS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  return req.session.user && adminIds.includes(String(req.session.user.id));
}

function requireAdmin(req, res, next) {
  if (!isAdmin(req)) {
    return res.redirect("/admin/login");
  }
  next();
}

function randomSegment(len) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "";
  for (let i = 0; i < len; i++) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

function generateKeyToken(tier = "free") {
  const prefix = tier === "paid" ? "EXHUBPAID" : KEY_PREFIX;
  return `${prefix}-${randomSegment(4)}${randomSegment(4)}-${randomSegment(
    4
  )}-${randomSegment(4)}`;
}

function nowMs() {
  return Date.now();
}

/* ========= REDIS HELPERS ========= */

async function saveKeyForUser({ userId, provider, ip, tier = "free" }) {
  const token = generateKeyToken(tier);
  const createdAt = nowMs();
  const expiresAfter = createdAt + KEY_TTL_MS;

  const keyInfo = {
    token,
    createdAt,
    expiresAfter,
    userId,
    byIp: ip || "0.0.0.0",
    provider,
    deleted: false,
  };

  const keyKey = `key:${token}`;

  await redis.set(keyKey, keyInfo, {
    px: KEY_TTL_MS + 60 * 60 * 1000,
  });

  await redis.lpush(`user:${userId}:keys`, token);
  return keyInfo;
}

async function loadKeyInfo(token) {
  if (!token) return null;
  return await redis.get(`key:${token}`);
}

async function loadUserKeys(userId) {
  if (!userId) return [];
  const tokens = await redis.lrange(`user:${userId}:keys`, 0, -1);
  if (!tokens || tokens.length === 0) return [];

  const results = await Promise.all(tokens.map((t) => redis.get(`key:${t}`)));

  return results
    .map((info, i) => {
      if (!info) return null;
      info.token = info.token || tokens[i];
      return info;
    })
    .filter(Boolean);
}

function isKeyActive(info) {
  if (!info || info.deleted) return false;
  if (!info.expiresAfter) return false;
  return info.expiresAfter > nowMs();
}

/* ========= DISCORD AUTH FLOW ========= */

app.get("/login", (req, res) => {
  const nextParam =
    typeof req.query.next === "string" && req.query.next.trim()
      ? req.query.next
      : "/dashboard";
  res.render("discord-login", {
    nextUrl: nextParam,
  });
});

app.get("/auth/discord", (req, res) => {
  const nextParam =
    typeof req.query.next === "string" && req.query.next.trim()
      ? req.query.next
      : "/dashboard";

  const state = encodeURIComponent(nextParam);

  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: "code",
    scope: "identify email guilds.join",
    state,
  });

  const authUrl = `https://discord.com/oauth2/authorize?${params.toString()}`;
  res.redirect(authUrl);
});

app.get("/auth/discord/callback", async (req, res) => {
  const code = req.query.code;
  const rawState = req.query.state;

  let nextPath = "/dashboard";
  if (typeof rawState === "string" && rawState.length > 0) {
    try {
      const decoded = decodeURIComponent(rawState);
      if (decoded.startsWith("/")) {
        nextPath = decoded;
      }
    } catch (e) {
      console.warn("[WARN] Failed decode state, using /dashboard");
    }
  }

  if (!code) {
    return res.redirect("/login");
  }

  try {
    const tokenRes = await axios.post(
      "https://discord.com/api/oauth2/token",
      new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: DISCORD_REDIRECT_URI,
      }).toString(),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    const accessToken = tokenRes.data.access_token;

    const userRes = await axios.get("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    const user = userRes.data;

    if (DISCORD_GUILD_ID && DISCORD_BOT_TOKEN) {
      try {
        await axios.put(
          `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${user.id}`,
          { access_token: accessToken },
          { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
        );
      } catch (err) {
        console.warn(
          "Failed to add to guild:",
          err.response?.data || err.message
        );
      }
    }

    req.session.user = {
      id: String(user.id),
      username: user.username,
      global_name: user.global_name || user.username,
      avatar: user.avatar,
    };

    console.log("[LOGIN] user", user.id, "redirect ->", nextPath);
    res.redirect(nextPath);
  } catch (err) {
    console.error("Discord OAuth error:", err.response?.data || err.message);
    res.redirect("/login");
  }
});

app.get("/logout", (req, res) => {
  req.session = null;
  res.redirect("/");
});

/* ========= PUBLIC PAGES ========= */

app.get("/", (req, res) => {
  const scriptsPreview = loaderConfig.scripts.slice(0, 3);
  res.render("home", {
    loaderConfig,
    scriptsPreview,
  });
});

app.get("/scripts", (req, res) => {
  const scripts = loaderConfig.scripts || [];
  res.render("scripts", { scripts, loaderConfig });
});

/* ========= ADMIN LOGIN ========= */

app.get("/admin/login", (req, res) => {
  if (isAdmin(req)) {
    return res.redirect("/admin");
  }

  res.render("admin-login", {
    error: null,
  });
});

app.post("/admin/login", (req, res) => {
  const { username, password } = req.body || {};

  if (!ADMIN_USER || !ADMIN_PASS) {
    return res.status(500).send("Admin login is not configured.");
  }

  if (username === ADMIN_USER && password === ADMIN_PASS) {
    req.session.adminUser = {
      username: ADMIN_USER,
      loggedInAt: new Date().toISOString(),
    };
    return res.redirect("/admin");
  }

  return res.status(401).render("admin-login", {
    error: "Username atau password salah",
  });
});

app.post("/admin/logout", (req, res) => {
  if (req.session) {
    delete req.session.adminUser;
  }
  res.redirect("/");
});

/* ========= DASHBOARD ========= */

app.get("/dashboard", requireAuth, async (req, res) => {
  const user = req.session.user;
  const keys = await loadUserKeys(user.id);

  const totalKeys = keys.length;
  const activeKeys = keys.filter(isKeyActive).length;
  const premiumKeys = keys.filter((k) =>
    String(k.token || "").startsWith("EXHUBPAID-")
  ).length;

  res.render("dashboarddc", {
    user,
    stats: {
      totalKeys,
      activeKeys,
      premiumKeys,
    },
    keys,
  });
});

/* ========= GET KEY FLOW ========= */

// GET: tampilan pilih provider & list key
app.get("/get-key", requireAuth, async (req, res) => {
  const provider = (req.query.provider || req.query.ads || "workink").toLowerCase();
  const user = req.session.user;

  const keys = await loadUserKeys(user.id);
  const newKeyToken = req.query.newKey || null;

  res.render("get-key", {
    provider,
    user,
    keys,
    newKeyToken,
    keyTtlHours: KEY_TTL_MS / 3600000,
  });
});

// POST: user klik "Start" -> tandai di Redis, lalu redirect ke Work.ink / Linkvertise
app.post("/get-key/start", requireAuth, async (req, res) => {
  const provider = (req.query.provider || "workink").toLowerCase();
  const user = req.session.user;

  // sekali pakai per provider+user
  const verifyKey = `verify:${provider}:user:${user.id}`;

  await redis.set(
    verifyKey,
    {
      userId: user.id,
      provider,
      createdAt: nowMs(),
      status: "pending",
    },
    { ex: VERIFY_SESSION_TTL_SEC }
  );

  let targetBase = WORKINK_BASE_URL;
  if (provider === "linkvertise") targetBase = LINKVERTISE_BASE_URL;

  // redirect ke halaman ads
  res.redirect(targetBase);
});

// GET: callback dari Work.ink / Linkvertise
app.get("/get-key/callback", requireAuth, async (req, res) => {
  const provider = (req.query.provider || "workink").toLowerCase();
  const user = req.session.user;

  const verifyKey = `verify:${provider}:user:${user.id}`;
  const session = await redis.get(verifyKey);

  if (!session || session.userId !== user.id || session.provider !== provider) {
    console.warn(
      "[GET-KEY] invalid or expired verification",
      "provider=",
      provider,
      "user=",
      user.id
    );
    return res.status(400).send("Invalid or expired verification session.");
  }

  // sekali pakai: hapus flag verifikasi
  await redis.del(verifyKey);

  const keyInfo = await saveKeyForUser({
    userId: user.id,
    provider,
    ip:
      req.headers["x-forwarded-for"] ||
      req.socket.remoteAddress ||
      "0.0.0.0",
    tier: "free",
  });

  res.redirect(
    `/get-key?provider=${provider}&newKey=${encodeURIComponent(
      keyInfo.token
    )}`
  );
});

/* ========= ADMIN DASHBOARD ========= */

app.get("/admin", requireAdmin, async (req, res) => {
  const scripts = loaderConfig.scripts || [];
  const adminUser = req.session.adminUser || req.session.user || {
    username: "Admin",
  };

  res.render("admin-dashboard", {
    user: adminUser,
    scripts,
  });
});

/* ========= API: VALIDASI KEY ========= */

app.get("/api/isValidate/:token", async (req, res) => {
  const token = req.params.token;
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Access-Control-Allow-Origin", "*");

  if (!token) {
    return res.json({
      valid: false,
      deleted: false,
      info: null,
      message: "Missing token",
    });
  }

  const keyInfo = await loadKeyInfo(token);
  if (!keyInfo) {
    return res.json({
      valid: false,
      deleted: false,
      info: null,
      message: "Key not found",
    });
  }

  const expired = keyInfo.expiresAfter && keyInfo.expiresAfter <= nowMs();
  const deleted = !!keyInfo.deleted;

  if (expired || deleted) {
    return res.json({
      valid: false,
      deleted,
      info: keyInfo,
      message: expired ? "Key expired" : "Key deleted",
    });
  }

  return res.json({
    valid: true,
    deleted: false,
    info: keyInfo,
  });
});

/* ========= API: LUA LOADER SCRIPT ========= */

const loaderLuaPath = path.join(__dirname, "scripts", "loader.lua");
const loaderLuaSource = fs.readFileSync(loaderLuaPath, "utf8");

app.get("/api/script/loader", (req, res) => {
  const accept = (req.headers.accept || "").toLowerCase();
  const ua = (req.headers["user-agent"] || "").toLowerCase();

  const looksBrowser =
    accept.includes("text/html") ||
    ua.includes("mozilla") ||
    ua.includes("chrome");

  if (looksBrowser) {
    return res.status(404).render("api-404");
  }

  res.type("text/plain").send(loaderLuaSource);
});

/* ========= 404 FALLBACK ========= */

app.use((req, res) => {
  res.status(404).render("api-404");
});

/* ========= EXPORT / START LOCAL ========= */

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`ExHub web running on http://localhost:${PORT}`);
  });
}

module.exports = app;
