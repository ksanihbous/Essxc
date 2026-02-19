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
  res.locals.siteName = loaderConfig.siteName;
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

  // TTL = masa berlaku + 1 jam buffer
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

/* ========= ADMIN KEY STATS & CLEANUP HELPERS ========= */

function isKeyExpired(info) {
  if (!info) return true;
  if (info.deleted) return true;
  if (!info.expiresAfter) return true;
  return info.expiresAfter <= nowMs();
}

// Bangun data untuk admin-dashboard: summary + per user
async function buildAdminKeyStats() {
  const now = nowMs();
  const users = [];

  let totalUsers = 0;
  let totalKeys = 0;
  let activeKeys = 0;
  let expiredKeys = 0;
  let deletedKeys = 0;
  let orphanTokens = 0;

  // Ambil semua list user:*:keys
  const listKeys = await redis.keys("user:*:keys");

  for (const listKey of listKeys) {
    const m = listKey.match(/^user:(.+):keys$/);
    const userId = m ? m[1] : listKey;

    const tokens = await redis.lrange(listKey, 0, -1);
    if (!tokens || !tokens.length) continue;

    totalUsers += 1;

    let userTotal = 0;
    let userActive = 0;
    let userExpired = 0;
    let userDeleted = 0;
    let userOrphan = 0;

    const tokenDetails = [];

    for (const token of tokens) {
      if (!token) continue;
      userTotal += 1;
      totalKeys += 1;

      const info = await redis.get(`key:${token}`);

      if (!info) {
        orphanTokens += 1;
        userOrphan += 1;
        tokenDetails.push({
          token,
          missing: true,
          active: false,
          expired: true,
          deleted: false,
          info: null,
        });
        continue;
      }

      const expired = info.expiresAfter && info.expiresAfter <= now;
      const deleted = !!info.deleted;
      const active = !expired && !deleted;

      if (active) {
        activeKeys += 1;
        userActive += 1;
      } else {
        if (expired) {
          expiredKeys += 1;
          userExpired += 1;
        }
        if (deleted) {
          deletedKeys += 1;
          userDeleted += 1;
        }
      }

      tokenDetails.push({
        token,
        missing: false,
        active,
        expired,
        deleted,
        info,
      });
    }

    users.push({
      userId,
      totalKeys: userTotal,
      activeKeys: userActive,
      expiredKeys: userExpired,
      deletedKeys: userDeleted,
      orphanTokens: userOrphan,
      tokens: tokenDetails,
    });
  }

  return {
    summary: {
      totalUsers,
      totalKeys,
      activeKeys,
      expiredKeys,
      deletedKeys,
      orphanTokens,
    },
    users,
  };
}

// Cleanup: hapus token di list user + (opsional) hapus dokumen key yang expired/deleted/missing
async function cleanupAllUserKeys() {
  const now = nowMs();
  const listKeys = await redis.keys("user:*:keys");

  let scannedTokens = 0;
  let removedFromLists = 0;
  let affectedUsers = 0;
  let deletedKeyDocs = 0;

  for (const listKey of listKeys) {
    const tokens = await redis.lrange(listKey, 0, -1);
    if (!tokens || !tokens.length) continue;

    let userRemoved = 0;

    for (const token of tokens) {
      if (!token) continue;
      scannedTokens++;

      const keyKey = `key:${token}`;
      const info = await redis.get(keyKey);

      let shouldRemove = false;
      let shouldDeleteDoc = false;

      if (!info) {
        // key di Redis sudah hilang (TTL) => buang dari list user
        shouldRemove = true;
      } else {
        const expired = info.expiresAfter && info.expiresAfter <= now;
        const deleted = !!info.deleted;
        if (expired || deleted) {
          shouldRemove = true;
          shouldDeleteDoc = true;
        }
      }

      if (shouldRemove) {
        const removedCount = await redis.lrem(listKey, 0, token);
        if (removedCount > 0) {
          removedFromLists += removedCount;
          userRemoved += removedCount;
        }
      }

      if (shouldDeleteDoc && info) {
        const delRes = await redis.del(keyKey);
        if (delRes) deletedKeyDocs += delRes;
      }
    }

    if (userRemoved > 0) {
      affectedUsers += 1;
    }
  }

  return {
    listKeysCount: listKeys.length,
    scannedTokens,
    removedFromLists,
    affectedUsers,
    deletedKeyDocs,
  };
}

// Hapus SEMUA key milik satu user (hard delete)
async function deleteAllKeysForUser(userId) {
  const listKey = `user:${userId}:keys`;
  const tokens = await redis.lrange(listKey, 0, -1);

  let deletedDocs = 0;

  if (tokens && tokens.length) {
    for (const token of tokens) {
      const keyKey = `key:${token}`;
      const delRes = await redis.del(keyKey);
      if (delRes) deletedDocs += delRes;
    }
  }

  const deletedList = await redis.del(listKey);

  return {
    userId,
    deletedDocs,
    deletedList,
  };
}

// Hapus satu key di semua tempat (dokumen key:... + dari list user)
async function deleteKeyEverywhere(token) {
  if (!token) {
    return { ok: false, reason: "missing token" };
  }

  const keyKey = `key:${token}`;
  const info = await redis.get(keyKey);

  let userId = info && info.userId ? info.userId : null;
  let removedFromList = 0;

  // Kalau userId tidak ada di dokumen, cari di list user:*:keys
  if (!userId) {
    const listKeys = await redis.keys("user:*:keys");
    for (const listKey of listKeys) {
      const tokens = await redis.lrange(listKey, 0, -1);
      if (tokens && tokens.includes(token)) {
        const m = listKey.match(/^user:(.+):keys$/);
        if (m) {
          userId = m[1];
          break;
        }
      }
    }
  }

  if (userId) {
    const listKey = `user:${userId}:keys`;
    removedFromList = await redis.lrem(listKey, 0, token);
  }

  const deletedDoc = await redis.del(keyKey);

  return {
    ok: true,
    userId: userId || null,
    removedFromList,
    deletedDoc,
  };
}

// Cleanup user: hapus user:*:keys yang TIDAK punya key aktif sama sekali
async function cleanupUsersWithoutActiveKeys() {
  const now = nowMs();
  const listKeys = await redis.keys("user:*:keys");

  let totalUserLists = 0;
  let deletedUserLists = 0;
  let usersWithActiveKeys = 0;

  for (const listKey of listKeys) {
    totalUserLists += 1;

    const tokens = await redis.lrange(listKey, 0, -1);
    if (!tokens || !tokens.length) {
      // list kosong -> hapus langsung
      await redis.del(listKey);
      deletedUserLists += 1;
      continue;
    }

    let hasActive = false;

    for (const token of tokens) {
      const info = await redis.get(`key:${token}`);
      if (!info) continue;
      const expired = info.expiresAfter && info.expiresAfter <= now;
      const deleted = !!info.deleted;
      if (!expired && !deleted) {
        hasActive = true;
        break;
      }
    }

    if (!hasActive) {
      await redis.del(listKey);
      deletedUserLists += 1;
    } else {
      usersWithActiveKeys += 1;
    }
  }

  return {
    totalUserLists,
    deletedUserLists,
    usersWithActiveKeys,
  };
}

/* ========= BROWSER & EXECUTOR DETECTION UNTUK /api/script/loader ========= */

// Deteksi *browser asli* (Chrome/Firefox/Edge/Safari, dll).
// Semua executor / HttpService / script non-browser akan lolos.
function looksLikeRealBrowser(req) {
  const headers = req.headers || {};
  const ua = (headers["user-agent"] || "").toLowerCase();
  const accept = (headers["accept"] || "").toLowerCase();

  // header khas browser modern
  const hasSecFetch =
    typeof headers["sec-fetch-site"] === "string" ||
    typeof headers["sec-fetch-mode"] === "string" ||
    typeof headers["sec-fetch-dest"] === "string";

  const hasSecUA = typeof headers["sec-ch-ua"] === "string";
  const hasUpgradeInsecure =
    typeof headers["upgrade-insecure-requests"] === "string";

  const isBrowserUA =
    ua.includes("mozilla") ||
    ua.includes("chrome") ||
    ua.includes("safari") ||
    ua.includes("firefox") ||
    ua.includes("edg");

  const wantsHtml = accept.includes("text/html");

  const hasBrowserHints = hasSecFetch || hasSecUA || hasUpgradeInsecure;

  // dianggap browser kalau:
  //  - UA khas browser, dan
  //  - ada header khas browser / atau jelas minta text/html
  return isBrowserUA && (hasBrowserHints || wantsHtml);
}

// Deteksi request yang datang dari client Roblox (executor apa pun yang berjalan di dalam Roblox)
function isRobloxUserAgent(req) {
  const ua = (req.headers["user-agent"] || "").toLowerCase();
  return ua.includes("roblox");
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

/* ========= USER DASHBOARD (DISCORD USER) ========= */

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
  const provider = (
    req.query.provider ||
    req.query.ads ||
    "workink"
  ).toLowerCase();
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

  let keyStats = null;
  try {
    keyStats = await buildAdminKeyStats();
  } catch (err) {
    console.error("Failed to build admin key stats:", err);
    keyStats = null;
  }

  const cleanupSummary = req.session.cleanupSummary || null;
  if (req.session.cleanupSummary) {
    delete req.session.cleanupSummary;
  }

  res.render("admin-dashboard", {
    user: adminUser,
    scripts,
    keyStats,
    cleanupSummary,
  });
});

/* ========= ADMIN: CLEANUP KEYS (GLOBAL) ========= */

app.post("/admin/cleanup-keys", requireAdmin, async (req, res) => {
  try {
    const result = await cleanupAllUserKeys();
    req.session.cleanupSummary = {
      type: "success",
      message: `Cleanup keys selesai: scanned=${result.scannedTokens}, removedFromLists=${result.removedFromLists}, deletedKeyDocs=${result.deletedKeyDocs}, affectedUsers=${result.affectedUsers}`,
      result,
    };
  } catch (err) {
    console.error("Failed to cleanup keys:", err);
    req.session.cleanupSummary = {
      type: "error",
      message: "Cleanup keys gagal: " + err.message,
    };
  }
  res.redirect("/admin");
});

/* ========= ADMIN: CLEANUP USERS (GLOBAL) ========= */

app.post("/admin/cleanup-users", requireAdmin, async (req, res) => {
  try {
    const result = await cleanupUsersWithoutActiveKeys();
    req.session.cleanupSummary = {
      type: "success",
      message: `Cleanup users selesai: totalUserLists=${result.totalUserLists}, deletedUserLists=${result.deletedUserLists}, usersWithActiveKeys=${result.usersWithActiveKeys}`,
      result,
    };
  } catch (err) {
    console.error("Failed to cleanup users:", err);
    req.session.cleanupSummary = {
      type: "error",
      message: "Cleanup users gagal: " + err.message,
    };
  }
  res.redirect("/admin");
});

/* ========= ADMIN: DELETE SATU KEY ========= */

app.post("/admin/delete-key", requireAdmin, async (req, res) => {
  const token = (req.body.token || "").trim();

  if (!token) {
    req.session.cleanupSummary = {
      type: "error",
      message: "Token tidak boleh kosong.",
    };
    return res.redirect("/admin");
  }

  try {
    const result = await deleteKeyEverywhere(token);
    if (!result.ok) {
      req.session.cleanupSummary = {
        type: "error",
        message: "Gagal menghapus key: " + (result.reason || "unknown"),
      };
    } else {
      req.session.cleanupSummary = {
        type: "success",
        message: `Key ${token} berhasil dihapus. userId=${result.userId ||
          "unknown"}, removedFromList=${result.removedFromList}, deletedDoc=${result.deletedDoc}`,
      };
    }
  } catch (err) {
    console.error("Failed to delete key:", err);
    req.session.cleanupSummary = {
      type: "error",
      message: "Gagal menghapus key: " + err.message,
    };
  }

  res.redirect("/admin");
});

/* ========= ADMIN: DELETE SEMUA KEY USER ========= */

app.post("/admin/delete-user-keys", requireAdmin, async (req, res) => {
  const userId = (req.body.userId || "").trim();

  if (!userId) {
    req.session.cleanupSummary = {
      type: "error",
      message: "userId tidak boleh kosong.",
    };
    return res.redirect("/admin");
  }

  try {
    const result = await deleteAllKeysForUser(userId);
    req.session.cleanupSummary = {
      type: "success",
      message: `Semua key untuk user ${userId} dihapus. deletedDocs=${result.deletedDocs}, deletedList=${result.deletedList}`,
      result,
    };
  } catch (err) {
    console.error("Failed to delete all keys for user:", err);
    req.session.cleanupSummary = {
      type: "error",
      message: "Gagal menghapus semua key user: " + err.message,
    };
  }

  res.redirect("/admin");
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

// baca loader.lua sekali, dengan error handling
let loaderLuaSource = "";
try {
  const loaderLuaPath = path.join(__dirname, "scripts", "loader.lua");
  loaderLuaSource = fs.readFileSync(loaderLuaPath, "utf8");
  console.log("[LOADER] Loaded scripts/loader.lua");
} catch (err) {
  console.error("[LOADER] Failed to read scripts/loader.lua:", err.message);
}

app.get("/api/script/loader", (req, res) => {
  // Kalau file belum terbaca / hilang → 500
  if (!loaderLuaSource) {
    return res
      .status(500)
      .type("text/plain")
      .send("-- loader.lua missing or unreadable on the server");
  }

  // 1) Blokir browser asli supaya nggak bisa akses script
  if (looksLikeRealBrowser(req)) {
    return res.status(404).render("api-404");
  }

  // 2) Tambahan proteksi: kombinasi isRobloxUserAgent + x-loader-key
  //
  //    - Kalau LOADER_KEY TIDAK di-set:
  //        → hanya pakai anti-browser (semua non-browser lolos).
  //    - Kalau LOADER_KEY di-set:
  //        → UA mengandung "roblox"   => lolos (executor Roblox apa pun).
  //        → Non-roblox client       => wajib kirim header x-loader-key yang cocok.
  const expectedKey = process.env.LOADER_KEY;
  const loaderKey = req.headers["x-loader-key"];
  const robloxUA = isRobloxUserAgent(req);
  const hasValidKey = expectedKey && loaderKey === expectedKey;

  if (expectedKey && !robloxUA && !hasValidKey) {
    console.warn(
      "[LOADER] Forbidden non-roblox client tanpa x-loader-key valid. UA=",
      req.headers["user-agent"] || ""
    );
    // Jangan bocorin info apa-apa, render 404 juga
    return res.status(403).render("api-404");
  }

  // Non-browser (+ lolos filter di atas) → kirim Lua mentah
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  return res.send(loaderLuaSource);
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
