require("dotenv").config();

const express = require("express");
const path = require("path");
const fs = require("fs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { Redis } = require("@upstash/redis");

// node-fetch v3 (ESM) di CommonJS
const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

const app = express();

// === CONFIG & CLIENTS ===
const siteConfig = JSON.parse(
  fs.readFileSync(path.join(__dirname, "config/loader.json"), "utf8")
);

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN
});

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || "http://localhost:" + PORT;
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-secret";
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI =
  process.env.DISCORD_REDIRECT_URI ||
  BASE_URL + "/auth/discord/callback";
const REQUIRED_GUILD_ID = process.env.REQUIRED_GUILD_ID || null;
const WORKINK_URL = process.env.WORKINK_URL || "https://work.ink/your-link";
const LINKVERTISE_URL =
  process.env.LINKVERTISE_URL || "https://linkvertise.com/your-link";
const KEY_EXPIRE_HOURS = Number(process.env.KEY_EXPIRE_HOURS || 3);
const ADMIN_IDS = (process.env.ADMIN_IDS || "").split(",").filter(Boolean);

// === EXPRESS SETUP ===
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// === HELPER FUNCTIONS ===

function getIp(req) {
  const raw = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";
  return raw.split(",")[0].trim();
}

function generateKeyString() {
  const pool = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  function part(len) {
    let out = "";
    for (let i = 0; i < len; i++) {
      out += pool[Math.floor(Math.random() * pool.length)];
    }
    return out;
  }
  return `SIX-${part(4)}-${part(4)}-${part(4)}`;
}

function msToTime(ms) {
  if (ms <= 0) return "Expired";
  const totalSec = Math.floor(ms / 1000);
  const h = String(Math.floor(totalSec / 3600)).padStart(2, "0");
  const m = String(Math.floor((totalSec % 3600) / 60)).padStart(2, "0");
  const s = String(totalSec % 60).padStart(2, "0");
  return `${h}:${m}:${s}`;
}

async function saveKeyRecord(record) {
  await redis.set(`key:${record.key}`, JSON.stringify(record));
  await redis.sadd(`user:${record.discordId}:keys`, record.key);
  await redis.incr("stats:totalKeys");
  await redis.incr("stats:activeKeys");
}

async function updateKeyRecord(key, updater) {
  const raw = await redis.get(`key:${key}`);
  if (!raw) return null;
  const data = JSON.parse(raw);
  const updated = updater(data) || data;
  await redis.set(`key:${key}`, JSON.stringify(updated));
  return updated;
}

async function getUserKeys(discordId) {
  const keys = (await redis.smembers(`user:${discordId}:keys`)) || [];
  if (!keys.length) return [];
  const results = await Promise.all(
    keys.map((k) => redis.get(`key:${k}`))
  );
  return results
    .filter(Boolean)
    .map((raw) => JSON.parse(raw))
    .sort((a, b) => b.createdAt - a.createdAt);
}

async function getScripts() {
  const fromDb = await redis.get("scripts");
  if (fromDb) return JSON.parse(fromDb);
  return siteConfig.scripts || [];
}

async function setScripts(list) {
  await redis.set("scripts", JSON.stringify(list));
}

// JWT session <-> req.user
app.use((req, res, next) => {
  const token = req.cookies.session;
  if (!token) {
    res.locals.user = null;
    return next();
  }
  try {
    const payload = jwt.verify(token, SESSION_SECRET);
    req.user = payload;
    res.locals.user = payload;
  } catch (err) {
    res.clearCookie("session");
    res.locals.user = null;
  }
  next();
});

function requireAuth(req, res, next) {
  if (!req.user) return res.redirect("/login-required");
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || !ADMIN_IDS.includes(req.user.id)) {
    return res.status(403).send("Forbidden");
  }
  next();
}

// === DISCORD OAUTH ===

// tombol login
app.get("/login", (req, res) => {
  res.render("discord-login", { siteConfig });
});

app.get("/login-required", (req, res) => {
  res.render("logindc-required", { siteConfig });
});

app.get("/logout", (req, res) => {
  res.clearCookie("session");
  res.redirect("/");
});

app.get("/auth/discord", (req, res) => {
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: "code",
    scope: "identify email guilds guilds.join"
  });
  res.redirect("https://discord.com/api/oauth2/authorize?" + params.toString());
});

app.get("/auth/discord/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.redirect("/login");

  try {
    // exchange code
    const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: DISCORD_REDIRECT_URI
      })
    });

    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) {
      console.error("OAuth token error", tokenData);
      return res.redirect("/login");
    }

    // get user info
    const userRes = await fetch("https://discord.com/api/users/@me", {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`
      }
    });
    const user = await userRes.json();

    // (optional) check guild membership, invite, dll kalau perlu

    const payload = {
      id: user.id,
      username: user.username,
      global_name: user.global_name || user.username,
      avatar: user.avatar
    };

    const jwtToken = jwt.sign(payload, SESSION_SECRET, {
      expiresIn: "7d"
    });

    res.cookie("session", jwtToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax"
    });

    res.redirect("/dashboard");
  } catch (err) {
    console.error(err);
    res.redirect("/login");
  }
});

// === ROUTES PUBLIC ===

// Home (TAB 1)
app.get("/", async (req, res) => {
  let totalKeys = 0;
  let activeKeys = 0;
  try {
    totalKeys = Number((await redis.get("stats:totalKeys")) || 0);
    activeKeys = Number((await redis.get("stats:activeKeys")) || 0);
  } catch (err) {
    // ignore
  }

  res.render("home", {
    siteConfig,
    stats: { totalKeys, activeKeys }
  });
});

// Dashboard user (seperti Gbr 8)
app.get("/dashboard", requireAuth, async (req, res) => {
  const keys = await getUserKeys(req.user.id);
  const now = Date.now();
  const totalKeys = keys.length;
  const active = keys.filter(
    (k) => k.status === "active" && k.expiresAfter > now
  ).length;

  res.render("dashboarddc.ejs", {
    siteConfig,
    keys,
    summary: {
      totalKeys,
      activeKeys: active
    }
  });
});

// Scripts (TAB 3)
app.get("/scripts", async (req, res) => {
  const scripts = await getScripts();
  res.render("scripts", {
    siteConfig,
    scripts,
    loader: siteConfig.loader
  });
});

// === GET KEY FLOW (TAB 2) ===

app.get("/get-key", requireAuth, async (req, res) => {
  const provider = req.query.provider || null;
  const keys = await getUserKeys(req.user.id);
  const now = Date.now();

  const keysWithTime = keys.map((k) => ({
    ...k,
    timeLeft: msToTime(k.expiresAfter - now),
    isExpired: k.expiresAfter <= now || k.status !== "active"
  }));

  let sessionCompleted = false;
  if (provider) {
    const flag = await redis.get(
      `session-complete:${req.user.id}:${provider}`
    );
    sessionCompleted = Boolean(flag);
  }

  res.render("get-key", {
    siteConfig,
    provider,
    keys: keysWithTime,
    sessionCompleted
  });
});

// Start verification (redirect ke Work.ink/Linkvertise + simpan session)
app.get("/provider/start", requireAuth, async (req, res) => {
  const provider = req.query.provider;
  if (!["workink", "linkvertise"].includes(provider)) {
    return res.redirect("/get-key");
  }

  const sessionId = crypto.randomUUID();
  await redis.set(
    `session:${sessionId}`,
    JSON.stringify({ discordId: req.user.id, provider }),
    { ex: 600 } // 10 menit
  );

  const externalUrl =
    provider === "workink"
      ? `${WORKINK_URL}?sid=${sessionId}`
      : `${LINKVERTISE_URL}?sid=${sessionId}`;

  res.redirect(externalUrl);
});

// Callback setelah user selesai dari provider
// di Work.ink/Linkvertise redirect ke:
// https://exc-webs.vercel.app/provider/callback?provider=workink&sid={sid}
app.get("/provider/callback", async (req, res) => {
  const { provider, sid } = req.query;
  if (!provider || !sid) return res.redirect("/get-key");

  const raw = await redis.get(`session:${sid}`);
  if (!raw) {
    return res.redirect("/get-key?error=session");
  }
  const data = JSON.parse(raw);
  await redis.del(`session:${sid}`);

  await redis.set(
    `session-complete:${data.discordId}:${provider}`,
    "1",
    { ex: 600 } // 10 menit untuk generate key
  );

  res.redirect(`/get-key?provider=${provider}`);
});

// Generate New Key
app.post("/get-key/generate", requireAuth, async (req, res) => {
  const provider = req.body.provider;
  if (!["workink", "linkvertise"].includes(provider)) {
    return res.redirect("/get-key");
  }

  const sessionFlag = await redis.get(
    `session-complete:${req.user.id}:${provider}`
  );
  if (!sessionFlag) {
    return res.redirect(
      `/get-key?provider=${provider}&error=need_verification`
    );
  }

  const key = generateKeyString();
  const now = Date.now();
  const expiresAfter = now + KEY_EXPIRE_HOURS * 60 * 60 * 1000;

  const record = {
    key,
    discordId: req.user.id,
    provider,
    createdAt: now,
    expiresAfter,
    status: "active",
    byIp: null,
    hwid: null
  };

  await saveKeyRecord(record);
  await redis.del(`session-complete:${req.user.id}:${provider}`);

  res.redirect(`/get-key?provider=${provider}#key-${key}`);
});

// Extend / Renew key (hanya contoh simple)
app.post("/keys/:key/extend", requireAuth, async (req, res) => {
  const key = req.params.key;
  const hours = Number(req.body.hours || KEY_EXPIRE_HOURS);
  const userId = req.user.id;

  await updateKeyRecord(key, (data) => {
    if (data.discordId !== userId) return data;
    const addMs = hours * 60 * 60 * 1000;
    const base = Math.max(Date.now(), data.expiresAfter || 0);
    data.expiresAfter = base + addMs;
    data.status = "active";
    return data;
  });

  res.redirect("/get-key");
});

// === ADMIN DASHBOARD ===

app.get("/admin", requireAdmin, async (req, res) => {
  const scripts = await getScripts();
  const totalKeys = Number((await redis.get("stats:totalKeys")) || 0);
  const activeKeys = Number((await redis.get("stats:activeKeys")) || 0);

  res.render("admin-dashboard", {
    siteConfig,
    scripts,
    stats: { totalKeys, activeKeys }
  });
});

app.post("/admin/scripts", requireAdmin, async (req, res) => {
  const { name, description, version, status, thumbnail, gameUrl, isFree } =
    req.body;

  const scripts = await getScripts();
  const id =
    req.body.id ||
    name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/(^-|-$)/g, "");

  const existingIndex = scripts.findIndex((s) => s.id === id);
  const item = {
    id,
    name,
    description,
    version,
    status,
    thumbnail,
    gameUrl,
    isFree: !!isFree
  };

  if (existingIndex >= 0) {
    scripts[existingIndex] = item;
  } else {
    scripts.push(item);
  }

  await setScripts(scripts);
  res.redirect("/admin");
});

// === API UNTUK LOADER LUA ===

// Endpoint loader (hanya bisa diakses dari HttpService Roblox)
app.get("/api/script/loader", (req, res) => {
  const ua = (req.headers["user-agent"] || "").toLowerCase();

  // simple proteksi: kalau kedeteksi browser biasa, lempar ke 404 ejs
  const isRoblox = ua.includes("roblox") || ua.includes("httpservice");
  if (!isRoblox) {
    return res.status(404).render("api-404", { siteConfig });
  }

  const filePath = path.join(__dirname, "scripts", "loader.lua");
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.send(fs.readFileSync(filePath, "utf8"));
});

// Endpoint validasi key (dipanggil dari loader.lua)
app.get("/api/isValidate/:key", async (req, res) => {
  const key = req.params.key;
  const hwid = req.query.hwid || null;
  const ip = getIp(req);

  const raw = await redis.get(`key:${key}`);
  if (!raw) {
    return res.json({
      valid: false,
      deleted: false,
      info: null
    });
  }

  let data = JSON.parse(raw);
  const now = Date.now();

  if (data.expiresAfter <= now) {
    data.status = "expired";
    await redis.set(`key:${key}`, JSON.stringify(data));
    return res.json({
      valid: false,
      deleted: false,
      info: null
    });
  }

  // HWID locking
  if (!data.hwid && hwid) {
    data.hwid = hwid;
    data.byIp = ip;
    await redis.set(`key:${key}`, JSON.stringify(data));
  } else if (data.hwid && hwid && data.hwid !== hwid) {
    // HWID beda -> invalid
    return res.json({
      valid: false,
      deleted: true,
      info: null
    });
  }

  const response = {
    valid: true,
    deleted: false,
    info: {
      token: data.key,
      createdAt: data.createdAt,
      byIp: data.byIp || ip,
      linkId: data.provider || null,
      userId: data.discordId,
      expiresAfter: data.expiresAfter
    }
  };

  res.json(response);
});

// 404 default
app.use((req, res) => {
  res.status(404).render("api-404", { siteConfig });
});

// START
app.listen(PORT, () => {
  console.log("EXC Webs running on port", PORT);
});