// MADMAN VISION DEPT. — Serveur (étape 1 : comptes + suivi des visites) — PostgreSQL (Supabase)
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const path = require("path");

const PORT = process.env.PORT || 3000;
const PROD = process.env.NODE_ENV === "production";
const ADMIN_PHONES = (process.env.ADMIN_PHONES || "").split(",").map(s => s.trim()).filter(Boolean);
const SESSION_DAYS = 30;

if (!process.env.DATABASE_URL) { console.error("DATABASE_URL manquante."); process.exit(1); }
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "off" ? false : { rejectUnauthorized: false },
  max: 8,
});
pool.on("error", e => console.error("Erreur base de données :", e.message));
const q = (text, params) => pool.query(text, params);
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => {
  res.set({ "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "strict-origin-when-cross-origin" });
  next();
});

/* ---------- utilitaires ---------- */
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const clean = (s, max) => String(s ?? "").trim().replace(/\s+/g, " ").slice(0, max);

function normalizePhone(raw) {
  let s = String(raw ?? "").replace(/[\s.\-()]/g, "");
  if (s.startsWith("+")) return /^\+\d{8,15}$/.test(s) ? s : null;
  if (s.startsWith("00")) s = "+" + s.slice(2);
  if (s.startsWith("+")) return /^\+\d{8,15}$/.test(s) ? s : null;
  if (s.startsWith("221") && s.length === 12) s = s.slice(3);
  return /^7[05678]\d{7}$/.test(s) ? "+221" + s : null;
}

const hits = new Map();
function limit(max, windowMs) {
  return (req, res, next) => {
    const k = req.ip + req.path, now = Date.now();
    const arr = (hits.get(k) || []).filter(t => now - t < windowMs);
    if (arr.length >= max) return res.status(429).json({ error: "Trop de tentatives. Réessayez dans quelques minutes." });
    arr.push(now); hits.set(k, arr); next();
  };
}
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some(t => now - t < 3600e3)) hits.delete(k); }, 600e3).unref();

function publicUser(u) {
  return { id: u.id, firstName: u.first_name, lastName: u.last_name, phone: u.phone, email: u.email, role: u.role };
}
async function startSession(res, userId) {
  const token = crypto.randomBytes(32).toString("hex");
  await q("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1,$2, now() + make_interval(days => $3))",
    [sha(token), userId, SESSION_DAYS]);
  res.cookie("mv_session", token, { httpOnly: true, sameSite: "lax", secure: PROD, maxAge: SESSION_DAYS * 864e5, path: "/" });
}
function readCookie(req, name) {
  const m = (req.headers.cookie || "").split(/;\s*/).find(c => c.startsWith(name + "="));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : null;
}
const auth = wrap(async (req, res, next) => {
  const token = readCookie(req, "mv_session");
  req.user = null;
  if (token) {
    const { rows } = await q(`SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = $1 AND s.expires_at > now()`, [sha(token)]);
    if (rows[0]) req.user = rows[0];
  }
  next();
});
app.use(auth);

/* ---------- API comptes ---------- */
app.post("/api/auth/register", limit(8, 15 * 60e3), wrap(async (req, res) => {
  const firstName = clean(req.body.firstName, 60), lastName = clean(req.body.lastName, 60);
  const phone = normalizePhone(req.body.phone);
  const email = clean(req.body.email, 120).toLowerCase() || null;
  const password = String(req.body.password ?? "");
  if (!firstName || !lastName) return res.status(400).json({ error: "Nom et prénom requis." });
  if (!phone) return res.status(400).json({ error: "Numéro de téléphone invalide." });
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Adresse e-mail invalide." });
  if (password.length < 6 || password.length > 100) return res.status(400).json({ error: "Mot de passe : 6 caractères minimum." });
  const role = ADMIN_PHONES.includes(phone) ? "admin" : "customer";
  let user;
  try {
    const r = await q(`INSERT INTO users (first_name,last_name,phone,email,password_hash,role)
      VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`, [firstName, lastName, phone, email, await bcrypt.hash(password, 10), role]);
    user = r.rows[0];
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "Ce numéro a déjà un compte. Connectez-vous." });
    throw e;
  }
  await startSession(res, user.id);
  res.status(201).json({ user: publicUser(user) });
}));

app.post("/api/auth/login", limit(10, 15 * 60e3), wrap(async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const u = phone ? (await q("SELECT * FROM users WHERE phone = $1", [phone])).rows[0] : null;
  if (!u || !(await bcrypt.compare(String(req.body.password ?? ""), u.password_hash)))
    return res.status(401).json({ error: "Numéro ou mot de passe incorrect." });
  await startSession(res, u.id);
  res.json({ user: publicUser(u) });
}));

app.post("/api/auth/logout", wrap(async (req, res) => {
  const token = readCookie(req, "mv_session");
  if (token) await q("DELETE FROM sessions WHERE token_hash = $1", [sha(token)]);
  res.clearCookie("mv_session", { path: "/" });
  res.json({ ok: true });
}));

app.get("/api/me", (req, res) => res.json({ user: req.user ? publicUser(req.user) : null }));

/* ---------- suivi des visites (alimente le futur dashboard) ---------- */
app.post("/api/track", limit(60, 60e3), wrap(async (req, res) => {
  const vid = clean(req.body.visitorId, 64);
  if (/^[a-f0-9-]{16,64}$/i.test(vid))
    await q("INSERT INTO visits (visitor_id,path,user_id) VALUES ($1,$2,$3)",
      [vid, clean(req.body.path, 200), req.user ? req.user.id : null]);
  res.status(204).end();
}));

app.get("/healthz", wrap(async (req, res) => { await q("SELECT 1"); res.send("ok"); }));
app.use("/api", (req, res) => res.status(404).json({ error: "Introuvable." }));
app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));

// gestion d'erreurs
app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "Erreur serveur. Réessayez." });
});

// nettoyage des sessions expirées
setInterval(() => q("DELETE FROM sessions WHERE expires_at < now()").catch(() => {}), 3600e3).unref();

app.listen(PORT, () => console.log(`MADMAN VISION DEPT. — serveur prêt sur le port ${PORT}`));
