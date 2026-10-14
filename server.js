// MADMAN VISION DEPT. — Serveur (étape 1 : comptes + suivi des visites)
const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const PORT = process.env.PORT || 3000;
const PROD = process.env.NODE_ENV === "production";
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data", "madman.db");
const ADMIN_PHONES = (process.env.ADMIN_PHONES || "").split(",").map(s => s.trim()).filter(Boolean);
const SESSION_DAYS = 30;

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  phone TEXT NOT NULL UNIQUE,
  email TEXT,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'customer',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS visits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  visitor_id TEXT NOT NULL,
  path TEXT,
  user_id INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_visits_time ON visits(created_at);
`);

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
function startSession(res, userId) {
  const token = crypto.randomBytes(32).toString("hex");
  db.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?,?,?)")
    .run(sha(token), userId, Date.now() + SESSION_DAYS * 864e5);
  res.cookie("mv_session", token, { httpOnly: true, sameSite: "lax", secure: PROD, maxAge: SESSION_DAYS * 864e5, path: "/" });
}
function readCookie(req, name) {
  const m = (req.headers.cookie || "").split(/;\s*/).find(c => c.startsWith(name + "="));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : null;
}
function auth(req, res, next) {
  const token = readCookie(req, "mv_session");
  req.user = null;
  if (token) {
    const row = db.prepare(`SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.expires_at > ?`).get(sha(token), Date.now());
    if (row) req.user = row;
  }
  next();
}
app.use(auth);

/* ---------- API comptes ---------- */
app.post("/api/auth/register", limit(8, 15 * 60e3), (req, res) => {
  const firstName = clean(req.body.firstName, 60), lastName = clean(req.body.lastName, 60);
  const phone = normalizePhone(req.body.phone);
  const email = clean(req.body.email, 120).toLowerCase() || null;
  const password = String(req.body.password ?? "");
  if (!firstName || !lastName) return res.status(400).json({ error: "Nom et prénom requis." });
  if (!phone) return res.status(400).json({ error: "Numéro de téléphone invalide." });
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Adresse e-mail invalide." });
  if (password.length < 6 || password.length > 100) return res.status(400).json({ error: "Mot de passe : 6 caractères minimum." });
  if (db.prepare("SELECT 1 FROM users WHERE phone = ?").get(phone))
    return res.status(409).json({ error: "Ce numéro a déjà un compte. Connectez-vous." });
  const role = ADMIN_PHONES.includes(phone) ? "admin" : "customer";
  const info = db.prepare(`INSERT INTO users (first_name,last_name,phone,email,password_hash,role,created_at)
    VALUES (?,?,?,?,?,?,?)`).run(firstName, lastName, phone, email, bcrypt.hashSync(password, 10), role, Date.now());
  startSession(res, info.lastInsertRowid);
  res.status(201).json({ user: publicUser(db.prepare("SELECT * FROM users WHERE id = ?").get(info.lastInsertRowid)) });
});

app.post("/api/auth/login", limit(10, 15 * 60e3), (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const u = phone && db.prepare("SELECT * FROM users WHERE phone = ?").get(phone);
  if (!u || !bcrypt.compareSync(String(req.body.password ?? ""), u.password_hash))
    return res.status(401).json({ error: "Numéro ou mot de passe incorrect." });
  startSession(res, u.id);
  res.json({ user: publicUser(u) });
});

app.post("/api/auth/logout", (req, res) => {
  const token = readCookie(req, "mv_session");
  if (token) db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(sha(token));
  res.clearCookie("mv_session", { path: "/" });
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => res.json({ user: req.user ? publicUser(req.user) : null }));

/* ---------- suivi des visites (alimente le futur dashboard) ---------- */
app.post("/api/track", limit(60, 60e3), (req, res) => {
  const vid = clean(req.body.visitorId, 64);
  if (/^[a-f0-9-]{16,64}$/i.test(vid))
    db.prepare("INSERT INTO visits (visitor_id,path,user_id,created_at) VALUES (?,?,?,?)")
      .run(vid, clean(req.body.path, 200), req.user ? req.user.id : null, Date.now());
  res.status(204).end();
});

app.get("/healthz", (req, res) => res.send("ok"));
app.use("/api", (req, res) => res.status(404).json({ error: "Introuvable." }));
app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));

// nettoyage des sessions expirées
setInterval(() => db.prepare("DELETE FROM sessions WHERE expires_at < ?").run(Date.now()), 3600e3).unref();

app.listen(PORT, () => console.log(`MADMAN VISION DEPT. — serveur prêt sur le port ${PORT}`));