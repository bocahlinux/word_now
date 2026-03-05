require("dotenv").config();
const path = require("path");
const express = require("express");
const helmet = require("helmet");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const cookieSession = require("cookie-session");
const bcrypt = require("bcryptjs");

const { openDb } = require("./db");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";
const NODE_ENV = process.env.NODE_ENV || "development";
const DB_PATH = process.env.DB_PATH || "./data/app.db";
const COOKIE_SECRET = process.env.COOKIE_SECRET || "CHANGE_ME_PLEASE";

// DB
const db = openDb(DB_PATH);

// hardening
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), {
  etag: true,
  maxAge: NODE_ENV === "production" ? "7d" : 0
}));

// session cookie
app.use(cookieSession({
  name: "khisess",
  secret: COOKIE_SECRET,
  httpOnly: true,
  sameSite: "lax",
  secure: NODE_ENV === "production"
}));

// rate limit khusus login biar nggak brute-force
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

// view engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

const expressLayouts = require("express-ejs-layouts");
app.use(expressLayouts);
app.set("layout", "layout");

// helpers
function todayISO() {
  // server timezone: gunakan lokal server; kalau mau WIB/WITA, set TZ di system/pm2 env
  const d = new Date();
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}`;
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.adminId) return next();
  return res.redirect("/admin/login");
}

function layoutData(req, extra = {}) {
  return {
    isAdmin: Boolean(req.session && req.session.adminId),
    ...extra
  };
}

// ===== PUBLIC =====

// Home: tampilkan quote hari ini (for_date = today) kalau ada, plus list terbaru
app.get("/", (req, res) => {
  const t = todayISO();
  const category = (req.query.category || "").trim();
  const page = Math.max(1, parseInt(req.query.page || "1", 10));
  const pageSize = 12;
  const offset = (page - 1) * pageSize;

  const categories = db.prepare(`
    SELECT category, COUNT(*) as count
    FROM quotes
    WHERE is_published=1
    GROUP BY category
    ORDER BY count DESC, category ASC
  `).all();

  const todayQuotes = db.prepare(`
    SELECT * FROM quotes
    WHERE is_published=1 AND for_date = ?
    ORDER BY updated_at DESC
  `).all(t);

  let list, total;
  if (category) {
    total = db.prepare(`
      SELECT COUNT(*) as c
      FROM quotes
      WHERE is_published=1 AND category = ?
    `).get(category).c;

    list = db.prepare(`
      SELECT * FROM quotes
      WHERE is_published=1 AND category = ?
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `).all(category, pageSize, offset);
  } else {
    total = db.prepare(`
      SELECT COUNT(*) as c
      FROM quotes
      WHERE is_published=1
    `).get().c;

    list = db.prepare(`
      SELECT * FROM quotes
      WHERE is_published=1
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `).all(pageSize, offset);
  }

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  res.render("home", layoutData(req, {
    today: t,
    todayQuotes,
    list,
    categories,
    selectedCategory: category,
    page,
    totalPages
  }));
});

// Detail quote
app.get("/q/:id", (req, res) => {
  const id = Number(req.params.id);
  const q = db.prepare(`
    SELECT * FROM quotes
    WHERE id=? AND is_published=1
  `).get(id);

  if (!q) return res.status(404).send("Quote tidak ditemukan.");
  res.render("quote", layoutData(req, { q }));
});

// Random quote
app.get("/random", (req, res) => {
  const q = db.prepare(`
    SELECT * FROM quotes
    WHERE is_published=1
    ORDER BY RANDOM()
    LIMIT 1
  `).get();

  if (!q) return res.redirect("/");
  res.redirect(`/q/${q.id}`);
});

// Search
app.get("/search", (req, res) => {
  const q = (req.query.q || "").trim();
  let results = [];
  if (q.length >= 2) {
    results = db.prepare(`
      SELECT * FROM quotes
      WHERE is_published=1
        AND (text LIKE ? OR category LIKE ? OR author LIKE ?)
      ORDER BY created_at DESC
      LIMIT 50
    `).all(`%${q}%`, `%${q}%`, `%${q}%`);
  }
  res.render("search", layoutData(req, { query: q, results }));
});

// healthcheck
app.get("/healthz", (req, res) => res.json({ ok: true }));

// ===== ADMIN =====

app.get("/admin/login", (req, res) => {
  res.render("admin/login", layoutData(req, { error: null }));
});

app.post("/admin/login", loginLimiter, (req, res) => {
  const username = (req.body.username || "").trim();
  const password = (req.body.password || "");

  const admin = db.prepare(`SELECT * FROM admins WHERE username=?`).get(username);
  if (!admin) {
    return res.status(401).render("admin/login", layoutData(req, { error: "Login gagal." }));
  }
  const ok = bcrypt.compareSync(password, admin.password_hash);
  if (!ok) {
    return res.status(401).render("admin/login", layoutData(req, { error: "Login gagal." }));
  }

  req.session.adminId = admin.id;
  res.redirect("/admin");
});

app.post("/admin/logout", (req, res) => {
  req.session = null;
  res.redirect("/");
});

app.get("/admin", requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT * FROM quotes
    ORDER BY created_at DESC
    LIMIT 200
  `).all();

  res.render("admin/dashboard", layoutData(req, { rows }));
});

app.get("/admin/new", requireAdmin, (req, res) => {
  res.render("admin/form", layoutData(req, {
    mode: "new",
    q: { text: "", category: "gombalan", author: "", for_date: "", is_published: 1 },
    error: null
  }));
});

app.post("/admin/new", requireAdmin, (req, res) => {
  const text = (req.body.text || "").trim();
  const category = (req.body.category || "lainnya").trim() || "lainnya";
  const author = (req.body.author || "").trim() || null;
  const for_date = (req.body.for_date || "").trim() || null;
  const is_published = req.body.is_published ? 1 : 0;

  if (text.length < 3) {
    return res.status(400).render("admin/form", layoutData(req, {
      mode: "new",
      q: { text, category, author, for_date, is_published },
      error: "Teks terlalu pendek."
    }));
  }

  db.prepare(`
    INSERT INTO quotes(text, category, author, for_date, is_published, updated_at)
    VALUES(?,?,?,?,?, datetime('now'))
  `).run(text, category, author, for_date, is_published);

  res.redirect("/admin");
});

app.get("/admin/edit/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const q = db.prepare(`SELECT * FROM quotes WHERE id=?`).get(id);
  if (!q) return res.status(404).send("Data tidak ditemukan.");
  res.render("admin/form", layoutData(req, { mode: "edit", q, error: null }));
});

app.post("/admin/edit/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const existing = db.prepare(`SELECT * FROM quotes WHERE id=?`).get(id);
  if (!existing) return res.status(404).send("Data tidak ditemukan.");

  const text = (req.body.text || "").trim();
  const category = (req.body.category || "lainnya").trim() || "lainnya";
  const author = (req.body.author || "").trim() || null;
  const for_date = (req.body.for_date || "").trim() || null;
  const is_published = req.body.is_published ? 1 : 0;

  if (text.length < 3) {
    return res.status(400).render("admin/form", layoutData(req, {
      mode: "edit",
      q: { ...existing, text, category, author, for_date, is_published },
      error: "Teks terlalu pendek."
    }));
  }

  db.prepare(`
    UPDATE quotes
    SET text=?, category=?, author=?, for_date=?, is_published=?, updated_at=datetime('now')
    WHERE id=?
  `).run(text, category, author, for_date, is_published, id);

  res.redirect("/admin");
});

app.post("/admin/delete/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  db.prepare(`DELETE FROM quotes WHERE id=?`).run(id);
  res.redirect("/admin");
});

app.post("/admin/toggle/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  db.prepare(`
    UPDATE quotes
    SET is_published = CASE WHEN is_published=1 THEN 0 ELSE 1 END,
        updated_at = datetime('now')
    WHERE id=?
  `).run(id);
  res.redirect("/admin");
});

app.listen(PORT, HOST, () => {
  console.log(`[kata-hari-ini] http://${HOST}:${PORT} env=${NODE_ENV}`);
});