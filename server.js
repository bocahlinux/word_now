require("dotenv").config();
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
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
const BASE_URL = (process.env.BASE_URL || "").trim();
const COOKIE_SECRET = process.env.COOKIE_SECRET || "CHANGE_ME_PLEASE";
const TRUST_PROXY = Number(process.env.TRUST_PROXY || (NODE_ENV === "production" ? 1 : 0));
const COOKIE_SECURE = (process.env.COOKIE_SECURE || "").toLowerCase();
const USE_SECURE_COOKIE = COOKIE_SECURE
  ? COOKIE_SECURE === "true"
  : NODE_ENV === "production";

const BACKUP_ENABLED = (process.env.BACKUP_ENABLED || "true").toLowerCase() !== "false";
const BACKUP_INTERVAL_HOURS = Math.max(1, Number(process.env.BACKUP_INTERVAL_HOURS || 24));
const BACKUP_RETENTION_DAYS = Math.max(1, Number(process.env.BACKUP_RETENTION_DAYS || 14));
const BACKUP_DIR = path.resolve(process.env.BACKUP_DIR || "./data/backups");

const CATEGORY_OPTIONS = [
  "gombalan",
  "motivasi",
  "galau",
  "lucu",
  "romantis",
  "bijak",
  "lainnya"
];

const PUBLISHED_WHERE = `
  q.is_published=1
  AND (q.publish_at IS NULL OR q.publish_at <= datetime('now', 'localtime'))
`;

const quoteSelectFields = `
  q.*,
  COALESCE((SELECT GROUP_CONCAT(qc.category, ', ') FROM quote_categories qc WHERE qc.quote_id = q.id), q.category) AS categories,
  COALESCE((SELECT COUNT(*) FROM quote_views v WHERE v.quote_id = q.id), 0) AS view_count,
  COALESCE((SELECT COUNT(*) FROM quote_likes l WHERE l.quote_id = q.id), 0) AS like_count,
  COALESCE((SELECT COUNT(*) FROM quote_bookmarks b WHERE b.quote_id = q.id), 0) AS bookmark_count,
  COALESCE((SELECT COUNT(*) FROM quote_comments c WHERE c.quote_id = q.id AND c.is_hidden = 0), 0) AS comment_count,
  s.name AS series_name,
  s.weekday AS series_weekday
`;

const quoteFromClause = `
  FROM quotes q
  LEFT JOIN quote_series s ON s.id = q.series_id
`;

const db = openDb(DB_PATH);

const insertQuoteStmt = db.prepare(`
  INSERT INTO quotes(text, category, author, for_date, is_published, publish_at, slug, series_id, updated_at)
  VALUES(?,?,?,?,?,?,?,?, datetime('now'))
`);

const updateQuoteStmt = db.prepare(`
  UPDATE quotes
  SET text=?, category=?, author=?, for_date=?, is_published=?, publish_at=?, slug=?, series_id=?, updated_at=datetime('now')
  WHERE id=?
`);

const updateQuoteSlugStmt = db.prepare(`UPDATE quotes SET slug=? WHERE id=?`);

const autoPublishStmt = db.prepare(`
  UPDATE quotes
  SET is_published = 1,
      updated_at = datetime('now')
  WHERE is_published = 0
    AND publish_at IS NOT NULL
    AND publish_at <= datetime('now', 'localtime')
`);

const deleteQuoteCategoriesStmt = db.prepare(`DELETE FROM quote_categories WHERE quote_id=?`);
const insertQuoteCategoryStmt = db.prepare(`INSERT OR IGNORE INTO quote_categories(quote_id, category) VALUES(?, ?)`);
const readQuoteCategoriesStmt = db.prepare(`SELECT category FROM quote_categories WHERE quote_id=? ORDER BY category ASC`);

const readSeriesOptionsStmt = db.prepare(`
  SELECT id, name, weekday, category_hint, is_active
  FROM quote_series
  ORDER BY weekday ASC, name ASC
`);

const readSeriesActiveOptionsStmt = db.prepare(`
  SELECT id, name, weekday, category_hint, is_active
  FROM quote_series
  WHERE is_active=1
  ORDER BY weekday ASC, name ASC
`);

const readSeriesTodayStmt = db.prepare(`
  SELECT id, name, weekday, category_hint
  FROM quote_series
  WHERE is_active=1 AND weekday=?
  ORDER BY id ASC
  LIMIT 1
`);

const readLikeStmt = db.prepare(`SELECT 1 FROM quote_likes WHERE quote_id=? AND session_key=?`);
const insertLikeStmt = db.prepare(`INSERT OR IGNORE INTO quote_likes(quote_id, session_key) VALUES(?, ?)`);
const deleteLikeStmt = db.prepare(`DELETE FROM quote_likes WHERE quote_id=? AND session_key=?`);

const readBookmarkStmt = db.prepare(`SELECT 1 FROM quote_bookmarks WHERE quote_id=? AND session_key=?`);
const insertBookmarkStmt = db.prepare(`INSERT OR IGNORE INTO quote_bookmarks(quote_id, session_key) VALUES(?, ?)`);
const deleteBookmarkStmt = db.prepare(`DELETE FROM quote_bookmarks WHERE quote_id=? AND session_key=?`);

const insertQuoteViewStmt = db.prepare(`INSERT INTO quote_views(quote_id, viewer_type) VALUES(?, ?)`);
const insertSearchLogStmt = db.prepare(`INSERT INTO search_logs(query, hits, viewer_type) VALUES(?, ?, ?)`);
const insertCommentStmt = db.prepare(`INSERT INTO quote_comments(quote_id, session_key, author, comment) VALUES(?,?,?,?)`);

const toggleCommentVisibilityStmt = db.prepare(`
  UPDATE quote_comments
  SET is_hidden = CASE WHEN is_hidden=1 THEN 0 ELSE 1 END
  WHERE id=?
`);

const toggleSeriesStmt = db.prepare(`
  UPDATE quote_series
  SET is_active = CASE WHEN is_active=1 THEN 0 ELSE 1 END
  WHERE id=?
`);

const replaceQuoteCategories = db.transaction((quoteId, categories) => {
  deleteQuoteCategoriesStmt.run(quoteId);
  for (const category of categories) {
    insertQuoteCategoryStmt.run(quoteId, category);
  }
});

const backupState = {
  running: false,
  lastRunAt: null,
  lastFile: null,
  lastError: null,
  nextRunAt: null
};

app.disable("x-powered-by");
if (TRUST_PROXY > 0) app.set("trust proxy", TRUST_PROXY);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), {
  etag: true,
  maxAge: NODE_ENV === "production" ? "7d" : 0
}));

app.use(cookieSession({
  name: "khisess",
  secret: COOKIE_SECRET,
  httpOnly: true,
  sameSite: "lax",
  secure: USE_SECURE_COOKIE
}));

app.use((req, res, next) => {
  if (!req.session) req.session = {};
  if (!req.session.visitorId) req.session.visitorId = crypto.randomUUID();
  next();
});

app.use((req, res, next) => {
  autoPublishStmt.run();
  next();
});

const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

const commentLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false
});

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

const expressLayouts = require("express-ejs-layouts");
app.use(expressLayouts);
app.set("layout", "layout");
function todayISO() {
  const d = new Date();
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}`;
}

function nowSqlLocal() {
  const d = new Date();
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`;
}

function weekdayName(day) {
  const names = ["Minggu", "Senin", "Selasa", "Rabu", "Kamis", "Jumat", "Sabtu"];
  return names[day] || "-";
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

function viewerTypeFromRequest(req) {
  return req.session && req.session.adminId ? "admin" : "user";
}

function normalizeCategory(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, " ");
}

function parseCategories(selectedValue, customValue) {
  const selected = Array.isArray(selectedValue)
    ? selectedValue
    : (selectedValue ? [selectedValue] : []);
  const custom = String(customValue || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

  const normalized = [];
  for (const raw of [...selected, ...custom]) {
    const category = normalizeCategory(raw);
    if (!category || normalized.includes(category)) continue;
    normalized.push(category);
  }

  if (normalized.length === 0) return ["lainnya"];
  return normalized;
}

function splitCategoryText(rawCategory) {
  return String(rawCategory || "")
    .split(",")
    .map((item) => normalizeCategory(item))
    .filter(Boolean);
}

function getQuoteCategories(quoteId, fallbackCategory) {
  const fromDb = readQuoteCategoriesStmt.all(quoteId).map((row) => row.category);
  if (fromDb.length > 0) return fromDb;

  const fallback = splitCategoryText(fallbackCategory);
  return fallback.length > 0 ? fallback : ["lainnya"];
}

function slugify(text) {
  const cleaned = String(text || "")
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, "")
    .trim()
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 60);

  return cleaned || "quote";
}

function buildQuoteSlug(id, text) {
  return `${slugify(text)}-${id}`;
}

function normalizePublishAtInput(rawValue) {
  const raw = String(rawValue || "").trim();
  if (!raw) return null;

  const match = raw.match(/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})(?::\d{2})?$/);
  if (!match) return null;

  return `${match[1]} ${match[2]}:00`;
}

function formatPublishAtForInput(rawValue) {
  const raw = String(rawValue || "").trim();
  if (!raw) return "";
  return raw.replace(" ", "T").slice(0, 16);
}

function computePublishState(isPublishedInput, publishAt) {
  let isPublished = isPublishedInput ? 1 : 0;
  if (publishAt && publishAt > nowSqlLocal()) isPublished = 0;
  return isPublished;
}

function parseSeriesId(rawValue) {
  const value = Number(rawValue);
  if (!Number.isInteger(value) || value <= 0) return null;
  const exists = db.prepare("SELECT id FROM quote_series WHERE id=?").get(value);
  return exists ? value : null;
}

function getBaseUrl(req) {
  if (BASE_URL) return BASE_URL.replace(/\/+$/, "");

  const forwardedProto = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim();
  const proto = forwardedProto || req.protocol || "http";
  const host = req.get("host") || `localhost:${PORT}`;
  return `${proto}://${host}`;
}

function absoluteUrl(req, pathname) {
  const base = getBaseUrl(req);
  if (!pathname) return base;
  const normalized = pathname.startsWith("/") ? pathname : `/${pathname}`;
  return `${base}${normalized}`;
}

function buildSeo(req, options = {}) {
  const title = options.title || "Kata Hari Ini";
  const description = options.description || "Kumpulan quote harian: gombalan, motivasi, galau, lucu, dan lainnya.";
  const pathName = options.pathName || req.path;
  const canonical = options.canonical || absoluteUrl(req, pathName);
  const image = options.image ? options.image : absoluteUrl(req, "/og-default.svg");

  return {
    title,
    description,
    canonical,
    url: canonical,
    image,
    type: options.type || "website",
    robots: options.robots || "index,follow",
    keywords: options.keywords || "quote, gombalan, motivasi, kata-kata, kata hari ini",
    jsonLd: options.jsonLd || null
  };
}

function escapeXml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function wrapText(value, maxChars = 40) {
  const words = String(value || "").trim().split(/\s+/).filter(Boolean);
  if (words.length === 0) return [""];

  const lines = [];
  let current = "";
  for (const word of words) {
    const candidate = current ? `${current} ${word}` : word;
    if (candidate.length <= maxChars) {
      current = candidate;
    } else {
      if (current) lines.push(current);
      current = word;
    }
  }
  if (current) lines.push(current);
  return lines.slice(0, 8);
}

function getAnalytics(viewerType) {
  const topQuote = db.prepare(`
    SELECT q.id, q.slug, q.text, COUNT(v.id) as total
    FROM quote_views v
    JOIN quotes q ON q.id = v.quote_id
    WHERE v.viewer_type = ?
    GROUP BY q.id
    ORDER BY total DESC, q.id DESC
    LIMIT 1
  `).get(viewerType);

  let topCategories = db.prepare(`
    SELECT qc.category, COUNT(v.id) as total
    FROM quote_views v
    JOIN quote_categories qc ON qc.quote_id = v.quote_id
    WHERE v.viewer_type = ?
    GROUP BY qc.category
    ORDER BY total DESC, qc.category ASC
    LIMIT 5
  `).all(viewerType);

  if (topCategories.length === 0) {
    topCategories = db.prepare(`
      SELECT qc.category, COUNT(*) as total
      FROM quote_categories qc
      JOIN quotes q ON q.id = qc.quote_id
      WHERE ${PUBLISHED_WHERE}
      GROUP BY qc.category
      ORDER BY total DESC, qc.category ASC
      LIMIT 5
    `).all();
  }

  const topSearches = db.prepare(`
    SELECT query, COUNT(*) as total
    FROM search_logs
    WHERE viewer_type = ?
    GROUP BY query
    ORDER BY total DESC, query ASC
    LIMIT 5
  `).all(viewerType);

  return { topQuote, topCategories, topSearches };
}

function findQuoteBySlug(rawSlug, options = {}) {
  const slug = String(rawSlug || "").trim().toLowerCase();
  const includeUnpublished = Boolean(options.includeUnpublished);

  let q = db.prepare(`
    SELECT ${quoteSelectFields}
    ${quoteFromClause}
    WHERE q.slug = ?
      ${includeUnpublished ? "" : `AND ${PUBLISHED_WHERE}`}
  `).get(slug);

  if (!q) {
    const fallback = slug.match(/-(\d+)$/);
    if (fallback) {
      const id = Number(fallback[1]);
      q = db.prepare(`
        SELECT ${quoteSelectFields}
        ${quoteFromClause}
        WHERE q.id = ?
          ${includeUnpublished ? "" : `AND ${PUBLISHED_WHERE}`}
      `).get(id);
    }
  }

  return q || null;
}

function formatBackupTimestamp(date = new Date()) {
  const yyyy = date.getFullYear();
  const mm = String(date.getMonth() + 1).padStart(2, "0");
  const dd = String(date.getDate()).padStart(2, "0");
  const hh = String(date.getHours()).padStart(2, "0");
  const mi = String(date.getMinutes()).padStart(2, "0");
  const ss = String(date.getSeconds()).padStart(2, "0");
  return `${yyyy}${mm}${dd}-${hh}${mi}${ss}`;
}

function pruneBackups() {
  if (!fs.existsSync(BACKUP_DIR)) return;

  const files = fs.readdirSync(BACKUP_DIR)
    .filter((name) => name.endsWith(".db"))
    .map((name) => {
      const fullPath = path.join(BACKUP_DIR, name);
      const stat = fs.statSync(fullPath);
      return { fullPath, mtimeMs: stat.mtimeMs };
    });

  const threshold = Date.now() - (BACKUP_RETENTION_DAYS * 24 * 60 * 60 * 1000);
  for (const file of files) {
    if (file.mtimeMs < threshold) fs.unlinkSync(file.fullPath);
  }
}

async function createDbBackup(trigger = "auto") {
  if (!BACKUP_ENABLED || backupState.running) return null;

  backupState.running = true;
  backupState.lastError = null;

  try {
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const filename = `app-${formatBackupTimestamp()}.db`;
    const destination = path.join(BACKUP_DIR, filename);

    if (typeof db.backup === "function") {
      await db.backup(destination);
    } else {
      fs.copyFileSync(path.resolve(DB_PATH), destination);
    }

    pruneBackups();

    backupState.lastRunAt = new Date().toISOString();
    backupState.lastFile = destination;
    backupState.nextRunAt = new Date(Date.now() + BACKUP_INTERVAL_HOURS * 60 * 60 * 1000).toISOString();

    return { trigger, destination };
  } catch (err) {
    backupState.lastError = err && err.message ? err.message : String(err);
    throw err;
  } finally {
    backupState.running = false;
  }
}

if (BACKUP_ENABLED) {
  createDbBackup("startup").catch(() => {});
  setInterval(() => {
    createDbBackup("auto").catch(() => {});
  }, BACKUP_INTERVAL_HOURS * 60 * 60 * 1000);
}
// ===== PUBLIC =====

app.get("/", (req, res) => {
  const t = todayISO();
  const category = normalizeCategory(req.query.category || "");
  const page = Math.max(1, parseInt(req.query.page || "1", 10));
  const pageSize = 12;
  const offset = (page - 1) * pageSize;

  const categories = db.prepare(`
    SELECT qc.category AS category, COUNT(DISTINCT qc.quote_id) as count
    FROM quote_categories qc
    JOIN quotes q ON q.id = qc.quote_id
    WHERE ${PUBLISHED_WHERE}
    GROUP BY qc.category
    ORDER BY count DESC, qc.category ASC
  `).all();

  const todayQuotes = db.prepare(`
    SELECT ${quoteSelectFields}
    ${quoteFromClause}
    WHERE ${PUBLISHED_WHERE}
      AND q.for_date = ?
    ORDER BY q.updated_at DESC
  `).all(t);

  let list;
  let total;

  if (category) {
    total = db.prepare(`
      SELECT COUNT(*) as c
      FROM quotes q
      WHERE ${PUBLISHED_WHERE}
        AND EXISTS (
          SELECT 1
          FROM quote_categories qc
          WHERE qc.quote_id = q.id
            AND qc.category = ?
        )
    `).get(category).c;

    list = db.prepare(`
      SELECT ${quoteSelectFields}
      ${quoteFromClause}
      WHERE ${PUBLISHED_WHERE}
        AND EXISTS (
          SELECT 1
          FROM quote_categories qc
          WHERE qc.quote_id = q.id
            AND qc.category = ?
        )
      ORDER BY q.created_at DESC
      LIMIT ? OFFSET ?
    `).all(category, pageSize, offset);
  } else {
    total = db.prepare(`
      SELECT COUNT(*) as c
      FROM quotes q
      WHERE ${PUBLISHED_WHERE}
    `).get().c;

    list = db.prepare(`
      SELECT ${quoteSelectFields}
      ${quoteFromClause}
      WHERE ${PUBLISHED_WHERE}
      ORDER BY q.created_at DESC
      LIMIT ? OFFSET ?
    `).all(pageSize, offset);
  }

  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const todaySeries = readSeriesTodayStmt.get(new Date().getDay());
  const seriesQuotes = todaySeries
    ? db.prepare(`
      SELECT ${quoteSelectFields}
      ${quoteFromClause}
      WHERE ${PUBLISHED_WHERE}
        AND q.series_id = ?
      ORDER BY q.created_at DESC
      LIMIT 6
    `).all(todaySeries.id)
    : [];

  res.render("home", layoutData(req, {
    today: t,
    todayQuotes,
    list,
    categories,
    selectedCategory: category,
    page,
    totalPages,
    analyticsUser: getAnalytics("user"),
    todaySeries: todaySeries ? { ...todaySeries, weekdayLabel: weekdayName(todaySeries.weekday) } : null,
    seriesQuotes,
    seo: buildSeo(req, {
      title: category ? `Kata ${category} - Kata Hari Ini` : "Kata Hari Ini",
      description: "Quote harian, gombalan, motivasi, galau, dan tema mingguan yang bisa kamu bookmark.",
      pathName: req.originalUrl || "/",
      jsonLd: {
        "@context": "https://schema.org",
        "@type": "WebSite",
        name: "Kata Hari Ini",
        url: absoluteUrl(req, "/")
      }
    })
  }));
});

app.get("/bookmarks", (req, res) => {
  const rows = db.prepare(`
    SELECT ${quoteSelectFields}
    ${quoteFromClause}
    JOIN quote_bookmarks b ON b.quote_id = q.id
    WHERE b.session_key = ?
      AND ${PUBLISHED_WHERE}
    ORDER BY b.created_at DESC
  `).all(req.session.visitorId);

  res.render("bookmarks", layoutData(req, {
    rows,
    seo: buildSeo(req, {
      title: "Bookmark Saya - Kata Hari Ini",
      description: "Daftar quote yang kamu bookmark di sesi ini.",
      robots: "noindex,follow"
    })
  }));
});

app.get("/q/:id", (req, res) => {
  const id = Number(req.params.id);
  const q = db.prepare(`
    SELECT ${quoteSelectFields}
    ${quoteFromClause}
    WHERE q.id=?
      AND ${PUBLISHED_WHERE}
  `).get(id);

  if (!q) return res.status(404).send("Quote tidak ditemukan.");
  return res.redirect(`/quote/${q.slug}`);
});

app.get("/quote/:slug", (req, res) => {
  const slug = String(req.params.slug || "").trim().toLowerCase();
  const q = findQuoteBySlug(slug, { includeUnpublished: false });
  if (!q) return res.status(404).send("Quote tidak ditemukan.");

  if (slug !== q.slug) {
    return res.redirect(`/quote/${q.slug}`);
  }

  insertQuoteViewStmt.run(q.id, viewerTypeFromRequest(req));

  const comments = db.prepare(`
    SELECT id, author, comment, created_at
    FROM quote_comments
    WHERE quote_id=? AND is_hidden=0
    ORDER BY created_at DESC
    LIMIT 50
  `).all(q.id);

  const liked = Boolean(readLikeStmt.get(q.id, req.session.visitorId));
  const bookmarked = Boolean(readBookmarkStmt.get(q.id, req.session.visitorId));

  const canonicalPath = `/quote/${q.slug}`;
  const shareImagePath = `/quote/${q.slug}/share.svg`;

  res.render("quote", layoutData(req, {
    q,
    comments,
    liked,
    bookmarked,
    seo: buildSeo(req, {
      title: `${q.text.slice(0, 55)} - Kata Hari Ini`,
      description: `${q.text.slice(0, 150)} ${q.author ? `- ${q.author}` : ""}`.trim(),
      pathName: canonicalPath,
      type: "article",
      image: absoluteUrl(req, shareImagePath),
      jsonLd: {
        "@context": "https://schema.org",
        "@type": "CreativeWork",
        name: q.text,
        text: q.text,
        author: q.author || "Anon",
        datePublished: q.created_at,
        genre: q.categories,
        url: absoluteUrl(req, canonicalPath)
      }
    })
  }));
});

app.get("/quote/:slug/share.svg", (req, res) => {
  const q = findQuoteBySlug(req.params.slug, { includeUnpublished: false });
  if (!q) return res.status(404).send("Quote tidak ditemukan.");

  const lines = wrapText(q.text, 36);
  const author = q.author ? `- ${q.author}` : "- Anon";

  const textLines = lines.map((line, idx) => {
    const y = 330 + (idx * 64);
    return `<text x="100" y="${y}" font-family="'Plus Jakarta Sans', sans-serif" font-size="48" fill="#ffffff">${escapeXml(line)}</text>`;
  }).join("\n");

  const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="1080" height="1080" viewBox="0 0 1080 1080">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#0ea5a2"/>
      <stop offset="100%" stop-color="#2563eb"/>
    </linearGradient>
  </defs>
  <rect width="1080" height="1080" fill="url(#bg)"/>
  <rect x="70" y="70" width="940" height="940" rx="42" fill="rgba(10,20,34,0.35)" stroke="rgba(255,255,255,0.18)"/>
  <text x="100" y="180" font-family="'Cormorant Garamond', serif" font-size="58" fill="#ffffff">Kata Hari Ini</text>
  <text x="100" y="248" font-family="'Plus Jakarta Sans', sans-serif" font-size="28" fill="rgba(255,255,255,0.85)">${escapeXml(q.categories || "quote")}</text>
  ${textLines}
  <text x="100" y="860" font-family="'Plus Jakarta Sans', sans-serif" font-size="34" fill="rgba(255,255,255,0.92)">${escapeXml(author)}</text>
  <text x="100" y="930" font-family="'Plus Jakarta Sans', sans-serif" font-size="24" fill="rgba(255,255,255,0.72)">/quote/${escapeXml(q.slug)}</text>
</svg>`;

  res.type("image/svg+xml");
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.send(svg);
});

app.post("/quote/:slug/like", (req, res) => {
  const q = findQuoteBySlug(req.params.slug, { includeUnpublished: false });
  if (!q) return res.status(404).send("Quote tidak ditemukan.");

  const existing = readLikeStmt.get(q.id, req.session.visitorId);
  if (existing) {
    deleteLikeStmt.run(q.id, req.session.visitorId);
  } else {
    insertLikeStmt.run(q.id, req.session.visitorId);
  }

  const next = String(req.body.next || `/quote/${q.slug}`).trim();
  res.redirect(next);
});

app.post("/quote/:slug/bookmark", (req, res) => {
  const q = findQuoteBySlug(req.params.slug, { includeUnpublished: false });
  if (!q) return res.status(404).send("Quote tidak ditemukan.");

  const existing = readBookmarkStmt.get(q.id, req.session.visitorId);
  if (existing) {
    deleteBookmarkStmt.run(q.id, req.session.visitorId);
  } else {
    insertBookmarkStmt.run(q.id, req.session.visitorId);
  }

  const next = String(req.body.next || `/quote/${q.slug}`).trim();
  res.redirect(next);
});

app.post("/quote/:slug/comment", commentLimiter, (req, res) => {
  const q = findQuoteBySlug(req.params.slug, { includeUnpublished: false });
  if (!q) return res.status(404).send("Quote tidak ditemukan.");

  const author = String(req.body.author || "").trim().slice(0, 60) || "Anon";
  const comment = String(req.body.comment || "").trim().slice(0, 280);

  if (comment.length >= 2) {
    insertCommentStmt.run(q.id, req.session.visitorId, author, comment);
  }

  res.redirect(`/quote/${q.slug}#comments`);
});

app.get("/random", (req, res) => {
  const q = db.prepare(`
    SELECT ${quoteSelectFields}
    ${quoteFromClause}
    WHERE ${PUBLISHED_WHERE}
    ORDER BY RANDOM()
    LIMIT 1
  `).get();

  if (!q) return res.redirect("/");
  res.redirect(`/quote/${q.slug}`);
});

app.get("/search", (req, res) => {
  const query = (req.query.q || "").trim();
  let results = [];

  if (query.length >= 2) {
    results = db.prepare(`
      SELECT ${quoteSelectFields}
      ${quoteFromClause}
      WHERE ${PUBLISHED_WHERE}
        AND (
          q.text LIKE ?
          OR q.author LIKE ?
          OR EXISTS (
            SELECT 1
            FROM quote_categories qc
            WHERE qc.quote_id = q.id
              AND qc.category LIKE ?
          )
        )
      ORDER BY q.created_at DESC
      LIMIT 50
    `).all(`%${query}%`, `%${query}%`, `%${query}%`);

    insertSearchLogStmt.run(query.toLowerCase(), results.length, viewerTypeFromRequest(req));
  }

  res.render("search", layoutData(req, {
    query,
    results,
    seo: buildSeo(req, {
      title: query ? `Hasil: ${query} - Kata Hari Ini` : "Cari Quote - Kata Hari Ini",
      description: query ? `Hasil pencarian quote untuk kata kunci: ${query}` : "Cari quote berdasarkan kata kunci.",
      pathName: req.originalUrl || "/search",
      robots: query ? "noindex,follow" : "index,follow"
    })
  }));
});

app.get("/og-default.svg", (req, res) => {
  const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#0ea5a2"/>
      <stop offset="100%" stop-color="#2563eb"/>
    </linearGradient>
  </defs>
  <rect width="1200" height="630" fill="url(#bg)"/>
  <text x="70" y="250" font-family="Arial, sans-serif" font-size="72" fill="#ffffff">Kata Hari Ini</text>
  <text x="70" y="330" font-family="Arial, sans-serif" font-size="36" fill="rgba(255,255,255,0.88)">Gombalan, motivasi, dan quote harian</text>
</svg>`;

  res.type("image/svg+xml");
  res.send(svg);
});

app.get("/sitemap.xml", (req, res) => {
  const base = getBaseUrl(req);
  const quotes = db.prepare(`
    SELECT q.slug, q.updated_at
    FROM quotes q
    WHERE ${PUBLISHED_WHERE}
    ORDER BY q.updated_at DESC
  `).all();

  const urls = [
    { loc: `${base}/`, lastmod: null },
    { loc: `${base}/search`, lastmod: null },
    ...quotes.map((q) => ({
      loc: `${base}/quote/${q.slug}`,
      lastmod: q.updated_at ? q.updated_at.replace(" ", "T") + "Z" : null
    }))
  ];

  const body = urls.map((item) => {
    const lastmod = item.lastmod ? `<lastmod>${escapeXml(item.lastmod)}</lastmod>` : "";
    return `<url><loc>${escapeXml(item.loc)}</loc>${lastmod}</url>`;
  }).join("");

  const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${body}</urlset>`;
  res.type("application/xml");
  res.send(xml);
});

app.get("/robots.txt", (req, res) => {
  const sitemapUrl = absoluteUrl(req, "/sitemap.xml");
  res.type("text/plain");
  res.send(`User-agent: *\nAllow: /\nSitemap: ${sitemapUrl}\n`);
});

app.get("/healthz", (req, res) => res.json({ ok: true }));
// ===== ADMIN =====

app.get("/admin/login", (req, res) => {
  res.render("admin/login", layoutData(req, {
    title: "Login Admin",
    error: null,
    seo: buildSeo(req, {
      title: "Login Admin - Kata Hari Ini",
      robots: "noindex,nofollow"
    })
  }));
});

app.post("/admin/login", loginLimiter, (req, res) => {
  const username = (req.body.username || "").trim();
  const password = req.body.password || "";

  const admin = db.prepare(`SELECT * FROM admins WHERE username=?`).get(username);
  if (!admin || typeof admin.password_hash !== "string" || admin.password_hash.length < 10) {
    return res.status(401).render("admin/login", layoutData(req, {
      title: "Login Admin",
      error: "Login gagal.",
      seo: buildSeo(req, {
        title: "Login Admin - Kata Hari Ini",
        robots: "noindex,nofollow"
      })
    }));
  }

  const ok = bcrypt.compareSync(password, admin.password_hash);
  if (!ok) {
    return res.status(401).render("admin/login", layoutData(req, {
      title: "Login Admin",
      error: "Login gagal.",
      seo: buildSeo(req, {
        title: "Login Admin - Kata Hari Ini",
        robots: "noindex,nofollow"
      })
    }));
  }

  req.session.adminId = admin.id;
  return res.redirect("/admin");
});

app.post("/admin/logout", (req, res) => {
  req.session = null;
  res.redirect("/");
});

app.get("/admin", requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT ${quoteSelectFields}
    ${quoteFromClause}
    ORDER BY q.created_at DESC
    LIMIT 200
  `).all();

  const comments = db.prepare(`
    SELECT c.id, c.author, c.comment, c.is_hidden, c.created_at, q.id as quote_id, q.slug, q.text
    FROM quote_comments c
    JOIN quotes q ON q.id = c.quote_id
    ORDER BY c.created_at DESC
    LIMIT 50
  `).all();

  const backupFiles = fs.existsSync(BACKUP_DIR)
    ? fs.readdirSync(BACKUP_DIR).filter((name) => name.endsWith(".db")).sort().reverse().slice(0, 5)
    : [];

  res.render("admin/dashboard", layoutData(req, {
    rows,
    comments,
    seriesRows: readSeriesOptionsStmt.all().map((row) => ({ ...row, weekdayLabel: weekdayName(row.weekday) })),
    analyticsUser: getAnalytics("user"),
    analyticsAdmin: getAnalytics("admin"),
    backupState,
    backupFiles,
    backupStatus: String(req.query.backup || ""),
    seo: buildSeo(req, {
      title: "Dashboard Admin - Kata Hari Ini",
      robots: "noindex,nofollow"
    })
  }));
});

app.post("/admin/backup", requireAdmin, async (req, res) => {
  try {
    await createDbBackup("manual");
    res.redirect("/admin?backup=ok");
  } catch (_) {
    res.redirect("/admin?backup=fail");
  }
});

app.post("/admin/comments/:id/toggle", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (Number.isFinite(id) && id > 0) toggleCommentVisibilityStmt.run(id);
  res.redirect("/admin");
});

app.post("/admin/series/:id/toggle", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (Number.isFinite(id) && id > 0) toggleSeriesStmt.run(id);
  res.redirect("/admin");
});

app.get("/admin/new", requireAdmin, (req, res) => {
  const todaySeries = readSeriesTodayStmt.get(new Date().getDay());

  res.render("admin/form", layoutData(req, {
    mode: "new",
    q: {
      text: "",
      author: "",
      for_date: "",
      is_published: 0,
      publish_at_input: "",
      series_id: todaySeries ? todaySeries.id : ""
    },
    categoryOptions: CATEGORY_OPTIONS,
    selectedCategories: ["gombalan"],
    categoriesCustom: "",
    seriesOptions: readSeriesActiveOptionsStmt.all().map((row) => ({ ...row, weekdayLabel: weekdayName(row.weekday) })),
    error: null,
    seo: buildSeo(req, {
      title: "Tambah Quote - Admin",
      robots: "noindex,nofollow"
    })
  }));
});

app.post("/admin/new", requireAdmin, (req, res) => {
  const text = (req.body.text || "").trim();
  const author = (req.body.author || "").trim() || null;
  const for_date = (req.body.for_date || "").trim() || null;
  const publishAt = normalizePublishAtInput(req.body.publish_at);
  const is_published = computePublishState(Boolean(req.body.is_published), publishAt);
  const categories = parseCategories(req.body.categories, req.body.categories_custom);
  const primaryCategory = categories[0];
  const seriesId = parseSeriesId(req.body.series_id);

  if (text.length < 3) {
    return res.status(400).render("admin/form", layoutData(req, {
      mode: "new",
      q: {
        text,
        author,
        for_date,
        is_published,
        publish_at: publishAt,
        publish_at_input: formatPublishAtForInput(publishAt),
        category: primaryCategory,
        series_id: seriesId || ""
      },
      categoryOptions: CATEGORY_OPTIONS,
      selectedCategories: categories,
      categoriesCustom: (req.body.categories_custom || "").trim(),
      seriesOptions: readSeriesActiveOptionsStmt.all().map((row) => ({ ...row, weekdayLabel: weekdayName(row.weekday) })),
      error: "Teks terlalu pendek.",
      seo: buildSeo(req, {
        title: "Tambah Quote - Admin",
        robots: "noindex,nofollow"
      })
    }));
  }

  const info = insertQuoteStmt.run(text, primaryCategory, author, for_date, is_published, publishAt, null, seriesId);
  const quoteId = Number(info.lastInsertRowid);
  const slug = buildQuoteSlug(quoteId, text);

  updateQuoteSlugStmt.run(slug, quoteId);
  replaceQuoteCategories(quoteId, categories);

  res.redirect("/admin");
});
app.get("/admin/edit/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const q = db.prepare(`SELECT * FROM quotes WHERE id=?`).get(id);
  if (!q) return res.status(404).send("Data tidak ditemukan.");

  const selectedCategories = getQuoteCategories(id, q.category);

  res.render("admin/form", layoutData(req, {
    mode: "edit",
    q: {
      ...q,
      publish_at_input: formatPublishAtForInput(q.publish_at),
      series_id: q.series_id || ""
    },
    categoryOptions: CATEGORY_OPTIONS,
    selectedCategories,
    categoriesCustom: "",
    seriesOptions: readSeriesActiveOptionsStmt.all().map((row) => ({ ...row, weekdayLabel: weekdayName(row.weekday) })),
    error: null,
    seo: buildSeo(req, {
      title: `Edit Quote #${id} - Admin`,
      robots: "noindex,nofollow"
    })
  }));
});

app.post("/admin/edit/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const existing = db.prepare(`SELECT * FROM quotes WHERE id=?`).get(id);
  if (!existing) return res.status(404).send("Data tidak ditemukan.");

  const text = (req.body.text || "").trim();
  const author = (req.body.author || "").trim() || null;
  const for_date = (req.body.for_date || "").trim() || null;
  const publishAt = normalizePublishAtInput(req.body.publish_at);
  const is_published = computePublishState(Boolean(req.body.is_published), publishAt);
  const categories = parseCategories(req.body.categories, req.body.categories_custom);
  const primaryCategory = categories[0];
  const seriesId = parseSeriesId(req.body.series_id);
  const slug = buildQuoteSlug(id, text);

  if (text.length < 3) {
    return res.status(400).render("admin/form", layoutData(req, {
      mode: "edit",
      q: {
        ...existing,
        text,
        author,
        for_date,
        is_published,
        publish_at: publishAt,
        publish_at_input: formatPublishAtForInput(publishAt),
        category: primaryCategory,
        slug,
        series_id: seriesId || ""
      },
      categoryOptions: CATEGORY_OPTIONS,
      selectedCategories: categories,
      categoriesCustom: (req.body.categories_custom || "").trim(),
      seriesOptions: readSeriesActiveOptionsStmt.all().map((row) => ({ ...row, weekdayLabel: weekdayName(row.weekday) })),
      error: "Teks terlalu pendek.",
      seo: buildSeo(req, {
        title: `Edit Quote #${id} - Admin`,
        robots: "noindex,nofollow"
      })
    }));
  }

  updateQuoteStmt.run(text, primaryCategory, author, for_date, is_published, publishAt, slug, seriesId, id);
  replaceQuoteCategories(id, categories);

  res.redirect("/admin");
});

app.get("/admin/preview/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const q = db.prepare(`
    SELECT ${quoteSelectFields}
    ${quoteFromClause}
    WHERE q.id = ?
  `).get(id);

  if (!q) return res.status(404).send("Data tidak ditemukan.");

  insertQuoteViewStmt.run(q.id, "admin");

  res.render("admin/preview", layoutData(req, {
    title: `Preview: ${q.slug || q.id}`,
    q,
    seo: buildSeo(req, {
      title: `Preview Quote #${id} - Admin`,
      robots: "noindex,nofollow"
    })
  }));
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
        publish_at = CASE WHEN is_published=0 THEN NULL ELSE publish_at END,
        updated_at = datetime('now')
    WHERE id=?
  `).run(id);
  res.redirect("/admin");
});

app.listen(PORT, HOST, () => {
  console.log(`[kata-hari-ini] http://${HOST}:${PORT} env=${NODE_ENV}`);
});
