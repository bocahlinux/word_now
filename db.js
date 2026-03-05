const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
}

function normalizeCategory(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, " ");
}

function splitCategories(rawCategory) {
  const parts = String(rawCategory || "")
    .split(",")
    .map((part) => normalizeCategory(part))
    .filter(Boolean);

  if (parts.length === 0) return ["lainnya"];
  return [...new Set(parts)];
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

function hasColumn(db, tableName, columnName) {
  const rows = db.prepare(`PRAGMA table_info(${tableName})`).all();
  return rows.some((row) => row.name === columnName);
}

function ensureQuoteColumns(db) {
  if (!hasColumn(db, "quotes", "publish_at")) {
    db.exec("ALTER TABLE quotes ADD COLUMN publish_at TEXT");
  }

  if (!hasColumn(db, "quotes", "slug")) {
    db.exec("ALTER TABLE quotes ADD COLUMN slug TEXT");
  }

  if (!hasColumn(db, "quotes", "series_id")) {
    db.exec("ALTER TABLE quotes ADD COLUMN series_id INTEGER");
  }
}

function ensureDefaultSeries(db) {
  const count = db.prepare("SELECT COUNT(*) as c FROM quote_series").get().c;
  if (count > 0) return;

  const rows = [
    { name: "Minggu Santai", weekday: 0, category_hint: "lucu" },
    { name: "Senin Motivasi", weekday: 1, category_hint: "motivasi" },
    { name: "Selasa Romantis", weekday: 2, category_hint: "romantis" },
    { name: "Rabu Bijak", weekday: 3, category_hint: "bijak" },
    { name: "Kamis Gombalan", weekday: 4, category_hint: "gombalan" },
    { name: "Jumat Menyentuh", weekday: 5, category_hint: "galau" },
    { name: "Sabtu Ceria", weekday: 6, category_hint: "lucu" }
  ];

  const insert = db.prepare(`
    INSERT INTO quote_series(name, weekday, category_hint, is_active)
    VALUES(?,?,?,1)
  `);

  const tx = db.transaction((items) => {
    for (const item of items) {
      insert.run(item.name, item.weekday, item.category_hint);
    }
  });

  tx(rows);
}

function syncQuoteCategories(db) {
  const rows = db.prepare("SELECT id, category FROM quotes").all();
  const insertCategory = db.prepare(`
    INSERT OR IGNORE INTO quote_categories(quote_id, category)
    VALUES(?, ?)
  `);
  const updatePrimaryCategory = db.prepare(`
    UPDATE quotes
    SET category = ?
    WHERE id = ?
  `);

  const tx = db.transaction((items) => {
    for (const item of items) {
      const categories = splitCategories(item.category);
      for (const category of categories) {
        insertCategory.run(item.id, category);
      }
      updatePrimaryCategory.run(categories[0], item.id);
    }
  });

  tx(rows);
}

function syncQuoteSlugs(db) {
  const rows = db.prepare("SELECT id, text, slug FROM quotes").all();
  const updateSlug = db.prepare("UPDATE quotes SET slug = ? WHERE id = ?");

  const tx = db.transaction((items) => {
    for (const item of items) {
      const expected = buildQuoteSlug(item.id, item.text);
      if (item.slug !== expected) {
        updateSlug.run(expected, item.id);
      }
    }
  });

  tx(rows);
}

function openDb(dbPath) {
  const full = path.resolve(dbPath);
  ensureDir(path.dirname(full));
  const db = new Database(full);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");

  db.exec(`
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS quote_series (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      weekday INTEGER NOT NULL,
      category_hint TEXT,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS quotes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      text TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT 'lainnya',
      author TEXT,
      for_date TEXT,
      is_published INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS quote_categories (
      quote_id INTEGER NOT NULL,
      category TEXT NOT NULL,
      PRIMARY KEY (quote_id, category),
      FOREIGN KEY (quote_id) REFERENCES quotes(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS quote_views (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      quote_id INTEGER NOT NULL,
      viewer_type TEXT NOT NULL DEFAULT 'user',
      viewed_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
      FOREIGN KEY (quote_id) REFERENCES quotes(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS quote_likes (
      quote_id INTEGER NOT NULL,
      session_key TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
      PRIMARY KEY (quote_id, session_key),
      FOREIGN KEY (quote_id) REFERENCES quotes(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS quote_bookmarks (
      quote_id INTEGER NOT NULL,
      session_key TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
      PRIMARY KEY (quote_id, session_key),
      FOREIGN KEY (quote_id) REFERENCES quotes(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS quote_comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      quote_id INTEGER NOT NULL,
      session_key TEXT NOT NULL,
      author TEXT,
      comment TEXT NOT NULL,
      is_hidden INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
      FOREIGN KEY (quote_id) REFERENCES quotes(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS search_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      query TEXT NOT NULL,
      hits INTEGER NOT NULL DEFAULT 0,
      viewer_type TEXT NOT NULL DEFAULT 'user',
      searched_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
    );

    CREATE INDEX IF NOT EXISTS idx_quotes_published_date
      ON quotes(is_published, for_date);

    CREATE INDEX IF NOT EXISTS idx_quotes_category
      ON quotes(category);

    CREATE INDEX IF NOT EXISTS idx_quotes_created
      ON quotes(created_at);

    CREATE INDEX IF NOT EXISTS idx_quote_categories_category
      ON quote_categories(category);

    CREATE INDEX IF NOT EXISTS idx_quote_views_quote
      ON quote_views(quote_id);

    CREATE INDEX IF NOT EXISTS idx_quote_likes_quote
      ON quote_likes(quote_id);

    CREATE INDEX IF NOT EXISTS idx_quote_bookmarks_session
      ON quote_bookmarks(session_key);

    CREATE INDEX IF NOT EXISTS idx_quote_comments_quote
      ON quote_comments(quote_id);

    CREATE INDEX IF NOT EXISTS idx_search_logs_query
      ON search_logs(query);

    CREATE INDEX IF NOT EXISTS idx_quote_series_weekday
      ON quote_series(weekday, is_active);
  `);

  ensureQuoteColumns(db);
  db.exec(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_quotes_slug_unique
      ON quotes(slug);

    CREATE INDEX IF NOT EXISTS idx_quotes_slug
      ON quotes(slug);

    CREATE INDEX IF NOT EXISTS idx_quotes_publish_at
      ON quotes(publish_at);

    CREATE INDEX IF NOT EXISTS idx_quotes_series_id
      ON quotes(series_id);
  `);

  ensureDefaultSeries(db);
  syncQuoteCategories(db);
  syncQuoteSlugs(db);

  return db;
}

module.exports = { openDb };
