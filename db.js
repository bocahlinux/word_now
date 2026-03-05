const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
}

function openDb(dbPath) {
  const full = path.resolve(dbPath);
  ensureDir(path.dirname(full));
  const db = new Database(full);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");

  // schema
  db.exec(`
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS quotes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      text TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT 'lainnya',
      author TEXT,
      for_date TEXT, -- YYYY-MM-DD (opsional buat "hari ini")
      is_published INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_quotes_published_date
      ON quotes(is_published, for_date);

    CREATE INDEX IF NOT EXISTS idx_quotes_category
      ON quotes(category);

    CREATE INDEX IF NOT EXISTS idx_quotes_created
      ON quotes(created_at);
  `);

  return db;
}

module.exports = { openDb };