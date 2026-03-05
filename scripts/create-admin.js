require("dotenv").config();
const bcrypt = require("bcryptjs");
const { openDb } = require("../db");

const DB_PATH = process.env.DB_PATH || "./data/app.db";
const db = openDb(DB_PATH);

const [, , usernameArg, passwordArg] = process.argv;
const username = (usernameArg || "").trim();
const password = passwordArg || "";

if (!username || !password || password.length < 8) {
  console.log("Usage: node scripts/create-admin.js <username> <password_min_8>");
  process.exit(1);
}

const exists = db.prepare("SELECT id FROM admins WHERE username=?").get(username);
if (exists) {
  console.log("Admin sudah ada.");
  process.exit(0);
}

const hash = bcrypt.hashSync(password, 12);
db.prepare("INSERT INTO admins(username, password_hash) VALUES(?,?)").run(username, hash);
console.log("OK: admin dibuat.");