const Database = require("better-sqlite3");
const db = new Database("auth-server.db");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS clients (
  client_id TEXT PRIMARY KEY,
  client_secret TEXT NOT NULL,
  redirect_uri TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS codes (
  code TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  username TEXT NOT NULL
);

`);

module.exports = db;
