import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    name          TEXT    NOT NULL,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL
  );

  -- Refresh tokens are stored as SHA-256 hashes: a leaked database cannot be replayed.
  -- family_id links every token issued from one login, so reuse of an old token can
  -- revoke the whole chain (refresh token rotation with reuse detection).
  CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash  TEXT    PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    family_id   TEXT    NOT NULL,
    expires_at  INTEGER NOT NULL,           -- unix seconds
    used_at     INTEGER,                    -- set when rotated
    revoked_at  INTEGER
  );
  CREATE INDEX IF NOT EXISTS ix_refresh_tokens_family ON refresh_tokens (family_id);
  CREATE INDEX IF NOT EXISTS ix_refresh_tokens_user ON refresh_tokens (user_id);
`;

/** Opens (and if needed creates) the database. Use ":memory:" in tests. */
export function openDatabase(path) {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;");
  db.exec(SCHEMA);
  return db;
}
