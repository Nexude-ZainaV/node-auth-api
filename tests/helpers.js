// Test helpers: a fresh app per test and a sample user.
import { createApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { openDatabase } from "../src/db.js";

export const TEST_SECRET = "test-secret-that-is-long-enough-1234567890";

/** A fresh app with its own in-memory database, so tests never share state. */
export function makeApp(overrides = {}) {
  // A high rate limit so the suite never trips it; the hardening test passes a low one.
  const config = loadConfig({ JWT_SECRET: TEST_SECRET, RATE_LIMIT_PER_WINDOW: "1000", ...overrides });
  const db = openDatabase(":memory:");
  return { app: createApp({ db, config }), db, config };
}

export const alice = { email: "alice@example.com", name: "Alice", password: "correct horse battery" };
