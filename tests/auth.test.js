// HTTP tests for every route, including token attacks and hardening checks.
// Each test gets a fresh app and in-memory database. Run: npm test
import assert from "node:assert/strict";
import { beforeEach, describe, it } from "node:test";
import jwt from "jsonwebtoken";
import request from "supertest";
import { alice, makeApp, TEST_SECRET } from "./helpers.js";

let app;
let db;
beforeEach(() => {
  ({ app, db } = makeApp());
});

const register = (body = alice) => request(app).post("/auth/register").send(body);
const login = (body = { email: alice.email, password: alice.password }) => request(app).post("/auth/login").send(body);

describe("POST /auth/register", () => {
  it("creates a user and never returns the password hash", async () => {
    const res = await register();
    assert.equal(res.status, 201);
    assert.equal(res.body.user.email, alice.email);
    assert.equal(res.body.user.password_hash, undefined);
    assert.match(db.prepare("SELECT password_hash FROM users").get().password_hash, /^scrypt\$/);
  });

  it("normalises the email and rejects duplicates regardless of case", async () => {
    await register({ ...alice, email: "  Alice@Example.COM " });
    const res = await register();
    assert.equal(res.status, 409);
  });

  it("validates input with field details", async () => {
    const res = await register({ email: "not-an-email", name: "", password: "short" });
    assert.equal(res.status, 400);
    assert.deepEqual(Object.keys(res.body.details).sort(), ["email", "name", "password"]);
  });
});

describe("POST /auth/login", () => {
  beforeEach(async () => {
    await register();
  });

  it("returns an access token and a refresh token", async () => {
    const res = await login();
    assert.equal(res.status, 200);
    assert.equal(res.body.tokenType, "Bearer");
    const claims = jwt.verify(res.body.accessToken, TEST_SECRET);
    assert.equal(claims.sub, String(res.body.user.id));
    assert.ok(res.body.refreshToken.length >= 40);
  });

  it("gives the same error for a wrong password and an unknown email", async () => {
    const wrongPassword = await login({ email: alice.email, password: "wrong password!!" });
    const unknownUser = await login({ email: "nobody@example.com", password: "whatever password" });
    assert.equal(wrongPassword.status, 401);
    assert.equal(unknownUser.status, 401);
    assert.deepEqual(wrongPassword.body, unknownUser.body);
  });

  it("stores only a hash of the refresh token", async () => {
    const { body } = await login();
    const stored = db.prepare("SELECT token_hash FROM refresh_tokens").all();
    assert.equal(stored.length, 1);
    assert.notEqual(stored[0].token_hash, body.refreshToken);
  });
});

describe("GET /me", () => {
  it("returns the current user with a valid access token", async () => {
    await register();
    const { body } = await login();
    const res = await request(app).get("/me").set("Authorization", `Bearer ${body.accessToken}`);
    assert.equal(res.status, 200);
    assert.equal(res.body.user.email, alice.email);
  });

  it("rejects missing, forged, expired and 'none'-algorithm tokens", async () => {
    const forged = jwt.sign({ sub: "1" }, "a-different-secret-that-is-long-enough!!", { issuer: "node-auth-api", audience: "node-auth-api:clients" });
    const expired = jwt.sign({ sub: "1", exp: Math.floor(Date.now() / 1000) - 60 }, TEST_SECRET, { issuer: "node-auth-api", audience: "node-auth-api:clients" });
    const unsigned = jwt.sign({ sub: "1" }, null, { algorithm: "none" });

    assert.equal((await request(app).get("/me")).status, 401);
    for (const token of [forged, expired, unsigned, "garbage"]) {
      const res = await request(app).get("/me").set("Authorization", `Bearer ${token}`);
      assert.equal(res.status, 401, `token should be rejected: ${token.slice(0, 20)}…`);
    }
    const res = await request(app).get("/me").set("Authorization", `Bearer ${expired}`);
    assert.equal(res.body.error, "Access token expired.");
  });
});

describe("refresh token rotation", () => {
  let first;
  beforeEach(async () => {
    await register();
    first = (await login()).body;
  });

  it("exchanges a refresh token for a new pair", async () => {
    const res = await request(app).post("/auth/refresh").send({ refreshToken: first.refreshToken });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.refreshToken, first.refreshToken);
    assert.ok(res.body.accessToken);
  });

  it("detects reuse of an old token and revokes the whole session", async () => {
    const second = (await request(app).post("/auth/refresh").send({ refreshToken: first.refreshToken })).body;

    // An attacker replays the first (already used) token...
    const replay = await request(app).post("/auth/refresh").send({ refreshToken: first.refreshToken });
    assert.equal(replay.status, 401);

    // ...so the legitimate newer token is revoked too.
    const legit = await request(app).post("/auth/refresh").send({ refreshToken: second.refreshToken });
    assert.equal(legit.status, 401);
  });

  it("logout revokes the session and is idempotent", async () => {
    assert.equal((await request(app).post("/auth/logout").send({ refreshToken: first.refreshToken })).status, 204);
    assert.equal((await request(app).post("/auth/refresh").send({ refreshToken: first.refreshToken })).status, 401);
    assert.equal((await request(app).post("/auth/logout").send({ refreshToken: "unknown" })).status, 204);
  });

  it("rejects expired refresh tokens", async () => {
    db.prepare("UPDATE refresh_tokens SET expires_at = 0").run();
    const res = await request(app).post("/auth/refresh").send({ refreshToken: first.refreshToken });
    assert.equal(res.status, 401);
  });
});

describe("hardening", () => {
  it("rate-limits auth endpoints", async () => {
    ({ app } = makeApp({ RATE_LIMIT_PER_WINDOW: "3" }));
    const statuses = [];
    for (let i = 0; i < 4; i++) statuses.push((await login({ email: "x@example.com", password: "nope" })).status);
    assert.deepEqual(statuses, [401, 401, 401, 429]);
  });

  it("sends security headers and hides the framework", async () => {
    const res = await request(app).get("/health");
    assert.equal(res.headers["x-powered-by"], undefined);
    assert.equal(res.headers["x-content-type-options"], "nosniff");
    assert.ok(res.headers["content-security-policy"]);
  });

  it("returns JSON errors for bad JSON, large bodies and unknown routes", async () => {
    const badJson = await request(app).post("/auth/login").set("Content-Type", "application/json").send("{bad");
    assert.equal(badJson.status, 400);
    const huge = await request(app).post("/auth/login").send({ email: "a@b.co", password: "x".repeat(20_000) });
    assert.equal(huge.status, 413);
    const missing = await request(app).get("/nope");
    assert.equal(missing.status, 404);
    assert.match(missing.body.error, /No route/);
  });
});
