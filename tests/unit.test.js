import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { hashPassword, verifyPassword } from "../src/auth/password.js";
import { loadConfig } from "../src/config.js";

describe("password hashing", () => {
  it("verifies the right password and rejects others", async () => {
    const hash = await hashPassword("correct horse battery");
    assert.equal(await verifyPassword("correct horse battery", hash), true);
    assert.equal(await verifyPassword("Correct horse battery", hash), false);
  });

  it("salts every hash", async () => {
    assert.notEqual(await hashPassword("same password"), await hashPassword("same password"));
  });

  it("rejects malformed stored hashes", async () => {
    assert.equal(await verifyPassword("x", "md5$abc"), false);
  });
});

describe("loadConfig", () => {
  it("applies defaults and parses CORS origins", () => {
    const config = loadConfig({ JWT_SECRET: "x".repeat(32), CORS_ORIGINS: "https://a.com, https://b.com" });
    assert.equal(config.PORT, 3000);
    assert.equal(config.ACCESS_TOKEN_TTL_S, 900);
    assert.deepEqual(config.CORS_ORIGINS, ["https://a.com", "https://b.com"]);
  });

  it("refuses to start with a missing or short JWT secret", () => {
    assert.throws(() => loadConfig({}), /JWT_SECRET/);
    assert.throws(() => loadConfig({ JWT_SECRET: "short" }), /at least 32/);
  });
});
