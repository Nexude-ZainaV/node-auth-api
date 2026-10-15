// Token helpers: signed JWT access tokens and opaque refresh tokens.
import { createHash, randomBytes, randomUUID } from "node:crypto";
import jwt from "jsonwebtoken";

const ISSUER = "node-auth-api";
const AUDIENCE = "node-auth-api:clients";
const ALGORITHM = "HS256";

/** Short-lived, stateless access token (JWT). */
export function signAccessToken(user, { secret, ttlSeconds }) {
  return jwt.sign({ email: user.email }, secret, {
    algorithm: ALGORITHM,
    subject: String(user.id),
    expiresIn: ttlSeconds,
    issuer: ISSUER,
    audience: AUDIENCE,
  });
}

/**
 * Verifies signature, expiry, issuer and audience. The algorithm list is pinned so a
 * token signed with "none" or a different algorithm is rejected.
 * @returns {{ sub: string, email: string }} the claims, or throws
 */
export function verifyAccessToken(token, { secret }) {
  return jwt.verify(token, secret, { algorithms: [ALGORITHM], issuer: ISSUER, audience: AUDIENCE });
}

/** Long-lived, opaque refresh token: random bytes, only its hash is stored. */
export function createRefreshToken() {
  return randomBytes(32).toString("base64url");
}

/**
 * Plain SHA-256 is enough here (no salt, no scrypt): the token is 256 random bits,
 * so there is nothing to guess, unlike a password. It also keeps lookups by hash simple.
 */
export function hashToken(token) {
  return createHash("sha256").update(token).digest("hex");
}

/** One family id per login. Every rotated refresh token keeps it. */
export function newTokenFamily() {
  return randomUUID();
}
