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

export function hashToken(token) {
  return createHash("sha256").update(token).digest("hex");
}

export function newTokenFamily() {
  return randomUUID();
}
