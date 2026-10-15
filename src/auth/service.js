// Auth business rules on top of the users and refresh_tokens tables (schema in db.js).
import { DUMMY_HASH, hashPassword, verifyPassword } from "./password.js";
import { createRefreshToken, hashToken, newTokenFamily, signAccessToken } from "./tokens.js";
import { HttpError } from "../http-error.js";

const nowSeconds = () => Math.floor(Date.now() / 1000);

/**
 * Registration, login, token refresh and logout. All SQL for users and tokens lives
 * here and uses bound parameters.
 */
export class AuthService {
  /** @param {import("node:sqlite").DatabaseSync} db */
  constructor(db, { jwtSecret, accessTokenTtlS, refreshTokenTtlS }) {
    this.db = db;
    this.jwt = { secret: jwtSecret, ttlSeconds: accessTokenTtlS };
    this.refreshTtlS = refreshTokenTtlS;
  }

  async register({ email, name, password }) {
    const passwordHash = await hashPassword(password);
    try {
      const result = this.db
        .prepare("INSERT INTO users (email, name, password_hash, created_at) VALUES (?, ?, ?, ?)")
        .run(email, name, passwordHash, new Date().toISOString());
      return this.findUser(Number(result.lastInsertRowid));
    } catch (error) {
      // The UNIQUE index on email is the duplicate check. A SELECT first would race with a parallel signup.
      if (String(error.message).includes("UNIQUE")) throw new HttpError(409, "An account with this email already exists.");
      throw error;
    }
  }

  async login({ email, password }) {
    const row = this.db.prepare("SELECT id, password_hash FROM users WHERE email = ?").get(email);
    // Always run one scrypt verification, whether or not the user exists (timing-safe).
    const isValid = await verifyPassword(password, row?.password_hash ?? DUMMY_HASH);
    if (!row || !isValid) throw new HttpError(401, "Invalid email or password."); // same message for both cases
    return this.issueTokens(this.findUser(row.id), newTokenFamily());
  }

  /**
   * Rotation: every refresh token works once and is replaced by a new one. If a token
   * that was already used shows up again, it was probably stolen, so the whole family
   * (every token from that login) is revoked and the user must sign in again.
   */
  refresh(refreshToken) {
    const row = this.db.prepare("SELECT * FROM refresh_tokens WHERE token_hash = ?").get(hashToken(refreshToken));
    const now = nowSeconds();
    if (!row || row.revoked_at !== null || row.expires_at <= now) {
      throw new HttpError(401, "Refresh token is invalid or expired.");
    }
    if (row.used_at !== null) {
      this.revokeFamily(row.family_id);
      throw new HttpError(401, "Refresh token was already used. Please sign in again.");
    }
    // Mark this token as spent before handing out its replacement.
    this.db.prepare("UPDATE refresh_tokens SET used_at = ? WHERE token_hash = ?").run(now, row.token_hash);
    return this.issueTokens(this.findUser(row.user_id), row.family_id);
  }

  /** Revokes the session the refresh token belongs to. Unknown tokens are ignored (idempotent). */
  logout(refreshToken) {
    const row = this.db.prepare("SELECT family_id FROM refresh_tokens WHERE token_hash = ?").get(hashToken(refreshToken));
    if (row) this.revokeFamily(row.family_id);
  }

  findUser(id) {
    const row = this.db.prepare("SELECT id, email, name, created_at FROM users WHERE id = ?").get(id);
    return row ? { id: row.id, email: row.email, name: row.name, createdAt: row.created_at } : undefined;
  }

  /** Saves a new refresh token in the login's family and signs a matching access token. */
  issueTokens(user, familyId) {
    const refreshToken = createRefreshToken();
    this.db
      .prepare("INSERT INTO refresh_tokens (token_hash, user_id, family_id, expires_at) VALUES (?, ?, ?, ?)")
      .run(hashToken(refreshToken), user.id, familyId, nowSeconds() + this.refreshTtlS);
    return {
      user,
      accessToken: signAccessToken(user, this.jwt),
      refreshToken,
      tokenType: "Bearer",
      expiresIn: this.jwt.ttlSeconds,
    };
  }

  /** Ends a login session: every token in the family stops working. */
  revokeFamily(familyId) {
    this.db
      .prepare("UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL")
      .run(nowSeconds(), familyId);
  }
}
