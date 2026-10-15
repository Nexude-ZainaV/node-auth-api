// Password hashing with scrypt from node:crypto.
// Stored format: scrypt$N$r$p$salt$hash, so old hashes still verify after a parameter change.
import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scryptAsync = promisify(scrypt);

// scrypt is memory-hard, which makes GPU brute force expensive. N=2^15, r=8 is the
// OWASP-recommended baseline; parameters are stored with each hash so they can be
// raised later without invalidating existing passwords.
const PARAMS = { N: 2 ** 15, r: 8, p: 1 };
const KEY_LENGTH = 64;
const SALT_BYTES = 16;
// N=2^15, r=8 needs 128 * N * r = 32 MiB, which is right at Node's default maxmem, so raise the cap.
const MAX_MEMORY = 64 * 1024 * 1024;

/** @returns {Promise<string>} "scrypt$N$r$p$saltBase64$hashBase64" */
export async function hashPassword(password) {
  const salt = randomBytes(SALT_BYTES);
  const hash = await scryptAsync(password, salt, KEY_LENGTH, { ...PARAMS, maxmem: MAX_MEMORY });
  return ["scrypt", PARAMS.N, PARAMS.r, PARAMS.p, salt.toString("base64"), hash.toString("base64")].join("$");
}

/** Constant-time comparison, so response timing reveals nothing about the hash. */
export async function verifyPassword(password, stored) {
  const [scheme, N, r, p, saltB64, hashB64] = stored.split("$");
  if (scheme !== "scrypt" || !hashB64) return false; // unknown or truncated format: just fail
  const expected = Buffer.from(hashB64, "base64");
  const actual = await scryptAsync(password, Buffer.from(saltB64, "base64"), expected.length, {
    N: Number(N),
    r: Number(r),
    p: Number(p),
    maxmem: MAX_MEMORY,
  });
  return timingSafeEqual(actual, expected);
}

// Verifying against this when the email is unknown makes "no such user" take as long
// as "wrong password", so login timing cannot be used to discover registered emails.
export const DUMMY_HASH = await hashPassword(randomBytes(16).toString("hex"));
