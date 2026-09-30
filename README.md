# Auth API (Node.js + Express 5)

[![CI](https://github.com/Nexude-ZainaV/node-auth-api/actions/workflows/ci.yml/badge.svg)](https://github.com/Nexude-ZainaV/node-auth-api/actions/workflows/ci.yml)
![Node.js 22+](https://img.shields.io/badge/Node.js-22%2B-5FA04E?logo=nodedotjs&logoColor=white)
![Express 5](https://img.shields.io/badge/Express-5-000000?logo=express)
![JWT](https://img.shields.io/badge/auth-JWT%20%2B%20refresh%20rotation-orange)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

A production-style authentication service: registration, login, short-lived JWT
access tokens, rotating refresh tokens with reuse detection, logout, and a protected
`/me` route. Passwords are hashed with scrypt from `node:crypto`, and data is stored
in SQLite through the built-in `node:sqlite` module.

## Endpoints

| Method | Route | Body | Success |
|---|---|---|---|
| `POST` | `/auth/register` | `{ email, name, password }` | `201 { user }` |
| `POST` | `/auth/login` | `{ email, password }` | `200 { user, accessToken, refreshToken, tokenType, expiresIn }` |
| `POST` | `/auth/refresh` | `{ refreshToken }` | `200` new token pair (the old refresh token stops working) |
| `POST` | `/auth/logout` | `{ refreshToken }` | `204` (revokes the session) |
| `GET` | `/me` | `Authorization: Bearer <accessToken>` | `200 { user }` |
| `GET` | `/health` | | `200 { status: "ok" }` |

Errors are JSON: `{ "error": "...", "details": { "field": "message" } }` with `400`,
`401`, `404`, `409`, `413` or `429`. Sample requests: [docs/api.http](docs/api.http).

## Security design

| Concern | Approach |
|---|---|
| Password storage | scrypt (memory-hard) with a per-user random salt; parameters stored with the hash so they can be raised later; constant-time comparison |
| Password policy | 12 to 128 characters (length over composition rules, per NIST SP 800-63B); the max bounds hashing cost |
| User enumeration | Login returns the same message for "no such user" and "wrong password", and runs a dummy hash for unknown emails so response time is the same |
| Access tokens | JWT, 15 minutes, HS256 with the algorithm pinned (rejects `alg: none`), issuer and audience checked |
| Refresh tokens | Random 256-bit opaque tokens, stored only as SHA-256 hashes; **rotated on every use**; replaying a used token revokes every token from that login |
| Brute force | `express-rate-limit` on the auth routes (20 attempts / 15 min / IP, configurable) |
| Transport and headers | `helmet` (CSP, HSTS, nosniff, frame protection), `x-powered-by` disabled, CORS limited to an allowlist |
| Input | Zod validation on every body; emails trimmed and lower-cased; 10 KB JSON body limit |
| Errors | Unknown errors are logged server-side and returned as a generic 500 (no stack traces) |
| Configuration | Validated at startup; the server refuses to start with a missing or short `JWT_SECRET` |

Known trade-off: `/auth/register` answers `409` for an existing email, which reveals
that the email is registered. Hiding it means switching to email verification
("check your inbox" either way), which needs an email provider.

## Architecture

```
src/server.js         entry point: config, database, listen, graceful shutdown
src/app.js            createApp({ db, config }): middleware and routes, no globals
src/config.js         environment validation (Zod)
src/db.js             schema and connection (node:sqlite)
src/routes/auth.js    HTTP layer: schemas, rate limits, status codes
src/auth/service.js   business rules: register, login, refresh rotation, logout
src/auth/password.js  scrypt hashing
src/auth/tokens.js    JWT and refresh token helpers
src/middleware.js     validation, bearer auth, 404 and error handling
```

`createApp` takes its dependencies as arguments, so each test builds an app with its
own in-memory database and drives it with supertest, no network or cleanup needed.

## Run it

Requires Node.js 22.13+ (`node:sqlite` prints an "experimental" warning, which is expected).

```bash
npm install
cp .env.example .env        # then set JWT_SECRET (openssl rand -base64 48)
npm run dev                 # http://localhost:3000, restarts on file changes
```

```bash
npm test                    # node:test + supertest (20 tests)
npm run lint                # ESLint, zero warnings allowed
```

## License

[MIT](LICENSE)
