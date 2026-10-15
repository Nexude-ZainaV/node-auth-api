# Auth API (Node.js + Express 5)

[![CI](https://github.com/Nexude-ZainaV/node-auth-api/actions/workflows/ci.yml/badge.svg)](https://github.com/Nexude-ZainaV/node-auth-api/actions/workflows/ci.yml)
![Node.js 22+](https://img.shields.io/badge/Node.js-22%2B-5FA04E?logo=nodedotjs&logoColor=white)
![Express 5](https://img.shields.io/badge/Express-5-000000?logo=express)
![JWT](https://img.shields.io/badge/auth-JWT%20%2B%20refresh%20rotation-orange)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

An authentication service with registration, login, short-lived JWT access tokens,
rotating refresh tokens with reuse detection, logout and a protected `/me` route.
I hash passwords with scrypt from `node:crypto` and store data in SQLite through the
built-in `node:sqlite` module, so the only runtime dependencies are Express, a few
security middlewares, `jsonwebtoken` and Zod.

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
`401`, `404`, `409`, `413` or `429`. There are sample requests in
[docs/api.http](docs/api.http).

## Security design

| Concern | Approach |
|---|---|
| Password storage | scrypt (memory-hard) with a random salt per user. The parameters are stored with the hash so they can be raised later. Comparison is constant-time. |
| Password policy | 12 to 128 characters. NIST SP 800-63B favours length over composition rules, and the upper limit caps the hashing cost. |
| User enumeration | Login gives the same message for "no such user" and "wrong password", and runs a dummy hash for unknown emails so both take the same time. |
| Access tokens | JWT, 15 minutes, HS256 with the algorithm pinned (so `alg: none` is rejected), issuer and audience checked. |
| Refresh tokens | Random 256-bit opaque tokens, stored only as SHA-256 hashes. Each one is rotated on use, and replaying a used token revokes every token from that login. |
| Brute force | `express-rate-limit` on the auth routes (20 attempts per 15 minutes per IP, configurable). |
| Transport and headers | `helmet` (CSP, HSTS, nosniff, frame protection), `x-powered-by` off, CORS limited to an allowlist. |
| Input | Zod validates every body. Emails are trimmed and lower-cased. JSON bodies are capped at 10 KB. |
| Errors | Unknown errors are logged on the server and returned as a generic 500, with no stack trace. |
| Configuration | Validated at startup. The server won't start with a missing or short `JWT_SECRET`. |

One trade-off I accepted: `/auth/register` answers `409` for an existing email, which
tells the caller that the email is registered. Hiding that means switching to email
verification ("check your inbox" either way), and that needs an email provider.

## Layout

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

`createApp` takes its dependencies as arguments. Each test builds its own app with an
in-memory database and drives it with supertest, so there's no network and nothing to
clean up.

## Run it

You need Node.js 22.13 or newer. `node:sqlite` prints an "experimental" warning on
startup; that's expected.

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
