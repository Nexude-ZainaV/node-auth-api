import cors from "cors";
import express from "express";
import helmet from "helmet";
import { AuthService } from "./auth/service.js";
import { errorHandler, notFound } from "./middleware.js";
import { authRouter } from "./routes/auth.js";

const JSON_BODY_LIMIT = "10kb";

/**
 * Builds the Express app from its dependencies. No globals and no listen(): tests
 * create an app with an in-memory database and drive it with supertest.
 */
export function createApp({ db, config }) {
  const auth = new AuthService(db, {
    jwtSecret: config.JWT_SECRET,
    accessTokenTtlS: config.ACCESS_TOKEN_TTL_S,
    refreshTokenTtlS: config.REFRESH_TOKEN_TTL_S,
  });

  const app = express();
  app.disable("x-powered-by");
  app.use(helmet()); // security headers: CSP, HSTS, no-sniff, frame protection...
  app.use(cors({ origin: config.CORS_ORIGINS.length ? config.CORS_ORIGINS : false }));
  app.use(express.json({ limit: JSON_BODY_LIMIT }));

  app.get("/health", (_req, res) => res.json({ status: "ok" }));
  app.use(authRouter(auth, { jwtSecret: config.JWT_SECRET, rateLimitPerWindow: config.RATE_LIMIT_PER_WINDOW }));

  app.use(notFound);
  app.use(errorHandler);
  return app;
}
