import { Router } from "express";
import { rateLimit } from "express-rate-limit";
import { z } from "zod";
import { HttpError } from "../http-error.js";
import { requireAuth, validateBody } from "../middleware.js";

const PASSWORD_MIN_LENGTH = 12; // NIST SP 800-63B favours length over composition rules
const PASSWORD_MAX_LENGTH = 128; // bounds hashing cost per request

const email = z.string().trim().toLowerCase().max(254).pipe(z.email("Enter a valid email address."));
const password = z
  .string()
  .min(PASSWORD_MIN_LENGTH, `Password must be at least ${PASSWORD_MIN_LENGTH} characters.`)
  .max(PASSWORD_MAX_LENGTH, `Password must be at most ${PASSWORD_MAX_LENGTH} characters.`);

const registerSchema = z.object({ email, name: z.string().trim().min(1, "Name is required.").max(80), password });
const loginSchema = z.object({ email, password: z.string().min(1).max(PASSWORD_MAX_LENGTH) });
const refreshSchema = z.object({ refreshToken: z.string().min(1).max(200) });

/**
 * @param {import("../auth/service.js").AuthService} auth
 * @param {{ jwtSecret: string, rateLimitPerWindow?: number }} options
 */
export function authRouter(auth, { jwtSecret, rateLimitPerWindow = 20 }) {
  const router = Router();

  // Slows password guessing: at most N auth attempts per IP per 15 minutes.
  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: rateLimitPerWindow,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { error: "Too many attempts. Try again later." },
  });

  // Express 5 forwards rejected promises from async handlers to the error handler.
  router.post("/auth/register", limiter, validateBody(registerSchema), async (req, res) => {
    const user = await auth.register(req.body);
    res.status(201).location(`/me`).json({ user });
  });

  router.post("/auth/login", limiter, validateBody(loginSchema), async (req, res) => {
    res.json(await auth.login(req.body));
  });

  router.post("/auth/refresh", limiter, validateBody(refreshSchema), (req, res) => {
    res.json(auth.refresh(req.body.refreshToken));
  });

  router.post("/auth/logout", validateBody(refreshSchema), (req, res) => {
    auth.logout(req.body.refreshToken);
    res.status(204).end();
  });

  router.get("/me", requireAuth({ jwtSecret }), (req, res) => {
    const user = auth.findUser(req.user.id);
    if (!user) throw new HttpError(404, "User no longer exists.");
    res.json({ user });
  });

  return router;
}
