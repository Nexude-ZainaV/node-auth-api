// Middleware shared by the routes: body validation, bearer auth, 404 and the error handler.
import { HttpError } from "./http-error.js";
import { verifyAccessToken } from "./auth/tokens.js";

/** Validates req.body against a Zod schema; on success, req.body is the parsed value. */
export function validateBody(schema) {
  return (req, _res, next) => {
    const result = schema.safeParse(req.body ?? {});
    if (!result.success) {
      const details = {};
      // One message per field (the first one), keyed by its path, e.g. { email: "..." }.
      for (const issue of result.error.issues) details[issue.path.join(".") || "body"] ??= issue.message;
      return next(new HttpError(400, "Validation failed.", details));
    }
    req.body = result.data;
    next();
  };
}

/** Requires "Authorization: Bearer <access token>"; sets req.user = { id, email }. */
export function requireAuth({ jwtSecret }) {
  return (req, _res, next) => {
    const [scheme, token] = (req.get("authorization") ?? "").split(" ");
    if (scheme !== "Bearer" || !token) return next(new HttpError(401, "Missing bearer token."));
    try {
      const claims = verifyAccessToken(token, { secret: jwtSecret });
      req.user = { id: Number(claims.sub), email: claims.email };
      next();
    } catch (error) {
      const expired = error.name === "TokenExpiredError";
      next(new HttpError(401, expired ? "Access token expired." : "Invalid access token."));
    }
  };
}

/** Catch-all for unmatched routes, so a 404 is JSON like every other error. */
export function notFound(req, _res, next) {
  next(new HttpError(404, `No route for ${req.method} ${req.path}`));
}

/**
 * Last middleware. Known errors become JSON with their status; anything else is logged
 * and returned as a generic 500, so stack traces and SQL never reach the client.
 */
// Express recognises error handlers by their four parameters, so _next must stay.
export function errorHandler(error, _req, res, _next) {
  if (error instanceof HttpError) {
    return res.status(error.status).json({ error: error.message, ...(error.details && { details: error.details }) });
  }
  // body-parser errors from express.json(): bad JSON and the size limit.
  if (error.type === "entity.parse.failed") return res.status(400).json({ error: "Malformed JSON body." });
  if (error.type === "entity.too.large") return res.status(413).json({ error: "Request body too large." });

  console.error(error);
  res.status(500).json({ error: "Internal server error." });
}
