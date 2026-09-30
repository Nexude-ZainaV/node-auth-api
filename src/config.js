import { z } from "zod";

// Fail fast at startup on missing or weak configuration, instead of at the first request.
const configSchema = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  DATABASE_PATH: z.string().min(1).default("data/auth.db"),
  JWT_SECRET: z.string().min(32, "JWT_SECRET must be at least 32 characters (use: openssl rand -base64 48)"),
  ACCESS_TOKEN_TTL_S: z.coerce.number().int().positive().default(15 * 60),
  REFRESH_TOKEN_TTL_S: z.coerce.number().int().positive().default(30 * 24 * 60 * 60),
  // Auth attempts allowed per IP per 15-minute window.
  RATE_LIMIT_PER_WINDOW: z.coerce.number().int().positive().default(20),
  // Comma-separated list of browser origins allowed to call the API.
  CORS_ORIGINS: z
    .string()
    .default("")
    .transform((value) => value.split(",").map((origin) => origin.trim()).filter(Boolean)),
});

/** @returns {z.infer<typeof configSchema>} */
export function loadConfig(env = process.env) {
  const result = configSchema.safeParse(env);
  if (!result.success) {
    const problems = result.error.issues.map((issue) => `  ${issue.path.join(".")}: ${issue.message}`).join("\n");
    throw new Error(`Invalid configuration:\n${problems}`);
  }
  return result.data;
}
