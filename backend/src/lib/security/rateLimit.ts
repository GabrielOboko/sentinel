import { connection } from "../queue.js";

/**
 * Simple fixed-window rate limiter backed by Redis (shared connection
 * with BullMQ). Two independent limits are enforced by callers:
 *   - per target hostname (stop hammering one site)
 *   - per client IP (stop one caller from spamming many targets)
 */
export async function checkRateLimit(
  key: string,
  limit: number,
  windowSeconds: number
): Promise<{ allowed: boolean; remaining: number }> {
  const redisKey = `ratelimit:${key}`;
  const count = await connection.incr(redisKey);
  if (count === 1) {
    await connection.expire(redisKey, windowSeconds);
  }
  return { allowed: count <= limit, remaining: Math.max(0, limit - count) };
}
