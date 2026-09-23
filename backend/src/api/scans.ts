import type { FastifyInstance } from "fastify";
import { pool } from "../db/pool.js";
import { CreateScanSchema, type ScanJobData } from "../types/index.js";
import { scanQueue } from "../lib/queue.js";
import { resolvePinnedIp, UnsafeTargetError } from "../lib/security/ssrf.js";
import { checkRateLimit } from "../lib/security/rateLimit.js";
import { z } from "zod";

// Tunable limits — deliberately conservative for a self-hosted v1.
const SCANS_PER_TARGET_PER_HOUR = 6;
const SCANS_PER_IP_PER_HOUR = 20;

const ScanIdParamsSchema = z.object({
  id: z.string().uuid(),
});

export async function scansRoutes(app: FastifyInstance) {
  // Create a scan. Runs the full authorization pipeline BEFORE enqueueing
  // anything, so a rejected request never reaches the worker or does any
  // network activity:
  //
  //   ownership verified -> hostname/IP safety -> rate limits -> enqueue
  app.post("/scans", async (req, reply) => {
    const parsed = CreateScanSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: parsed.error.flatten() });
    }
    const { targetId, modules } = parsed.data;

    const targetRes = await pool.query(
      `SELECT hostname, verified_at FROM targets WHERE id = $1`,
      [targetId]
    );
    if (targetRes.rowCount === 0) {
      return reply.code(404).send({ error: "target not found" });
    }
    const target = targetRes.rows[0];

    // 1. Authorization / ownership check
    if (!target.verified_at) {
      return reply.code(403).send({
        error: "target is not verified — publish the DNS TXT record and call /targets/:id/verify first",
      });
    }

        // 2. Hostname validation + private/internal IP protection + rebinding
    //    protection setup.
    //
    // Development scan mode has one explicit exception:
    // sentinel.local is handled entirely by the synthetic worker path and
    // never makes a network connection.
    const isDevScan =
      process.env.SENTINEL_DEV_SCAN_MODE === "true" &&
      target.hostname === "sentinel.local";

    if (!isDevScan) {
      try {
        await resolvePinnedIp(target.hostname);
      } catch (err) {
        if (err instanceof UnsafeTargetError) {
          return reply.code(400).send({ error: err.message });
        }
        throw err;
      }
    }

    // 3. Rate limiting — per target and per client IP
    const clientIp = req.ip;
    const [targetLimit, ipLimit] = await Promise.all([
      checkRateLimit(`target:${targetId}`, SCANS_PER_TARGET_PER_HOUR, 3600),
      checkRateLimit(`client:${clientIp}`, SCANS_PER_IP_PER_HOUR, 3600),
    ]);
    if (!targetLimit.allowed) {
      return reply.code(429).send({ error: "rate limit exceeded for this target, try again later" });
    }
    if (!ipLimit.allowed) {
      return reply.code(429).send({ error: "rate limit exceeded for your IP, try again later" });
    }

    // 4. Enqueue — the worker re-validates (assertStillSafe) immediately
    //    before it actually connects, as defense in depth against rebinding.
    const scanRes = await pool.query(
      `INSERT INTO scans (target_id, status, modules)
       VALUES ($1, 'queued', $2)
       RETURNING id, status, modules, queued_at`,
      [targetId, modules]
    );
    const scan = scanRes.rows[0];

    const jobData: ScanJobData = { scanId: scan.id, hostname: target.hostname, modules };
    await scanQueue.add("run-scan", jobData, {
      jobId: scan.id,
      // Scan isolation: bounded retries and an overall job timeout so a
      // stuck module can't hold a worker slot indefinitely.
      attempts: 1,
    });

    return reply.code(202).send(scan);
  });

  app.get("/scans/:id", async (req, reply) => {
    const parsedParams = ScanIdParamsSchema.safeParse(req.params);
    if (!parsedParams.success) {
      return reply.code(400).send({ error: "invalid scan id" });
    }

    const { id } = parsedParams.data;
    const scanRes = await pool.query(
      `SELECT s.id, s.status, s.risk_score, s.modules, s.error,
              s.queued_at, s.started_at, s.completed_at,
              t.hostname, t.id AS target_id
       FROM scans s JOIN targets t ON t.id = s.target_id
       WHERE s.id = $1`,
      [id]
    );
    if (scanRes.rowCount === 0) return reply.code(404).send({ error: "scan not found" });

    const findingsRes = await pool.query(
      `SELECT id, module, severity, title, description, remediation, raw_evidence, created_at
       FROM findings WHERE scan_id = $1
       ORDER BY CASE severity
         WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
         WHEN 'low' THEN 3 ELSE 4 END`,
      [id]
    );

    return reply.send({ ...scanRes.rows[0], findings: findingsRes.rows });
  });

  app.get("/scans/:id/events", async (req, reply) => {
    const parsedParams = ScanIdParamsSchema.safeParse(req.params);
    if (!parsedParams.success) {
      return reply.code(400).send({ error: "invalid scan id" });
    }

    const { id } = parsedParams.data;
    const { rows } = await pool.query(
      `SELECT message, created_at FROM scan_events WHERE scan_id = $1 ORDER BY created_at ASC`,
      [id]
    );
    return reply.send(rows);
  });
}
