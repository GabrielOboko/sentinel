import type { FastifyInstance } from "fastify";
import { pool } from "../db/pool.js";
import { CreateTargetSchema } from "../types/index.js";
import {
  generateVerificationToken,
  checkTxtVerification,
  verificationRecordFor,
} from "../lib/security/ownership.js";

export async function targetsRoutes(app: FastifyInstance) {
  // Create (or fetch, if it already exists) a target by hostname.
  // In development mode, sentinel.local is automatically verified so the
  // scanner can be tested without owning a real public domain.
  app.post("/targets", async (req, reply) => {
    const parsed = CreateTargetSchema.safeParse(req.body);

    if (!parsed.success) {
      return reply.code(400).send({ error: parsed.error.flatten() });
    }

    const { hostname, label } = parsed.data;

    const DEV_SCAN_HOSTS = new Set([
  "sentinel.local",
  "example.com",
  ]);

    const isDevTarget =
  process.env.SENTINEL_DEV_SCAN_MODE === "true" &&
  DEV_SCAN_HOSTS.has(hostname);

    const token = generateVerificationToken();

    const { rows } = await pool.query(
      `INSERT INTO targets (hostname, label, verification_token)
       VALUES ($1, $2, $3)
       ON CONFLICT (hostname)
       DO UPDATE SET label = COALESCE(EXCLUDED.label, targets.label)
       RETURNING id, hostname, label, verified_at, verification_token, created_at`,
      [hostname, label ?? null, token]
    );

    const target = rows[0];

    if (isDevTarget && !target.verified_at) {
      await pool.query(
        `UPDATE targets
         SET verified_at = now()
         WHERE id = $1`,
        [target.id]
      );

      target.verified_at = new Date().toISOString();
    }

    return reply.code(201).send({
      ...target,
      verificationRecord: verificationRecordFor(target.verification_token),
      instructions: isDevTarget
        ? "Development target automatically verified because SENTINEL_DEV_SCAN_MODE=true."
        : `Add a DNS TXT record on ${target.hostname} with value "${verificationRecordFor(
            target.verification_token
          )}", then POST /targets/${target.id}/verify. Scans are blocked until verified.`,
    });
  });

  // Check the TXT record and mark the target verified if it matches.
  app.post("/targets/:id/verify", async (req, reply) => {
    const { id } = req.params as { id: string };

    const { rows } = await pool.query(
      `SELECT hostname, verification_token, verified_at
       FROM targets
       WHERE id = $1`,
      [id]
    );

    if (rows.length === 0) {
      return reply.code(404).send({ error: "target not found" });
    }

    const target = rows[0];

    if (target.verified_at) {
      return reply.send({
        verified: true,
        alreadyVerified: true,
      });
    }

    const ok = await checkTxtVerification(
      target.hostname,
      target.verification_token
    );

    if (!ok) {
      return reply.code(422).send({
        verified: false,
        error:
          "TXT record not found or does not match. DNS changes can take a few minutes to propagate.",
        expectedRecord: verificationRecordFor(target.verification_token),
      });
    }

    await pool.query(
      `UPDATE targets
       SET verified_at = now()
       WHERE id = $1`,
      [id]
    );

    return reply.send({ verified: true });
  });

  app.get("/targets", async (_req, reply) => {
    const { rows } = await pool.query(
      `SELECT id, hostname, label, verified_at, created_at
       FROM targets
       ORDER BY created_at DESC`
    );

    return reply.send(rows);
  });

  app.get("/targets/:id/scans", async (req, reply) => {
    const { id } = req.params as { id: string };

    const { rows } = await pool.query(
      `SELECT id, status, risk_score, modules, queued_at, started_at, completed_at
       FROM scans
       WHERE target_id = $1
       ORDER BY queued_at DESC
       LIMIT 50`,
      [id]
    );

    return reply.send(rows);
  });
}