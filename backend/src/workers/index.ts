import { Worker, type Job } from "bullmq";
import "dotenv/config";
import { connection, SCAN_QUEUE_NAME } from "../lib/queue.js";
import { pool } from "../db/pool.js";
import { emitScanEvent, withTimeout } from "../lib/scanEvents.js";
import {
  resolvePinnedIp,
  UnsafeTargetError,
  type PinnedTarget,
} from "../lib/security/ssrf.js";
import { computeRiskScore } from "../scanners/riskScore.js";
import { scanTls } from "../scanners/tls.js";
import { scanHttp } from "../scanners/http.js";
import { scanDns } from "../scanners/dns.js";
import { scanPorts } from "../scanners/ports.js";
import {
  SCAN_MODULES,
  type RawFinding,
  type ScanJobData,
  type ScanModule,
} from "../types/index.js";

const MODULE_TIMEOUT_MS = 15_000;

// Keep the worker deliberately bounded.
const WORKER_CONCURRENCY = 3;

const MODULE_RUNNERS: Record<
  ScanModule,
  (pinned: PinnedTarget) => Promise<RawFinding[]>
> = {
  tls: scanTls,
  http: scanHttp,
  dns: scanDns,
  ports: scanPorts,
};

function isScanModule(value: unknown): value is ScanModule {
  return (
    typeof value === "string" &&
    (SCAN_MODULES as readonly string[]).includes(value)
  );
}

function validateJobData(data: unknown): asserts data is ScanJobData {
  if (!data || typeof data !== "object") {
    throw new Error("Invalid scan job payload");
  }

  const job = data as Record<string, unknown>;

  if (typeof job.scanId !== "string" || job.scanId.length === 0) {
    throw new Error("Invalid scan job: missing scanId");
  }

  if (
    typeof job.hostname !== "string" ||
    job.hostname.length === 0 ||
    job.hostname.length > 255
  ) {
    throw new Error("Invalid scan job: invalid hostname");
  }

  if (
    !Array.isArray(job.modules) ||
    job.modules.length === 0 ||
    job.modules.length > SCAN_MODULES.length ||
    !job.modules.every(isScanModule)
  ) {
    throw new Error("Invalid scan job: invalid modules");
  }
}

/**
 * PostgreSQL is the source of truth.
 *
 * Redis/BullMQ only transports the scan ID. The hostname, verification
 * state, and requested modules are reloaded from PostgreSQL and compared
 * against the job payload before any network operation occurs.
 */
async function loadAndAuthorizeScan(job: Job<ScanJobData>): Promise<{
  scanId: string;
  hostname: string;
  modules: ScanModule[];
}> {
  validateJobData(job.data);

  const { scanId } = job.data;

  const result = await pool.query(
    `SELECT
       s.id,
       s.status,
       s.modules,
       t.hostname,
       t.verified_at
     FROM scans s
     JOIN targets t ON t.id = s.target_id
     WHERE s.id = $1`,
    [scanId]
  );

  if (result.rowCount !== 1) {
    throw new Error("Scan does not exist");
  }

  const row = result.rows[0];

  // A scan should only be processed once from the queued state.
  if (row.status !== "queued") {
    throw new Error(`Scan is not queued (current status: ${row.status})`);
  }

  // Ownership verification must still be valid when the worker starts.
  if (!row.verified_at) {
    throw new Error("Target is no longer verified");
  }

  if (typeof row.hostname !== "string" || row.hostname.length === 0) {
    throw new Error("Scan target has an invalid hostname");
  }

  if (!Array.isArray(row.modules) || row.modules.length === 0) {
    throw new Error("Scan contains no modules");
  }

  const dbModules = row.modules.filter(isScanModule);

  if (
    dbModules.length !== row.modules.length ||
    dbModules.length === 0 ||
    dbModules.length > SCAN_MODULES.length
  ) {
    throw new Error("Scan contains invalid modules");
  }

  // Detect a malformed or tampered Redis job rather than silently trusting it.
  if (job.data.hostname !== row.hostname) {
    throw new Error("Scan job hostname does not match database record");
  }

  const jobModules = [...job.data.modules].sort();
  const authoritativeModules = [...dbModules].sort();

  if (
    jobModules.length !== authoritativeModules.length ||
    jobModules.some((module, index) => module !== authoritativeModules[index])
  ) {
    throw new Error("Scan job modules do not match database record");
  }

  return {
    scanId: row.id,
    hostname: row.hostname,
    modules: dbModules,
  };
}

async function markScanFailed(scanId: string, message: string) {
  await pool.query(
    `UPDATE scans
     SET status = 'failed',
         error = $2,
         completed_at = now()
     WHERE id = $1
       AND status IN ('queued', 'running')`,
    [scanId, message]
  );
}

async function runScan(job: Job<ScanJobData>) {
  // Validate the job and reload authoritative state before doing anything
  // network-related.
  const { scanId, hostname, modules } = await loadAndAuthorizeScan(job);

  await pool.query(
    `UPDATE scans
     SET status = 'running',
         started_at = now()
     WHERE id = $1
       AND status = 'queued'`,
    [scanId]
  );

  const statusCheck = await pool.query(
    `SELECT status
     FROM scans
     WHERE id = $1`,
    [scanId]
  );

  if (statusCheck.rowCount !== 1 || statusCheck.rows[0].status !== "running") {
    throw new Error("Scan could not transition to running state");
  }

  await emitScanEvent(scanId, `Scan started for ${hostname}`);

  // Resolve and validate immediately before scanner execution.
  // Every scanner receives this pinned target and must never resolve the
  // hostname independently.
  let pinned: PinnedTarget;

  try {
    pinned = await resolvePinnedIp(hostname);
  } catch (err) {
    const message =
      err instanceof UnsafeTargetError
        ? err.message
        : "Failed to resolve target safely";

    await markScanFailed(scanId, message);
    await emitScanEvent(scanId, `Scan aborted: ${message}`);
    return;
  }

  const allFindings: RawFinding[] = [];

  for (const mod of modules) {
    await emitScanEvent(scanId, `Running ${mod} checks...`);

    try {
      const runner = MODULE_RUNNERS[mod];

      const findings = await withTimeout(
        runner(pinned),
        MODULE_TIMEOUT_MS,
        `${mod} module`
      );

      allFindings.push(...findings);

      await emitScanEvent(
        scanId,
        `${mod} checks complete (${findings.length} finding(s))`
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);

      // SSRF violations are not converted into successful scan findings.
      // They terminate the scan instead.
      if (err instanceof UnsafeTargetError) {
        await markScanFailed(scanId, message);
        await emitScanEvent(scanId, `${mod} aborted: ${message}`);
        return;
      }

      allFindings.push({
        module: mod,
        severity: "info",
        title: `${mod} module failed to complete`,
        description: message,
      });

      await emitScanEvent(
        scanId,
        `${mod} checks failed: ${message}`
      );
    }
  }

  const riskScore = computeRiskScore(allFindings);

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    for (const finding of allFindings) {
      await client.query(
        `INSERT INTO findings (
           scan_id,
           module,
           severity,
           title,
           description,
           remediation,
           raw_evidence
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          scanId,
          finding.module,
          finding.severity,
          finding.title,
          finding.description,
          finding.remediation ?? null,
          finding.rawEvidence ?? null,
        ]
      );
    }

    const updateResult = await client.query(
      `UPDATE scans
       SET status = 'completed',
           risk_score = $2,
           completed_at = now()
       WHERE id = $1
         AND status = 'running'`,
      [scanId, riskScore]
    );

    if (updateResult.rowCount !== 1) {
      throw new Error("Scan state changed before completion");
    }

    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }

  await emitScanEvent(
    scanId,
    `Scan complete — risk score ${riskScore}/100`
  );
}

const worker = new Worker<ScanJobData>(
  SCAN_QUEUE_NAME,
  async (job) => {
    await runScan(job);
  },
  {
    connection,
    concurrency: WORKER_CONCURRENCY,
  }
);

worker.on("failed", async (job, err) => {
  if (!job) return;

  console.error(
    `[worker] scan ${job.data?.scanId ?? "unknown"} failed:`,
    err
  );

  if (typeof job.data?.scanId === "string") {
    await markScanFailed(job.data.scanId, err.message);
  }
});

worker.on("ready", () => {
  console.log("[worker] SENTINEL worker ready, waiting for scans...");
});

worker.on("error", (err) => {
  console.error("[worker] worker error:", err);
});




