import { pool } from "../db/pool.js";

export async function emitScanEvent(scanId: string, message: string): Promise<void> {
  await pool.query(`INSERT INTO scan_events (scan_id, message) VALUES ($1, $2)`, [scanId, message]);
}

/**
 * Scan isolation: every module runs under a hard timeout so a hung
 * connection (e.g. a target that accepts a TCP connection but never
 * responds) can't block the worker indefinitely or starve other jobs.
 */
export async function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  label: string
): Promise<T> {
  let timer: NodeJS.Timeout;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer!);
  }
}
