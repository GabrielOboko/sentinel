import { Queue } from "bullmq";
import IORedis from "ioredis";
import "dotenv/config";

export const connection = new IORedis(
  process.env.REDIS_URL ?? "redis://localhost:6379",
  { maxRetriesPerRequest: null }
);

export const SCAN_QUEUE_NAME = "sentinel-scans";

export const scanQueue = new Queue(SCAN_QUEUE_NAME, { connection });
