import { z } from "zod";

export const SCAN_MODULES = ["tls", "http", "dns", "ports"] as const;
export type ScanModule = (typeof SCAN_MODULES)[number];

export const ScanStatusEnum = z.enum(["queued", "running", "completed", "failed"]);
export type ScanStatus = z.infer<typeof ScanStatusEnum>;

export const SeverityEnum = z.enum(["critical", "high", "medium", "low", "info"]);
export type Severity = z.infer<typeof SeverityEnum>;

// --- request payloads ---

export const CreateTargetSchema = z.object({
  hostname: z
    .string()
    .min(1)
    .max(255)
    .regex(
      /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.?$/,
      "must be a valid hostname (no protocol, no path)"
    ),
  label: z.string().max(120).optional(),
});
export type CreateTargetInput = z.infer<typeof CreateTargetSchema>;

export const CreateScanSchema = z.object({
  targetId: z.string().uuid(),
  modules: z.array(z.enum(SCAN_MODULES)).min(1).default([...SCAN_MODULES]),
});
export type CreateScanInput = z.infer<typeof CreateScanSchema>;

// --- job payload passed to BullMQ ---

export interface ScanJobData {
  scanId: string;
  hostname: string;
  modules: ScanModule[];
}

// --- structured finding shape every scanner module must emit ---

export interface RawFinding {
  module: ScanModule;
  severity: Severity;
  title: string;
  description: string;
  remediation?: string;
  rawEvidence?: unknown;
}
