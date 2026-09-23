const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:4000";

export interface Target {
  id: string;
  hostname: string;
  label: string | null;
  verified_at: string | null;
  created_at: string;
}

export interface TargetWithVerification extends Target {
  verificationRecord: string;
  instructions: string;
}

export type ScanStatus = "queued" | "running" | "completed" | "failed";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ScanModule = "tls" | "http" | "dns" | "ports";

export interface Finding {
  id: string;
  module: ScanModule;
  severity: Severity;
  title: string;
  description: string;
  remediation: string | null;
  raw_evidence: unknown;
  created_at: string;
}

export interface ScanSummary {
  id: string;
  status: ScanStatus;
  risk_score: number | null;
  modules: ScanModule[];
  queued_at: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface ScanDetail extends ScanSummary {
  hostname: string;
  target_id: string;
  error: string | null;
  findings: Finding[];
}

export interface ScanEvent {
  message: string;
  created_at: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(body?.error ? JSON.stringify(body.error) : `Request failed: ${res.status}`);
  }
  return body as T;
}

export const api = {
  listTargets: () => request<Target[]>("/targets"),
  createTarget: (hostname: string, label?: string) =>
    request<TargetWithVerification>("/targets", {
      method: "POST",
      body: JSON.stringify({ hostname, label }),
    }),
  verifyTarget: (id: string) =>
    request<{ verified: boolean; error?: string; expectedRecord?: string }>(
      `/targets/${id}/verify`,
      { method: "POST" }
    ),
  listScansForTarget: (targetId: string) => request<ScanSummary[]>(`/targets/${targetId}/scans`),
  createScan: (targetId: string, modules: ScanModule[]) =>
    request<ScanSummary>("/scans", {
      method: "POST",
      body: JSON.stringify({ targetId, modules }),
    }),
  getScan: (scanId: string) => request<ScanDetail>(`/scans/${scanId}`),
  getScanEvents: (scanId: string) => request<ScanEvent[]>(`/scans/${scanId}/events`),
};
