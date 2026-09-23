import net from "node:net";
import type { PinnedTarget } from "../lib/security/ssrf.js";
import { assertStillSafe } from "../lib/security/ssrf.js";
import type { RawFinding } from "../types/index.js";

// A curated list rather than a full 1-65535 sweep: fast, low-noise,
// and covers the services that actually matter for an external
// exposure review. Expand this later behind an explicit "deep scan"
// opt-in rather than by default.
const COMMON_PORTS: Record<number, string> = {
  21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
  80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
  443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
  1433: "MSSQL", 1521: "Oracle", 3000: "Dev-server", 3306: "MySQL",
  3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
  8080: "HTTP-alt", 8443: "HTTPS-alt", 9200: "Elasticsearch", 27017: "MongoDB",
};

const RISKY_IF_OPEN = new Set([21, 23, 135, 139, 445, 3389, 5900, 6379, 9200, 27017, 1433, 3306, 5432]);
const CONNECT_TIMEOUT_MS = 2000;

function probePort(ip: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let done = false;
    const finish = (open: boolean) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(CONNECT_TIMEOUT_MS);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
    socket.connect(port, ip);
  });
}

export async function scanPorts(pinned: PinnedTarget): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const ports = Object.keys(COMMON_PORTS).map(Number);

  // Bounded concurrency so we don't open 40 sockets at once.
  const CONCURRENCY = 8;
  const openPorts: number[] = [];
  for (let i = 0; i < ports.length; i += CONCURRENCY) {
    assertStillSafe(pinned); // re-check on each batch, cheap insurance
    const batch = ports.slice(i, i + CONCURRENCY);
    const results = await Promise.all(batch.map((p) => probePort(pinned.ip, p)));
    results.forEach((open, idx) => {
      if (open) openPorts.push(batch[idx]);
    });
  }

  for (const port of openPorts) {
    const service = COMMON_PORTS[port];
    const risky = RISKY_IF_OPEN.has(port);
    findings.push({
      module: "ports",
      severity: risky ? "high" : "info",
      title: `Port ${port} (${service}) is open`,
      description: risky
        ? `${service} on port ${port} is reachable from the internet. This service is commonly targeted and often shouldn't be exposed directly.`
        : `${service} on port ${port} is open, which is expected for a public-facing web service.`,
      remediation: risky
        ? "Restrict access via firewall rules/security groups, or move it behind a VPN/bastion if it doesn't need to be public."
        : undefined,
      rawEvidence: { port, service },
    });
  }

  if (openPorts.length === 0) {
    findings.push({
      module: "ports",
      severity: "info",
      title: "No commonly-scanned ports found open",
      description: `Checked ${ports.length} common ports — none responded. Note: this is a curated port list, not an exhaustive scan.`,
    });
  }

  return findings;
}
