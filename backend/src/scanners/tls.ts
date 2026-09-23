import tls from "node:tls";
import type { PinnedTarget } from "../lib/security/ssrf.js";
import { assertStillSafe, UnsafeTargetError } from "../lib/security/ssrf.js";
import type { RawFinding } from "../types/index.js";

const WEAK_PROTOCOLS = new Set(["TLSv1", "TLSv1.1"]);
const CERT_EXPIRY_WARN_DAYS = 30;
const TLS_TIMEOUT_MS = 8000;

export async function scanTls(
  pinned: PinnedTarget,
  port = 443
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  // Final SSRF boundary immediately before creating the outbound socket.
  assertStillSafe(pinned);

  const result = await new Promise<{
    protocol: string | null;
    cert: tls.PeerCertificate | null;
    cipher: tls.CipherNameAndProtocol | null;
    authorized: boolean;
    authError?: string;
  }>((resolve, reject) => {
    // Defense in depth: validate the exact pinned address again before
    // handing it to Node's networking stack.
    try {
      assertStillSafe(pinned);
    } catch (err) {
      reject(err);
      return;
    }

    let settled = false;

    const finish = (callback: () => void) => {
      if (settled) return;
      settled = true;
      callback();
    };

    const socket = tls.connect({
      host: pinned.ip,
      port,

      // Connect to the pinned IP, but present the verified hostname through
      // TLS SNI so virtual-hosted HTTPS services return the correct cert.
      servername: pinned.hostname,

      timeout: TLS_TIMEOUT_MS,

      // We intentionally inspect certificate problems ourselves.
      rejectUnauthorized: false,
    });

    socket.once("secureConnect", () => {
      finish(() => {
        const authorizationError = socket.authorizationError;

        resolve({
          protocol: socket.getProtocol(),
          cert: socket.getPeerCertificate(),
          cipher: socket.getCipher(),
          authorized: socket.authorized,
          authError:
            typeof authorizationError === "string"
              ? authorizationError
              : undefined,
        });

        socket.end();
      });
    });

    socket.once("timeout", () => {
      socket.destroy();
      finish(() => reject(new Error("TLS connection timed out")));
    });

    socket.once("error", (err) => {
      finish(() => reject(err));
    });

    socket.once("close", () => {
      if (!settled) {
        finish(() => reject(new Error("TLS connection closed before handshake completed")));
      }
    });
  });

  // --- Certificate validity ---
  if (!result.authorized) {
    findings.push({
      module: "tls",
      severity: "high",
      title: "TLS certificate is not trusted",
      description: `Certificate validation failed: ${
        result.authError ?? "unknown reason"
      }`,
      remediation:
        "Install a certificate from a trusted CA (e.g. Let's Encrypt) covering this hostname.",
      rawEvidence: {
        authError: result.authError,
      },
    });
  }

  if (result.cert && result.cert.valid_to) {
    const expiry = new Date(result.cert.valid_to);

    if (!Number.isNaN(expiry.getTime())) {
      const daysLeft = Math.floor(
        (expiry.getTime() - Date.now()) / 86_400_000
      );

      if (daysLeft < 0) {
        findings.push({
          module: "tls",
          severity: "critical",
          title: "TLS certificate has expired",
          description: `Certificate expired ${Math.abs(daysLeft)} day(s) ago (${result.cert.valid_to}).`,
          remediation: "Renew the certificate immediately.",
        });
      } else if (daysLeft < CERT_EXPIRY_WARN_DAYS) {
        findings.push({
          module: "tls",
          severity: "medium",
          title: "TLS certificate expiring soon",
          description: `Certificate expires in ${daysLeft} day(s) (${result.cert.valid_to}).`,
          remediation:
            "Renew the certificate before it expires to avoid an outage.",
        });
      }
    }
  }

  // --- Protocol strength ---
  if (result.protocol && WEAK_PROTOCOLS.has(result.protocol)) {
    findings.push({
      module: "tls",
      severity: "high",
      title: `Outdated TLS protocol in use: ${result.protocol}`,
      description: `The server negotiated ${result.protocol}, which is deprecated and has known weaknesses.`,
      remediation: "Disable TLS 1.0/1.1 and require TLS 1.2 or higher.",
    });
  } else if (!result.protocol) {
    findings.push({
      module: "tls",
      severity: "info",
      title: "Could not determine negotiated TLS protocol",
      description:
        "The connection succeeded but the negotiated protocol version was not reported.",
    });
  }

  if (findings.length === 0) {
    findings.push({
      module: "tls",
      severity: "info",
      title: "TLS configuration looks healthy",
      description: `Valid certificate, negotiated protocol ${
        result.protocol ?? "unknown"
      }.`,
    });
  }

  return findings;
}
