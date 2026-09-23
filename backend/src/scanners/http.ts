import http from "node:http";
import https from "node:https";
import type { PinnedTarget } from "../lib/security/ssrf.js";
import { assertStillSafe, UnsafeTargetError } from "../lib/security/ssrf.js";
import type { RawFinding } from "../types/index.js";

interface HeaderCheck {
  header: string;
  severity: RawFinding["severity"];
  description: string;
  remediation: string;
  validate?: (value: string) => boolean;
}

const CHECKS: HeaderCheck[] = [
  {
    header: "strict-transport-security",
    severity: "high",
    description: "HSTS header is missing, so browsers won't enforce HTTPS on repeat visits.",
    remediation: 'Add "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload".',
  },
  {
    header: "content-security-policy",
    severity: "medium",
    description: "No Content-Security-Policy header, leaving the site more exposed to XSS.",
    remediation: "Define a CSP that restricts script/style/frame sources to trusted origins.",
  },
  {
    header: "x-frame-options",
    severity: "medium",
    description: "X-Frame-Options is missing, so the page can be embedded in a clickjacking iframe.",
    remediation: 'Add "X-Frame-Options: DENY" or an equivalent frame-ancestors CSP directive.',
  },
  {
    header: "x-content-type-options",
    severity: "low",
    description: "X-Content-Type-Options is missing, allowing MIME-sniffing in older browsers.",
    remediation: 'Add "X-Content-Type-Options: nosniff".',
  },
  {
    header: "referrer-policy",
    severity: "low",
    description:
      "No Referrer-Policy set; full URLs (possibly with sensitive query params) may leak on outbound links.",
    remediation: 'Add "Referrer-Policy: strict-origin-when-cross-origin" or stricter.',
  },
];

function fetchHeaders(
  pinned: PinnedTarget,
  useHttps: boolean
): Promise<{
  status: number;
  headers: http.IncomingHttpHeaders;
}> {
  // Final synchronous SSRF boundary immediately before creating
  // the outbound connection.
  assertStillSafe(pinned);

  const lib = useHttps ? https : http;

  return new Promise((resolve, reject) => {
    let settled = false;

    const finish = (callback: () => void) => {
      if (settled) return;
      settled = true;
      callback();
    };

    const req = lib.request(
      {
        // IMPORTANT:
        // Connect directly to the already-validated IP.
        // Never give the HTTP client the original hostname as `host`,
        // otherwise DNS resolution could happen again.
        host: pinned.ip,

        // Explicit family prevents Node from performing another
        // address-family resolution decision.
        family: pinned.family,

        port: useHttps ? 443 : 80,
        method: "HEAD",
        path: "/",

        // Preserve the verified hostname at the HTTP layer while
        // connecting directly to the pinned IP.
        headers: {
          Host: pinned.hostname,
          Connection: "close",
          "User-Agent": "SENTINEL/1.0 security-scanner",
        },

        // TLS SNI must remain the verified hostname.
        servername: useHttps ? pinned.hostname : undefined,

        // SENTINEL intentionally inspects certificate problems itself.
        rejectUnauthorized: false,

        // Hard upper bound for the request.
        timeout: 8000,

        // Never follow redirects. node:http/node:https do not follow
        // redirects automatically, and SENTINEL must never introduce
        // redirect-following behavior here.
      },
      (res) => {
        const status = res.statusCode ?? 0;
        const headers = res.headers;

        // We only need headers.
        //
        // Destroy rather than downloading an attacker-controlled body.
        res.destroy();

        finish(() => {
          resolve({
            status,
            headers,
          });
        });
      }
    );

    req.on("timeout", () => {
      req.destroy(new Error("HTTP request timed out"));
    });

    req.on("error", (err) => {
      finish(() => reject(err));
    });

    req.end();
  });
}

export async function scanHttp(pinned: PinnedTarget): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  let httpsResult:
    | {
        status: number;
        headers: http.IncomingHttpHeaders;
      }
    | undefined;

  try {
    httpsResult = await fetchHeaders(pinned, true);
  } catch (err) {
    if (err instanceof UnsafeTargetError) throw err;

    findings.push({
      module: "http",
      severity: "high",
      title: "HTTPS is not available",
      description: "Could not establish an HTTPS connection on port 443.",
      remediation: "Configure TLS termination and serve the site over HTTPS.",
    });
  }

  if (httpsResult) {
    for (const check of CHECKS) {
      const value = httpsResult.headers[check.header];

      if (!value || (check.validate && !check.validate(String(value)))) {
        findings.push({
          module: "http",
          severity: check.severity,
          title: `Missing header: ${check.header}`,
          description: check.description,
          remediation: check.remediation,
        });
      }
    }

    // Plaintext HTTP -> HTTPS redirect check.
    //
    // We inspect the Location header but deliberately NEVER follow it.
    try {
      const httpResult = await fetchHeaders(pinned, false);

      const location = String(httpResult.headers.location ?? "");

      const redirectsToHttps =
        httpResult.status >= 300 &&
        httpResult.status < 400 &&
        location.toLowerCase().startsWith("https://");

      if (!redirectsToHttps) {
        findings.push({
          module: "http",
          severity: "medium",
          title: "HTTP does not redirect to HTTPS",
          description:
            "Requests to the plaintext port 80 endpoint are not redirected to HTTPS.",
          remediation:
            "Configure a permanent (301/308) redirect from HTTP to HTTPS.",
        });
      }
    } catch {
      // Port 80 being unavailable is not itself a finding.
      // HTTPS-only deployments are valid.
    }
  }

  if (findings.length === 0) {
    findings.push({
      module: "http",
      severity: "info",
      title: "Security headers look healthy",
      description: "All checked security headers are present on the HTTPS response.",
    });
  }

  return findings;
}
