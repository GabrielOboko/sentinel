import { useEffect, useState } from "react";
import type {
  ScanDetail as ScanDetailType,
  ScanEvent,
  ScanModule,
} from "../lib/api";
import { api } from "../lib/api";
import { SeverityBadge } from "./SeverityBadge";

const MODULE_LABEL: Record<ScanModule, string> = {
  tls: "TLS / SSL",
  http: "HTTP Headers",
  dns: "DNS / Email Auth",
  ports: "Open Ports",
};

export function ScanDetail({ scanId }: { scanId: string }) {
  const [scan, setScan] = useState<ScanDetailType | null>(null);
  const [events, setEvents] = useState<ScanEvent[]>([]);

  useEffect(() => {
    let cancelled = false;
    let interval: ReturnType<typeof setInterval>;

    async function poll() {
      try {
        const [scanData, eventData] = await Promise.all([
          api.getScan(scanId),
          api.getScanEvents(scanId),
        ]);

        if (cancelled) return;

        setScan(scanData);
        setEvents(eventData);

        if (
          scanData.status === "completed" ||
          scanData.status === "failed"
        ) {
          clearInterval(interval);
        }
      } catch {
        // Keep the existing UI alive if a polling request temporarily fails.
      }
    }

    poll();
    interval = setInterval(poll, 1500);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [scanId]);

  if (!scan) {
    return (
      <div className="flex items-center gap-3 py-8 text-xs text-muted">
        <span className="h-1.5 w-1.5 rounded-full bg-signal scan-pulse" />
        Loading security assessment…
      </div>
    );
  }

  const grouped = new Map<ScanModule, typeof scan.findings>();

  for (const finding of scan.findings) {
    if (!grouped.has(finding.module)) {
      grouped.set(finding.module, []);
    }

    grouped.get(finding.module)!.push(finding);
  }

  if (scan.status === "queued" || scan.status === "running") {
    return (
      <div className="border border-hairline bg-surface">
        <div className="flex items-center justify-between border-b border-hairline px-5 py-4">
          <div>
            <div className="font-display text-sm font-semibold text-text">
              Security assessment
            </div>

            <div className="mt-1 font-mono text-[9px] uppercase tracking-[0.16em] text-muted">
              {scan.status === "queued"
                ? "Waiting for worker"
                : "Analysis in progress"}
            </div>
          </div>

          <span className="flex items-center gap-2 font-mono text-[9px] uppercase tracking-wider text-signal">
            <span className="h-1.5 w-1.5 rounded-full bg-signal scan-pulse" />
            Live
          </span>
        </div>

        <div className="max-h-64 overflow-y-auto px-5 py-5">
          <div className="space-y-2 font-mono text-[10px]">
            {events.length === 0 && (
              <div className="text-muted">
                Waiting for scan to start…
              </div>
            )}

            {events.map((event, index) => (
              <div key={index} className="flex gap-3">
                <span className="shrink-0 text-muted/50">
                  {new Date(event.created_at).toLocaleTimeString()}
                </span>

                <span className="text-text/75">
                  {event.message}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {scan.status === "failed" && (
        <div className="border border-risk/30 bg-risk/5 px-5 py-4">
          <div className="font-display text-sm font-semibold text-risk">
            Scan failed
          </div>

          <p className="mt-1 text-xs leading-5 text-risk/80">
            {scan.error}
          </p>
        </div>
      )}

      {scan.status === "completed" && scan.findings.length === 0 && (
        <div className="border border-teal/20 bg-teal/5 px-5 py-8 text-center">
          <div className="mx-auto mb-3 flex h-8 w-8 items-center justify-center rounded-full border border-teal/30">
            <span className="h-2 w-2 rounded-full bg-teal" />
          </div>

          <div className="font-display text-sm font-semibold text-text">
            No findings detected
          </div>

          <p className="mt-1 text-xs text-muted">
            The analyzed attack surface passed all current checks.
          </p>
        </div>
      )}

      {(["tls", "http", "dns", "ports"] as ScanModule[]).map(
        (module) => {
          const findings = grouped.get(module);

          if (!findings || findings.length === 0) return null;

          return (
            <section key={module}>
              <div className="mb-3 flex items-end justify-between border-b border-hairline pb-3">
                <div>
                  <div className="font-display text-sm font-semibold text-text">
                    {MODULE_LABEL[module]}
                  </div>

                  <div className="mt-0.5 font-mono text-[9px] uppercase tracking-[0.14em] text-muted">
                    {findings.length} finding
                    {findings.length === 1 ? "" : "s"}
                  </div>
                </div>
              </div>

              <div className="divide-y divide-hairline border-y border-hairline">
                {findings.map((finding) => (
                  <article
                    key={finding.id}
                    className="group px-1 py-5 transition hover:bg-surface"
                  >
                    <div className="flex gap-4">
                      <div className="min-w-0 flex-1">
                        <div className="mb-2 flex flex-wrap items-center gap-2">
                          <SeverityBadge severity={finding.severity} />

                          <span className="font-mono text-[9px] uppercase tracking-wider text-muted/60">
                            {module}
                          </span>
                        </div>

                        <h4 className="font-display text-sm font-semibold text-text">
                          {finding.title}
                        </h4>

                        <p className="mt-1.5 max-w-3xl text-xs leading-5 text-muted">
                          {finding.description}
                        </p>

                        {finding.remediation && (
                          <div className="mt-4 border-l-2 border-teal/30 pl-3">
                            <div className="mb-1 font-mono text-[8px] font-medium uppercase tracking-[0.16em] text-teal/70">
                              Recommendation
                            </div>

                            <p className="text-xs leading-5 text-teal/80">
                              {finding.remediation}
                            </p>
                          </div>
                        )}
                      </div>

                      <div className="hidden shrink-0 pt-1 font-mono text-[9px] text-muted/40 sm:block">
                        {new Date(
                          finding.created_at
                        ).toLocaleDateString()}
                      </div>
                    </div>
                  </article>
                ))}
              </div>
            </section>
          );
        }
      )}
    </div>
  );
}
