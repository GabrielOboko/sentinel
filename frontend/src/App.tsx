import { useEffect, useState } from "react";
import { Sidebar } from "./components/Sidebar";
import { VerificationPanel } from "./components/VerificationPanel";
import { RiskGauge } from "./components/RiskGauge";
import { ScanDetail } from "./components/ScanDetail";
import { api } from "./lib/api";
import type { ScanSummary, Target } from "./lib/api";

export default function App() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);

  const selected = targets.find((t) => t.id === selectedId) ?? null;
  const latestScan = scans[0] ?? null;

  async function refreshTargets() {
  const list = await api.listTargets();
  setTargets(list);

  setSelectedId((current) => {
    if (current && list.some((target) => target.id === current)) {
      return current;
    }

    return list[0]?.id ?? null;
  });
  }

  async function refreshScans(targetId: string) {
    const list = await api.listScansForTarget(targetId);
    setScans(list);
  }

  useEffect(() => {
    refreshTargets();
  }, []);

  useEffect(() => {
  if (!selectedId) return;

  const targetId = selectedId;

  setActiveScanId(null);

  let cancelled = false;
  let interval: ReturnType<typeof setInterval> | undefined;

  async function pollScans() {
    try {
      const list = await api.listScansForTarget(targetId);

      if (cancelled) return;

      setScans(list);

      const latest = list[0];

      if (
        latest &&
        (latest.status === "queued" || latest.status === "running")
      ) {
        interval ??= setInterval(pollScans, 1500);
      } else if (interval) {
        clearInterval(interval);
        interval = undefined;
      }
    } catch {
      // Keep the existing dashboard state if polling temporarily fails.
    }
  }

  pollScans();

  return () => {
    cancelled = true;

    if (interval) {
      clearInterval(interval);
    }
  };
}, [selectedId]);

  async function handleCreateTarget(hostname: string) {
    const t = await api.createTarget(hostname);
    await refreshTargets();
    setSelectedId(t.id);
  }

  async function handleStartScan() {
    if (!selected) return;

    setStarting(true);

    try {
      const scan = await api.createScan(selected.id, [
        "tls",
        "http",
        "dns",
        "ports",
      ]);

      setActiveScanId(scan.id);
      await refreshScans(selected.id);
    } catch (e) {
      alert(e instanceof Error ? e.message : "Failed to start scan");
    } finally {
      setStarting(false);
    }
  }

  const displayedScanId = activeScanId ?? latestScan?.id ?? null;

  const scanning =
    latestScan?.status === "queued" ||
    latestScan?.status === "running";

  const statusLabel = !selected
    ? "No target selected"
    : selected.verified_at
      ? "Verified target"
      : "Verification required";

  return (
    <div className="flex h-screen overflow-hidden bg-bg text-text">
      <Sidebar
        targets={targets}
        selectedId={selectedId}
        onSelect={setSelectedId}
        onCreate={handleCreateTarget}
      />

      <main className="min-w-0 flex-1 overflow-y-auto">
        {!selected ? (
          <div className="flex min-h-full items-center justify-center px-8">
            <div className="max-w-lg text-center">
              <div className="mb-6 text-xs font-mono uppercase tracking-[0.25em] text-muted">
                Attack surface monitoring
              </div>

              <h2 className="font-display text-4xl font-semibold tracking-[-0.03em] text-text">
                Select a target
              </h2>

              <p className="mx-auto mt-4 max-w-md text-sm leading-6 text-muted">
                Monitor TLS, HTTP security headers, DNS authentication,
                and exposed network services from one security console.
              </p>

              <div className="mt-8 border border-hairline bg-surface px-6 py-5 text-left">
                <div className="text-xs font-mono uppercase tracking-[0.18em] text-muted">
                  Getting started
                </div>

                <div className="mt-3 text-sm text-text">
                  Add a hostname from the sidebar to begin monitoring.
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="mx-auto max-w-6xl px-8 py-8 lg:px-10">
            {/* Header */}
            <header className="border-b border-hairline pb-7">
              <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
                <div>
                  <div className="mb-3 flex items-center gap-3">
                    <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-muted">
                      Target
                    </span>

                    <span className="h-px w-8 bg-hairline" />

                    <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-muted">
                      {statusLabel}
                    </span>
                  </div>

                  <h1 className="font-mono text-3xl font-medium tracking-[-0.03em] text-text lg:text-4xl">
                    {selected.hostname}
                  </h1>

                  <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-muted">
                    <span>
                      Added{" "}
                      {new Date(selected.created_at).toLocaleDateString()}
                    </span>

                    {selected.verified_at && (
                      <>
                        <span className="text-hairline">/</span>
                        <span>
                          Verified{" "}
                          {new Date(
                            selected.verified_at
                          ).toLocaleDateString()}
                        </span>
                      </>
                    )}
                  </div>
                </div>

                {selected.verified_at && (
                  <button
                    onClick={handleStartScan}
                    disabled={starting || scanning}
                    className="inline-flex h-10 shrink-0 items-center justify-center border border-text bg-text px-5 text-xs font-semibold uppercase tracking-[0.12em] text-bg transition hover:bg-muted hover:border-muted disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    {scanning
                      ? "Scan running"
                      : starting
                        ? "Starting"
                        : "Run security scan"}
                  </button>
                )}
              </div>
            </header>

            {!selected.verified_at ? (
              <section className="pt-8">
                <VerificationPanel
                  target={selected}
                  onVerified={refreshTargets}
                />
              </section>
            ) : (
              <>
                {/* Security overview */}
                <section className="grid border-b border-hairline lg:grid-cols-[minmax(280px,0.8fr)_1.2fr]">
                  <div className="border-b border-hairline py-10 lg:border-b-0 lg:border-r lg:pr-10">
                    <div className="mb-6">
                      <div className="text-xs font-mono uppercase tracking-[0.2em] text-muted">
                        Security posture
                      </div>

                      <div className="mt-1 text-sm text-muted">
                        Latest assessment
                      </div>
                    </div>

                    <div className="flex justify-center">
                      <RiskGauge
                        score={latestScan?.risk_score ?? null}
                        scanning={scanning}
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 divide-x divide-y divide-hairline sm:grid-cols-4 lg:divide-y-0">
                    <Metric
                      label="TLS"
                      value={latestScan ? "SCAN" : "—"}
                      detail="Transport security"
                    />

                    <Metric
                      label="HTTP"
                      value={latestScan ? "SCAN" : "—"}
                      detail="Web security"
                    />

                    <Metric
                      label="DNS"
                      value={latestScan ? "SCAN" : "—"}
                      detail="Domain security"
                    />

                    <Metric
                      label="PORTS"
                      value={latestScan ? "SCAN" : "—"}
                      detail="Exposure"
                    />
                  </div>
                </section>

                {/* Scan information */}
                <section className="border-b border-hairline py-7">
                  <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                    <div>
                      <div className="text-xs font-mono uppercase tracking-[0.2em] text-muted">
                        Latest assessment
                      </div>

                      <div className="mt-2 flex items-center gap-3">
                        <span className="text-sm font-medium text-text">
                          {latestScan
                            ? latestScan.status.toUpperCase()
                            : "NO SCANS"}
                        </span>

                        {latestScan && (
                          <span className="font-mono text-xs text-muted">
                            {latestScan.id}
                          </span>
                        )}
                      </div>
                    </div>

                    {latestScan?.completed_at && (
                      <div className="font-mono text-xs text-muted">
                        Completed{" "}
                        {new Date(
                          latestScan.completed_at
                        ).toLocaleString()}
                      </div>
                    )}
                  </div>
                </section>

                {/* Findings */}
                <section className="pt-8">
                  <div className="mb-5 flex items-end justify-between">
                    <div>
                      <div className="text-xs font-mono uppercase tracking-[0.2em] text-muted">
                        Findings
                      </div>

                      <h2 className="mt-1 text-lg font-semibold tracking-tight text-text">
                        Security findings
                      </h2>
                    </div>

                    {latestScan && (
                      <span className="font-mono text-xs text-muted">
                        {latestScan.modules.length} modules
                      </span>
                    )}
                  </div>

                  {displayedScanId ? (
                    <ScanDetail scanId={displayedScanId} />
                  ) : (
                    <div className="border border-hairline bg-surface px-6 py-12 text-center">
                      <div className="font-mono text-xs uppercase tracking-[0.18em] text-muted">
                        No assessment data
                      </div>

                      <p className="mt-3 text-sm text-muted">
                        Run a security scan to populate findings.
                      </p>
                    </div>
                  )}
                </section>
              </>
            )}
          </div>
        )}
      </main>
    </div>
  );
}

interface MetricProps {
  label: string;
  value: string;
  detail: string;
}

function Metric({ label, value, detail }: MetricProps) {
  return (
    <div className="flex min-h-[150px] flex-col justify-between p-5 sm:p-6">
      <span className="font-mono text-[11px] font-medium tracking-[0.16em] text-muted">
        {label}
      </span>

      <div>
        <div className="font-mono text-lg font-medium text-text">
          {value}
        </div>

        <div className="mt-1 text-xs text-muted">
          {detail}
        </div>
      </div>
    </div>
  );
}
