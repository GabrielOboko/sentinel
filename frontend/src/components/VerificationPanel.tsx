import { useState } from "react";
import type { Target, TargetWithVerification } from "../lib/api";
import { api } from "../lib/api";

interface VerificationPanelProps {
  target: Target;
  onVerified: () => void;
}

export function VerificationPanel({ target, onVerified }: VerificationPanelProps) {
  const [record, setRecord] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadRecord() {
    // Re-issuing create returns the same target with its verification
    // record (idempotent on hostname), which is how we surface the
    // TXT value again if the user navigated away before verifying.
    const t = (await api.createTarget(target.hostname)) as TargetWithVerification;
    setRecord(t.verificationRecord);
  }

  async function handleVerify() {
    setChecking(true);
    setError(null);
    try {
      const result = await api.verifyTarget(target.id);
      if (result.verified) {
        onVerified();
      } else {
        setError(result.error ?? "Verification failed");
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Verification failed");
    } finally {
      setChecking(false);
    }
  }

  return (
    <div className="rounded-lg border border-amber/30 bg-amber/5 p-6">
      <div className="flex items-start gap-3">
        <div className="mt-1 h-2 w-2 shrink-0 rounded-full bg-amber" />
        <div className="flex-1">
          <h3 className="font-display text-base font-semibold text-text">
            Ownership verification required
          </h3>
          <p className="mt-1 text-sm text-muted">
            Scans are blocked until you prove control of this domain's DNS. This stops SENTINEL
            from being used to scan hosts you don't own.
          </p>

          {!record ? (
            <button
              onClick={loadRecord}
              className="mt-4 rounded-md bg-amber/15 px-3 py-2 text-sm font-medium text-amber hover:bg-amber/25"
            >
              Get verification record
            </button>
          ) : (
            <div className="mt-4 space-y-3">
              <div>
                <p className="mb-1 text-xs text-muted">
                  Add this as a TXT record on <span className="font-mono">{target.hostname}</span>:
                </p>
                <code className="block break-all rounded-md border border-hairline bg-surfaceRaised px-3 py-2 font-mono text-xs text-teal">
                  {record}
                </code>
              </div>
              <button
                onClick={handleVerify}
                disabled={checking}
                className="rounded-md bg-teal/15 px-3 py-2 text-sm font-medium text-teal hover:bg-teal/25 disabled:opacity-40"
              >
                {checking ? "Checking DNS…" : "Check verification"}
              </button>
              {error && <p className="text-xs text-risk">{error}</p>}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
