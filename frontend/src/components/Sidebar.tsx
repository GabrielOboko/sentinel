import { useState } from "react";
import type { Target } from "../lib/api";
import { ThemeToggle } from "./ThemeToggle";

interface SidebarProps {
  targets: Target[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  onCreate: (hostname: string) => Promise<void>;
}

export function Sidebar({
  targets,
  selectedId,
  onSelect,
  onCreate,
}: SidebarProps) {
  const [hostname, setHostname] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();

    if (!hostname.trim()) return;

    setSubmitting(true);

    try {
      await onCreate(hostname.trim());
      setHostname("");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <aside className="flex h-full w-80 shrink-0 flex-col border-r border-hairline bg-surface">
      <div className="border-b border-hairline px-6 py-6">
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-3">
              <div className="h-2.5 w-2.5 rounded-full bg-text" />

              <h1 className="font-display text-2xl font-semibold uppercase tracking-[0.08em] text-text">
                SENTINEL
              </h1>
            </div>

            <p className="mt-2 pl-[22px] text-[10px] font-mono uppercase tracking-[0.22em] text-muted">
              Attack surface monitor
            </p>
          </div>

          <ThemeToggle />
        </div>
      </div>

      <form
        onSubmit={handleSubmit}
        className="border-b border-hairline px-5 py-5"
      >
        <label
          htmlFor="new-target"
          className="mb-2 block text-[10px] font-semibold uppercase tracking-[0.18em] text-muted"
        >
          Add target
        </label>

        <input
          id="new-target"
          value={hostname}
          onChange={(e) => setHostname(e.target.value)}
          placeholder="example.com"
          className="w-full border border-hairline bg-bg px-3 py-2.5 font-mono text-sm text-text outline-none placeholder:text-muted/50 focus:border-text"
        />

        <button
          type="submit"
          disabled={submitting || !hostname.trim()}
          className="mt-2.5 w-full border border-text bg-text px-3 py-2.5 text-xs font-semibold uppercase tracking-[0.12em] text-bg transition hover:bg-muted hover:border-muted disabled:cursor-not-allowed disabled:opacity-40"
        >
          {submitting ? "Adding…" : "Add target"}
        </button>
      </form>

      <div className="px-5 pb-2 pt-5">
        <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-muted">
          Monitored targets
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 py-2">
        {targets.length === 0 && (
          <p className="px-3 py-6 text-center text-xs leading-5 text-muted">
            No targets yet.
            <br />
            Add a hostname above.
          </p>
        )}

        {targets.map((t) => (
          <button
            key={t.id}
            onClick={() => onSelect(t.id)}
            className={`mb-1 flex w-full flex-col items-start border px-3 py-3 text-left transition ${
              selectedId === t.id
                ? "border-hairline bg-bg"
                : "border-transparent hover:border-hairline hover:bg-bg/50"
            }`}
          >
            <div className="flex w-full items-center justify-between gap-3">
              <span className="truncate font-mono text-sm text-text">
                {t.hostname}
              </span>

              <span
                className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                  t.verified_at ? "bg-text" : "bg-muted/40"
                }`}
                title={t.verified_at ? "Verified" : "Unverified"}
              />
            </div>

            {t.label && (
              <span className="mt-1 text-xs text-muted">
                {t.label}
              </span>
            )}
          </button>
        ))}
      </nav>

      <div className="border-t border-hairline px-5 py-4">
        <div className="flex items-center justify-between">
          <span className="text-[9px] font-mono uppercase tracking-[0.18em] text-muted">
            System
          </span>

          <span className="flex items-center gap-2 text-[9px] font-mono uppercase tracking-[0.12em] text-muted">
            <span className="h-1.5 w-1.5 rounded-full bg-text" />
            Operational
          </span>
        </div>
      </div>
    </aside>
  );
}
