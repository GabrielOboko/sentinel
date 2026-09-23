import type { Severity } from "../lib/api";

const SEVERITY_STYLE: Record<
  Severity,
  { bg: string; text: string; label: string }
> = {
  critical: {
    bg: "bg-risk/10",
    text: "text-risk",
    label: "Critical",
  },
  high: {
    bg: "bg-risk/10",
    text: "text-risk",
    label: "High",
  },
  medium: {
    bg: "bg-amber/10",
    text: "text-amber",
    label: "Medium",
  },
  low: {
    bg: "bg-teal/10",
    text: "text-teal",
    label: "Low",
  },
  info: {
    bg: "bg-muted/10",
    text: "text-muted",
    label: "Info",
  },
};

export function SeverityBadge({
  severity,
}: {
  severity: Severity;
}) {
  const style = SEVERITY_STYLE[severity];

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 font-mono text-[9px] font-medium uppercase tracking-wider ${style.bg} ${style.text}`}
    >
      <span className="h-1 w-1 rounded-full bg-current" />
      {style.label}
    </span>
  );
}
