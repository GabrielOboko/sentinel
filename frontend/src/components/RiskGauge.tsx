interface RiskGaugeProps {
  score: number | null;
  scanning: boolean;
}

export function RiskGauge({ score, scanning }: RiskGaugeProps) {
  const radius = 78;
  const circumference = Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, score ?? 0));
  const progress = (clamped / 100) * circumference;

  const color =
    clamped >= 80
      ? "var(--hex-teal)"
      : clamped >= 50
        ? "var(--hex-amber)"
        : "var(--hex-risk)";

  const status =
    score === null
      ? "AWAITING FIRST SCAN"
      : clamped >= 80
        ? "LOW EXPOSURE"
        : clamped >= 50
          ? "MODERATE EXPOSURE"
          : "HIGH EXPOSURE";

  return (
    <div className="relative w-[280px]">
      <div className="mb-2 text-center font-mono text-[9px] uppercase tracking-[0.2em] text-muted">
        Security score
      </div>

      <svg
        width="280"
        height="150"
        viewBox="0 0 280 150"
        className="overflow-visible"
      >
        <path
          d="M 35 120 A 105 105 0 0 1 245 120"
          fill="none"
          stroke="var(--hex-hairline)"
          strokeWidth="12"
          strokeLinecap="round"
        />

        {!scanning && score !== null && (
          <path
            d="M 35 120 A 105 105 0 0 1 245 120"
            fill="none"
            stroke={color}
            strokeWidth="12"
            strokeLinecap="round"
            strokeDasharray={`${progress} ${circumference}`}
            style={{
              transition:
                "stroke-dasharray 0.9s cubic-bezier(.22,1,.36,1)",
            }}
          />
        )}

        {scanning && (
          <g
            className="radar-sweep"
            style={{ transformOrigin: "140px 120px" }}
          >
            <path
              d="M 35 120 A 105 105 0 0 1 245 120"
              fill="none"
              stroke="var(--hex-signal)"
              strokeWidth="12"
              strokeLinecap="round"
              strokeDasharray={`${circumference * 0.11} ${circumference}`}
            />
          </g>
        )}
      </svg>

      <div className="absolute left-0 right-0 top-[62px] flex flex-col items-center">
        {scanning ? (
          <>
            <span className="font-mono text-3xl font-medium tracking-widest text-signal">
              ···
            </span>
            <span className="mt-1 font-mono text-[9px] uppercase tracking-[0.18em] text-muted scan-pulse">
              scan in progress
            </span>
          </>
        ) : (
          <>
            <span
              className="font-display text-[54px] font-bold leading-none tracking-tighter"
              style={{ color: score === null ? "var(--hex-hairline)" : color }}
            >
              {score ?? "—"}
            </span>

            <span
              className="mt-2 font-mono text-[9px] font-medium tracking-[0.16em]"
              style={{
                color:
                  score === null ? "var(--hex-hairline)" : color,
              }}
            >
              {status}
            </span>
          </>
        )}
      </div>
    </div>
  );
}
