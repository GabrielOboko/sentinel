import type { RawFinding } from "../types/index.js";

// Points deducted per finding by severity. Diminishing returns per
// module (see below) so ten "low" findings in one module don't sink
// the score as hard as one "critical" would.
const SEVERITY_WEIGHT: Record<RawFinding["severity"], number> = {
  critical: 30,
  high: 18,
  medium: 8,
  low: 3,
  info: 0,
};

export function computeRiskScore(findings: RawFinding[]): number {
  let score = 100;

  const byModule = new Map<string, RawFinding[]>();
  for (const f of findings) {
    if (!byModule.has(f.module)) byModule.set(f.module, []);
    byModule.get(f.module)!.push(f);
  }

  for (const moduleFindings of byModule.values()) {
    let moduleDeduction = 0;
    for (const f of moduleFindings) {
      moduleDeduction += SEVERITY_WEIGHT[f.severity];
    }
    // Diminishing returns: cap how much a single module can drag the
    // score down, so one noisy module doesn't dwarf the rest.
    moduleDeduction = Math.min(moduleDeduction, 40);
    score -= moduleDeduction;
  }

  return Math.max(0, Math.min(100, Math.round(score)));
}
