export enum Severity {
  Info = 'info',
  Low = 'low',
  Medium = 'medium',
  High = 'high',
  Critical = 'critical',
}

export const severityOrder: Record<Severity, number> = {
  [Severity.Info]: 0,
  [Severity.Low]: 1,
  [Severity.Medium]: 2,
  [Severity.High]: 3,
  [Severity.Critical]: 4,
};

export function compareSeverity(a: Severity, b: Severity): number {
  return severityOrder[a] - severityOrder[b];
}

export function parseSeverity(value: string): Severity | undefined {
  const normalized = value.toLowerCase();
  return Object.values(Severity).find((s) => s === normalized);
}
