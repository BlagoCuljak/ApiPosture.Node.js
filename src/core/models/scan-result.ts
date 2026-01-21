import { Endpoint } from './endpoint.js';
import { Finding } from './finding.js';
import { Severity, severityOrder } from './severity.js';

export interface ScanResult {
  projectPath: string;
  scanDate: Date;
  endpoints: Endpoint[];
  findings: Finding[];
  filesScanned: number;
  scanDurationMs: number;
}

export interface ScanSummary {
  totalEndpoints: number;
  totalFindings: number;
  findingsBySeverity: Record<Severity, number>;
  suppressedFindings: number;
}

export function createScanResult(
  partial: Partial<ScanResult> & Pick<ScanResult, 'projectPath'>
): ScanResult {
  return {
    projectPath: partial.projectPath,
    scanDate: partial.scanDate ?? new Date(),
    endpoints: partial.endpoints ?? [],
    findings: partial.findings ?? [],
    filesScanned: partial.filesScanned ?? 0,
    scanDurationMs: partial.scanDurationMs ?? 0,
  };
}

export function getScanSummary(result: ScanResult): ScanSummary {
  const activeFindings = result.findings.filter((f) => !f.suppressed);
  const findingsBySeverity = Object.values(Severity).reduce(
    (acc, severity) => {
      acc[severity] = activeFindings.filter((f) => f.severity === severity).length;
      return acc;
    },
    {} as Record<Severity, number>
  );

  return {
    totalEndpoints: result.endpoints.length,
    totalFindings: activeFindings.length,
    findingsBySeverity,
    suppressedFindings: result.findings.filter((f) => f.suppressed).length,
  };
}

export function getHighestSeverity(result: ScanResult): Severity | null {
  const activeFindings = result.findings.filter((f) => !f.suppressed);
  if (activeFindings.length === 0) return null;

  return activeFindings.reduce((highest, finding) => {
    return severityOrder[finding.severity] > severityOrder[highest]
      ? finding.severity
      : highest;
  }, activeFindings[0].severity);
}
