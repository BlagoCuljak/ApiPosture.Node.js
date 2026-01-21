import { OutputFormatter } from './formatter-interface.js';
import { ScanResult, getScanSummary } from '../core/models/scan-result.js';

export class JsonFormatter implements OutputFormatter {
  readonly name = 'json';

  format(result: ScanResult): string {
    const summary = getScanSummary(result);

    const output = {
      scanInfo: {
        projectPath: result.projectPath,
        scanDate: result.scanDate.toISOString(),
        filesScanned: result.filesScanned,
        scanDurationMs: result.scanDurationMs,
      },
      summary: {
        totalEndpoints: summary.totalEndpoints,
        totalFindings: summary.totalFindings,
        findingsBySeverity: summary.findingsBySeverity,
        suppressedFindings: summary.suppressedFindings,
      },
      endpoints: result.endpoints.map((e) => ({
        route: e.route,
        method: e.method,
        handler: e.handlerName,
        controller: e.controllerName,
        framework: e.type,
        location: {
          file: e.location.filePath,
          line: e.location.line,
          column: e.location.column,
        },
        authorization: {
          classification: e.authorization.classification,
          isAuthenticated: e.authorization.isAuthenticated,
          isExplicitlyPublic: e.authorization.isExplicitlyPublic,
          roles: e.authorization.roles,
          policies: e.authorization.policies,
        },
      })),
      findings: result.findings
        .filter((f) => !f.suppressed)
        .map((f) => ({
          ruleId: f.ruleId,
          ruleName: f.ruleName,
          severity: f.severity,
          message: f.message,
          endpoint: {
            route: f.endpoint.route,
            method: f.endpoint.method,
          },
          location: {
            file: f.location.filePath,
            line: f.location.line,
            column: f.location.column,
          },
          recommendation: f.recommendation,
        })),
      suppressedFindings: result.findings
        .filter((f) => f.suppressed)
        .map((f) => ({
          ruleId: f.ruleId,
          ruleName: f.ruleName,
          severity: f.severity,
          endpoint: {
            route: f.endpoint.route,
            method: f.endpoint.method,
          },
          suppressionReason: f.suppressionReason,
        })),
    };

    return JSON.stringify(output, null, 2);
  }
}
