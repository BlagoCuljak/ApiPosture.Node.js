import Table from 'cli-table3';
import { OutputFormatter, FormatterOptions } from './formatter-interface.js';
import { AccessibilityHelper } from './accessibility-helper.js';
import { ScanResult, getScanSummary } from '../core/models/scan-result.js';
import { Finding } from '../core/models/finding.js';
import { Severity, severityOrder } from '../core/models/severity.js';
import { formatSourceLocation } from '../core/models/source-location.js';

export class TerminalFormatter implements OutputFormatter {
  readonly name = 'terminal';
  private helper: AccessibilityHelper;

  constructor(options: FormatterOptions = {}) {
    this.helper = new AccessibilityHelper({
      noColor: options.noColor,
      noIcons: options.noIcons,
    });
  }

  format(result: ScanResult): string {
    const lines: string[] = [];
    const summary = getScanSummary(result);

    // Header
    lines.push('');
    lines.push(this.helper.bold('ApiPosture Security Scan Results'));
    lines.push(this.helper.dim('=' .repeat(50)));
    lines.push('');

    // Scan info
    lines.push(`Project: ${this.helper.cyan(result.projectPath)}`);
    lines.push(`Files scanned: ${result.filesScanned}`);
    lines.push(`Endpoints found: ${summary.totalEndpoints}`);
    lines.push(`Scan duration: ${result.scanDurationMs}ms`);
    lines.push('');

    // Findings summary
    if (summary.totalFindings === 0) {
      lines.push(
        this.helper.green(`${this.helper.checkmark()} No security findings detected!`)
      );
    } else {
      lines.push(this.helper.bold('Findings Summary:'));
      lines.push(this.formatFindingsSummary(summary.findingsBySeverity));
      lines.push('');

      // Findings details
      lines.push(this.helper.bold('Findings Details:'));
      lines.push(this.helper.dim('-'.repeat(50)));

      const activeFindings = result.findings.filter((f) => !f.suppressed);
      const sortedFindings = this.sortFindingsBySeverity(activeFindings);

      for (const finding of sortedFindings) {
        lines.push(this.formatFinding(finding));
      }
    }

    // Suppressed findings
    if (summary.suppressedFindings > 0) {
      lines.push('');
      lines.push(
        this.helper.dim(`(${summary.suppressedFindings} findings suppressed)`)
      );
    }

    lines.push('');
    return lines.join('\n');
  }

  private formatFindingsSummary(bySeverity: Record<Severity, number>): string {
    const parts: string[] = [];

    for (const severity of Object.values(Severity).reverse()) {
      const count = bySeverity[severity];
      if (count > 0) {
        const icon = this.helper.severityIcon(severity);
        const text = this.helper.severityColor(
          severity,
          `${severity}: ${count}`
        );
        parts.push(`  ${icon} ${text}`);
      }
    }

    return parts.join('\n');
  }

  private formatFinding(finding: Finding): string {
    const lines: string[] = [];
    const icon = this.helper.severityIcon(finding.severity);
    const severityText = this.helper.severityColor(
      finding.severity,
      finding.severity.toUpperCase()
    );

    lines.push('');
    lines.push(`${icon} ${this.helper.bold(finding.ruleId)}: ${finding.ruleName}`);
    lines.push(`   Severity: ${severityText}`);
    lines.push(`   Endpoint: ${this.helper.cyan(`${finding.endpoint.method} ${finding.endpoint.route}`)}`);
    lines.push(`   Location: ${this.helper.dim(formatSourceLocation(finding.location))}`);
    lines.push(`   Message: ${finding.message}`);
    lines.push(`   ${this.helper.dim('Recommendation:')} ${finding.recommendation}`);

    return lines.join('\n');
  }

  private sortFindingsBySeverity(findings: Finding[]): Finding[] {
    return [...findings].sort(
      (a, b) => severityOrder[b.severity] - severityOrder[a.severity]
    );
  }
}
