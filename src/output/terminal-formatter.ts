import { OutputFormatter, FormatterOptions } from './formatter-interface.js';
import { AccessibilityHelper } from './accessibility-helper.js';
import { ScanResult, getScanSummary } from '../core/models/scan-result.js';
import { Finding } from '../core/models/finding.js';
import { Endpoint } from '../core/models/endpoint.js';
import { Severity, severityOrder } from '../core/models/severity.js';
import { SecurityClassification } from '../core/models/security-classification.js';
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
    const activeFindings = result.findings.filter((f) => !f.suppressed);
    const sortedFindings = this.sortFindingsBySeverity(activeFindings);

    // Header
    lines.push('');
    lines.push(this.rule('ApiPosture Security Scan'));
    lines.push('');

    // Findings details FIRST (so they appear at top when scrolling up)
    if (sortedFindings.length > 0) {
      lines.push(this.leftRule(`Security Findings (${sortedFindings.length})`));
      for (const finding of sortedFindings) {
        lines.push(this.formatFinding(finding));
      }

      // Scroll hint separator
      lines.push('');
      lines.push(this.rule('^^^^ Scroll up for finding details ^^^^'));
      lines.push('');
    }

    // Summary table
    lines.push(this.formatSummaryTable(result, summary.totalEndpoints, summary.totalFindings));
    lines.push('');

    // Severity breakdown
    if (summary.totalFindings > 0) {
      lines.push(this.formatSeverityBreakdown(summary.findingsBySeverity));
      lines.push('');
    }

    // Suppressed findings note
    if (summary.suppressedFindings > 0) {
      lines.push(this.helper.dim(`(${summary.suppressedFindings} findings suppressed)`));
      lines.push('');
    }

    // Endpoints table at BOTTOM (visible immediately after scan)
    if (result.endpoints.length > 0) {
      lines.push(this.leftRule('Discovered Endpoints'));
      lines.push(this.formatEndpointsTable(result.endpoints));
      lines.push('');
    }

    // Final status
    if (sortedFindings.length === 0) {
      lines.push(this.helper.green(`${this.helper.checkmark()} No security findings!`));
      lines.push('');
    }

    return lines.join('\n');
  }

  private rule(title: string): string {
    const width = 60;
    const padded = ` ${title} `;
    const totalDashes = Math.max(0, width - padded.length);
    const left = Math.floor(totalDashes / 2);
    const right = totalDashes - left;
    const line = `${'─'.repeat(left)}${padded}${'─'.repeat(right)}`;
    return this.helper.dim(line);
  }

  private leftRule(title: string): string {
    const width = 60;
    const padded = ` ${title} `;
    const dashes = Math.max(0, width - padded.length);
    const line = `${padded}${'─'.repeat(dashes)}`;
    return this.helper.bold(line);
  }

  private formatSummaryTable(result: ScanResult, filteredEndpoints: number, filteredFindings: number): string {
    const rows: [string, string][] = [
      ['Scanned Path', result.projectPath],
      ['Files Scanned', String(result.filesScanned)],
      ['Total Endpoints', String(result.endpoints.length)],
      ['Filtered Endpoints', String(filteredEndpoints)],
      ['Total Findings', String(result.findings.length)],
      ['Filtered Findings', String(filteredFindings)],
      ['Scan Duration', `${result.scanDurationMs}ms`],
    ];

    const col1Width = Math.max(...rows.map(([k]) => k.length));
    const col2Width = Math.max(...rows.map(([, v]) => v.length));

    const top =    `╭${'─'.repeat(col1Width + 2)}┬${'─'.repeat(col2Width + 2)}╮`;
    const divider = `├${'─'.repeat(col1Width + 2)}┼${'─'.repeat(col2Width + 2)}┤`;
    const bottom = `╰${'─'.repeat(col1Width + 2)}┴${'─'.repeat(col2Width + 2)}╯`;

    const tableLines: string[] = [top];
    for (let i = 0; i < rows.length; i++) {
      const [key, val] = rows[i];
      const k = key.padEnd(col1Width);
      const v = val.padEnd(col2Width);
      tableLines.push(`│ ${this.helper.bold(k)} │ ${v} │`);
      if (i < rows.length - 1) tableLines.push(divider);
    }
    tableLines.push(bottom);

    return tableLines.join('\n');
  }

  private formatSeverityBreakdown(bySeverity: Record<Severity, number>): string {
    const lines: string[] = ['Severity Breakdown:'];
    for (const severity of [Severity.Critical, Severity.High, Severity.Medium, Severity.Low, Severity.Info]) {
      const count = bySeverity[severity];
      if (count > 0) {
        const icon = this.helper.severityIcon(severity);
        const text = this.helper.severityColor(severity, `${severity}: ${count}`);
        lines.push(`  ${icon} ${text}`);
      }
    }
    return lines.join('\n');
  }

  private formatEndpointsTable(endpoints: Endpoint[]): string {
    const headers = ['Route', 'Method', 'Type', 'Classification'];
    const rows = endpoints.map((ep) => [
      ep.route,
      ep.method.toUpperCase(),
      ep.type,
      this.formatClassification(ep.authorization.classification),
    ]);

    const colWidths = headers.map((h, i) =>
      Math.max(h.length, ...rows.map((r) => r[i].length))
    );

    const top =    `╭${colWidths.map((w) => '─'.repeat(w + 2)).join('┬')}╮`;
    const head =   `│${headers.map((h, i) => ` ${this.helper.bold(h.padEnd(colWidths[i]))} `).join('│')}│`;
    const divider = `├${colWidths.map((w) => '─'.repeat(w + 2)).join('┼')}┤`;
    const bottom = `╰${colWidths.map((w) => '─'.repeat(w + 2)).join('┴')}╯`;

    const tableLines: string[] = [top, head, divider];
    for (let ri = 0; ri < rows.length; ri++) {
      const row = rows[ri];
      const cells = row.map((cell, i) => {
        const padded = cell.padEnd(colWidths[i]);
        if (i === 3) {
          return ` ${this.colorClassification(endpoints[ri].authorization.classification, padded)} `;
        }
        return ` ${padded} `;
      });
      tableLines.push(`│${cells.join('│')}│`);
    }
    tableLines.push(bottom);

    return tableLines.join('\n');
  }

  private formatClassification(classification: SecurityClassification): string {
    const icon = this.helper.classificationIcon(classification);
    return `${icon} ${classification}`;
  }

  private colorClassification(classification: SecurityClassification, text: string): string {
    if (!this.helper.useColors) return text;
    const colors: Record<SecurityClassification, string> = {
      [SecurityClassification.Public]: '\x1b[31m',       // red
      [SecurityClassification.Authenticated]: '\x1b[32m', // green
      [SecurityClassification.RoleRestricted]: '\x1b[33m', // yellow
      [SecurityClassification.PolicyRestricted]: '\x1b[36m', // cyan
    };
    return `${colors[classification]}${text}\x1b[0m`;
  }

  private formatFinding(finding: Finding): string {
    const lines: string[] = [];
    const icon = this.helper.severityIcon(finding.severity);
    const severityColor = (text: string) => this.helper.severityColor(finding.severity, text);

    const headerText = `${icon} [${finding.ruleId}] ${finding.ruleName} (${finding.severity})`;
    const panelWidth = 60;
    const headerPad = Math.max(0, panelWidth - 4 - headerText.length);

    const topBorder    = `╭─ ${severityColor(headerText)} ${'─'.repeat(headerPad)}╮`;
    const bottomBorder = `╰${'─'.repeat(panelWidth - 2)}╯`;

    const route    = `${this.helper.bold('Route:')} ${this.helper.cyan(`${finding.endpoint.method.toUpperCase()} ${finding.endpoint.route}`)}`;
    const location = `${this.helper.bold('Location:')} ${this.helper.dim(formatSourceLocation(finding.location))}`;
    const message  = finding.message;
    const rec      = `${this.helper.dim('Recommendation:')} ${finding.recommendation}`;

    lines.push(topBorder);
    lines.push(`│  ${route}`);
    lines.push(`│  ${location}`);
    lines.push('│');
    lines.push(`│  ${message}`);
    lines.push('│');
    lines.push(`│  ${rec}`);
    lines.push(bottomBorder);

    return lines.join('\n');
  }

  private sortFindingsBySeverity(findings: Finding[]): Finding[] {
    return [...findings].sort(
      (a, b) => severityOrder[b.severity] - severityOrder[a.severity]
    );
  }
}
