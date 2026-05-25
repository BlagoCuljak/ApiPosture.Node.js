import { OutputFormatter } from './formatter-interface.js';
import { ScanResult, getScanSummary } from '../core/models/scan-result.js';
import { Finding } from '../core/models/finding.js';
import { Severity, severityOrder } from '../core/models/severity.js';
import { formatSourceLocation } from '../core/models/source-location.js';

export class HtmlFormatter implements OutputFormatter {
  readonly name = 'html';

  format(result: ScanResult): string {
    const summary = getScanSummary(result);
    const activeFindings = result.findings.filter((f) => !f.suppressed);
    const sortedFindings = this.sortFindingsBySeverity(activeFindings);

    const lines: string[] = [];

    lines.push(this.renderHead());
    lines.push('<body><div class="container">');
    lines.push('<h1>&#x1F6E1;&#xFE0F; ApiPosture Security Scan Report</h1>');
    lines.push(`<div class="meta"><strong>Generated:</strong> ${new Date().toISOString()} UTC</div>`);
    lines.push(this.renderSummary(result, summary));
    lines.push(this.renderSeverityBreakdown(summary));

    if (result.endpoints.length > 0) {
      lines.push(this.renderEndpoints(result));
    }

    if (sortedFindings.length > 0) {
      lines.push('<h2>Security Findings</h2>');
      for (const finding of sortedFindings) {
        lines.push(this.renderFinding(finding));
      }
    } else {
      lines.push('<h2>Security Findings</h2>');
      lines.push('<div class="success">&#x2705; No security findings detected!</div>');
    }

    if (summary.suppressedFindings > 0) {
      lines.push('<h2>Suppressed Findings</h2>');
      lines.push(`<p class="section-subtitle">${summary.suppressedFindings} finding(s) were suppressed.</p>`);
    }

    lines.push('</div></body></html>');
    return lines.join('\n');
  }

  private renderHead(): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ApiPosture Security Scan Report</title>
    <style>
        :root {
            --bg: #f3f6fb; --panel: #ffffff; --panel-light: #f8fafc;
            --border: #dbe3ee; --text: #1e293b; --muted: #64748b;
            --critical: #dc2626; --high: #ea580c; --medium: #d97706;
            --low: #2563eb; --info: #64748b; --shadow: rgba(15,23,42,0.08);
        }
        * { box-sizing: border-box; } html { scroll-behavior: smooth; }
        body { margin:0; padding:32px; background:linear-gradient(to bottom right,#f8fafc,#eef4fb); color:var(--text); font-family:Inter,Segoe UI,Arial,sans-serif; line-height:1.6; }
        .container { max-width:1500px; margin:0 auto; }
        h1 { font-size:42px; margin-bottom:8px; color:#0f172a; }
        h2 { margin-top:50px; margin-bottom:20px; border-bottom:1px solid var(--border); padding-bottom:12px; color:#0f172a; }
        h3 { margin-top:0; color:#1e293b; }
        .meta { color:var(--muted); margin-bottom:40px; }
        .summary-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:18px; margin-bottom:40px; }
        .summary-card { background:var(--panel); border:1px solid var(--border); border-radius:16px; padding:24px; transition:0.2s ease; box-shadow:0 6px 20px var(--shadow); }
        .summary-card:hover { transform:translateY(-2px); }
        .summary-card .label { color:var(--muted); font-size:14px; }
        .summary-card .value { font-size:34px; font-weight:700; margin-top:8px; color:#0f172a; }
        table { width:100%; border-collapse:collapse; margin-top:18px; margin-bottom:30px; overflow:hidden; border-radius:14px; box-shadow:0 6px 18px var(--shadow); }
        th { background:#eff6ff; color:#1e293b; text-align:left; padding:15px; font-size:14px; border-bottom:1px solid var(--border); }
        td { background:var(--panel); border-top:1px solid var(--border); padding:15px; vertical-align:top; }
        tr:hover td { background:#f8fbff; }
        code { background:#eef2ff; color:#1d4ed8; padding:4px 8px; border-radius:6px; font-family:Consolas,monospace; font-size:13px; }
        .finding { background:var(--panel); border:1px solid var(--border); border-left:6px solid var(--medium); border-radius:16px; padding:24px; margin-bottom:24px; transition:0.2s ease; box-shadow:0 6px 18px var(--shadow); }
        .finding:hover { transform:translateY(-2px); }
        .finding.critical { border-left-color:var(--critical); } .finding.high { border-left-color:var(--high); }
        .finding.medium { border-left-color:var(--medium); } .finding.low { border-left-color:var(--low); }
        .severity-badge { display:inline-block; padding:5px 12px; border-radius:999px; font-size:12px; font-weight:bold; text-transform:uppercase; margin-bottom:14px; }
        .severity-critical { background:#fee2e2; color:#b91c1c; } .severity-high { background:#ffedd5; color:#c2410c; }
        .severity-medium { background:#fef3c7; color:#b45309; } .severity-low { background:#dbeafe; color:#1d4ed8; }
        .severity-info { background:#e5e7eb; color:#4b5563; }
        .recommendation { margin-top:20px; background:#f8fafc; border:1px solid var(--border); border-radius:12px; padding:18px; }
        .recommendation-title { color:#2563eb; font-weight:bold; margin-bottom:10px; }
        .severity-list { padding-left:18px; } .severity-list li { margin-bottom:8px; }
        .success { padding:18px; border-radius:12px; background:#dcfce7; color:#166534; border:1px solid #86efac; font-weight:bold; }
        .section-subtitle { color:var(--muted); margin-bottom:20px; }
    </style>
</head>`;
  }

  private renderSummary(result: ScanResult, summary: ReturnType<typeof getScanSummary>): string {
    const cards = [
      { label: 'Files Scanned', value: String(result.filesScanned) },
      { label: 'Endpoints Found', value: String(summary.totalEndpoints) },
      { label: 'Total Findings', value: String(summary.totalFindings) },
      { label: 'Suppressed', value: String(summary.suppressedFindings) },
      { label: 'Scan Duration', value: `${result.scanDurationMs}ms` },
    ];

    const cardsHtml = cards
      .map(
        (c) =>
          `<div class="summary-card"><div class="label">${this.escape(c.label)}</div><div class="value">${this.escape(c.value)}</div></div>`
      )
      .join('\n');

    return `<h2>Summary</h2>
<div class="summary-grid">${cardsHtml}</div>
<p class="section-subtitle"><strong>Project:</strong> <code>${this.escape(result.projectPath)}</code> &mdash; <strong>Date:</strong> ${this.escape(result.scanDate.toISOString())}</p>`;
  }

  private renderSeverityBreakdown(summary: ReturnType<typeof getScanSummary>): string {
    if (summary.totalFindings === 0) return '';

    const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info'] as Severity[];
    const items = order
      .filter((s) => (summary.findingsBySeverity[s] ?? 0) > 0)
      .map(
        (s) =>
          `<li><span class="severity-badge severity-${s}">${this.escape(s)}</span> &mdash; ${summary.findingsBySeverity[s]} finding(s)</li>`
      )
      .join('\n');

    return `<h2>Severity Breakdown</h2><ul class="severity-list">${items}</ul>`;
  }

  private renderEndpoints(result: ScanResult): string {
    const rows = result.endpoints
      .map(
        (ep) =>
          `<tr><td><code>${this.escape(ep.route)}</code></td><td>${this.escape(ep.method)}</td><td>${this.escape(ep.authorization.classification)}</td><td>${this.escape(ep.type)}</td><td>${this.escape(ep.location.filePath)}:${ep.location.line}</td></tr>`
      )
      .join('\n');

    return `<h2>Discovered Endpoints</h2>
<table>
  <thead><tr><th>Route</th><th>Method</th><th>Classification</th><th>Framework</th><th>Location</th></tr></thead>
  <tbody>${rows}</tbody>
</table>`;
  }

  private renderFinding(finding: Finding): string {
    const sev = finding.severity.toLowerCase();
    const loc = formatSourceLocation(finding.location);

    return `<div class="finding ${this.escape(sev)}">
  <span class="severity-badge severity-${this.escape(sev)}">${this.escape(finding.severity)}</span>
  <h3>[${this.escape(finding.ruleId)}] ${this.escape(finding.ruleName)}</h3>
  <p><strong>Endpoint:</strong> <code>${this.escape(finding.endpoint.method)} ${this.escape(finding.endpoint.route)}</code></p>
  <p><strong>Location:</strong> <code>${this.escape(loc)}</code></p>
  <p>${this.escape(finding.message)}</p>
  <div class="recommendation">
    <div class="recommendation-title">Recommendation</div>
    <div>${this.escape(finding.recommendation)}</div>
  </div>
</div>`;
  }

  private escape(value: string | null | undefined): string {
    if (!value) return '';
    return value
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
  }

  private sortFindingsBySeverity(findings: Finding[]): Finding[] {
    return [...findings].sort(
      (a, b) => severityOrder[b.severity] - severityOrder[a.severity]
    );
  }
}
