import { Endpoint } from '../../core/models/endpoint.js';
import { Finding, createFinding } from '../../core/models/finding.js';
import { Severity } from '../../core/models/severity.js';
import { SecurityClassification } from '../../core/models/security-classification.js';
import { SecurityRule } from '../rule-interface.js';

/**
 * AP007: Sensitive route keywords
 *
 * Detects publicly accessible routes that contain sensitive keywords
 * like 'admin', 'debug', 'internal', 'export', etc. These routes
 * typically should not be publicly accessible.
 */
export class SensitiveRouteKeywords implements SecurityRule {
  readonly id = 'AP007';
  readonly name = 'Sensitive route keywords';
  readonly description = 'Public route contains sensitive keywords';
  readonly severity = Severity.Medium;

  private readonly sensitiveKeywords = [
    'admin',
    'debug',
    'internal',
    'export',
    'import',
    'backup',
    'config',
    'settings',
    'system',
    'management',
    'dashboard',
    'metrics',
    'logs',
    'audit',
    'secret',
    'private',
    'hidden',
    'test',
    'dev',
    'staging',
  ];

  evaluate(endpoint: Endpoint): Finding[] {
    const findings: Finding[] = [];

    const auth = endpoint.authorization;

    // Only check public endpoints
    if (auth.classification !== SecurityClassification.Public) {
      return findings;
    }

    const routeLower = endpoint.route.toLowerCase();
    const foundKeywords = this.sensitiveKeywords.filter((keyword) =>
      routeLower.includes(keyword)
    );

    if (foundKeywords.length > 0) {
      findings.push(
        createFinding({
          ruleId: this.id,
          ruleName: this.name,
          severity: this.severity,
          message: `${endpoint.method} ${endpoint.route} is public but contains sensitive keywords: ${foundKeywords.join(', ')}`,
          endpoint,
          location: endpoint.location,
          recommendation:
            `Routes containing "${foundKeywords[0]}" typically indicate sensitive functionality ` +
            'that should require authentication. Add authentication middleware or guards, ' +
            'or rename the route if it is truly meant to be public.',
        })
      );
    }

    return findings;
  }
}
