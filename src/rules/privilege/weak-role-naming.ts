import { Endpoint } from '../../core/models/endpoint.js';
import { Finding, createFinding } from '../../core/models/finding.js';
import { Severity } from '../../core/models/severity.js';
import { SecurityRule } from '../rule-interface.js';

/**
 * AP006: Weak role naming
 *
 * Detects generic or weak role names that don't clearly define
 * the access level or purpose. Examples: 'User', 'Admin', 'Guest'.
 * More specific names like 'billing-admin' or 'content-editor' are preferred.
 */
export class WeakRoleNaming implements SecurityRule {
  readonly id = 'AP006';
  readonly name = 'Weak role naming';
  readonly description = 'Role names are too generic or weak';
  readonly severity = Severity.Low;

  private readonly weakPatterns = [
    /^user$/i,
    /^admin$/i,
    /^guest$/i,
    /^member$/i,
    /^moderator$/i,
    /^manager$/i,
    /^superuser$/i,
    /^root$/i,
    /^default$/i,
    /^basic$/i,
    /^standard$/i,
    /^premium$/i,
    /^vip$/i,
  ];

  evaluate(endpoint: Endpoint): Finding[] {
    const findings: Finding[] = [];

    const roles = endpoint.authorization.roles;
    const weakRoles = roles.filter((role) =>
      this.weakPatterns.some((pattern) => pattern.test(role))
    );

    if (weakRoles.length > 0) {
      findings.push(
        createFinding({
          ruleId: this.id,
          ruleName: this.name,
          severity: this.severity,
          message: `${endpoint.method} ${endpoint.route} uses generic role names: ${weakRoles.join(', ')}`,
          endpoint,
          location: endpoint.location,
          recommendation:
            'Consider using more descriptive role names that indicate specific permissions ' +
            `or responsibilities. Instead of "${weakRoles[0]}", consider names like ` +
            '"billing-admin", "content-editor", "inventory-manager", or "read-only-analyst".',
        })
      );
    }

    return findings;
  }
}
