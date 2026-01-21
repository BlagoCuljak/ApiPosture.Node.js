import { Endpoint } from '../../core/models/endpoint.js';
import { Finding, createFinding } from '../../core/models/finding.js';
import { Severity } from '../../core/models/severity.js';
import { SecurityRule } from '../rule-interface.js';

/**
 * AP005: Excessive role access
 *
 * Detects endpoints that allow too many roles (>3 by default).
 * This may indicate overly permissive access control or a need
 * for refactoring the authorization model.
 */
export class ExcessiveRoleAccess implements SecurityRule {
  readonly id = 'AP005';
  readonly name = 'Excessive role access';
  readonly description = 'Endpoint allows more than 3 roles';
  readonly severity = Severity.Low;

  private readonly maxRoles = 3;

  evaluate(endpoint: Endpoint): Finding[] {
    const findings: Finding[] = [];

    const roles = endpoint.authorization.roles;

    if (roles.length > this.maxRoles) {
      findings.push(
        createFinding({
          ruleId: this.id,
          ruleName: this.name,
          severity: this.severity,
          message: `${endpoint.method} ${endpoint.route} allows ${roles.length} roles: ${roles.join(', ')}`,
          endpoint,
          location: endpoint.location,
          recommendation:
            `This endpoint allows ${roles.length} different roles which may indicate ` +
            'overly permissive access. Consider: (1) Creating a permission-based system ' +
            'instead of role-based, (2) Creating role hierarchies, or (3) Using policies ' +
            'to combine related access patterns.',
        })
      );
    }

    return findings;
  }
}
