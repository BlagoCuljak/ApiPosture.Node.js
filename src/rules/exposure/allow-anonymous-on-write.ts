import { Endpoint } from '../../core/models/endpoint.js';
import { Finding, createFinding } from '../../core/models/finding.js';
import { Severity } from '../../core/models/severity.js';
import { isWriteMethod } from '../../core/models/http-method.js';
import { SecurityRule } from '../rule-interface.js';

/**
 * AP002: AllowAnonymous on write operation
 *
 * Detects write operations (POST, PUT, DELETE, PATCH) that have been
 * explicitly marked as public. Write operations should typically require
 * authentication to prevent unauthorized data modification.
 */
export class AllowAnonymousOnWrite implements SecurityRule {
  readonly id = 'AP002';
  readonly name = 'AllowAnonymous on write operation';
  readonly description =
    'Write operation (POST/PUT/DELETE/PATCH) is explicitly marked as public';
  readonly severity = Severity.High;

  evaluate(endpoint: Endpoint): Finding[] {
    const findings: Finding[] = [];

    const auth = endpoint.authorization;

    // Only flag if:
    // 1. It's a write method
    // 2. It's explicitly marked as public (intentional)
    if (isWriteMethod(endpoint.method) && auth.isExplicitlyPublic) {
      findings.push(
        createFinding({
          ruleId: this.id,
          ruleName: this.name,
          severity: this.severity,
          message: `${endpoint.method} ${endpoint.route} is a write operation explicitly marked as public`,
          endpoint,
          location: endpoint.location,
          recommendation: this.getRecommendation(endpoint),
        })
      );
    }

    return findings;
  }

  private getRecommendation(endpoint: Endpoint): string {
    return (
      `Write operations like ${endpoint.method} typically require authentication. ` +
      'If public access is truly needed (e.g., user registration, contact form), ' +
      'consider adding rate limiting and input validation. ' +
      'Otherwise, remove the public marker and add authentication.'
    );
  }
}
