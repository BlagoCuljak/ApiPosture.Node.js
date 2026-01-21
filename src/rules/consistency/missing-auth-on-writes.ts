import { Endpoint } from '../../core/models/endpoint.js';
import { Finding, createFinding } from '../../core/models/finding.js';
import { Severity } from '../../core/models/severity.js';
import { SecurityClassification } from '../../core/models/security-classification.js';
import { isWriteMethod } from '../../core/models/http-method.js';
import { SecurityRule } from '../rule-interface.js';

/**
 * AP004: Missing authentication on write operations
 *
 * Detects write operations (POST, PUT, DELETE, PATCH) that have no
 * authentication and no explicit public marker. This is the most
 * dangerous scenario: an unprotected write endpoint that may have
 * been accidentally left open.
 */
export class MissingAuthOnWrites implements SecurityRule {
  readonly id = 'AP004';
  readonly name = 'Missing authentication on write operations';
  readonly description =
    'Write operation has no authentication and no explicit public marker';
  readonly severity = Severity.Critical;

  evaluate(endpoint: Endpoint): Finding[] {
    const findings: Finding[] = [];

    const auth = endpoint.authorization;

    // Flag if:
    // 1. It's a write method
    // 2. No authentication
    // 3. No explicit public marker (so it's accidentally open, not intentionally)
    if (
      isWriteMethod(endpoint.method) &&
      auth.classification === SecurityClassification.Public &&
      !auth.isAuthenticated &&
      !auth.isExplicitlyPublic
    ) {
      findings.push(
        createFinding({
          ruleId: this.id,
          ruleName: this.name,
          severity: this.severity,
          message: `${endpoint.method} ${endpoint.route} is an unprotected write operation`,
          endpoint,
          location: endpoint.location,
          recommendation: this.getRecommendation(endpoint),
        })
      );
    }

    return findings;
  }

  private getRecommendation(endpoint: Endpoint): string {
    switch (endpoint.type) {
      case 'express':
        return (
          'CRITICAL: Add authentication middleware immediately. ' +
          'Example: router.post("/path", passport.authenticate("jwt"), handler)'
        );
      case 'nestjs':
        return (
          'CRITICAL: Add @UseGuards(AuthGuard) decorator immediately. ' +
          'If this endpoint must be public, add @Public() to make intent explicit.'
        );
      case 'fastify':
        return (
          'CRITICAL: Add authentication via preHandler hook. ' +
          'Example: { preHandler: [fastify.authenticate] }'
        );
      case 'koa':
        return 'CRITICAL: Add authentication middleware before the route handler.';
      default:
        return 'CRITICAL: Add authentication to this write endpoint immediately.';
    }
  }
}
