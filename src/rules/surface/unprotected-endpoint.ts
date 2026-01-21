import { Endpoint } from '../../core/models/endpoint.js';
import { Finding, createFinding } from '../../core/models/finding.js';
import { Severity } from '../../core/models/severity.js';
import { SecurityClassification } from '../../core/models/security-classification.js';
import { SecurityRule } from '../rule-interface.js';

/**
 * AP008: Unprotected endpoint
 *
 * Detects endpoints with no authentication middleware chain at all.
 * This is different from AP001 in that it specifically checks for
 * the absence of any middleware, not just auth middleware.
 */
export class UnprotectedEndpoint implements SecurityRule {
  readonly id = 'AP008';
  readonly name = 'Unprotected endpoint';
  readonly description = 'Endpoint has no middleware chain for protection';
  readonly severity = Severity.High;

  evaluate(endpoint: Endpoint): Finding[] {
    const findings: Finding[] = [];

    const auth = endpoint.authorization;

    // Only flag if:
    // 1. It's public (no auth)
    // 2. No middleware chain at all
    // 3. No guards
    // 4. Not explicitly marked as public
    if (
      auth.classification === SecurityClassification.Public &&
      auth.middlewareChain.length === 0 &&
      auth.guardNames.length === 0 &&
      !auth.isExplicitlyPublic
    ) {
      findings.push(
        createFinding({
          ruleId: this.id,
          ruleName: this.name,
          severity: this.severity,
          message: `${endpoint.method} ${endpoint.route} has no middleware chain`,
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
          'This endpoint has no middleware. Consider adding: ' +
          '(1) Authentication middleware, (2) Rate limiting, (3) Input validation, ' +
          '(4) Request logging. Example: app.get("/path", auth, validate, handler)'
        );
      case 'nestjs':
        return (
          'This endpoint has no guards or interceptors. Consider adding: ' +
          '(1) @UseGuards() for authentication, (2) @UseInterceptors() for logging, ' +
          '(3) @UsePipes() for validation.'
        );
      case 'fastify':
        return (
          'This endpoint has no hooks. Consider adding preHandler hooks for ' +
          'authentication, validation, and logging.'
        );
      case 'koa':
        return (
          'This endpoint has no middleware chain. Consider adding middleware for ' +
          'authentication, validation, and error handling.'
        );
      default:
        return 'Add middleware for authentication, validation, and security.';
    }
  }
}
