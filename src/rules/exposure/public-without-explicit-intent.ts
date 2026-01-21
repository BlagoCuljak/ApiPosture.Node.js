import { Endpoint } from '../../core/models/endpoint.js';
import { Finding, createFinding } from '../../core/models/finding.js';
import { Severity } from '../../core/models/severity.js';
import { SecurityClassification } from '../../core/models/security-classification.js';
import { SecurityRule } from '../rule-interface.js';

/**
 * AP001: Public without explicit intent
 *
 * Detects endpoints that are publicly accessible without an explicit
 * @Public decorator or allowAnonymous middleware. This catches endpoints
 * that may be accidentally exposed due to missing authentication.
 */
export class PublicWithoutExplicitIntent implements SecurityRule {
  readonly id = 'AP001';
  readonly name = 'Public without explicit intent';
  readonly description =
    'Endpoint is publicly accessible without explicit @Public or allowAnonymous marker';
  readonly severity = Severity.High;

  evaluate(endpoint: Endpoint): Finding[] {
    const findings: Finding[] = [];

    const auth = endpoint.authorization;

    // Only flag if:
    // 1. Endpoint is classified as public
    // 2. No explicit public marker
    // 3. No authentication middleware
    if (
      auth.classification === SecurityClassification.Public &&
      !auth.isExplicitlyPublic &&
      !auth.isAuthenticated &&
      auth.guardNames.length === 0
    ) {
      findings.push(
        createFinding({
          ruleId: this.id,
          ruleName: this.name,
          severity: this.severity,
          message: `${endpoint.method} ${endpoint.route} is publicly accessible without explicit intent`,
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
          'Add authentication middleware (e.g., passport.authenticate) or ' +
          'mark as explicitly public with allowAnonymous middleware if intentional.'
        );
      case 'nestjs':
        return (
          'Add @UseGuards(AuthGuard) to require authentication, or ' +
          'add @Public() decorator if public access is intentional.'
        );
      case 'fastify':
        return (
          'Add preHandler hook for authentication or ' +
          'mark as explicitly public if intentional.'
        );
      case 'koa':
        return (
          'Add authentication middleware or ' +
          'mark as explicitly public if intentional.'
        );
      default:
        return 'Add authentication or mark as explicitly public if intentional.';
    }
  }
}
