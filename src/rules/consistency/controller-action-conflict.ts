import { Endpoint } from '../../core/models/endpoint.js';
import { Finding, createFinding } from '../../core/models/finding.js';
import { Severity } from '../../core/models/severity.js';
import { EndpointType } from '../../core/models/endpoint-type.js';
import { SecurityRule } from '../rule-interface.js';

/**
 * AP003: Controller/action authorization conflict
 *
 * Detects when a method-level @Public decorator overrides class-level
 * @UseGuards. This can indicate a security misconfiguration where
 * developers may not realize the method is bypassing controller auth.
 */
export class ControllerActionConflict implements SecurityRule {
  readonly id = 'AP003';
  readonly name = 'Controller/action authorization conflict';
  readonly description =
    'Method-level public marker overrides class-level authentication guards';
  readonly severity = Severity.Medium;

  evaluate(endpoint: Endpoint): Finding[] {
    const findings: Finding[] = [];

    // This rule primarily applies to NestJS decorator patterns
    if (endpoint.type !== EndpointType.NestJS) {
      return findings;
    }

    const auth = endpoint.authorization;

    // Detect conflict: both authenticated (from class) and explicitly public (from method)
    if (auth.isAuthenticated && auth.isExplicitlyPublic) {
      findings.push(
        createFinding({
          ruleId: this.id,
          ruleName: this.name,
          severity: this.severity,
          message: `${endpoint.method} ${endpoint.route} has @Public overriding class-level guards`,
          endpoint,
          location: endpoint.location,
          recommendation:
            'This endpoint has @Public decorator that overrides class-level @UseGuards. ' +
            'Ensure this is intentional. If the endpoint should be public, consider ' +
            'documenting why. If not, remove the @Public decorator.',
        })
      );
    }

    return findings;
  }
}
