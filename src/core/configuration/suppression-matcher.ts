import { Finding } from '../models/finding.js';
import { Endpoint } from '../models/endpoint.js';
import { SuppressionConfig } from './config-loader.js';

export class SuppressionMatcher {
  private suppressions: SuppressionConfig[];

  constructor(suppressions: SuppressionConfig[] = []) {
    this.suppressions = suppressions;
  }

  applySuppressionsToFindings(findings: Finding[]): Finding[] {
    return findings.map((finding) => {
      const suppression = this.findMatchingSuppression(finding);
      if (suppression) {
        return {
          ...finding,
          suppressed: true,
          suppressionReason: suppression.reason,
        };
      }
      return finding;
    });
  }

  isEndpointSuppressed(endpoint: Endpoint, ruleId: string): SuppressionConfig | null {
    for (const suppression of this.suppressions) {
      if (this.matchesEndpoint(suppression, endpoint, ruleId)) {
        return suppression;
      }
    }
    return null;
  }

  private findMatchingSuppression(finding: Finding): SuppressionConfig | null {
    for (const suppression of this.suppressions) {
      if (this.matchesFinding(suppression, finding)) {
        return suppression;
      }
    }
    return null;
  }

  private matchesFinding(suppression: SuppressionConfig, finding: Finding): boolean {
    return this.matchesEndpoint(suppression, finding.endpoint, finding.ruleId);
  }

  private matchesEndpoint(
    suppression: SuppressionConfig,
    endpoint: Endpoint,
    ruleId: string
  ): boolean {
    // Check rule ID
    if (suppression.ruleId && suppression.ruleId !== ruleId) {
      return false;
    }

    // Check HTTP method
    if (suppression.method && suppression.method.toUpperCase() !== endpoint.method) {
      return false;
    }

    // Check exact route match
    if (suppression.route && suppression.route !== endpoint.route) {
      return false;
    }

    // Check route pattern (regex or glob-like)
    if (suppression.routePattern) {
      if (!this.matchesRoutePattern(suppression.routePattern, endpoint.route)) {
        return false;
      }
    }

    return true;
  }

  private matchesRoutePattern(pattern: string, route: string): boolean {
    // Convert glob-like pattern to regex
    // * matches any segment, ** matches any path
    let regexPattern = pattern
      .replace(/\*\*/g, '<<<DOUBLE_STAR>>>')
      .replace(/\*/g, '[^/]+')
      .replace(/<<<DOUBLE_STAR>>>/g, '.*');

    // Escape regex special chars except those we converted
    regexPattern = regexPattern.replace(/[.+^${}()|[\]\\]/g, '\\$&');

    // Anchor the pattern
    regexPattern = `^${regexPattern}$`;

    try {
      const regex = new RegExp(regexPattern);
      return regex.test(route);
    } catch {
      return false;
    }
  }
}
