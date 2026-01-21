import { Endpoint } from '../core/models/endpoint.js';
import { Finding } from '../core/models/finding.js';
import { SecurityRule, RuleConfig } from './rule-interface.js';

// Import all rules
import { PublicWithoutExplicitIntent } from './exposure/public-without-explicit-intent.js';
import { AllowAnonymousOnWrite } from './exposure/allow-anonymous-on-write.js';
import { ControllerActionConflict } from './consistency/controller-action-conflict.js';
import { MissingAuthOnWrites } from './consistency/missing-auth-on-writes.js';
import { ExcessiveRoleAccess } from './privilege/excessive-role-access.js';
import { WeakRoleNaming } from './privilege/weak-role-naming.js';
import { SensitiveRouteKeywords } from './surface/sensitive-route-keywords.js';
import { UnprotectedEndpoint } from './surface/unprotected-endpoint.js';

export interface RuleEngineConfig {
  rules?: Record<string, RuleConfig>;
}

export class RuleEngine {
  private rules: SecurityRule[] = [];

  constructor(config?: RuleEngineConfig) {
    this.initializeRules(config);
  }

  private initializeRules(config?: RuleEngineConfig): void {
    const allRules: SecurityRule[] = [
      new PublicWithoutExplicitIntent(),
      new AllowAnonymousOnWrite(),
      new ControllerActionConflict(),
      new MissingAuthOnWrites(),
      new ExcessiveRoleAccess(),
      new WeakRoleNaming(),
      new SensitiveRouteKeywords(),
      new UnprotectedEndpoint(),
    ];

    // Filter and configure rules based on config
    for (const rule of allRules) {
      const ruleConfig = config?.rules?.[rule.id];

      if (ruleConfig?.enabled === false) {
        continue;
      }

      this.rules.push(rule);
    }
  }

  evaluate(endpoints: Endpoint[]): Finding[] {
    const findings: Finding[] = [];

    for (const endpoint of endpoints) {
      for (const rule of this.rules) {
        const ruleFindings = rule.evaluate(endpoint);
        findings.push(...ruleFindings);
      }
    }

    return findings;
  }

  getRules(): SecurityRule[] {
    return [...this.rules];
  }

  getRuleById(id: string): SecurityRule | undefined {
    return this.rules.find((r) => r.id === id);
  }
}
