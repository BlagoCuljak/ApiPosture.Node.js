import { Endpoint } from '../core/models/endpoint.js';
import { Finding } from '../core/models/finding.js';
import { Severity } from '../core/models/severity.js';

export interface SecurityRule {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly severity: Severity;

  evaluate(endpoint: Endpoint): Finding[];
}

export interface RuleConfig {
  enabled: boolean;
  severity?: Severity;
  options?: Record<string, unknown>;
}
