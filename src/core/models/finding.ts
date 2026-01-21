import { Endpoint } from './endpoint.js';
import { Severity } from './severity.js';
import { SourceLocation } from './source-location.js';

export interface Finding {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  message: string;
  endpoint: Endpoint;
  location: SourceLocation;
  recommendation: string;
  suppressed: boolean;
  suppressionReason?: string;
}

export function createFinding(
  partial: Omit<Finding, 'suppressed' | 'suppressionReason'> & {
    suppressed?: boolean;
    suppressionReason?: string;
  }
): Finding {
  return {
    ...partial,
    suppressed: partial.suppressed ?? false,
    suppressionReason: partial.suppressionReason,
  };
}
