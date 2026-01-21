import { Severity } from '../core/models/severity.js';
import { SecurityClassification, parseSecurityClassification } from '../core/models/security-classification.js';
import { HttpMethod, parseHttpMethod } from '../core/models/http-method.js';
import { EndpointType, parseEndpointType } from '../core/models/endpoint-type.js';

export interface ScanOptions {
  output: 'terminal' | 'json' | 'markdown';
  outputFile?: string;
  config?: string;
  severity?: Severity;
  failOn?: Severity;
  sortBy?: 'severity' | 'route' | 'method' | 'classification';
  sortDir?: 'asc' | 'desc';
  classification?: SecurityClassification[];
  method?: HttpMethod[];
  routeContains?: string;
  apiStyle?: EndpointType[];
  rule?: string[];
  groupBy?: string;
  noColor: boolean;
  noIcons: boolean;
}

export const defaultScanOptions: ScanOptions = {
  output: 'terminal',
  noColor: false,
  noIcons: false,
};

export function parseClassificationList(value: string): SecurityClassification[] {
  return value
    .split(',')
    .map((v) => parseSecurityClassification(v.trim()))
    .filter((v): v is SecurityClassification => v !== undefined);
}

export function parseMethodList(value: string): HttpMethod[] {
  return value
    .split(',')
    .map((v) => parseHttpMethod(v.trim()))
    .filter((v): v is HttpMethod => v !== undefined);
}

export function parseApiStyleList(value: string): EndpointType[] {
  return value
    .split(',')
    .map((v) => parseEndpointType(v.trim()))
    .filter((v): v is EndpointType => v !== undefined);
}

export function parseRuleList(value: string): string[] {
  return value.split(',').map((v) => v.trim().toUpperCase());
}
