import { ScanResult } from '../core/models/scan-result.js';

export interface OutputFormatter {
  readonly name: string;
  format(result: ScanResult): string;
}

export interface FormatterOptions {
  noColor?: boolean;
  noIcons?: boolean;
  verbose?: boolean;
}
