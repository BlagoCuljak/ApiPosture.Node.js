import { Severity } from '../core/models/severity.js';
import { SecurityClassification } from '../core/models/security-classification.js';

export interface AccessibilityOptions {
  noColor: boolean;
  noIcons: boolean;
}

const severityIcons: Record<Severity, string> = {
  [Severity.Critical]: '\u26a0\ufe0f',
  [Severity.High]: '\ud83d\udd34',
  [Severity.Medium]: '\ud83d\udfe0',
  [Severity.Low]: '\ud83d\udfe1',
  [Severity.Info]: '\ud83d\udfe2',
};

const severityColors: Record<Severity, string> = {
  [Severity.Critical]: '\x1b[91m', // bright red
  [Severity.High]: '\x1b[31m', // red
  [Severity.Medium]: '\x1b[33m', // yellow
  [Severity.Low]: '\x1b[36m', // cyan
  [Severity.Info]: '\x1b[32m', // green
};

const classificationIcons: Record<SecurityClassification, string> = {
  [SecurityClassification.Public]: '\ud83c\udf10',
  [SecurityClassification.Authenticated]: '\ud83d\udd10',
  [SecurityClassification.RoleRestricted]: '\ud83d\udc65',
  [SecurityClassification.PolicyRestricted]: '\ud83d\udcdc',
};

export class AccessibilityHelper {
  private options: AccessibilityOptions;

  constructor(options: Partial<AccessibilityOptions> = {}) {
    this.options = {
      noColor: options.noColor ?? false,
      noIcons: options.noIcons ?? false,
    };
  }

  severityIcon(severity: Severity): string {
    if (this.options.noIcons) {
      return `[${severity.toUpperCase()}]`;
    }
    return severityIcons[severity];
  }

  severityColor(severity: Severity, text: string): string {
    if (this.options.noColor) {
      return text;
    }
    return `${severityColors[severity]}${text}\x1b[0m`;
  }

  classificationIcon(classification: SecurityClassification): string {
    if (this.options.noIcons) {
      return `[${classification}]`;
    }
    return classificationIcons[classification];
  }

  bold(text: string): string {
    if (this.options.noColor) {
      return text;
    }
    return `\x1b[1m${text}\x1b[0m`;
  }

  dim(text: string): string {
    if (this.options.noColor) {
      return text;
    }
    return `\x1b[2m${text}\x1b[0m`;
  }

  green(text: string): string {
    if (this.options.noColor) {
      return text;
    }
    return `\x1b[32m${text}\x1b[0m`;
  }

  red(text: string): string {
    if (this.options.noColor) {
      return text;
    }
    return `\x1b[31m${text}\x1b[0m`;
  }

  yellow(text: string): string {
    if (this.options.noColor) {
      return text;
    }
    return `\x1b[33m${text}\x1b[0m`;
  }

  cyan(text: string): string {
    if (this.options.noColor) {
      return text;
    }
    return `\x1b[36m${text}\x1b[0m`;
  }

  checkmark(): string {
    if (this.options.noIcons) {
      return '[OK]';
    }
    return '\u2714';
  }

  crossmark(): string {
    if (this.options.noIcons) {
      return '[X]';
    }
    return '\u2716';
  }
}
