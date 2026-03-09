import { Severity } from '../core/models/severity.js';
import { SecurityClassification } from '../core/models/security-classification.js';

export interface AccessibilityOptions {
  noColor: boolean;
  noIcons: boolean;
}

const severityIcons: Record<Severity, string> = {
  [Severity.Critical]: '\u274c',      // Red X
  [Severity.High]: '\u26a0\ufe0f',   // Warning sign
  [Severity.Medium]: '\u26a1',        // Lightning bolt
  [Severity.Low]: '\u2139\ufe0f',    // Info
  [Severity.Info]: '\u2139\ufe0f',   // Info
};

const severityLabels: Record<Severity, string> = {
  [Severity.Critical]: '[CRIT]',
  [Severity.High]: '[HIGH]',
  [Severity.Medium]: '[MED]',
  [Severity.Low]: '[LOW]',
  [Severity.Info]: '[INFO]',
};

const severityColors: Record<Severity, string> = {
  [Severity.Critical]: '\x1b[91m', // bright red
  [Severity.High]: '\x1b[31m', // red
  [Severity.Medium]: '\x1b[33m', // yellow
  [Severity.Low]: '\x1b[36m', // cyan
  [Severity.Info]: '\x1b[32m', // green
};

const classificationIcons: Record<SecurityClassification, string> = {
  [SecurityClassification.Public]: '\ud83d\udd13',          // Unlocked
  [SecurityClassification.Authenticated]: '\ud83d\udd10',   // Lock with key
  [SecurityClassification.RoleRestricted]: '\ud83d\udd12',  // Locked
  [SecurityClassification.PolicyRestricted]: '\ud83d\udee1\ufe0f', // Shield
};

const classificationLabels: Record<SecurityClassification, string> = {
  [SecurityClassification.Public]: '[PUBLIC]',
  [SecurityClassification.Authenticated]: '[AUTH]',
  [SecurityClassification.RoleRestricted]: '[ROLE]',
  [SecurityClassification.PolicyRestricted]: '[POLICY]',
};

export class AccessibilityHelper {
  private options: AccessibilityOptions;

  constructor(options: Partial<AccessibilityOptions> = {}) {
    // CLI flag takes highest priority; then auto-detect from environment
    const noColorFlag = options.noColor ?? false;
    const noIconsFlag = options.noIcons ?? false;

    this.options = {
      noColor: AccessibilityHelper.determineNoColor(noColorFlag),
      noIcons: AccessibilityHelper.determineNoIcons(noIconsFlag),
    };
  }

  private static determineNoColor(noColorFlag: boolean): boolean {
    if (noColorFlag) return true;
    // NO_COLOR environment variable (https://no-color.org/)
    if (process.env['NO_COLOR'] !== undefined && process.env['NO_COLOR'] !== '') return true;
    // Disable colors when output is redirected (not a TTY)
    if (process.stdout.isTTY !== true) return true;
    return false;
  }

  private static determineNoIcons(noIconsFlag: boolean): boolean {
    if (noIconsFlag) return true;
    // Auto-detect: disable icons on Windows legacy consoles (cmd.exe, PowerShell)
    // which cannot render emoji. Windows Terminal sets WT_SESSION and handles emoji fine.
    if (process.platform === 'win32' && !process.env['WT_SESSION']) return true;
    return false;
  }

  get useColors(): boolean {
    return !this.options.noColor;
  }

  get useIcons(): boolean {
    return !this.options.noIcons;
  }

  severityIcon(severity: Severity): string {
    if (this.options.noIcons) {
      return severityLabels[severity];
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
      return classificationLabels[classification];
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
    return '\u2705';
  }

  crossmark(): string {
    if (this.options.noIcons) {
      return '[FAIL]';
    }
    return '\u274c';
  }

  warningmark(): string {
    if (this.options.noIcons) {
      return '[WARN]';
    }
    return '\u26a0\ufe0f';
  }
}
