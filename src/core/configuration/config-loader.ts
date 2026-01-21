import * as fs from 'fs';
import * as path from 'path';
import { parseSeverity } from '../models/severity.js';
import { RuleConfig } from '../../rules/rule-interface.js';

export interface ApiPostureConfig {
  rules?: Record<string, RuleConfig>;
  suppressions?: SuppressionConfig[];
  output?: {
    format?: 'terminal' | 'json' | 'markdown';
    noColor?: boolean;
    noIcons?: boolean;
  };
  scan?: {
    excludePatterns?: string[];
    includePatterns?: string[];
  };
}

export interface SuppressionConfig {
  ruleId?: string;
  route?: string;
  routePattern?: string;
  method?: string;
  reason: string;
}

const CONFIG_FILE_NAMES = [
  '.apiposture.json',
  'apiposture.json',
  '.apiposture.config.json',
];

export class ConfigLoader {
  async load(configPath?: string): Promise<ApiPostureConfig> {
    let filePath: string | null = configPath ?? null;

    // If no path specified, search for config file
    if (!filePath) {
      filePath = this.findConfigFile(process.cwd());
    }

    if (!filePath) {
      return {};
    }

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const config = JSON.parse(content) as ApiPostureConfig;
      return this.validateConfig(config);
    } catch (error) {
      if (configPath) {
        // Only throw if user explicitly specified a config path
        throw new Error(`Failed to load config from ${filePath}: ${error}`);
      }
      return {};
    }
  }

  private findConfigFile(startDir: string): string | null {
    let currentDir = startDir;
    let parentDir = path.dirname(currentDir);

    while (currentDir !== parentDir) {
      for (const fileName of CONFIG_FILE_NAMES) {
        const filePath = path.join(currentDir, fileName);
        if (fs.existsSync(filePath)) {
          return filePath;
        }
      }

      currentDir = parentDir;
      parentDir = path.dirname(currentDir);
    }

    return null;
  }

  private validateConfig(config: ApiPostureConfig): ApiPostureConfig {
    // Validate rules config
    if (config.rules) {
      for (const [ruleId, ruleConfig] of Object.entries(config.rules)) {
        if (ruleConfig.severity) {
          const parsed = parseSeverity(ruleConfig.severity as unknown as string);
          if (!parsed) {
            console.warn(`Invalid severity "${ruleConfig.severity}" for rule ${ruleId}`);
          }
        }
      }
    }

    // Validate suppressions
    if (config.suppressions) {
      config.suppressions = config.suppressions.filter((s) => {
        if (!s.reason) {
          console.warn('Suppression missing required "reason" field, skipping');
          return false;
        }
        return true;
      });
    }

    return config;
  }
}
