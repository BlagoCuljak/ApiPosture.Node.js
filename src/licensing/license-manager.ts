import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import axios from 'axios';
import {
  LicenseInfo,
  LicenseContext,
  createCommunityContext,
  createLicensedContext,
} from '../core/licensing/license-context.js';
import {
  LicenseFeature,
  proFeatures,
  enterpriseFeatures,
} from '../core/licensing/license-features.js';

const LICENSE_DIR = path.join(os.homedir(), '.apiposture');
const LICENSE_FILE = path.join(LICENSE_DIR, 'license.json');
const LICENSE_SERVER = 'https://apiposture.com/api/license';
const ENV_VAR_KEY = 'APIPOSTURE_LICENSE_KEY';

export interface ActivationResult {
  success: boolean;
  error?: string;
  licenseType?: string;
  expiresAt?: Date;
  features?: string[];
}

export interface DeactivationResult {
  success: boolean;
  error?: string;
}

export interface LicenseStatus {
  isActive: boolean;
  licenseType?: string;
  expiresAt?: Date;
  features?: string[];
}

export class LicenseManager {
  private context: LicenseContext;

  constructor() {
    this.context = this.loadContext();
  }

  async activate(key: string): Promise<ActivationResult> {
    try {
      // Validate key format
      if (!this.isValidKeyFormat(key)) {
        return { success: false, error: 'Invalid license key format' };
      }

      // Try to activate with server
      const response = await this.activateWithServer(key);

      if (response.success && response.license) {
        // Save license locally
        this.saveLicense(response.license);
        this.context = createLicensedContext(response.license);

        return {
          success: true,
          licenseType: response.license.type,
          expiresAt: response.license.expiresAt ?? undefined,
          features: response.license.features,
        };
      }

      return { success: false, error: response.error ?? 'Activation failed' };
    } catch (error) {
      // For now, allow offline activation for development
      const offlineResult = this.activateOffline(key);
      if (offlineResult.success) {
        return offlineResult;
      }
      return {
        success: false,
        error: `Activation failed: ${error instanceof Error ? error.message : error}`,
      };
    }
  }

  async deactivate(): Promise<DeactivationResult> {
    try {
      // Try to deactivate with server
      if (this.context.info?.key) {
        await this.deactivateWithServer(this.context.info.key);
      }
    } catch {
      // Continue with local deactivation even if server fails
    }

    // Remove local license
    this.removeLicense();
    this.context = createCommunityContext();

    return { success: true };
  }

  async getStatus(): Promise<LicenseStatus> {
    if (!this.context.isLicensed || !this.context.info) {
      return { isActive: false };
    }

    // Check expiration
    if (this.context.info.expiresAt && new Date() > this.context.info.expiresAt) {
      return { isActive: false };
    }

    return {
      isActive: true,
      licenseType: this.context.info.type,
      expiresAt: this.context.info.expiresAt ?? undefined,
      features: this.context.info.features,
    };
  }

  getContext(): LicenseContext {
    return this.context;
  }

  hasFeature(feature: LicenseFeature): boolean {
    return this.context.hasFeature(feature);
  }

  private loadContext(): LicenseContext {
    // Check environment variable first
    const envKey = process.env[ENV_VAR_KEY];
    if (envKey) {
      const offlineResult = this.activateOffline(envKey);
      if (offlineResult.success) {
        return this.context;
      }
    }

    // Try to load from file
    const license = this.loadLicense();
    if (license) {
      // Check expiration
      if (license.expiresAt && new Date() > license.expiresAt) {
        return createCommunityContext();
      }
      return createLicensedContext(license);
    }

    return createCommunityContext();
  }

  private loadLicense(): LicenseInfo | null {
    try {
      if (fs.existsSync(LICENSE_FILE)) {
        const content = fs.readFileSync(LICENSE_FILE, 'utf-8');
        const data = JSON.parse(content);
        return {
          ...data,
          expiresAt: data.expiresAt ? new Date(data.expiresAt) : null,
          activatedAt: new Date(data.activatedAt),
        };
      }
    } catch {
      // Ignore load errors
    }
    return null;
  }

  private saveLicense(license: LicenseInfo): void {
    try {
      if (!fs.existsSync(LICENSE_DIR)) {
        fs.mkdirSync(LICENSE_DIR, { recursive: true });
      }
      fs.writeFileSync(LICENSE_FILE, JSON.stringify(license, null, 2), 'utf-8');
    } catch (error) {
      console.warn('Failed to save license:', error);
    }
  }

  private removeLicense(): void {
    try {
      if (fs.existsSync(LICENSE_FILE)) {
        fs.unlinkSync(LICENSE_FILE);
      }
    } catch {
      // Ignore remove errors
    }
  }

  private isValidKeyFormat(key: string): boolean {
    // Expected format: XXXX-XXXX-XXXX-XXXX or similar
    return /^[A-Z0-9]{4}(-[A-Z0-9]{4}){3,}$/i.test(key);
  }

  private async activateWithServer(
    key: string
  ): Promise<{ success: boolean; license?: LicenseInfo; error?: string }> {
    const response = await axios.post(
      `${LICENSE_SERVER}/activate`,
      { key, machineId: this.getMachineId() },
      { timeout: 10000 }
    );

    return response.data;
  }

  private async deactivateWithServer(key: string): Promise<void> {
    await axios.post(
      `${LICENSE_SERVER}/deactivate`,
      { key, machineId: this.getMachineId() },
      { timeout: 10000 }
    );
  }

  private activateOffline(key: string): ActivationResult {
    // Offline activation for development/testing
    // In production, this would validate against embedded public key
    const keyLower = key.toLowerCase();

    let type: 'pro' | 'enterprise' = 'pro';
    let features = proFeatures;

    if (keyLower.includes('enterprise') || keyLower.startsWith('ent-')) {
      type = 'enterprise';
      features = enterpriseFeatures;
    }

    const license: LicenseInfo = {
      key,
      type,
      features,
      expiresAt: null, // Never expires for offline
      activatedAt: new Date(),
    };

    this.saveLicense(license);
    this.context = createLicensedContext(license);

    return {
      success: true,
      licenseType: type,
      features,
    };
  }

  private getMachineId(): string {
    // Simple machine ID based on hostname and platform
    return `${os.hostname()}-${os.platform()}-${os.arch()}`;
  }
}
