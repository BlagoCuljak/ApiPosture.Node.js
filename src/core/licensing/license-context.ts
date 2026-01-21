import { LicenseFeature } from './license-features.js';

export interface LicenseInfo {
  key: string;
  type: 'community' | 'pro' | 'enterprise';
  features: LicenseFeature[];
  expiresAt: Date | null;
  activatedAt: Date;
  machineId?: string;
}

export interface LicenseContext {
  isLicensed: boolean;
  info: LicenseInfo | null;
  hasFeature(feature: LicenseFeature): boolean;
}

export function createCommunityContext(): LicenseContext {
  return {
    isLicensed: false,
    info: null,
    hasFeature: () => false,
  };
}

export function createLicensedContext(info: LicenseInfo): LicenseContext {
  return {
    isLicensed: true,
    info,
    hasFeature: (feature: LicenseFeature) => info.features.includes(feature),
  };
}
