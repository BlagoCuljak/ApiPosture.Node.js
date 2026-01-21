export enum LicenseFeature {
  DiffMode = 'diff-mode',
  HistoricalTracking = 'historical-tracking',
  RiskScoring = 'risk-scoring',
  AdvancedOwaspRules = 'advanced-owasp-rules',
  SecretsScanning = 'secrets-scanning',
  CustomRules = 'custom-rules',
  TeamReporting = 'team-reporting',
  CiCdIntegration = 'ci-cd-integration',
}

export const proFeatures: LicenseFeature[] = [
  LicenseFeature.DiffMode,
  LicenseFeature.HistoricalTracking,
  LicenseFeature.RiskScoring,
  LicenseFeature.AdvancedOwaspRules,
];

export const enterpriseFeatures: LicenseFeature[] = [
  ...proFeatures,
  LicenseFeature.SecretsScanning,
  LicenseFeature.CustomRules,
  LicenseFeature.TeamReporting,
  LicenseFeature.CiCdIntegration,
];

export function getFeatureDescription(feature: LicenseFeature): string {
  switch (feature) {
    case LicenseFeature.DiffMode:
      return 'Compare scans to track changes over time';
    case LicenseFeature.HistoricalTracking:
      return 'Store and analyze historical scan data';
    case LicenseFeature.RiskScoring:
      return 'Advanced risk scoring and prioritization';
    case LicenseFeature.AdvancedOwaspRules:
      return 'Additional OWASP security rules';
    case LicenseFeature.SecretsScanning:
      return 'Detect hardcoded secrets and credentials';
    case LicenseFeature.CustomRules:
      return 'Create custom security rules';
    case LicenseFeature.TeamReporting:
      return 'Team collaboration and reporting';
    case LicenseFeature.CiCdIntegration:
      return 'Advanced CI/CD pipeline integration';
    default:
      return feature;
  }
}
