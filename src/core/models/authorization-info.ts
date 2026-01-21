import { SecurityClassification } from './security-classification.js';

export interface AuthorizationInfo {
  isAuthenticated: boolean;
  isExplicitlyPublic: boolean;
  roles: string[];
  policies: string[];
  middlewareChain: string[];
  guardNames: string[];
  classification: SecurityClassification;
}

export function createDefaultAuthorizationInfo(): AuthorizationInfo {
  return {
    isAuthenticated: false,
    isExplicitlyPublic: false,
    roles: [],
    policies: [],
    middlewareChain: [],
    guardNames: [],
    classification: SecurityClassification.Public,
  };
}

export function determineClassification(
  auth: Omit<AuthorizationInfo, 'classification'>
): SecurityClassification {
  if (auth.policies.length > 0) {
    return SecurityClassification.PolicyRestricted;
  }
  if (auth.roles.length > 0) {
    return SecurityClassification.RoleRestricted;
  }
  if (auth.isAuthenticated) {
    return SecurityClassification.Authenticated;
  }
  return SecurityClassification.Public;
}
