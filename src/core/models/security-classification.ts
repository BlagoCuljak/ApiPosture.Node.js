export enum SecurityClassification {
  Public = 'public',
  Authenticated = 'authenticated',
  RoleRestricted = 'role-restricted',
  PolicyRestricted = 'policy-restricted',
}

export function parseSecurityClassification(
  value: string
): SecurityClassification | undefined {
  const normalized = value.toLowerCase();
  return Object.values(SecurityClassification).find((c) => c === normalized);
}
