/**
 * Shared utility for identifying known-public route segments.
 *
 * Covers auth entry points (login, register, OAuth flows, 2FA, WebAuthn),
 * infrastructure probes (health, liveness, readiness), and other endpoints
 * that are public by convention. Any new rule that needs to exempt public
 * routes should import this helper rather than maintaining its own list.
 */

/**
 * Route segments (case-insensitive, compared against individual path parts)
 * that are known to be public by design.
 */
const PUBLIC_ROUTE_SEGMENTS = new Set([
  // Auth entry points
  'login',
  'logout',
  'signin',
  'signout',
  'signup',
  'register',
  // Password / account flows
  'forgot',
  'reset',
  'verify',
  'confirm',
  'activate',
  'unsubscribe',
  'resend',
  // OAuth / token flows
  'callback',
  'oauth',
  'refresh',
  'authorize',
  // Multi-factor auth
  '2fa',
  'totp',
  'mfa',
  'webauthn',
  // Infrastructure probes
  'health',
  'healthz',
  'liveness',
  'readiness',
  'ping',
  // Contact / support
  'contact',
]);

/**
 * Returns true when the given route + method is a known-public endpoint
 * that should not be flagged by surface/exposure rules.
 *
 * Detection uses three tiers:
 *  1. OPTIONS method — always CORS preflight, never flag.
 *  2. /auth/* prefix  — entire /auth subtree is auth-flow by convention.
 *  3. Per-segment check — any non-param segment that exactly matches or
 *     starts with (for hyphenated variants like "forgot-password",
 *     "webauthn-start", "refresh-tokens") a public keyword is exempt.
 */
export function isKnownPublicEndpoint(route: string, method?: string): boolean {
  // Tier 1 — OPTIONS is always a CORS preflight
  if (method === 'OPTIONS') return true;

  const lower = route.toLowerCase();

  // Tier 2 — /auth subtree (OAuth provider routes and callbacks)
  if (lower === '/auth' || lower.startsWith('/auth/')) return true;

  // Tier 3 — segment-level check
  const segments = lower.split('/').filter(
    (seg) => seg.length > 0 && !seg.startsWith(':') && !seg.startsWith('{'),
  );

  for (const seg of segments) {
    // Exact match
    if (PUBLIC_ROUTE_SEGMENTS.has(seg)) return true;

    // Hyphenated compound: "forgot-password", "webauthn-start", "refresh-tokens"
    const firstPart = seg.split('-')[0];
    if (firstPart && firstPart !== seg && PUBLIC_ROUTE_SEGMENTS.has(firstPart)) return true;
  }

  return false;
}
