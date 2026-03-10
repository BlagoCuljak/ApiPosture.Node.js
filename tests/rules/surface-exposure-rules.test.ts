import { describe, it, expect } from 'vitest';
import { PublicWithoutExplicitIntent } from '../../src/rules/exposure/public-without-explicit-intent.js';
import { MissingAuthOnWrites } from '../../src/rules/consistency/missing-auth-on-writes.js';
import { UnprotectedEndpoint } from '../../src/rules/surface/unprotected-endpoint.js';
import { SensitiveRouteKeywords } from '../../src/rules/surface/sensitive-route-keywords.js';
import type { Endpoint } from '../../src/core/models/endpoint.js';
import { SecurityClassification } from '../../src/core/models/security-classification.js';

const PUBLIC_AUTH = {
  isAuthenticated: false,
  isExplicitlyPublic: false,
  roles: [] as string[],
  policies: [] as string[],
  middlewareChain: [] as string[],
  guardNames: [] as string[],
  classification: SecurityClassification.Public,
} as any;

function makeEndpoint(
  route: string,
  method = 'GET',
  type: 'express' | 'nestjs' | 'fastify' = 'express',
): Endpoint {
  return {
    route,
    method,
    handlerName: 'handler',
    type,
    location: { filePath: 'src/app.ts', line: 1, column: 1 },
    authorization: PUBLIC_AUTH,
  } as Endpoint;
}

// ─── AP001 ──────────────────────────────────────────────────────────────────

describe('AP001 PublicWithoutExplicitIntent', () => {
  const rule = new PublicWithoutExplicitIntent();

  it('flags unrecognised public GET endpoint', () => {
    const findings = rule.evaluate(makeEndpoint('/api/users'));
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('AP001');
  });

  it('does not flag OPTIONS (CORS preflight)', () => {
    expect(rule.evaluate(makeEndpoint('/*', 'OPTIONS'))).toHaveLength(0);
  });

  it('does not flag /login', () => {
    expect(rule.evaluate(makeEndpoint('/login', 'POST'))).toHaveLength(0);
  });

  it('does not flag /logout', () => {
    expect(rule.evaluate(makeEndpoint('/logout', 'GET'))).toHaveLength(0);
  });

  it('does not flag /signup and /register', () => {
    expect(rule.evaluate(makeEndpoint('/signup', 'POST'))).toHaveLength(0);
    expect(rule.evaluate(makeEndpoint('/register', 'POST'))).toHaveLength(0);
  });

  it('does not flag /forgot-password and /reset-password', () => {
    expect(rule.evaluate(makeEndpoint('/forgot-password', 'POST'))).toHaveLength(0);
    expect(rule.evaluate(makeEndpoint('/reset-password', 'POST'))).toHaveLength(0);
  });

  it('does not flag /auth/* OAuth routes', () => {
    expect(rule.evaluate(makeEndpoint('/auth/google'))).toHaveLength(0);
    expect(rule.evaluate(makeEndpoint('/auth/facebook/callback'))).toHaveLength(0);
    expect(rule.evaluate(makeEndpoint('/auth/failure'))).toHaveLength(0);
  });

  it('does not flag /health', () => {
    expect(rule.evaluate(makeEndpoint('/health'))).toHaveLength(0);
    expect(rule.evaluate(makeEndpoint('/api/health'))).toHaveLength(0);
  });

  it('does not flag 2FA and WebAuthn flows', () => {
    expect(rule.evaluate(makeEndpoint('/login/2fa', 'POST'))).toHaveLength(0);
    expect(rule.evaluate(makeEndpoint('/login/2fa/resend', 'POST'))).toHaveLength(0);
    expect(rule.evaluate(makeEndpoint('/login/webauthn-start', 'POST'))).toHaveLength(0);
  });

  it('does not flag NestJS /auth/login and /auth/register', () => {
    expect(rule.evaluate(makeEndpoint('/auth/login', 'POST', 'nestjs'))).toHaveLength(0);
    expect(rule.evaluate(makeEndpoint('/auth/register', 'POST', 'nestjs'))).toHaveLength(0);
  });

  it('does not flag /users/login (realworld-style)', () => {
    expect(rule.evaluate(makeEndpoint('/users/login', 'POST'))).toHaveLength(0);
  });

  it('does not flag /refresh-tokens', () => {
    expect(rule.evaluate(makeEndpoint('/refresh-tokens', 'POST'))).toHaveLength(0);
  });

  it('does not flag /verify-email and /account/verify/:token', () => {
    expect(rule.evaluate(makeEndpoint('/verify-email', 'POST'))).toHaveLength(0);
    expect(rule.evaluate(makeEndpoint('/account/verify/:token'))).toHaveLength(0);
  });

  it('still flags /me, /profile, /articles endpoints', () => {
    expect(rule.evaluate(makeEndpoint('/me'))).toHaveLength(1);
    expect(rule.evaluate(makeEndpoint('/articles'))).toHaveLength(1);
  });
});

// ─── AP004 ──────────────────────────────────────────────────────────────────

describe('AP004 MissingAuthOnWrites', () => {
  const rule = new MissingAuthOnWrites();

  it('flags unprotected POST on data route', () => {
    const findings = rule.evaluate(makeEndpoint('/articles', 'POST'));
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('AP004');
  });

  it('does not flag POST /login', () => {
    expect(rule.evaluate(makeEndpoint('/login', 'POST'))).toHaveLength(0);
  });

  it('does not flag POST /register and POST /signup', () => {
    expect(rule.evaluate(makeEndpoint('/register', 'POST'))).toHaveLength(0);
    expect(rule.evaluate(makeEndpoint('/signup', 'POST'))).toHaveLength(0);
  });

  it('does not flag POST /forgot, POST /reset/:token', () => {
    expect(rule.evaluate(makeEndpoint('/forgot', 'POST'))).toHaveLength(0);
    expect(rule.evaluate(makeEndpoint('/reset/:token', 'POST'))).toHaveLength(0);
  });

  it('does not flag POST /logout', () => {
    expect(rule.evaluate(makeEndpoint('/logout', 'POST'))).toHaveLength(0);
  });

  it('does not flag POST /refresh-tokens', () => {
    expect(rule.evaluate(makeEndpoint('/refresh-tokens', 'POST'))).toHaveLength(0);
  });

  it('does not flag POST /verify-email', () => {
    expect(rule.evaluate(makeEndpoint('/verify-email', 'POST'))).toHaveLength(0);
  });

  it('does not flag POST /contact', () => {
    expect(rule.evaluate(makeEndpoint('/contact', 'POST'))).toHaveLength(0);
  });

  it('does not flag POST /login/2fa and 2FA sub-routes', () => {
    expect(rule.evaluate(makeEndpoint('/login/2fa', 'POST'))).toHaveLength(0);
    expect(rule.evaluate(makeEndpoint('/login/2fa/resend', 'POST'))).toHaveLength(0);
    expect(rule.evaluate(makeEndpoint('/login/2fa/totp', 'POST'))).toHaveLength(0);
  });

  it('does not flag POST /login/webauthn-start and /login/webauthn-verify', () => {
    expect(rule.evaluate(makeEndpoint('/login/webauthn-start', 'POST'))).toHaveLength(0);
    expect(rule.evaluate(makeEndpoint('/login/webauthn-verify', 'POST'))).toHaveLength(0);
  });

  it('does not flag OPTIONS write', () => {
    expect(rule.evaluate(makeEndpoint('/*', 'OPTIONS'))).toHaveLength(0);
  });

  it('does not flag POST /auth/login and /auth/register', () => {
    expect(rule.evaluate(makeEndpoint('/auth/login', 'POST'))).toHaveLength(0);
    expect(rule.evaluate(makeEndpoint('/auth/register', 'POST'))).toHaveLength(0);
  });

  it('does not flag POST /forgot-password and /reset-password', () => {
    expect(rule.evaluate(makeEndpoint('/forgot-password', 'POST'))).toHaveLength(0);
    expect(rule.evaluate(makeEndpoint('/reset-password', 'POST'))).toHaveLength(0);
  });

  it('does not flag GET routes (only write methods)', () => {
    expect(rule.evaluate(makeEndpoint('/api/data', 'GET'))).toHaveLength(0);
  });
});

// ─── AP008 ──────────────────────────────────────────────────────────────────

describe('AP008 UnprotectedEndpoint', () => {
  const rule = new UnprotectedEndpoint();

  it('flags endpoint with no middleware chain', () => {
    const findings = rule.evaluate(makeEndpoint('/api/users'));
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('AP008');
  });

  it('does not flag OPTIONS', () => {
    expect(rule.evaluate(makeEndpoint('/*', 'OPTIONS'))).toHaveLength(0);
  });

  it('does not flag /login', () => {
    expect(rule.evaluate(makeEndpoint('/login', 'POST'))).toHaveLength(0);
  });

  it('does not flag /health', () => {
    expect(rule.evaluate(makeEndpoint('/health'))).toHaveLength(0);
  });

  it('does not flag /auth/* OAuth routes', () => {
    expect(rule.evaluate(makeEndpoint('/auth/google'))).toHaveLength(0);
    expect(rule.evaluate(makeEndpoint('/auth/github/callback'))).toHaveLength(0);
  });

  it('does not flag NestJS /auth/login', () => {
    expect(rule.evaluate(makeEndpoint('/auth/login', 'POST', 'nestjs'))).toHaveLength(0);
  });

  it('does not flag /users/login (realworld-style)', () => {
    expect(rule.evaluate(makeEndpoint('/users/login', 'POST'))).toHaveLength(0);
  });

  it('does not flag /ping and /liveness', () => {
    expect(rule.evaluate(makeEndpoint('/ping'))).toHaveLength(0);
    expect(rule.evaluate(makeEndpoint('/liveness'))).toHaveLength(0);
  });
});

// ─── AP007 ──────────────────────────────────────────────────────────────────

describe('AP007 SensitiveRouteKeywords', () => {
  const rule = new SensitiveRouteKeywords();

  it('flags /users/admin', () => {
    const findings = rule.evaluate(makeEndpoint('/users/admin'));
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('admin');
  });

  it('flags /api/debug', () => {
    const findings = rule.evaluate(makeEndpoint('/api/debug'));
    expect(findings).toHaveLength(1);
  });

  it('flags /internal/status', () => {
    const findings = rule.evaluate(makeEndpoint('/internal/status'));
    expect(findings).toHaveLength(1);
  });

  it('flags /api/test endpoint', () => {
    const findings = rule.evaluate(makeEndpoint('/api/test'));
    expect(findings).toHaveLength(1);
  });

  it('does NOT flag /api/latest (test is a substring, not a segment)', () => {
    expect(rule.evaluate(makeEndpoint('/api/latest'))).toHaveLength(0);
  });

  it('does NOT flag /api/developer (dev is a substring, not a segment)', () => {
    expect(rule.evaluate(makeEndpoint('/api/developer'))).toHaveLength(0);
  });

  it('does NOT flag /api/health (health removed from keywords)', () => {
    expect(rule.evaluate(makeEndpoint('/api/health'))).toHaveLength(0);
  });

  it('does NOT flag /healthz', () => {
    expect(rule.evaluate(makeEndpoint('/healthz'))).toHaveLength(0);
  });

  it('flags /dev/tools (dev is a standalone segment)', () => {
    const findings = rule.evaluate(makeEndpoint('/dev/tools'));
    expect(findings).toHaveLength(1);
  });

  it('flags /staging/api', () => {
    const findings = rule.evaluate(makeEndpoint('/staging/api'));
    expect(findings).toHaveLength(1);
  });

  it('does not flag authenticated endpoint', () => {
    const ep = {
      ...makeEndpoint('/api/admin'),
      authorization: {
        ...PUBLIC_AUTH,
        classification: SecurityClassification.Authenticated,
        isAuthenticated: true,
      },
    } as any;
    expect(rule.evaluate(ep)).toHaveLength(0);
  });
});
