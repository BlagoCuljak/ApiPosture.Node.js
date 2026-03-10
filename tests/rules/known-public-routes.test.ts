import { describe, it, expect } from 'vitest';
import { isKnownPublicEndpoint } from '../../src/rules/known-public-routes.js';

describe('isKnownPublicEndpoint', () => {
  describe('OPTIONS method', () => {
    it('should exempt any OPTIONS route (CORS preflight)', () => {
      expect(isKnownPublicEndpoint('/*', 'OPTIONS')).toBe(true);
      expect(isKnownPublicEndpoint('/api/users', 'OPTIONS')).toBe(true);
    });
  });

  describe('/auth/* prefix', () => {
    it('should exempt /auth exactly', () => {
      expect(isKnownPublicEndpoint('/auth')).toBe(true);
    });
    it('should exempt OAuth provider routes', () => {
      expect(isKnownPublicEndpoint('/auth/google')).toBe(true);
      expect(isKnownPublicEndpoint('/auth/facebook')).toBe(true);
      expect(isKnownPublicEndpoint('/auth/github/callback')).toBe(true);
      expect(isKnownPublicEndpoint('/auth/twitter/callback')).toBe(true);
      expect(isKnownPublicEndpoint('/auth/failure')).toBe(true);
    });
    it('should exempt nested /auth routes', () => {
      expect(isKnownPublicEndpoint('/auth/login')).toBe(true);
      expect(isKnownPublicEndpoint('/auth/register')).toBe(true);
    });
  });

  describe('auth entry point segments', () => {
    it('should exempt /login routes', () => {
      expect(isKnownPublicEndpoint('/login')).toBe(true);
      expect(isKnownPublicEndpoint('/api/login')).toBe(true);
      expect(isKnownPublicEndpoint('/users/login')).toBe(true);
    });
    it('should exempt /logout routes', () => {
      expect(isKnownPublicEndpoint('/logout')).toBe(true);
    });
    it('should exempt /signup and /register', () => {
      expect(isKnownPublicEndpoint('/signup')).toBe(true);
      expect(isKnownPublicEndpoint('/register')).toBe(true);
      expect(isKnownPublicEndpoint('/api/auth/register')).toBe(true);
    });
    it('should exempt /forgot and /reset routes', () => {
      expect(isKnownPublicEndpoint('/forgot')).toBe(true);
      expect(isKnownPublicEndpoint('/reset/:token')).toBe(true);
    });
    it('should exempt hyphenated variants', () => {
      expect(isKnownPublicEndpoint('/forgot-password')).toBe(true);
      expect(isKnownPublicEndpoint('/reset-password')).toBe(true);
      expect(isKnownPublicEndpoint('/verify-email')).toBe(true);
      expect(isKnownPublicEndpoint('/refresh-tokens')).toBe(true);
    });
  });

  describe('2FA / WebAuthn flows', () => {
    it('should exempt 2FA routes', () => {
      expect(isKnownPublicEndpoint('/login/2fa')).toBe(true);
      expect(isKnownPublicEndpoint('/login/2fa/resend')).toBe(true);
      expect(isKnownPublicEndpoint('/login/2fa/totp')).toBe(true);
    });
    it('should exempt WebAuthn routes', () => {
      expect(isKnownPublicEndpoint('/login/webauthn-start')).toBe(true);
      expect(isKnownPublicEndpoint('/login/webauthn-verify')).toBe(true);
    });
  });

  describe('infrastructure probes', () => {
    it('should exempt /health', () => {
      expect(isKnownPublicEndpoint('/health')).toBe(true);
      expect(isKnownPublicEndpoint('/api/health')).toBe(true);
    });
    it('should exempt /liveness and /readiness', () => {
      expect(isKnownPublicEndpoint('/liveness')).toBe(true);
      expect(isKnownPublicEndpoint('/readiness')).toBe(true);
    });
    it('should exempt /ping', () => {
      expect(isKnownPublicEndpoint('/ping')).toBe(true);
    });
  });

  describe('other known-public routes', () => {
    it('should exempt /contact', () => {
      expect(isKnownPublicEndpoint('/contact')).toBe(true);
    });
    it('should exempt /verify and /confirm', () => {
      expect(isKnownPublicEndpoint('/verify/:token')).toBe(true);
      expect(isKnownPublicEndpoint('/account/verify/:token')).toBe(true);
      expect(isKnownPublicEndpoint('/confirm')).toBe(true);
    });
    it('should exempt /callback', () => {
      expect(isKnownPublicEndpoint('/oauth/callback')).toBe(true);
    });
  });

  describe('non-public routes (should NOT be exempt)', () => {
    it('should not exempt arbitrary GET routes', () => {
      expect(isKnownPublicEndpoint('/api/users', 'GET')).toBe(false);
      expect(isKnownPublicEndpoint('/me', 'GET')).toBe(false);
      expect(isKnownPublicEndpoint('/articles', 'GET')).toBe(false);
    });
    it('should not exempt write operations on data routes', () => {
      expect(isKnownPublicEndpoint('/articles', 'POST')).toBe(false);
      expect(isKnownPublicEndpoint('/users/:id', 'DELETE')).toBe(false);
      expect(isKnownPublicEndpoint('/posts/:id', 'PUT')).toBe(false);
    });
    it('should not exempt route params that look like segments', () => {
      // :login is a param, not the segment "login"
      expect(isKnownPublicEndpoint('/:login/profile')).toBe(false);
    });
    it('should not treat substring matches as segment matches', () => {
      // "latest" contains "test" but it is not a separate segment
      expect(isKnownPublicEndpoint('/api/latest')).toBe(false);
      // "developer" contains "dev" but it is not a separate segment
      expect(isKnownPublicEndpoint('/api/developer')).toBe(false);
    });
  });
});
