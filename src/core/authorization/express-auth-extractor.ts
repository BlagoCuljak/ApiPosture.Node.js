import {
  AuthorizationInfo,
  createDefaultAuthorizationInfo,
  determineClassification,
} from '../models/authorization-info.js';
import {
  AuthorizationExtractor,
  AuthorizationExtractorContext,
} from './authorization-extractor.js';

// Common authentication middleware patterns
const AUTH_MIDDLEWARE_PATTERNS = [
  /^passport\.authenticate/i,
  /^jwt$/i,
  /^expressjwt$/i,
  /^requireAuth$/i,
  /^ensureAuthenticated$/i,
  /^isAuthenticated$/i,
  /^authenticate$/i,
  /^authMiddleware$/i,
  /^checkAuth$/i,
  /^verifyToken$/i,
  /^validateToken$/i,
  /^bearerToken$/i,
  /^auth$/i,
  /^protected$/i,
];

// Common explicit public/anonymous patterns
const PUBLIC_PATTERNS = [
  /^allowAnonymous$/i,
  /^public$/i,
  /^skipAuth$/i,
  /^noAuth$/i,
  /^optional$/i,
];

// Role-based middleware patterns
const ROLE_PATTERNS = [
  /^requireRole$/i,
  /^hasRole$/i,
  /^roles$/i,
  /^checkRole$/i,
  /^authorize$/i,
  /^can$/i,
  /^permit$/i,
];

export class ExpressAuthExtractor implements AuthorizationExtractor {
  extract(
    middlewares: string[],
    context?: AuthorizationExtractorContext
  ): AuthorizationInfo {
    const allMiddlewares = [
      ...(context?.routerMiddlewares ?? []),
      ...middlewares,
    ];

    const auth = createDefaultAuthorizationInfo();
    auth.middlewareChain = allMiddlewares;

    for (const middleware of allMiddlewares) {
      this.processMiddleware(middleware, auth);
    }

    auth.classification = determineClassification(auth);
    return auth;
  }

  private processMiddleware(middleware: string, auth: AuthorizationInfo): void {
    const normalizedName = middleware.trim();

    // Check for explicit public markers
    if (this.matchesPatterns(normalizedName, PUBLIC_PATTERNS)) {
      auth.isExplicitlyPublic = true;
      return;
    }

    // Check for authentication middleware
    if (this.matchesPatterns(normalizedName, AUTH_MIDDLEWARE_PATTERNS)) {
      auth.isAuthenticated = true;
      auth.guardNames.push(normalizedName);
      return;
    }

    // Check for role-based middleware
    if (this.matchesPatterns(normalizedName, ROLE_PATTERNS)) {
      auth.isAuthenticated = true;
      // Try to extract role names from common patterns
      const roles = this.extractRolesFromMiddleware(normalizedName);
      auth.roles.push(...roles);
      return;
    }

    // Check for common auth patterns in the middleware name
    if (this.containsAuthKeyword(normalizedName)) {
      auth.isAuthenticated = true;
      auth.guardNames.push(normalizedName);
    }
  }

  private matchesPatterns(name: string, patterns: RegExp[]): boolean {
    // Get just the function/method name (strip object prefix)
    const funcName = name.includes('.') ? name.split('.').pop()! : name;
    return patterns.some((pattern) => pattern.test(funcName));
  }

  private containsAuthKeyword(name: string): boolean {
    const keywords = ['auth', 'jwt', 'token', 'session', 'login', 'secure'];
    const lower = name.toLowerCase();
    return keywords.some((kw) => lower.includes(kw));
  }

  private extractRolesFromMiddleware(middleware: string): string[] {
    // Try to extract roles from patterns like:
    // requireRole('admin'), hasRole(['user', 'admin']), roles('manager')
    const roleMatch = middleware.match(/\(['"]?([^'")\]]+)['"]?\]/i);
    if (roleMatch) {
      return roleMatch[1].split(',').map((r) => r.trim().replace(/['"]/g, ''));
    }

    // For patterns like authorize.admin or can.read
    if (middleware.includes('.')) {
      const parts = middleware.split('.');
      const lastPart = parts[parts.length - 1];
      if (!this.matchesPatterns(lastPart, AUTH_MIDDLEWARE_PATTERNS)) {
        return [lastPart];
      }
    }

    return [];
  }
}
