import * as ts from 'typescript';
import {
  AuthorizationInfo,
  createDefaultAuthorizationInfo,
  determineClassification,
} from '../models/authorization-info.js';
import {
  getDecoratorName,
  getDecoratorArguments,
  getStringLiteralValue,
  getArrayLiteralElements,
} from '../analysis/source-file-loader.js';

// Auth guard patterns
const AUTH_GUARD_PATTERNS = [
  /AuthGuard/i,
  /JwtAuthGuard/i,
  /LocalAuthGuard/i,
  /SessionGuard/i,
  /BearerGuard/i,
  /TokenGuard/i,
];

// Public decorator names
const PUBLIC_DECORATORS = new Set([
  'Public',
  'AllowAnonymous',
  'SkipAuth',
  'NoAuth',
  'IsPublic',
]);

// Role decorator names
const ROLE_DECORATORS = new Set(['Roles', 'RequireRoles', 'HasRoles', 'Authorize']);

// Policy decorator names
const POLICY_DECORATORS = new Set(['Policies', 'RequirePolicies', 'CheckPolicies']);

export interface NestJSAuthContext {
  classGuards?: string[];
  classRoles?: string[];
  isPublic?: boolean;
}

export class NestJSAuthExtractor {
  extract(
    decorators: ts.Decorator[],
    context?: NestJSAuthContext
  ): AuthorizationInfo {
    const auth = createDefaultAuthorizationInfo();

    // Apply class-level auth first
    if (context?.classGuards) {
      for (const guard of context.classGuards) {
        if (this.isAuthGuard(guard)) {
          auth.isAuthenticated = true;
          auth.guardNames.push(guard);
        }
      }
    }

    if (context?.classRoles) {
      auth.roles.push(...context.classRoles);
      if (context.classRoles.length > 0) {
        auth.isAuthenticated = true;
      }
    }

    if (context?.isPublic) {
      auth.isExplicitlyPublic = true;
    }

    // Process method-level decorators (can override class-level)
    for (const decorator of decorators) {
      this.processDecorator(decorator, auth);
    }

    // Method-level @Public overrides class-level guards
    const hasMethodPublic = decorators.some((d) => {
      const name = getDecoratorName(d);
      return name && PUBLIC_DECORATORS.has(name);
    });

    if (hasMethodPublic) {
      auth.isExplicitlyPublic = true;
      // Don't clear isAuthenticated as it creates the AP003 conflict scenario
    }

    auth.classification = determineClassification(auth);
    return auth;
  }

  private processDecorator(decorator: ts.Decorator, auth: AuthorizationInfo): void {
    const name = getDecoratorName(decorator);
    if (!name) return;

    // Check for @Public or similar
    if (PUBLIC_DECORATORS.has(name)) {
      auth.isExplicitlyPublic = true;
      return;
    }

    // Check for @UseGuards
    if (name === 'UseGuards') {
      const args = getDecoratorArguments(decorator);
      for (const arg of args) {
        if (ts.isIdentifier(arg)) {
          const guardName = arg.text;
          if (this.isAuthGuard(guardName)) {
            auth.isAuthenticated = true;
          }
          auth.guardNames.push(guardName);
        }
        // Handle UseGuards(AuthGuard('jwt'))
        if (ts.isCallExpression(arg)) {
          if (ts.isIdentifier(arg.expression)) {
            const guardName = arg.expression.text;
            if (this.isAuthGuard(guardName)) {
              auth.isAuthenticated = true;
            }
            auth.guardNames.push(guardName);
          }
        }
      }
      return;
    }

    // Check for @Roles
    if (ROLE_DECORATORS.has(name)) {
      const args = getDecoratorArguments(decorator);
      for (const arg of args) {
        // @Roles('admin', 'user')
        const value = getStringLiteralValue(arg);
        if (value) {
          auth.roles.push(value);
          auth.isAuthenticated = true;
        }
        // @Roles(['admin', 'user'])
        const arrayElements = getArrayLiteralElements(arg);
        for (const elem of arrayElements) {
          const elemValue = getStringLiteralValue(elem);
          if (elemValue) {
            auth.roles.push(elemValue);
            auth.isAuthenticated = true;
          }
        }
      }
      return;
    }

    // Check for @Policies
    if (POLICY_DECORATORS.has(name)) {
      const args = getDecoratorArguments(decorator);
      for (const arg of args) {
        const value = getStringLiteralValue(arg);
        if (value) {
          auth.policies.push(value);
          auth.isAuthenticated = true;
        }
        const arrayElements = getArrayLiteralElements(arg);
        for (const elem of arrayElements) {
          const elemValue = getStringLiteralValue(elem);
          if (elemValue) {
            auth.policies.push(elemValue);
            auth.isAuthenticated = true;
          }
        }
      }
      return;
    }
  }

  private isAuthGuard(guardName: string): boolean {
    return AUTH_GUARD_PATTERNS.some((pattern) => pattern.test(guardName));
  }
}
