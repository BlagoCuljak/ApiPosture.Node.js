import * as ts from 'typescript';
import { EndpointDiscoverer } from './discoverer-interface.js';
import { LoadedSourceFile, getLineAndColumn, findNodes } from '../analysis/source-file-loader.js';
import { Endpoint, createEndpoint } from '../models/endpoint.js';
import { EndpointType } from '../models/endpoint-type.js';
import { HttpMethod, parseHttpMethod } from '../models/http-method.js';
import {
  AuthorizationInfo,
  createDefaultAuthorizationInfo,
  determineClassification,
} from '../models/authorization-info.js';

const KOA_HTTP_METHODS = new Set([
  'get', 'post', 'put', 'delete', 'patch', 'options', 'head', 'all'
]);

const KOA_ROUTER_IDENTIFIERS = new Set(['router', 'koaRouter', 'apiRouter']);

const AUTH_MIDDLEWARE_PATTERNS = [
  /authenticate/i,
  /auth/i,
  /jwt/i,
  /passport/i,
  /protect/i,
  /guard/i,
  /verify/i,
];

export class KoaDiscoverer implements EndpointDiscoverer {
  readonly name = 'Koa';

  async discover(file: LoadedSourceFile): Promise<Endpoint[]> {
    const endpoints: Endpoint[] = [];
    const { sourceFile, filePath } = file;

    const callExpressions = findNodes(sourceFile, ts.isCallExpression);

    for (const callExpr of callExpressions) {
      const endpoint = this.processRouteCall(callExpr, sourceFile, filePath);
      if (endpoint) {
        endpoints.push(endpoint);
      }
    }

    return endpoints;
  }

  private processRouteCall(
    callExpr: ts.CallExpression,
    sourceFile: ts.SourceFile,
    filePath: string
  ): Endpoint | null {
    if (!ts.isPropertyAccessExpression(callExpr.expression)) {
      return null;
    }

    const propAccess = callExpr.expression;
    const methodName = propAccess.name.text.toLowerCase();

    if (!KOA_HTTP_METHODS.has(methodName)) {
      return null;
    }

    const callerName = this.getCallerName(propAccess.expression);
    if (!callerName || !this.isKoaRouterIdentifier(callerName)) {
      return null;
    }

    const args = callExpr.arguments;
    if (args.length === 0) {
      return null;
    }

    // First arg is route path
    const routePath = this.extractStringValue(args[0]);
    if (!routePath) {
      return null;
    }

    // Extract middleware chain and handler
    const middlewares: string[] = [];
    let handlerName = 'anonymous';

    for (let i = 1; i < args.length; i++) {
      const arg = args[i];
      const name = this.extractMiddlewareName(arg, sourceFile);

      if (i === args.length - 1) {
        // Last argument is the handler
        handlerName = name ?? 'anonymous';
      } else if (name) {
        middlewares.push(name);
      }
    }

    // Build authorization info
    const authorization = this.buildAuthorizationInfo(middlewares);

    const location = getLineAndColumn(sourceFile, callExpr.getStart(sourceFile));

    return createEndpoint({
      route: this.normalizePath(routePath),
      method: parseHttpMethod(methodName.toUpperCase()) ?? HttpMethod.GET,
      handlerName,
      type: EndpointType.Koa,
      location: {
        filePath,
        line: location.line,
        column: location.column,
      },
      authorization,
    });
  }

  private buildAuthorizationInfo(middlewares: string[]): AuthorizationInfo {
    const auth = createDefaultAuthorizationInfo();
    auth.middlewareChain = middlewares;

    for (const middleware of middlewares) {
      if (this.isAuthMiddleware(middleware)) {
        auth.isAuthenticated = true;
        auth.guardNames.push(middleware);
      }
    }

    auth.classification = determineClassification(auth);
    return auth;
  }

  private isAuthMiddleware(name: string): boolean {
    return AUTH_MIDDLEWARE_PATTERNS.some((pattern) => pattern.test(name));
  }

  private getCallerName(expression: ts.Expression): string | null {
    if (ts.isIdentifier(expression)) {
      return expression.text;
    }
    return null;
  }

  private isKoaRouterIdentifier(name: string): boolean {
    if (KOA_ROUTER_IDENTIFIERS.has(name)) {
      return true;
    }
    const lower = name.toLowerCase();
    return lower.includes('router') || lower.includes('koa');
  }

  private extractStringValue(node: ts.Expression): string | null {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      return node.text;
    }
    return null;
  }

  private extractMiddlewareName(
    node: ts.Expression,
    sourceFile: ts.SourceFile
  ): string | null {
    if (ts.isIdentifier(node)) {
      return node.text;
    }
    if (ts.isPropertyAccessExpression(node)) {
      return node.getText(sourceFile);
    }
    if (ts.isCallExpression(node)) {
      if (ts.isIdentifier(node.expression)) {
        return node.expression.text;
      }
      if (ts.isPropertyAccessExpression(node.expression)) {
        return node.expression.getText(sourceFile);
      }
    }
    if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) {
      return null; // Anonymous function
    }
    return null;
  }

  private normalizePath(path: string): string {
    if (!path.startsWith('/')) {
      path = '/' + path;
    }
    path = path.replace(/\/+/g, '/');
    if (path.length > 1 && path.endsWith('/')) {
      path = path.slice(0, -1);
    }
    return path;
  }
}
