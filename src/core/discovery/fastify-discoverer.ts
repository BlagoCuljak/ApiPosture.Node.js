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

const FASTIFY_HTTP_METHODS = new Set([
  'get', 'post', 'put', 'delete', 'patch', 'options', 'head', 'all'
]);

const FASTIFY_IDENTIFIERS = new Set(['fastify', 'server', 'app', 'instance']);

const AUTH_HOOK_PATTERNS = [
  /authenticate/i,
  /verify/i,
  /jwt/i,
  /auth/i,
  /guard/i,
  /protected/i,
];

export class FastifyDiscoverer implements EndpointDiscoverer {
  readonly name = 'Fastify';

  async discover(file: LoadedSourceFile): Promise<Endpoint[]> {
    const endpoints: Endpoint[] = [];
    const { sourceFile, filePath } = file;

    const callExpressions = findNodes(sourceFile, ts.isCallExpression);

    for (const callExpr of callExpressions) {
      // Check for fastify.get(), fastify.post(), etc.
      const shorthandEndpoint = this.processShorthandRoute(callExpr, sourceFile, filePath);
      if (shorthandEndpoint) {
        endpoints.push(shorthandEndpoint);
        continue;
      }

      // Check for fastify.route({ method, url, ... })
      const routeEndpoint = this.processRouteMethod(callExpr, sourceFile, filePath);
      if (routeEndpoint) {
        endpoints.push(routeEndpoint);
      }
    }

    return endpoints;
  }

  private processShorthandRoute(
    callExpr: ts.CallExpression,
    sourceFile: ts.SourceFile,
    filePath: string
  ): Endpoint | null {
    if (!ts.isPropertyAccessExpression(callExpr.expression)) {
      return null;
    }

    const propAccess = callExpr.expression;
    const methodName = propAccess.name.text.toLowerCase();

    if (!FASTIFY_HTTP_METHODS.has(methodName)) {
      return null;
    }

    const callerName = this.getCallerName(propAccess.expression);
    if (!callerName || !this.isFastifyIdentifier(callerName)) {
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

    // Extract options/handler
    let handlerName = 'anonymous';
    let authorization = createDefaultAuthorizationInfo();

    // Check for options object: fastify.get('/path', { preHandler: [] }, handler)
    if (args.length >= 2 && ts.isObjectLiteralExpression(args[1])) {
      const options = args[1];
      authorization = this.extractAuthFromOptions(options, sourceFile);

      if (args.length >= 3) {
        handlerName = this.extractHandlerName(args[2], sourceFile);
      }
    } else if (args.length >= 2) {
      handlerName = this.extractHandlerName(args[1], sourceFile);
    }

    authorization.classification = determineClassification(authorization);

    const location = getLineAndColumn(sourceFile, callExpr.getStart(sourceFile));

    return createEndpoint({
      route: this.normalizePath(routePath),
      method: parseHttpMethod(methodName.toUpperCase()) ?? HttpMethod.GET,
      handlerName,
      type: EndpointType.Fastify,
      location: {
        filePath,
        line: location.line,
        column: location.column,
      },
      authorization,
    });
  }

  private processRouteMethod(
    callExpr: ts.CallExpression,
    sourceFile: ts.SourceFile,
    filePath: string
  ): Endpoint | null {
    if (!ts.isPropertyAccessExpression(callExpr.expression)) {
      return null;
    }

    const propAccess = callExpr.expression;
    if (propAccess.name.text !== 'route') {
      return null;
    }

    const callerName = this.getCallerName(propAccess.expression);
    if (!callerName || !this.isFastifyIdentifier(callerName)) {
      return null;
    }

    const args = callExpr.arguments;
    if (args.length === 0 || !ts.isObjectLiteralExpression(args[0])) {
      return null;
    }

    const options = args[0];
    let method: HttpMethod | null = null;
    let url: string | null = null;
    let handlerName = 'handler';
    let authorization = createDefaultAuthorizationInfo();

    for (const prop of options.properties) {
      if (!ts.isPropertyAssignment(prop) || !ts.isIdentifier(prop.name)) {
        continue;
      }

      const propName = prop.name.text;

      if (propName === 'method') {
        const methodStr = this.extractStringValue(prop.initializer);
        if (methodStr) {
          method = parseHttpMethod(methodStr.toUpperCase()) ?? null;
        }
      }

      if (propName === 'url') {
        url = this.extractStringValue(prop.initializer);
      }

      if (propName === 'handler') {
        handlerName = this.extractHandlerName(prop.initializer, sourceFile);
      }

      if (propName === 'preHandler' || propName === 'onRequest') {
        this.extractHooksAuth(prop.initializer, sourceFile, authorization);
      }
    }

    if (!method || !url) {
      return null;
    }

    authorization.classification = determineClassification(authorization);

    const location = getLineAndColumn(sourceFile, callExpr.getStart(sourceFile));

    return createEndpoint({
      route: this.normalizePath(url),
      method,
      handlerName,
      type: EndpointType.Fastify,
      location: {
        filePath,
        line: location.line,
        column: location.column,
      },
      authorization,
    });
  }

  private extractAuthFromOptions(
    options: ts.ObjectLiteralExpression,
    sourceFile: ts.SourceFile
  ): AuthorizationInfo {
    const auth = createDefaultAuthorizationInfo();

    for (const prop of options.properties) {
      if (!ts.isPropertyAssignment(prop) || !ts.isIdentifier(prop.name)) {
        continue;
      }

      const propName = prop.name.text;

      if (propName === 'preHandler' || propName === 'onRequest') {
        this.extractHooksAuth(prop.initializer, sourceFile, auth);
      }
    }

    return auth;
  }

  private extractHooksAuth(
    node: ts.Expression,
    sourceFile: ts.SourceFile,
    auth: AuthorizationInfo
  ): void {
    const hooks: string[] = [];

    if (ts.isArrayLiteralExpression(node)) {
      for (const elem of node.elements) {
        const hookName = this.extractHookName(elem, sourceFile);
        if (hookName) {
          hooks.push(hookName);
        }
      }
    } else {
      const hookName = this.extractHookName(node, sourceFile);
      if (hookName) {
        hooks.push(hookName);
      }
    }

    auth.middlewareChain.push(...hooks);

    for (const hook of hooks) {
      if (this.isAuthHook(hook)) {
        auth.isAuthenticated = true;
        auth.guardNames.push(hook);
      }
    }
  }

  private extractHookName(node: ts.Expression, sourceFile: ts.SourceFile): string | null {
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
    return null;
  }

  private isAuthHook(hookName: string): boolean {
    return AUTH_HOOK_PATTERNS.some((pattern) => pattern.test(hookName));
  }

  private getCallerName(expression: ts.Expression): string | null {
    if (ts.isIdentifier(expression)) {
      return expression.text;
    }
    return null;
  }

  private isFastifyIdentifier(name: string): boolean {
    if (FASTIFY_IDENTIFIERS.has(name.toLowerCase())) {
      return true;
    }
    return name.toLowerCase().includes('fastify');
  }

  private extractStringValue(node: ts.Expression): string | null {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      return node.text;
    }
    return null;
  }

  private extractHandlerName(node: ts.Expression, sourceFile: ts.SourceFile): string {
    if (ts.isIdentifier(node)) {
      return node.text;
    }
    if (ts.isPropertyAccessExpression(node)) {
      return node.getText(sourceFile);
    }
    if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) {
      return 'anonymous';
    }
    return 'unknown';
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
