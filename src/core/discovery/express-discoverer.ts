import * as ts from 'typescript';
import { EndpointDiscoverer } from './discoverer-interface.js';
import { LoadedSourceFile, getLineAndColumn, findNodes } from '../analysis/source-file-loader.js';
import { Endpoint, createEndpoint } from '../models/endpoint.js';
import { EndpointType } from '../models/endpoint-type.js';
import { HttpMethod, parseHttpMethod } from '../models/http-method.js';
import { RouteGroupRegistry } from './route-group-registry.js';
import { ExpressAuthExtractor } from '../authorization/express-auth-extractor.js';

const EXPRESS_HTTP_METHODS = new Set([
  'get', 'post', 'put', 'delete', 'patch', 'options', 'head', 'all'
]);

const EXPRESS_IDENTIFIERS = new Set(['app', 'router', 'express']);

export class ExpressDiscoverer implements EndpointDiscoverer {
  readonly name = 'Express.js';
  private registry: RouteGroupRegistry;
  private authExtractor: ExpressAuthExtractor;

  constructor() {
    this.registry = new RouteGroupRegistry();
    this.authExtractor = new ExpressAuthExtractor();
  }

  async discover(file: LoadedSourceFile): Promise<Endpoint[]> {
    const endpoints: Endpoint[] = [];
    const { sourceFile, filePath } = file;

    // First pass: collect router mounts and route groups
    this.collectRouterMounts(sourceFile, filePath);

    // Second pass: find route definitions
    const callExpressions = findNodes(sourceFile, ts.isCallExpression);

    for (const callExpr of callExpressions) {
      const endpoint = this.processCallExpression(callExpr, sourceFile, filePath);
      if (endpoint) {
        endpoints.push(endpoint);
      }
    }

    return endpoints;
  }

  private collectRouterMounts(sourceFile: ts.SourceFile, filePath: string): void {
    const callExpressions = findNodes(sourceFile, ts.isCallExpression);

    for (const callExpr of callExpressions) {
      // Look for app.use('/prefix', router) or app.use('/path', middleware())
      if (!ts.isPropertyAccessExpression(callExpr.expression)) continue;

      const propAccess = callExpr.expression;
      const methodName = propAccess.name.text;

      if (methodName !== 'use') continue;

      const args = callExpr.arguments;
      if (args.length < 2) continue;

      const firstArg = args[0];
      const secondArg = args[1];

      // Must start with a string path
      if (!ts.isStringLiteral(firstArg)) continue;

      const prefix = firstArg.text;
      const appName = ts.isIdentifier(propAccess.expression)
        ? propAccess.expression.text
        : '';

      if (!appName) continue;

      // Check for app.use('/prefix', router) — router is a simple identifier
      if (ts.isIdentifier(secondArg)) {
        this.registry.registerRouterMount(filePath, appName, prefix, secondArg.text);
      }

      // Also collect path-scoped middleware: app.use('/path', middleware(), ...)
      // These middleware apply to all routes matching the path prefix
      const pathMiddlewares: string[] = [];
      for (let i = 1; i < args.length; i++) {
        const mwName = this.extractMiddlewareName(args[i], sourceFile);
        if (mwName) {
          pathMiddlewares.push(mwName);
        }
      }
      if (pathMiddlewares.length > 0) {
        this.registry.registerPathMiddleware(filePath, prefix, pathMiddlewares);
      }
    }
  }

  private processCallExpression(
    callExpr: ts.CallExpression,
    sourceFile: ts.SourceFile,
    filePath: string
  ): Endpoint | null {
    // Check for pattern: app.get('/path', handler) or router.post('/path', handler)
    if (!ts.isPropertyAccessExpression(callExpr.expression)) {
      return null;
    }

    const propAccess = callExpr.expression;
    const methodName = propAccess.name.text.toLowerCase();

    // Check if this is an HTTP method call
    if (!EXPRESS_HTTP_METHODS.has(methodName)) {
      return null;
    }

    // Check if caller is an Express identifier
    const callerName = this.getCallerName(propAccess.expression);
    if (!callerName || !this.isExpressIdentifier(callerName)) {
      return null;
    }

    // Get route path from first argument
    const args = callExpr.arguments;
    if (args.length === 0) {
      return null;
    }

    const routePath = this.extractRoutePath(args[0]);
    if (!routePath) {
      return null;
    }

    // Get prefix if this is a router
    const prefix = this.registry.getRouterPrefix(filePath, callerName);
    const fullRoute = this.normalizePath(prefix + routePath);

    // Extract middleware chain (all arguments except last handler)
    const middlewares = this.extractMiddlewares(args, sourceFile);

    // When there are exactly 2 args (path + one function), the function is treated
    // as the handler. But it might actually be auth middleware (e.g., security.isAuthorized()).
    // Also extract its name as potential middleware so auth extraction can check it.
    const lastArg = args[args.length - 1];
    if (args.length === 2 && ts.isStringLiteral(args[0])) {
      const lastArgName = this.extractMiddlewareName(lastArg, sourceFile);
      if (lastArgName) {
        middlewares.push(lastArgName);
      }
    }

    // Get handler name
    const handlerName = this.extractHandlerName(lastArg, sourceFile);

    // Get location
    const location = getLineAndColumn(sourceFile, callExpr.getStart(sourceFile));

    // Include path-scoped middleware registered via app.use('/path', middleware())
    const pathMiddlewares = this.registry.getPathMiddlewares(fullRoute);

    // Extract authorization info
    const authorization = this.authExtractor.extract(middlewares, {
      isRouter: callerName !== 'app',
      routerMiddlewares: [
        ...this.registry.getAllMiddlewares(filePath, callerName),
        ...pathMiddlewares,
      ],
    });

    return createEndpoint({
      route: fullRoute,
      method: parseHttpMethod(methodName.toUpperCase()) ?? HttpMethod.GET,
      handlerName,
      type: EndpointType.Express,
      location: {
        filePath,
        line: location.line,
        column: location.column,
      },
      authorization,
    });
  }

  private getCallerName(expression: ts.Expression): string | null {
    if (ts.isIdentifier(expression)) {
      return expression.text;
    }
    return null;
  }

  private isExpressIdentifier(name: string): boolean {
    // Common Express variable names
    if (EXPRESS_IDENTIFIERS.has(name)) {
      return true;
    }
    // Also match common patterns like userRouter, apiRouter, etc.
    if (name.toLowerCase().includes('router') || name.toLowerCase().includes('app')) {
      return true;
    }
    return false;
  }

  private extractRoutePath(node: ts.Expression): string | null {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      return node.text;
    }
    // Handle template literals with embedded expressions (extract just the static parts)
    if (ts.isTemplateExpression(node)) {
      let path = node.head.text;
      for (const span of node.templateSpans) {
        path += ':param' + span.literal.text;
      }
      return path;
    }
    return null;
  }

  private extractMiddlewares(
    args: ts.NodeArray<ts.Expression>,
    sourceFile: ts.SourceFile
  ): string[] {
    const middlewares: string[] = [];

    // All arguments except possibly the last one (the main handler) could be middleware
    for (let i = 0; i < args.length - 1; i++) {
      const arg = args[i];
      // Skip the route path (first arg if it's a string)
      if (i === 0 && (ts.isStringLiteral(arg) || ts.isTemplateExpression(arg))) {
        continue;
      }

      const middlewareName = this.extractMiddlewareName(arg, sourceFile);
      if (middlewareName) {
        middlewares.push(middlewareName);
      }
    }

    return middlewares;
  }

  private extractMiddlewareName(
    node: ts.Expression,
    sourceFile: ts.SourceFile
  ): string | null {
    // Direct identifier: requireAuth
    if (ts.isIdentifier(node)) {
      return node.text;
    }

    // Call expression: passport.authenticate('jwt')
    if (ts.isCallExpression(node)) {
      if (ts.isPropertyAccessExpression(node.expression)) {
        const obj = node.expression.expression;
        const method = node.expression.name;
        if (ts.isIdentifier(obj) && ts.isIdentifier(method)) {
          return `${obj.text}.${method.text}`;
        }
      }
      if (ts.isIdentifier(node.expression)) {
        return node.expression.text;
      }
    }

    // Property access: auth.requireRole
    if (ts.isPropertyAccessExpression(node)) {
      const text = node.getText(sourceFile);
      return text;
    }

    // Array of middleware: [auth, validate]
    if (ts.isArrayLiteralExpression(node)) {
      return node.elements
        .map((el) => this.extractMiddlewareName(el, sourceFile))
        .filter(Boolean)
        .join(',');
    }

    return null;
  }

  private extractHandlerName(
    node: ts.Expression,
    sourceFile: ts.SourceFile
  ): string {
    // Direct identifier
    if (ts.isIdentifier(node)) {
      return node.text;
    }

    // Property access: controller.method
    if (ts.isPropertyAccessExpression(node)) {
      return node.getText(sourceFile);
    }

    // Arrow function or function expression
    if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) {
      return 'anonymous';
    }

    return 'unknown';
  }

  private normalizePath(path: string): string {
    // Ensure path starts with /
    if (!path.startsWith('/')) {
      path = '/' + path;
    }
    // Remove duplicate slashes
    path = path.replace(/\/+/g, '/');
    // Remove trailing slash (except for root)
    if (path.length > 1 && path.endsWith('/')) {
      path = path.slice(0, -1);
    }
    return path;
  }
}
