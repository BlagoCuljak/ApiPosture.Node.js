import * as ts from 'typescript';
import { EndpointDiscoverer } from './discoverer-interface.js';
import {
  LoadedSourceFile,
  getLineAndColumn,
  getDecorators,
  getDecoratorName,
  getDecoratorArguments,
  getStringLiteralValue,
} from '../analysis/source-file-loader.js';
import { Endpoint, createEndpoint } from '../models/endpoint.js';
import { EndpointType } from '../models/endpoint-type.js';
import { HttpMethod, parseHttpMethod } from '../models/http-method.js';
import { NestJSAuthExtractor } from '../authorization/nestjs-auth-extractor.js';

const NESTJS_HTTP_DECORATORS = new Map<string, HttpMethod>([
  ['Get', HttpMethod.GET],
  ['Post', HttpMethod.POST],
  ['Put', HttpMethod.PUT],
  ['Delete', HttpMethod.DELETE],
  ['Patch', HttpMethod.PATCH],
  ['Options', HttpMethod.OPTIONS],
  ['Head', HttpMethod.HEAD],
  ['All', HttpMethod.ALL],
]);

export class NestJSDiscoverer implements EndpointDiscoverer {
  readonly name = 'NestJS';
  private authExtractor: NestJSAuthExtractor;

  constructor() {
    this.authExtractor = new NestJSAuthExtractor();
  }

  async discover(file: LoadedSourceFile): Promise<Endpoint[]> {
    const endpoints: Endpoint[] = [];
    const { sourceFile, filePath } = file;

    // Find all classes with @Controller decorator
    ts.forEachChild(sourceFile, (node) => {
      if (ts.isClassDeclaration(node)) {
        const classEndpoints = this.processClass(node, sourceFile, filePath);
        endpoints.push(...classEndpoints);
      }
    });

    return endpoints;
  }

  private processClass(
    classNode: ts.ClassDeclaration,
    sourceFile: ts.SourceFile,
    filePath: string
  ): Endpoint[] {
    const endpoints: Endpoint[] = [];
    const decorators = getDecorators(classNode);

    // Find @Controller decorator
    const controllerDecorator = decorators.find(
      (d) => getDecoratorName(d) === 'Controller'
    );

    if (!controllerDecorator) {
      return endpoints;
    }

    // Get controller path
    const controllerPath = this.extractControllerPath(controllerDecorator);
    const controllerName = classNode.name?.text ?? 'UnknownController';

    // Extract class-level auth decorators
    const classAuth = this.extractClassAuthInfo(decorators);

    // Process all methods in the class
    for (const member of classNode.members) {
      if (ts.isMethodDeclaration(member)) {
        const endpoint = this.processMethod(
          member,
          sourceFile,
          filePath,
          controllerPath,
          controllerName,
          classAuth
        );
        if (endpoint) {
          endpoints.push(endpoint);
        }
      }
    }

    return endpoints;
  }

  private processMethod(
    methodNode: ts.MethodDeclaration,
    sourceFile: ts.SourceFile,
    filePath: string,
    controllerPath: string,
    controllerName: string,
    classAuth: ClassAuthInfo
  ): Endpoint | null {
    const decorators = getDecorators(methodNode);
    const methodName = methodNode.name
      ? ts.isIdentifier(methodNode.name)
        ? methodNode.name.text
        : methodNode.name.getText(sourceFile)
      : 'unknown';

    // Find HTTP method decorator
    let httpMethod: HttpMethod | null = null;
    let routePath = '';

    for (const decorator of decorators) {
      const decoratorName = getDecoratorName(decorator);
      if (decoratorName && NESTJS_HTTP_DECORATORS.has(decoratorName)) {
        httpMethod = NESTJS_HTTP_DECORATORS.get(decoratorName)!;
        routePath = this.extractRoutePath(decorator);
        break;
      }
    }

    if (!httpMethod) {
      return null;
    }

    // Build full route
    const fullRoute = this.buildRoute(controllerPath, routePath);

    // Get location
    const location = getLineAndColumn(sourceFile, methodNode.getStart(sourceFile));

    // Extract authorization info
    const authorization = this.authExtractor.extract(decorators, {
      classGuards: classAuth.guards,
      classRoles: classAuth.roles,
      isPublic: classAuth.isPublic,
    });

    return createEndpoint({
      route: fullRoute,
      method: httpMethod,
      handlerName: methodName,
      controllerName,
      type: EndpointType.NestJS,
      location: {
        filePath,
        line: location.line,
        column: location.column,
      },
      authorization,
    });
  }

  private extractControllerPath(decorator: ts.Decorator): string {
    const args = getDecoratorArguments(decorator);
    if (args.length === 0) {
      return '';
    }

    const firstArg = args[0];
    const path = getStringLiteralValue(firstArg);
    return path ?? '';
  }

  private extractRoutePath(decorator: ts.Decorator): string {
    const args = getDecoratorArguments(decorator);
    if (args.length === 0) {
      return '';
    }

    const firstArg = args[0];
    const path = getStringLiteralValue(firstArg);
    return path ?? '';
  }

  private buildRoute(controllerPath: string, methodPath: string): string {
    let route = '';

    if (controllerPath) {
      route = controllerPath.startsWith('/') ? controllerPath : '/' + controllerPath;
    } else {
      route = '/';
    }

    if (methodPath) {
      const normalizedMethodPath = methodPath.startsWith('/')
        ? methodPath
        : '/' + methodPath;
      route = route === '/' ? normalizedMethodPath : route + normalizedMethodPath;
    }

    // Normalize multiple slashes
    route = route.replace(/\/+/g, '/');

    // Ensure single leading slash
    if (!route.startsWith('/')) {
      route = '/' + route;
    }

    // Remove trailing slash (except for root)
    if (route.length > 1 && route.endsWith('/')) {
      route = route.slice(0, -1);
    }

    return route;
  }

  private extractClassAuthInfo(decorators: ts.Decorator[]): ClassAuthInfo {
    const info: ClassAuthInfo = {
      guards: [],
      roles: [],
      isPublic: false,
    };

    for (const decorator of decorators) {
      const name = getDecoratorName(decorator);

      if (name === 'UseGuards') {
        const args = getDecoratorArguments(decorator);
        for (const arg of args) {
          if (ts.isIdentifier(arg)) {
            info.guards.push(arg.text);
          }
        }
      }

      if (name === 'Roles') {
        const args = getDecoratorArguments(decorator);
        for (const arg of args) {
          const value = getStringLiteralValue(arg);
          if (value) {
            info.roles.push(value);
          }
        }
      }

      if (name === 'Public' || name === 'AllowAnonymous' || name === 'SkipAuth') {
        info.isPublic = true;
      }
    }

    return info;
  }
}

interface ClassAuthInfo {
  guards: string[];
  roles: string[];
  isPublic: boolean;
}
