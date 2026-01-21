import * as ts from 'typescript';
import { LoadedSourceFile, findNodes } from '../analysis/source-file-loader.js';

export interface GlobalAuthConfig {
  hasGlobalGuard: boolean;
  globalGuardName?: string;
  hasGlobalPrefix: boolean;
  globalPrefix?: string;
}

export class GlobalAuthAnalyzer {
  analyze(files: LoadedSourceFile[]): GlobalAuthConfig {
    const config: GlobalAuthConfig = {
      hasGlobalGuard: false,
      hasGlobalPrefix: false,
    };

    for (const file of files) {
      this.analyzeFile(file, config);
    }

    return config;
  }

  private analyzeFile(file: LoadedSourceFile, config: GlobalAuthConfig): void {
    const { sourceFile } = file;

    // Look for app.useGlobalGuards() calls
    const callExpressions = findNodes(sourceFile, ts.isCallExpression);

    for (const callExpr of callExpressions) {
      // Check for app.useGlobalGuards(new AuthGuard())
      if (ts.isPropertyAccessExpression(callExpr.expression)) {
        const propAccess = callExpr.expression;
        const methodName = propAccess.name.text;

        if (methodName === 'useGlobalGuards') {
          config.hasGlobalGuard = true;
          // Try to extract guard name
          if (callExpr.arguments.length > 0) {
            const arg = callExpr.arguments[0];
            if (ts.isNewExpression(arg) && ts.isIdentifier(arg.expression)) {
              config.globalGuardName = arg.expression.text;
            }
          }
        }

        if (methodName === 'setGlobalPrefix') {
          config.hasGlobalPrefix = true;
          if (callExpr.arguments.length > 0) {
            const arg = callExpr.arguments[0];
            if (ts.isStringLiteral(arg)) {
              config.globalPrefix = arg.text;
            }
          }
        }
      }

      // Check for APP_GUARD provider pattern
      // { provide: APP_GUARD, useClass: AuthGuard }
      if (
        callExpr.arguments.length > 0 &&
        ts.isObjectLiteralExpression(callExpr.arguments[0])
      ) {
        const objLiteral = callExpr.arguments[0];
        let hasAppGuard = false;
        let guardName: string | undefined;

        for (const prop of objLiteral.properties) {
          if (ts.isPropertyAssignment(prop) && ts.isIdentifier(prop.name)) {
            if (prop.name.text === 'provide') {
              if (ts.isIdentifier(prop.initializer)) {
                if (prop.initializer.text === 'APP_GUARD') {
                  hasAppGuard = true;
                }
              }
            }
            if (prop.name.text === 'useClass') {
              if (ts.isIdentifier(prop.initializer)) {
                guardName = prop.initializer.text;
              }
            }
          }
        }

        if (hasAppGuard && guardName) {
          config.hasGlobalGuard = true;
          config.globalGuardName = guardName;
        }
      }
    }
  }
}
