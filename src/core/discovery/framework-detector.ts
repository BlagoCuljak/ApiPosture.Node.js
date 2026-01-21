import * as fs from 'fs';
import * as path from 'path';
import { EndpointType } from '../models/endpoint-type.js';

export interface DetectedFrameworks {
  frameworks: EndpointType[];
  confidence: Record<EndpointType, number>;
}

export class FrameworkDetector {
  detect(projectPath: string): DetectedFrameworks {
    const result: DetectedFrameworks = {
      frameworks: [],
      confidence: {
        [EndpointType.Express]: 0,
        [EndpointType.NestJS]: 0,
        [EndpointType.Fastify]: 0,
        [EndpointType.Koa]: 0,
      },
    };

    // Read package.json
    const packageJsonPath = path.join(projectPath, 'package.json');
    if (!fs.existsSync(packageJsonPath)) {
      return result;
    }

    let packageJson: Record<string, unknown>;
    try {
      const content = fs.readFileSync(packageJsonPath, 'utf-8');
      packageJson = JSON.parse(content);
    } catch {
      return result;
    }

    const deps = {
      ...(packageJson.dependencies as Record<string, string> | undefined),
      ...(packageJson.devDependencies as Record<string, string> | undefined),
    };

    // Check for Express
    if (deps.express) {
      result.confidence[EndpointType.Express] = 100;
    }

    // Check for NestJS
    if (deps['@nestjs/core'] || deps['@nestjs/common']) {
      result.confidence[EndpointType.NestJS] = 100;
    }

    // Check for Fastify
    if (deps.fastify) {
      result.confidence[EndpointType.Fastify] = 100;
    }

    // Check for Koa
    if (deps.koa) {
      result.confidence[EndpointType.Koa] = 100;
      // If koa-router is present, increase confidence
      if (deps['koa-router'] || deps['@koa/router']) {
        result.confidence[EndpointType.Koa] = 100;
      }
    }

    // Build frameworks list (those with confidence > 0)
    for (const [framework, confidence] of Object.entries(result.confidence)) {
      if (confidence > 0) {
        result.frameworks.push(framework as EndpointType);
      }
    }

    return result;
  }
}
