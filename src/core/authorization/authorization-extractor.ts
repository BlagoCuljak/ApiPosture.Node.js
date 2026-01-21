import { AuthorizationInfo } from '../models/authorization-info.js';

export interface AuthorizationExtractorContext {
  isRouter?: boolean;
  routerMiddlewares?: string[];
  classGuards?: string[];
  classRoles?: string[];
}

export interface AuthorizationExtractor {
  extract(
    middlewares: string[],
    context?: AuthorizationExtractorContext
  ): AuthorizationInfo;
}
