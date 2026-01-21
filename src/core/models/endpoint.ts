import { AuthorizationInfo, createDefaultAuthorizationInfo } from './authorization-info.js';
import { EndpointType } from './endpoint-type.js';
import { HttpMethod } from './http-method.js';
import { SourceLocation } from './source-location.js';

export interface Endpoint {
  route: string;
  method: HttpMethod;
  handlerName: string;
  controllerName?: string;
  type: EndpointType;
  location: SourceLocation;
  authorization: AuthorizationInfo;
}

export function createEndpoint(
  partial: Partial<Endpoint> & Pick<Endpoint, 'route' | 'method' | 'type' | 'location'>
): Endpoint {
  return {
    route: partial.route,
    method: partial.method,
    handlerName: partial.handlerName ?? 'anonymous',
    controllerName: partial.controllerName,
    type: partial.type,
    location: partial.location,
    authorization: partial.authorization ?? createDefaultAuthorizationInfo(),
  };
}

export function formatEndpoint(endpoint: Endpoint): string {
  return `${endpoint.method} ${endpoint.route}`;
}
