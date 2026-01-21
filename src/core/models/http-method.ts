export enum HttpMethod {
  GET = 'GET',
  POST = 'POST',
  PUT = 'PUT',
  DELETE = 'DELETE',
  PATCH = 'PATCH',
  OPTIONS = 'OPTIONS',
  HEAD = 'HEAD',
  ALL = 'ALL',
}

export const writeMethods = new Set([
  HttpMethod.POST,
  HttpMethod.PUT,
  HttpMethod.DELETE,
  HttpMethod.PATCH,
]);

export function isWriteMethod(method: HttpMethod): boolean {
  return writeMethods.has(method);
}

export function parseHttpMethod(value: string): HttpMethod | undefined {
  const normalized = value.toUpperCase();
  return Object.values(HttpMethod).find((m) => m === normalized);
}
