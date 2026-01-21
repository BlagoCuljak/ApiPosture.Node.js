export enum EndpointType {
  Express = 'express',
  NestJS = 'nestjs',
  Fastify = 'fastify',
  Koa = 'koa',
}

export function parseEndpointType(value: string): EndpointType | undefined {
  const normalized = value.toLowerCase();
  return Object.values(EndpointType).find((t) => t === normalized);
}
