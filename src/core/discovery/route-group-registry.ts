export interface RouteGroup {
  prefix: string;
  middlewares: string[];
  variableName: string;
  filePath: string;
}

export class RouteGroupRegistry {
  private groups: Map<string, RouteGroup[]> = new Map();
  private routerMounts: Map<string, { prefix: string; routerName: string }[]> = new Map();
  private pathMiddlewares: { prefix: string; middlewares: string[]; filePath: string }[] = [];

  registerGroup(
    filePath: string,
    variableName: string,
    prefix: string = '',
    middlewares: string[] = []
  ): void {
    const key = this.makeKey(filePath, variableName);
    const group: RouteGroup = {
      prefix,
      middlewares,
      variableName,
      filePath,
    };

    if (!this.groups.has(key)) {
      this.groups.set(key, []);
    }
    this.groups.get(key)!.push(group);
  }

  registerRouterMount(
    filePath: string,
    appVariableName: string,
    prefix: string,
    routerName: string
  ): void {
    const key = this.makeKey(filePath, appVariableName);
    if (!this.routerMounts.has(key)) {
      this.routerMounts.set(key, []);
    }
    this.routerMounts.get(key)!.push({ prefix, routerName });
  }

  getGroup(filePath: string, variableName: string): RouteGroup | undefined {
    const key = this.makeKey(filePath, variableName);
    const groups = this.groups.get(key);
    return groups?.[groups.length - 1];
  }

  getRouterPrefix(filePath: string, routerName: string): string {
    for (const [, mounts] of this.routerMounts) {
      const mount = mounts.find((m) => m.routerName === routerName);
      if (mount) {
        return mount.prefix;
      }
    }
    return '';
  }

  getAllMiddlewares(filePath: string, variableName: string): string[] {
    const group = this.getGroup(filePath, variableName);
    return group?.middlewares ?? [];
  }

  registerPathMiddleware(filePath: string, prefix: string, middlewares: string[]): void {
    this.pathMiddlewares.push({ prefix, middlewares, filePath });
  }

  getPathMiddlewares(route: string): string[] {
    const result: string[] = [];
    for (const pm of this.pathMiddlewares) {
      // Check if route starts with the middleware prefix
      if (route === pm.prefix || route.startsWith(pm.prefix + '/')) {
        result.push(...pm.middlewares);
      }
    }
    return result;
  }

  clear(): void {
    this.groups.clear();
    this.routerMounts.clear();
    this.pathMiddlewares = [];
  }

  private makeKey(filePath: string, variableName: string): string {
    return `${filePath}::${variableName}`;
  }
}
