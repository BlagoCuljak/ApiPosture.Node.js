import * as ts from 'typescript';
import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';

export interface LoadedSourceFile {
  filePath: string;
  sourceFile: ts.SourceFile;
  content: string;
}

export interface SourceFileLoaderOptions {
  extensions?: string[];
  excludePatterns?: string[];
}

const defaultOptions: Required<SourceFileLoaderOptions> = {
  extensions: ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'],
  excludePatterns: [
    '**/node_modules/**',
    '**/dist/**',
    '**/build/**',
    '**/.git/**',
    '**/coverage/**',
    '**/*.spec.ts',
    '**/*.test.ts',
    '**/*.spec.js',
    '**/*.test.js',
  ],
};

export class SourceFileLoader {
  private options: Required<SourceFileLoaderOptions>;
  private cache: Map<string, LoadedSourceFile> = new Map();

  constructor(options: SourceFileLoaderOptions = {}) {
    this.options = { ...defaultOptions, ...options };
  }

  async loadDirectory(dirPath: string): Promise<LoadedSourceFile[]> {
    const absolutePath = path.resolve(dirPath);

    if (!fs.existsSync(absolutePath)) {
      throw new Error(`Directory not found: ${absolutePath}`);
    }

    const patterns = this.options.extensions.map(
      (ext) => `**/*${ext}`
    );

    const files: string[] = [];
    for (const pattern of patterns) {
      const matches = await glob(pattern, {
        cwd: absolutePath,
        ignore: this.options.excludePatterns,
        absolute: true,
        nodir: true,
      });
      files.push(...matches);
    }

    const uniqueFiles = [...new Set(files)];
    const loadedFiles: LoadedSourceFile[] = [];

    for (const filePath of uniqueFiles) {
      try {
        const loaded = await this.loadFile(filePath);
        if (loaded) {
          loadedFiles.push(loaded);
        }
      } catch (error) {
        // Skip files that can't be loaded/parsed
        console.warn(`Warning: Could not load ${filePath}: ${error}`);
      }
    }

    return loadedFiles;
  }

  async loadFile(filePath: string): Promise<LoadedSourceFile | null> {
    const absolutePath = path.resolve(filePath);

    if (this.cache.has(absolutePath)) {
      return this.cache.get(absolutePath)!;
    }

    if (!fs.existsSync(absolutePath)) {
      return null;
    }

    const content = fs.readFileSync(absolutePath, 'utf-8');
    const sourceFile = ts.createSourceFile(
      absolutePath,
      content,
      ts.ScriptTarget.Latest,
      true,
      this.getScriptKind(absolutePath)
    );

    const loaded: LoadedSourceFile = {
      filePath: absolutePath,
      sourceFile,
      content,
    };

    this.cache.set(absolutePath, loaded);
    return loaded;
  }

  private getScriptKind(filePath: string): ts.ScriptKind {
    const ext = path.extname(filePath).toLowerCase();
    switch (ext) {
      case '.ts':
        return ts.ScriptKind.TS;
      case '.tsx':
        return ts.ScriptKind.TSX;
      case '.js':
      case '.mjs':
      case '.cjs':
        return ts.ScriptKind.JS;
      case '.jsx':
        return ts.ScriptKind.JSX;
      default:
        return ts.ScriptKind.Unknown;
    }
  }

  clearCache(): void {
    this.cache.clear();
  }
}

export function getLineAndColumn(
  sourceFile: ts.SourceFile,
  position: number
): { line: number; column: number } {
  const { line, character } = sourceFile.getLineAndCharacterOfPosition(position);
  return { line: line + 1, column: character + 1 };
}

export function getNodeText(node: ts.Node, sourceFile: ts.SourceFile): string {
  return node.getText(sourceFile);
}

export function findNodes<T extends ts.Node>(
  node: ts.Node,
  predicate: (node: ts.Node) => node is T
): T[] {
  const results: T[] = [];

  function visit(n: ts.Node): void {
    if (predicate(n)) {
      results.push(n);
    }
    ts.forEachChild(n, visit);
  }

  visit(node);
  return results;
}

export function findNodesOfKind<T extends ts.Node>(
  node: ts.Node,
  kind: ts.SyntaxKind
): T[] {
  return findNodes(node, (n): n is T => n.kind === kind);
}

export function getDecorators(node: ts.Node): ts.Decorator[] {
  if (ts.canHaveDecorators(node)) {
    return (ts.getDecorators(node) ?? []) as ts.Decorator[];
  }
  return [];
}

export function getDecoratorName(decorator: ts.Decorator): string | null {
  const expression = decorator.expression;

  if (ts.isIdentifier(expression)) {
    return expression.text;
  }

  if (ts.isCallExpression(expression)) {
    const callee = expression.expression;
    if (ts.isIdentifier(callee)) {
      return callee.text;
    }
  }

  return null;
}

export function getDecoratorArguments(decorator: ts.Decorator): ts.Expression[] {
  const expression = decorator.expression;

  if (ts.isCallExpression(expression)) {
    return [...expression.arguments];
  }

  return [];
}

export function getStringLiteralValue(node: ts.Node): string | null {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
    return node.text;
  }
  return null;
}

export function getArrayLiteralElements(node: ts.Node): ts.Expression[] {
  if (ts.isArrayLiteralExpression(node)) {
    return [...node.elements];
  }
  return [];
}
