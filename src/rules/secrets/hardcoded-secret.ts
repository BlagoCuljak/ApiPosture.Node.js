import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import { Finding, createFinding } from '../../core/models/finding.js';
import { Severity } from '../../core/models/severity.js';
import { createEndpoint } from '../../core/models/endpoint.js';
import { HttpMethod } from '../../core/models/http-method.js';
import { EndpointType } from '../../core/models/endpoint-type.js';
import type { LoadedSourceFile } from '../../core/analysis/source-file-loader.js';

/**
 * AP201: Hardcoded secret
 *
 * High-precision, file-level detection of credentials with distinctive,
 * vendor-specific formats. Generic heuristics (password=, token=, JWT,
 * connection strings, ...) are intentionally NOT included.
 */

interface SecretPattern {
  type: string;
  regex: RegExp;
}

const SECRET_PATTERNS: SecretPattern[] = [
  { type: 'AWS access key ID', regex: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { type: 'GCP API key', regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { type: 'GitHub token', regex: /\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b/g },
  { type: 'GitHub fine-grained token', regex: /\bgithub_pat_[0-9A-Za-z_]{82}\b/g },
  { type: 'GitLab personal access token', regex: /\bglpat-[0-9A-Za-z\-_]{20,}\b/g },
  { type: 'Stripe live secret key', regex: /\b(sk|rk)_live_[0-9A-Za-z]{24,}\b/g },
  { type: 'Slack token', regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  {
    type: 'Slack webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8,}\/B[0-9A-Z]{8,}\/[0-9A-Za-z]{24}/g,
  },
  { type: 'SendGrid API key', regex: /\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b/g },
  { type: 'npm access token', regex: /\bnpm_[0-9A-Za-z]{36}\b/g },
  { type: 'DigitalOcean token', regex: /\bdop_v1_[0-9a-f]{64}\b/g },
  {
    type: 'Private key',
    regex: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----/g,
  },
];

const PLACEHOLDER_MARKERS = [
  'example',
  'xxxx',
  'your_',
  'your-',
  '<',
  '>',
  '${',
  '{{',
  'changeme',
  'dummy',
  'fake',
  'sample',
  'placeholder',
  'redacted',
  'akiaiosfodnn7example',
];

const EXCLUDED_DIRS = new Set([
  'test',
  'tests',
  'spec',
  '__tests__',
  '__mocks__',
  'fixtures',
  'testdata',
  'samples',
  'examples',
  'docs',
  'node_modules',
  'dist',
  'build',
  'coverage',
  '.git',
]);

const LOCKFILES = new Set([
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'npm-shrinkwrap.json',
  'bun.lockb',
  'composer.lock',
]);

const MAX_FILE_BYTES = 1024 * 1024;
const SCANNABLE_CODE_EXT = new Set(['.js', '.ts', '.mjs', '.cjs']);
const SCANNABLE_CONFIG_EXT = new Set(['.json', '.yaml', '.yml']);

export function isSecretScanExcludedPath(relativePath: string): boolean {
  const normalized = relativePath.split(path.sep).join('/');
  const segments = normalized.split('/');
  const fileName = segments[segments.length - 1];
  const dirs = segments.slice(0, -1);

  if (dirs.some((d) => EXCLUDED_DIRS.has(d.toLowerCase()))) return true;

  const lower = fileName.toLowerCase();
  if (LOCKFILES.has(lower)) return true;
  if (/\.(test|spec)\.[^.]+$/.test(lower)) return true;
  if (/\.min\.(js|mjs|cjs)$/.test(lower)) return true;
  if (lower.endsWith('.map')) return true;
  return false;
}

export function isPlaceholderValue(value: string): boolean {
  const lower = value.toLowerCase();
  return PLACEHOLDER_MARKERS.some((m) => lower.includes(m));
}

export function maskSecret(value: string): string {
  return `${value.slice(0, 4)}…`;
}

/** Expand a match to the surrounding token (up to whitespace/quotes/delimiters). */
function surroundingToken(line: string, start: number, end: number): string {
  const stop = /[\s'"`,;()[\]]/;
  let s = start;
  let e = end;
  while (s > 0 && !stop.test(line[s - 1])) s--;
  while (e < line.length && !stop.test(line[e])) e++;
  return line.slice(s, e);
}

export interface SecretMatch {
  type: string;
  line: number;
  masked: string;
}

export function findSecrets(content: string): SecretMatch[] {
  const results: SecretMatch[] = [];
  const seen = new Set<string>();
  const lines = content.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 5000) continue; // minified / generated content
    for (const { type, regex } of SECRET_PATTERNS) {
      regex.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = regex.exec(line)) !== null) {
        const value = m[0];
        const token = surroundingToken(line, m.index, m.index + value.length);
        if (isPlaceholderValue(value) || isPlaceholderValue(token)) continue;
        const key = `${i + 1}:${type}`;
        if (seen.has(key)) continue;
        seen.add(key);
        results.push({ type, line: i + 1, masked: maskSecret(value) });
      }
    }
  }
  return results;
}

export class HardcodedSecretRule {
  readonly id = 'AP201';
  readonly name = 'Hardcoded secret';
  readonly description = 'Source or config file contains a hardcoded credential';
  readonly severity = Severity.High;

  /** Scan one file's content. `relativePath` is relative to the scan root and is used for path guards. */
  scanContent(filePath: string, relativePath: string, content: string): Finding[] {
    if (isSecretScanExcludedPath(relativePath)) return [];

    const endpoint = createEndpoint({
      route: relativePath.split(path.sep).join('/'),
      method: HttpMethod.GET,
      type: EndpointType.Express,
      location: { filePath, line: 1, column: 1 },
    });

    return findSecrets(content).map((s) =>
      createFinding({
        ruleId: this.id,
        ruleName: this.name,
        severity: this.severity,
        message: `Hardcoded ${s.type} (${s.masked}) at line ${s.line}`,
        endpoint,
        location: { filePath, line: s.line, column: 1 },
        recommendation:
          'Remove the secret from source, rotate it, and load it from an environment variable or secret manager.',
      })
    );
  }

  /** Scan already-loaded JS/TS files plus .env and simple json/yaml config files under the root. */
  async scanProject(rootDir: string, loadedFiles: LoadedSourceFile[]): Promise<Finding[]> {
    const root = path.resolve(rootDir);
    const findings: Finding[] = [];
    const done = new Set<string>();

    const scan = (abs: string, content: string): void => {
      if (done.has(abs)) return;
      done.add(abs);
      findings.push(...this.scanContent(abs, path.relative(root, abs), content));
    };

    for (const f of loadedFiles) {
      if (!SCANNABLE_CODE_EXT.has(path.extname(f.filePath).toLowerCase())) continue;
      scan(f.filePath, f.content);
    }

    const extra = await glob(['**/.env', '**/.env.*', '**/*.env', '**/*.json', '**/*.yaml', '**/*.yml'], {
      cwd: root,
      absolute: true,
      nodir: true,
      dot: true,
      ignore: ['**/node_modules/**', '**/.git/**', '**/dist/**', '**/build/**', '**/coverage/**'],
    });

    for (const abs of extra) {
      const base = path.basename(abs).toLowerCase();
      const ext = path.extname(base);
      const isEnv = base === '.env' || base.startsWith('.env.') || ext === '.env';
      if (!isEnv && !SCANNABLE_CONFIG_EXT.has(ext)) continue;
      try {
        if (fs.statSync(abs).size > MAX_FILE_BYTES) continue;
        scan(abs, fs.readFileSync(abs, 'utf-8'));
      } catch {
        // unreadable file: skip
      }
    }

    return findings;
  }
}
