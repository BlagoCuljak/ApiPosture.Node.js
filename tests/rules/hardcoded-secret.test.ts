import { describe, it, expect } from 'vitest';
import {
  HardcodedSecretRule,
  findSecrets,
  isSecretScanExcludedPath,
  maskSecret,
} from '../../src/rules/secrets/hardcoded-secret.js';

// Secrets are assembled at runtime so no literal credential appears in the repo.
const R16 = 'Q7RT2KLM9PZ4VNBH';
const R36 = 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8';
const R24 = 'a1B2c3D4e5F6g7H8i9J0k1L2';
const R43 = 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v';
const HEX64 = 'a1b2c3d4e5f6a7b8'.repeat(4);

const positives: Array<[string, string]> = [
  ['AWS access key ID', 'AKIA' + R16],
  ['AWS access key ID', 'ASIA' + R16],
  ['GCP API key', 'AIza' + R36.slice(0, 35)],
  ['GitHub token', 'ghp_' + R36],
  ['GitHub token', 'gho_' + R36],
  ['GitHub fine-grained token', 'github_pat_' + R36 + R36 + 'a1B2c3D4e5F6g7'.slice(0, 10)],
  ['GitLab personal access token', 'glpat-' + R24],
  ['Stripe live secret key', 'sk_live_' + R24],
  ['Stripe live secret key', 'rk_live_' + R24],
  ['Slack token', 'xoxb-' + '1234567890-abcdefghij'],
  [
    'Slack webhook URL',
    'https://hooks.slack.com/services/' + 'T0ABCDEFG1' + '/' + 'B0ABCDEFG1' + '/' + R24,
  ],
  ['SendGrid API key', 'SG.' + R24.slice(0, 22) + '.' + R43],
  ['npm access token', 'npm_' + R36],
  ['DigitalOcean token', 'dop_v1_' + HEX64],
  ['Private key', '-----BEGIN ' + 'RSA PRIVATE KEY-----'],
  ['Private key', '-----BEGIN ' + 'PRIVATE KEY-----'],
  ['Private key', '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----'],
];

describe('AP201 hardcoded secret', () => {
  it.each(positives)('detects %s', (type, secret) => {
    const found = findSecrets(`const k = "${secret}";`);
    expect(found).toHaveLength(1);
    expect(found[0].type).toBe(type);
    expect(found[0].line).toBe(1);
  });

  it('never prints the full secret', () => {
    const secret = 'ghp_' + R36;
    const rule = new HardcodedSecretRule();
    const [f] = rule.scanContent('/p/src/a.ts', 'src/a.ts', `x = "${secret}"`);
    expect(f.ruleId).toBe('AP201');
    expect(f.severity).toBe('high');
    expect(f.message).not.toContain(secret);
    expect(f.message).toContain('ghp_…');
    expect(f.location.line).toBe(1);
    expect(f.location.filePath).toBe('/p/src/a.ts');
    expect(maskSecret(secret)).toBe('ghp_…');
  });

  it('reports one finding per (file, line, type)', () => {
    const a = 'ghp_' + R36;
    const b = 'ghs_' + R36;
    expect(findSecrets(`x("${a}", "${b}")`)).toHaveLength(1);
    expect(findSecrets(`x("${a}")\ny("${b}")`)).toHaveLength(2);
  });

  it('ignores placeholder values', () => {
    const cases = [
      'AKIAIOSFODNN7EXAMPLE',
      'AKIA' + 'XXXXXXXXXXXXXXXX',
      'sk_live_' + 'your_key_here_1234567890ab',
      'sk_live_' + 'changeme' + R24,
      'ghp_' + 'dummy' + R36.slice(5),
      'ghp_' + 'fake' + R36.slice(4),
      'npm_' + 'placeholder' + R36.slice(11),
      'ghp_' + 'redacted' + R36.slice(8),
      'ghp_' + 'sample' + R36.slice(6),
    ];
    for (const c of cases) {
      expect(findSecrets(`k = "${c}"`)).toHaveLength(0);
    }
    expect(findSecrets('k = `${AKIA' + R16 + '}`')).toHaveLength(0);
    expect(findSecrets('k = "{{AKIA' + R16 + '}}"')).toHaveLength(0);
    expect(findSecrets('k = "<AKIA' + R16 + '>"')).toHaveLength(0);
  });

  it('does not flag pk_live, generic passwords, or short lookalikes', () => {
    expect(findSecrets('k = "pk_live_' + R24 + '"')).toHaveLength(0);
    expect(findSecrets('password = "hunter2hunter2"')).toHaveLength(0);
    expect(findSecrets('token = "abcdef1234567890abcdef"')).toHaveLength(0);
    expect(findSecrets('k = "AKIA123"')).toHaveLength(0);
    expect(findSecrets('k = "-----BEGIN ' + 'PUBLIC KEY-----"')).toHaveLength(0);
  });

  it('skips excluded paths and file types', () => {
    const excluded = [
      'test/a.ts',
      'tests/a.ts',
      'src/__tests__/a.ts',
      'src/__mocks__/a.ts',
      'spec/a.ts',
      'fixtures/a.json',
      'testdata/a.json',
      'samples/a.ts',
      'examples/a.ts',
      'docs/a.ts',
      'node_modules/x/a.js',
      'dist/a.js',
      'build/a.js',
      'coverage/a.js',
      'src/a.test.ts',
      'src/a.spec.js',
      'public/app.min.js',
      'package-lock.json',
      'yarn.lock',
      'pnpm-lock.yaml',
      'dist/a.js.map',
    ];
    for (const p of excluded) expect(isSecretScanExcludedPath(p)).toBe(true);
    expect(isSecretScanExcludedPath('src/config.ts')).toBe(false);
    expect(isSecretScanExcludedPath('.env')).toBe(false);

    const rule = new HardcodedSecretRule();
    const content = `k = "AKIA${R16}"`;
    expect(rule.scanContent('/p/test/a.ts', 'test/a.ts', content)).toHaveLength(0);
    expect(rule.scanContent('/p/src/a.ts', 'src/a.ts', content)).toHaveLength(1);
  });

  it('detects secrets in .env style content', () => {
    expect(findSecrets('NPM_TOKEN=npm_' + R36 + '\n')).toHaveLength(1);
  });
});
