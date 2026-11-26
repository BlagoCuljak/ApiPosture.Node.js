/**
 * Library entry point for @apiposture/cli.
 * Re-exports public types, functions, and classes for programmatic use.
 */

// Models
export * from './core/models/index.js';

// Analysis
export { ProjectAnalyzer } from './core/analysis/project-analyzer.js';
export { SourceFileLoader } from './core/analysis/source-file-loader.js';

// Discovery
export * from './core/discovery/index.js';

// Rules
export { RuleEngine } from './rules/rule-engine.js';
export type { SecurityRule } from './rules/rule-interface.js';
export { isKnownPublicEndpoint } from './rules/known-public-routes.js';
export { HardcodedSecretRule } from './rules/secrets/hardcoded-secret.js';

// Output
export type { OutputFormatter, FormatterOptions } from './output/formatter-interface.js';
export { TerminalFormatter } from './output/terminal-formatter.js';
export { JsonFormatter } from './output/json-formatter.js';
export { MarkdownFormatter } from './output/markdown-formatter.js';
