import * as fs from 'fs';
import * as path from 'path';
import { Command } from 'commander';
import ora from 'ora';
import {
  ScanOptions,
  defaultScanOptions,
  parseClassificationList,
  parseMethodList,
  parseApiStyleList,
  parseRuleList,
} from '../options.js';
import { ProjectAnalyzer } from '../../core/analysis/project-analyzer.js';
import { ExpressDiscoverer } from '../../core/discovery/express-discoverer.js';
import { NestJSDiscoverer } from '../../core/discovery/nestjs-discoverer.js';
import { FastifyDiscoverer } from '../../core/discovery/fastify-discoverer.js';
import { KoaDiscoverer } from '../../core/discovery/koa-discoverer.js';
import { RuleEngine } from '../../rules/rule-engine.js';
import { ScanResult, getHighestSeverity } from '../../core/models/scan-result.js';
import { severityOrder, parseSeverity } from '../../core/models/severity.js';
import { TerminalFormatter } from '../../output/terminal-formatter.js';
import { JsonFormatter } from '../../output/json-formatter.js';
import { MarkdownFormatter } from '../../output/markdown-formatter.js';
import { OutputFormatter } from '../../output/formatter-interface.js';
import { ConfigLoader } from '../../core/configuration/config-loader.js';

export function createScanCommand(): Command {
  const command = new Command('scan')
    .description('Scan a Node.js project for API security issues')
    .argument('[path]', 'Path to the project to scan', '.')
    .option('-o, --output <format>', 'Output format: terminal, json, markdown', 'terminal')
    .option('-f, --output-file <path>', 'Write output to file')
    .option('-c, --config <path>', 'Path to config file (.apiposture.json)')
    .option('--severity <level>', 'Minimum severity: info, low, medium, high, critical')
    .option('--fail-on <level>', 'Exit with code 1 if findings at this level or higher')
    .option('--sort-by <field>', 'Sort by: severity, route, method, classification')
    .option('--sort-dir <dir>', 'Sort direction: asc, desc')
    .option('--classification <types>', 'Filter by classification (comma-separated)')
    .option('--method <methods>', 'Filter by HTTP method (comma-separated)')
    .option('--route-contains <str>', 'Filter routes containing string')
    .option('--api-style <styles>', 'Filter by framework: express, nestjs, fastify, koa')
    .option('--rule <rules>', 'Filter by rule ID (comma-separated)')
    .option('--group-by <field>', 'Group endpoints by field')
    .option('--no-color', 'Disable colors in output')
    .option('--no-icons', 'Disable icons in output')
    .action(async (projectPath: string, cmdOptions: Record<string, unknown>) => {
      await runScan(projectPath, cmdOptions);
    });

  return command;
}

async function runScan(
  projectPath: string,
  cmdOptions: Record<string, unknown>
): Promise<void> {
  const absolutePath = path.resolve(projectPath);

  // Validate project path exists
  if (!fs.existsSync(absolutePath)) {
    console.error(`Error: Path not found: ${absolutePath}`);
    process.exit(1);
  }

  // Load config if specified (for future use with rule configuration)
  const configPath = cmdOptions.config as string | undefined;
  if (configPath) {
    const configLoader = new ConfigLoader();
    await configLoader.load(configPath);
  }

  // Parse options
  const options: ScanOptions = {
    ...defaultScanOptions,
    output: (cmdOptions.output as ScanOptions['output']) ?? 'terminal',
    outputFile: cmdOptions.outputFile as string | undefined,
    severity: cmdOptions.severity ? parseSeverity(cmdOptions.severity as string) : undefined,
    failOn: cmdOptions.failOn ? parseSeverity(cmdOptions.failOn as string) : undefined,
    sortBy: cmdOptions.sortBy as ScanOptions['sortBy'],
    sortDir: cmdOptions.sortDir as ScanOptions['sortDir'],
    classification: cmdOptions.classification
      ? parseClassificationList(cmdOptions.classification as string)
      : undefined,
    method: cmdOptions.method
      ? parseMethodList(cmdOptions.method as string)
      : undefined,
    routeContains: cmdOptions.routeContains as string | undefined,
    apiStyle: cmdOptions.apiStyle
      ? parseApiStyleList(cmdOptions.apiStyle as string)
      : undefined,
    rule: cmdOptions.rule
      ? parseRuleList(cmdOptions.rule as string)
      : undefined,
    noColor: cmdOptions.color === false,
    noIcons: cmdOptions.icons === false,
  };

  // Start scanning
  const spinner = ora({
    text: 'Scanning project...',
    isSilent: options.output !== 'terminal',
  }).start();

  try {
    // Create analyzer
    const analyzer = new ProjectAnalyzer();

    // Register discoverers based on api-style filter or all by default
    const apiStyles = options.apiStyle ?? ['express', 'nestjs', 'fastify', 'koa'];

    if (apiStyles.includes('express' as any)) {
      analyzer.registerDiscoverer(new ExpressDiscoverer());
    }
    if (apiStyles.includes('nestjs' as any)) {
      analyzer.registerDiscoverer(new NestJSDiscoverer());
    }
    if (apiStyles.includes('fastify' as any)) {
      analyzer.registerDiscoverer(new FastifyDiscoverer());
    }
    if (apiStyles.includes('koa' as any)) {
      analyzer.registerDiscoverer(new KoaDiscoverer());
    }

    // Run analysis
    let result = await analyzer.analyze(absolutePath);

    // Apply rule evaluation
    const ruleEngine = new RuleEngine();
    const findings = ruleEngine.evaluate(result.endpoints);
    result = { ...result, findings };

    // Apply filters
    result = applyFilters(result, options);

    spinner.succeed(`Scan complete`);

    // Format and output
    const formatter = getFormatter(options);
    const output = formatter.format(result);

    if (options.outputFile) {
      fs.writeFileSync(options.outputFile, output, 'utf-8');
      console.log(`Output written to: ${options.outputFile}`);
    } else {
      console.log(output);
    }

    // Check fail-on condition
    if (options.failOn) {
      const highest = getHighestSeverity(result);
      if (highest && severityOrder[highest] >= severityOrder[options.failOn]) {
        process.exit(1);
      }
    }
  } catch (error) {
    spinner.fail('Scan failed');
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  }
}

function applyFilters(result: ScanResult, options: ScanOptions): ScanResult {
  let { endpoints, findings } = result;

  // Filter by severity
  if (options.severity) {
    const minSeverity = severityOrder[options.severity];
    findings = findings.filter((f) => severityOrder[f.severity] >= minSeverity);
  }

  // Filter by classification
  if (options.classification && options.classification.length > 0) {
    endpoints = endpoints.filter((e) =>
      options.classification!.includes(e.authorization.classification)
    );
    findings = findings.filter((f) =>
      options.classification!.includes(f.endpoint.authorization.classification)
    );
  }

  // Filter by method
  if (options.method && options.method.length > 0) {
    endpoints = endpoints.filter((e) => options.method!.includes(e.method));
    findings = findings.filter((f) => options.method!.includes(f.endpoint.method));
  }

  // Filter by route
  if (options.routeContains) {
    const searchStr = options.routeContains.toLowerCase();
    endpoints = endpoints.filter((e) =>
      e.route.toLowerCase().includes(searchStr)
    );
    findings = findings.filter((f) =>
      f.endpoint.route.toLowerCase().includes(searchStr)
    );
  }

  // Filter by api style
  if (options.apiStyle && options.apiStyle.length > 0) {
    endpoints = endpoints.filter((e) => options.apiStyle!.includes(e.type));
    findings = findings.filter((f) => options.apiStyle!.includes(f.endpoint.type));
  }

  // Filter by rule
  if (options.rule && options.rule.length > 0) {
    findings = findings.filter((f) => options.rule!.includes(f.ruleId));
  }

  // Apply sorting
  if (options.sortBy) {
    const dir = options.sortDir === 'desc' ? -1 : 1;

    endpoints = [...endpoints].sort((a, b) => {
      switch (options.sortBy) {
        case 'route':
          return dir * a.route.localeCompare(b.route);
        case 'method':
          return dir * a.method.localeCompare(b.method);
        case 'classification':
          return dir * a.authorization.classification.localeCompare(b.authorization.classification);
        default:
          return 0;
      }
    });

    findings = [...findings].sort((a, b) => {
      switch (options.sortBy) {
        case 'severity':
          return dir * (severityOrder[a.severity] - severityOrder[b.severity]);
        case 'route':
          return dir * a.endpoint.route.localeCompare(b.endpoint.route);
        case 'method':
          return dir * a.endpoint.method.localeCompare(b.endpoint.method);
        default:
          return 0;
      }
    });
  }

  return { ...result, endpoints, findings };
}

function getFormatter(options: ScanOptions): OutputFormatter {
  switch (options.output) {
    case 'json':
      return new JsonFormatter();
    case 'markdown':
      return new MarkdownFormatter();
    case 'terminal':
    default:
      return new TerminalFormatter({
        noColor: options.noColor,
        noIcons: options.noIcons,
      });
  }
}
