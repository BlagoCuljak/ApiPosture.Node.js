import { Endpoint } from '../models/endpoint.js';
import { Finding } from '../models/finding.js';
import { ScanResult, createScanResult } from '../models/scan-result.js';
import { SourceFileLoader, LoadedSourceFile } from './source-file-loader.js';
import { EndpointDiscoverer } from '../discovery/discoverer-interface.js';
import { SecurityRule } from '../../rules/rule-interface.js';

export interface ProjectAnalyzerOptions {
  configPath?: string;
}

export class ProjectAnalyzer {
  private sourceLoader: SourceFileLoader;
  private discoverers: EndpointDiscoverer[] = [];
  private rules: SecurityRule[] = [];

  constructor(options: ProjectAnalyzerOptions = {}) {
    this.sourceLoader = new SourceFileLoader();
  }

  registerDiscoverer(discoverer: EndpointDiscoverer): void {
    this.discoverers.push(discoverer);
  }

  registerRule(rule: SecurityRule): void {
    this.rules.push(rule);
  }

  registerRules(rules: SecurityRule[]): void {
    this.rules.push(...rules);
  }

  async analyze(projectPath: string): Promise<ScanResult> {
    const startTime = Date.now();

    const sourceFiles = await this.sourceLoader.loadDirectory(projectPath);

    const endpoints = await this.discoverEndpoints(sourceFiles);
    const findings = this.evaluateRules(endpoints);

    const scanDurationMs = Date.now() - startTime;

    return createScanResult({
      projectPath,
      endpoints,
      findings,
      filesScanned: sourceFiles.length,
      scanDurationMs,
    });
  }

  private async discoverEndpoints(
    sourceFiles: LoadedSourceFile[]
  ): Promise<Endpoint[]> {
    const endpoints: Endpoint[] = [];

    for (const discoverer of this.discoverers) {
      for (const file of sourceFiles) {
        const discovered = await discoverer.discover(file);
        endpoints.push(...discovered);
      }
    }

    return endpoints;
  }

  private evaluateRules(endpoints: Endpoint[]): Finding[] {
    const findings: Finding[] = [];

    for (const rule of this.rules) {
      for (const endpoint of endpoints) {
        const ruleFindings = rule.evaluate(endpoint);
        findings.push(...ruleFindings);
      }
    }

    return findings;
  }
}
