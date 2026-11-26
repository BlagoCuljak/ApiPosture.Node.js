#!/usr/bin/env node

import { createRequire } from 'module';
import { Command } from 'commander';
import { createScanCommand } from './cli/commands/scan.js';

const require = createRequire(import.meta.url);
const pkg = require('../package.json') as { version: string };

const program = new Command();

program
  .name('apiposture')
  .description('Static source-code analysis CLI for Node.js API security')
  .version(pkg.version);

// Add scan command (default)
program.addCommand(createScanCommand(), { isDefault: true });

// Parse and run
program.parse();
