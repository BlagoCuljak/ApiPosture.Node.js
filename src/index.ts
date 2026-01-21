#!/usr/bin/env node

import { Command } from 'commander';
import { createScanCommand } from './cli/commands/scan.js';
import { createActivateCommand } from './cli/commands/license/activate.js';
import { createDeactivateCommand } from './cli/commands/license/deactivate.js';
import { createStatusCommand } from './cli/commands/license/status.js';

const program = new Command();

program
  .name('apiposture')
  .description('Static source-code analysis CLI for Node.js API security')
  .version('1.0.0');

// Add scan command (default)
program.addCommand(createScanCommand(), { isDefault: true });

// Add license subcommands
const licenseCommand = new Command('license')
  .description('Manage license activation');

licenseCommand.addCommand(createActivateCommand());
licenseCommand.addCommand(createDeactivateCommand());
licenseCommand.addCommand(createStatusCommand());

program.addCommand(licenseCommand);

// Parse and run
program.parse();
