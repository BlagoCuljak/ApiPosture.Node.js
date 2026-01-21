import { Command } from 'commander';
import ora from 'ora';
import { LicenseManager } from '../../../licensing/license-manager.js';

export function createDeactivateCommand(): Command {
  return new Command('deactivate')
    .description('Deactivate the current license')
    .action(async () => {
      const spinner = ora('Deactivating license...').start();

      try {
        const manager = new LicenseManager();
        const result = await manager.deactivate();

        if (result.success) {
          spinner.succeed('License deactivated successfully');
        } else {
          spinner.fail('License deactivation failed');
          console.error(`Error: ${result.error}`);
          process.exit(1);
        }
      } catch (error) {
        spinner.fail('License deactivation failed');
        console.error(error instanceof Error ? error.message : error);
        process.exit(1);
      }
    });
}
