import { Command } from 'commander';
import ora from 'ora';
import { LicenseManager } from '../../../licensing/license-manager.js';

export function createActivateCommand(): Command {
  return new Command('activate')
    .description('Activate a license key')
    .argument('<key>', 'License key to activate')
    .action(async (key: string) => {
      const spinner = ora('Activating license...').start();

      try {
        const manager = new LicenseManager();
        const result = await manager.activate(key);

        if (result.success) {
          spinner.succeed('License activated successfully!');
          console.log(`\nLicense Type: ${result.licenseType}`);
          console.log(`Expires: ${result.expiresAt?.toLocaleDateString() ?? 'Never'}`);
          console.log('\nEnabled features:');
          for (const feature of result.features ?? []) {
            console.log(`  - ${feature}`);
          }
        } else {
          spinner.fail('License activation failed');
          console.error(`Error: ${result.error}`);
          process.exit(1);
        }
      } catch (error) {
        spinner.fail('License activation failed');
        console.error(error instanceof Error ? error.message : error);
        process.exit(1);
      }
    });
}
