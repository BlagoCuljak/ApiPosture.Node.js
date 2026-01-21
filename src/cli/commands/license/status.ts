import { Command } from 'commander';
import { LicenseManager } from '../../../licensing/license-manager.js';

export function createStatusCommand(): Command {
  return new Command('status')
    .description('Show current license status')
    .action(async () => {
      try {
        const manager = new LicenseManager();
        const status = await manager.getStatus();

        console.log('\nLicense Status');
        console.log('==============');

        if (status.isActive) {
          console.log(`Status: Active`);
          console.log(`Type: ${status.licenseType}`);
          console.log(`Expires: ${status.expiresAt?.toLocaleDateString() ?? 'Never'}`);
          console.log('\nEnabled Features:');
          for (const feature of status.features ?? []) {
            console.log(`  [x] ${feature}`);
          }
        } else {
          console.log('Status: Not licensed (Community Edition)');
          console.log('\nTo unlock Pro features, activate a license key:');
          console.log('  apiposture license activate <key>');
          console.log('\nOr set the APIPOSTURE_LICENSE_KEY environment variable.');
        }

        console.log('');
      } catch (error) {
        console.error('Failed to get license status');
        console.error(error instanceof Error ? error.message : error);
        process.exit(1);
      }
    });
}
