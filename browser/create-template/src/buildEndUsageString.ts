import chalk from 'chalk';
import {
  getPackagemanager,
  getRunCommand,
  startCommand,
} from './packageManager.js';

export function buildEndUsageString(template: string, folder: string): string {
  const packageManager = getPackagemanager();

  const commands = [
    chalk.blue('\nTo continue run the following commands:'),
    `cd ${folder}`,
    `${packageManager} install`,
    getRunCommand(packageManager, 'update-ontologies'),
    startCommand(template, packageManager),
  ];

  return commands.join('\n');
}
