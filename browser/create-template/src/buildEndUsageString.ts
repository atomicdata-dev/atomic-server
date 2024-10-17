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
    `\n${chalk.gray(
      'Check the README.md for more info about how the project is setup.',
    )}`,
  ];

  return commands.join('\n');
}
