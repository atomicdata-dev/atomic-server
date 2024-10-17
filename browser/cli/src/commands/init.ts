/* eslint-disable no-console */
import chalk from 'chalk';
import * as fs from 'fs';
import * as path from 'path';

const TEMPLATE_CONFIG_FILE = {
  outputFolder: './src/ontologies',
  moduleAlias: '@tomic/lib',
  ontologies: [],
};

export const initCommand = async (args: string[]) => {
  const forced = args.includes('--force') || args.includes('-f');
  const filePath = path.join(process.cwd(), 'atomic.config.json');
  const stat = fs.statSync(filePath, { throwIfNoEntry: false });

  if (stat?.isFile() && !forced) {
    return console.error(
      chalk.red(
        `ERROR: File already exists. If you meant to override the existing file, use the command with the ${chalk.cyan(
          '--force',
        )} flag.`,
      ),
    );
  }

  console.log(chalk.cyan(`Creating ${chalk.white('atomic.config.json')}`));

  const template = JSON.stringify(TEMPLATE_CONFIG_FILE, null, 2);
  fs.writeFileSync(filePath, template);

  console.log(chalk.green('Done!'));
  console.log(
    chalk.cyan(
      'Next add your ontologies to your atomic.config.json file. You can find more info on how to do this here: https://docs.atomicdata.dev/js-cli',
    ),
  );
};
