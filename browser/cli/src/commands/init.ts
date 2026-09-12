/* eslint-disable no-console */
import chalk from 'chalk';
import * as fs from 'fs';
import * as path from 'path';

const TEMPLATE_CONFIG_FILE = {
  outputFolder: './src/ontologies',
  moduleAlias: '@tomic/lib',
  serverUrl: 'http://localhost:9883',
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
      'Set "serverUrl" to your Atomic Server origin, then add ontology subjects (did:ad:… identifiers, not the https://host/did:ad:… address-bar URL). More info: https://docs.atomicdata.dev/js-cli',
    ),
  );
};
