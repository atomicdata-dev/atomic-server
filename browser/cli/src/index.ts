#!/usr/bin/env node
/* eslint-disable no-console */

import chalk from 'chalk';
import { usage } from './usage.js';

const command = process.argv[2];

const commands = new Map<string, () => Promise<void>>();

commands.set('ontologies', () =>
  import('./commands/ontologies.js').then(m =>
    m.ontologiesCommand(process.argv.slice(3)),
  ),
);

commands.set('init', () =>
  import('./commands/init.js').then(m => m.initCommand(process.argv.slice(3))),
);

if (commands.has(command)) {
  commands.get(command)?.();
} else {
  console.error(chalk.red('Unknown command'), chalk.cyan(command ?? ''));
  console.log(usage);
}
