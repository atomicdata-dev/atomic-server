#!/usr/bin/env node
/* eslint-disable no-console */
import path from 'node:path';
import { parseArgs } from 'node:util';
import { copyTemplate } from './copyTemplate.js';
import { createOutputFolder } from './createOutputFolder.js';
import { buildEndUsageString } from './buildEndUsageString.js';
import { postProcess } from './postprocess.js';
import { isTemplate } from './templates.js';
import { log } from './utils.js';
import chalk from 'chalk';

const args = parseArgs({
  options: {
    template: {
      type: 'string',
    },
    'server-url': {
      type: 'string',
    },
  },
  allowPositionals: true,
});

if (!args.values.template) {
  console.error(
    'Missing template argument, provide a template by adding --template <template> to the command',
  );
  process.exit(1);
}

if (!args.values['server-url']) {
  console.error(
    'Missing an AtomicServer server-url argument, provide a server-url by adding --server-url <server-url> to the command',
  );
  process.exit(1);
}

if (!isTemplate(args.values.template)) {
  console.error(`Invalid template: ${args.values.template}`);
  process.exit(1);
}

let outputDir = process.cwd();

if (args.positionals.length > 0) {
  outputDir = path.join(outputDir, args.positionals[0]);
}

await createOutputFolder(outputDir);

copyTemplate(args.values.template, outputDir);

await postProcess({
  folderPath: outputDir,
  template: args.values.template,
  serverUrl: args.values['server-url'],
});

log('');
log(chalk.green('Done!'));

const endUsage = buildEndUsageString(args.values.template, args.positionals[0]);
console.log(endUsage);
