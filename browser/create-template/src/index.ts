#!/usr/bin/env node
/* eslint-disable no-console */
import path from 'node:path';
import { parseArgs } from 'node:util';
import { copyTemplate } from './copyTemplate.js';
import { createOutputFolder } from './createOutputFolder.js';
import { buildEndUsageString } from './buildEndUsageString.js';

const templates = ['sveltekit-site'];

const args = parseArgs({
  options: {
    template: {
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

if (!templates.includes(args.values.template)) {
  console.error(`Invalid template: ${args.values.template}`);
  process.exit(1);
}

let outputDir = process.cwd();

if (args.positionals.length > 0) {
  outputDir = path.join(outputDir, args.positionals[0]);
}

await createOutputFolder(outputDir);

copyTemplate(args.values.template, outputDir);
const endUsage = buildEndUsageString(args.values.template, args.positionals[0]);
console.log(endUsage);
