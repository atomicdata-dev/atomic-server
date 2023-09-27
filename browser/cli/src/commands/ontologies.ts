/* eslint-disable no-console */

import * as fs from 'fs';
import chalk from 'chalk';

import * as path from 'path';
import { generateOntology } from '../generateOntology.js';
import { atomicConfig } from '../config.js';
import { generateIndex } from '../generateIndex.js';

export const ontologiesCommand = async (_args: string[]) => {
  console.log(
    chalk.blue(
      `Found ${chalk.red(
        Object.keys(atomicConfig.ontologies).length,
      )} ontologies`,
    ),
  );

  for (const subject of Object.values(atomicConfig.ontologies)) {
    write(await generateOntology(subject));
  }

  console.log(chalk.blue('Generating index...'));

  write(generateIndex(atomicConfig.ontologies));

  console.log(chalk.green('Done!'));
};

const write = ({
  filename,
  content,
}: {
  filename: string;
  content: string;
}) => {
  console.log(chalk.blue(`Writing ${chalk.red(filename)}...`));

  const filePath = path.join(
    process.cwd(),
    atomicConfig.outputFolder,
    filename,
  );

  fs.writeFileSync(filePath, content);

  console.log(chalk.blue('Wrote to'), chalk.cyan(filePath));
};
