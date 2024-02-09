/* eslint-disable no-console */
import * as fs from 'fs';
import chalk from 'chalk';
import * as prettier from 'prettier';
import * as path from 'path';
import { generateOntology } from '../generateOntology.js';
import { atomicConfig } from '../config.js';
import { generateIndex } from '../generateIndex.js';
import { PropertyRecord } from '../PropertyRecord.js';
import { generateExternals } from '../generateExternals.js';
import { validateOntologies } from '../validateOntologies.js';

export const ontologiesCommand = async (_args: string[]) => {
  const propertyRecord = new PropertyRecord();

  console.log(
    chalk.blue(`Found ${chalk.red(atomicConfig.ontologies.length)} ontologies`),
  );

  const [valid, report] = await validateOntologies(atomicConfig.ontologies);

  if (!valid) {
    console.log(chalk.red('Could not generate ontologies'));
    console.log(report);

    return;
  }

  for (const subject of atomicConfig.ontologies) {
    await write(await generateOntology(subject, propertyRecord));
  }

  const missingProps = propertyRecord.getMissingProperties();

  if (missingProps.length > 0) {
    console.log(
      chalk.yellow(
        'Found some properties that are not defined in any of your ontologies.\nGenerating extras.ts...',
      ),
    );

    const externalsContent = await generateExternals(missingProps);
    await write({ filename: 'externals.ts', content: externalsContent });
  }

  console.log(chalk.blue('Generating index...'));

  await write(generateIndex(atomicConfig.ontologies, missingProps.length > 0));

  console.log(chalk.green('Done!'));
};

const write = async ({
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

  let formatted = content;
  const prettierConfig = await prettier.resolveConfig(filePath);

  if (prettierConfig) {
    formatted = await prettier.format(content, {
      ...prettierConfig,
      parser: 'typescript',
    });
  }

  fs.writeFileSync(filePath, formatted);

  console.log(chalk.blue('Wrote to'), chalk.cyan(filePath));
};
