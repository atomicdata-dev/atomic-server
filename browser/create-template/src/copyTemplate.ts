import chalk from 'chalk';
import fs from 'node:fs';
import path from 'node:path';

export function copyTemplate(template: string, outputDir: string): void {
  // Copy the specified dir from the templates folder to the output dir
  fs.cpSync(
    path.join(import.meta.dirname, `../../templates/${template}`),
    outputDir,
    { recursive: true },
  );

  console.log(`${chalk.green('Success!')} Created template in ${outputDir}`);
}
