import fs from 'node:fs';
import path from 'node:path';
import { log } from './utils.js';

export function copyTemplate(template: string, outputDir: string): void {
  // Copy the specified dir from the templates folder to the output dir
  fs.cpSync(
    path.join(import.meta.dirname, `../../templates/${template}`),
    outputDir,
    { recursive: true },
  );

  log(`Created template in ${outputDir}`);
}
