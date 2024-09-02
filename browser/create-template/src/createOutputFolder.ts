import fs from 'node:fs';
import { ask } from './utils.js';

export async function createOutputFolder(outputDir: string): Promise<void> {
  if (fs.existsSync(outputDir)) {
    const shouldContinue = await ask(
      `Folder already exists, Everything in the existing folder will be deleted. Continue? (y/n) `,
    );

    if (shouldContinue.toLowerCase() !== 'y') {
      console.error('Aborted');
      process.exit(0);
    }

    fs.rmSync(outputDir, { recursive: true });
  }

  try {
    fs.mkdirSync(outputDir);
  } catch (error) {
    console.error(`Failed to create directory: ${outputDir}`);
    process.exit(1);
  }
}
