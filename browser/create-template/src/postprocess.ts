import path from 'node:path';
import fs from 'node:fs';
import { Store, type Resource } from '@tomic/lib';
import { type TemplateKey, templates } from './templates.js';
import chalk from 'chalk';
import { log } from './utils.js';
import { getPackagemanager } from './packageManager.js';

export interface PostProcessContext {
  folderPath: string;
  template: TemplateKey;
  serverUrl: string;
}

export async function postProcess(context: PostProcessContext) {
  const { folderPath, template, serverUrl } = context;

  const store = new Store({ serverUrl });
  const baseTemplate = templates[template];
  const ontologySubject = new URL(
    baseTemplate.ontologyID,
    serverUrl,
  ).toString();

  const ontology = await store.getResource(ontologySubject);

  if (ontology.error) {
    console.error(
      `The ${baseTemplate.name} does not exist on your drive. To get the template go to the Create Resource page and select the ${baseTemplate.name} template`,
    );
    process.exit(1);
  }

  await modifyConfig(folderPath, ontology);
  await modifyReadme(folderPath);
  await createEnvFile(folderPath, baseTemplate.generateEnv({ serverUrl }));
}

async function modifyConfig(folderPath: string, ontology: Resource) {
  log(`Generating ${chalk.gray('atomic.config.json')}...`);
  const configPath = path.join(folderPath, 'atomic.config.json');
  const content = await fs.promises.readFile(configPath, { encoding: 'utf-8' });

  const newContent = content.replaceAll('<ONTOLOGY>', ontology.subject);

  await fs.promises.writeFile(configPath, newContent);
}

async function modifyReadme(folderPath: string) {
  log(`Generating ${chalk.gray('README.md')}...`);
  const readmePath = path.join(folderPath, 'README.md');
  const content = await fs.promises.readFile(readmePath, { encoding: 'utf-8' });

  const packageManager = getPackagemanager();
  const newContent = content
    .replaceAll('<PACKAGE_MANAGER>', packageManager)
    .replaceAll(
      '<PACKAGE_MANAGER_RUN>',
      packageManager === 'npm' ? 'npm run' : packageManager,
    );

  await fs.promises.writeFile(readmePath, newContent);
}

async function createEnvFile(folderPath: string, envContent: string) {
  log(`Generating ${chalk.gray('.env')} file...`);

  const envPath = path.join(folderPath, '.env');
  await fs.promises.writeFile(envPath, envContent);
}
