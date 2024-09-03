import path from 'node:path';
import fs from 'node:fs';
import { CollectionBuilder, core, Store, type Resource } from '@tomic/lib';
import type { Template } from './templates.js';
import chalk from 'chalk';
import { log } from './utils.js';

export interface PostProcessContext {
  folderPath: string;
  template: Template;
  serverUrl: string;
}

const templateToOntologyMap: Record<Template, string> = {
  'sveltekit-site': 'website',
  'react-site': 'website',
};

export async function postProcess(context: PostProcessContext) {
  const { folderPath, template, serverUrl } = context;

  const store = new Store({ serverUrl });

  const collection = new CollectionBuilder(store)
    .setProperty(core.properties.isA)
    .setValue(core.classes.ontology)
    .build();

  const ontName = templateToOntologyMap[template];

  const results = await Promise.allSettled(
    (await collection.getAllMembers()).map(subject =>
      store.getResource(subject),
    ),
  );

  // TODO: Find the ontology based on something more reliable than name.
  const relevantOntology = results
    .filter(result => result.status === 'fulfilled')
    .find(({ value }) => !value.error && value.title === ontName)?.value;

  if (!relevantOntology) {
    throw new Error(`Could not find ontology ${ontName}`);
  }

  await modifyConfig(folderPath, relevantOntology);
  await createEnvFile(folderPath, serverUrl);
}

async function modifyConfig(folderPath: string, ontology: Resource) {
  log(`Generating ${chalk.gray('atomic.config.json')}...`);
  const configPath = path.join(folderPath, 'atomic.config.json');
  const content = await fs.promises.readFile(configPath, { encoding: 'utf-8' });

  const newContent = content.replaceAll('<ONTOLOGY>', ontology.subject);

  await fs.promises.writeFile(configPath, newContent);
}

async function createEnvFile(folderPath: string, serverUrl: string) {
  log(
    `Generating ${chalk.gray('.env')} file... ${chalk.blue(
      '(Make sure to add any missing variables before starting the server)',
    )}`,
  );
  const envPath = path.join(folderPath, '.env');
  const env = `PUBLIC_SERVER_URL=${serverUrl}\nPUBLIC_WEBSITE_RESOURCE=<Your Site resource subject>`;

  await fs.promises.writeFile(envPath, env);
}
