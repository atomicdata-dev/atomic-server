import { core } from '@tomic/lib';
import { fetchResource, store } from './store.js';
import chalk from 'chalk';

export const validateOntologies = async (
  ontologies: string[],
): Promise<[valid: boolean, report: string]> => {
  let isValid = true;
  let report = '';

  if (ontologies.length === 0) {
    return [
      false,
      `No ontologies listed in your ${chalk.blue('atomic.config.ts')}`,
    ];
  }

  for (const subject of ontologies) {
    try {
      const resource = await fetchResource(subject);

      if (resource.error) {
        throw resource.error;
      }

      if (!resource.hasClasses(core.classes.ontology)) {
        isValid = false;
        const isA = await fetchResource(resource.getClasses()[0]);
        report += `Expected ${chalk.cyan(
          resource.title,
        )} to have class Ontology but found ${chalk.cyan(isA.title)}\n`;
      }
    } catch (e) {
      isValid = false;
      const message = e instanceof Error ? e.message : String(e);
      report += `Could not fetch ontology at ${subject}\n  ${message}\n`;

      if (/ECONNREFUSED|Could not reach|no server URL/i.test(message)) {
        const hint = store.getServerUrl()
          ? `Check that ${chalk.cyan('serverUrl')} (${store.getServerUrl()}) is the Atomic Server that hosts this ontology.`
          : `Set ${chalk.cyan('serverUrl')} in ${chalk.cyan('atomic.config.json')} to your Atomic Server origin (the CLI cannot fetch a did:ad: subject without one).`;
        report += `  ${hint}\n`;
      }
    }
  }

  return [isValid, report];
};
