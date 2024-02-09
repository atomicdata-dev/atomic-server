import { core } from '@tomic/lib';
import { store } from './store.js';
import chalk from 'chalk';

export const validateOntologies = async (
  ontologies: string[],
): Promise<[valid: boolean, report: string]> => {
  let isValid = true;
  let report = '';

  for (const subject of ontologies) {
    try {
      const resource = await store.getResourceAsync(subject);

      if (!resource.hasClasses(core.classes.ontology)) {
        isValid = false;
        const isA = await store.getResourceAsync(resource.getClasses()[0]);
        report += `Expected ${chalk.cyan(
          resource.title,
        )} to have class Ontology but found ${chalk.cyan(isA.title)}\n`;
      }
    } catch (e) {
      isValid = false;
      report += `Could not fetch ontology at ${subject}\n`;
    }
  }

  return [isValid, report];
};
