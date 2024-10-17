import { core } from '@tomic/lib';
import { store } from './store.js';
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
      const resource = await store.getResource(subject);

      if (resource.error) {
        throw resource.error;
      }

      if (!resource.hasClasses(core.classes.ontology)) {
        isValid = false;
        const isA = await store.getResource(resource.getClasses()[0]);
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
