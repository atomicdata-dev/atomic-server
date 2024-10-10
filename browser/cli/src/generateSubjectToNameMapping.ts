import { Resource, core } from '@tomic/lib';
import { ReverseMapping } from './generateBaseObject.js';

export function generateSubjectToNameMapping(
  ontology: Resource,
  reverseMapping: ReverseMapping,
) {
  const properties = ontology.getArray(core.properties.properties) as string[];

  const lines = properties
    .map(prop => propLine(prop, reverseMapping))
    .filter(line => line);

  return `interface PropSubjectToNameMapping {
    ${lines.join('\n')}
  }`;
}

const propLine = (subject: string, reverseMapping: ReverseMapping) => {
  const name = reverseMapping[subject]?.split('.')[2];

  if (!name) {
    return undefined;
  }

  return `[${reverseMapping[subject]}]: '${name}',`;
};
