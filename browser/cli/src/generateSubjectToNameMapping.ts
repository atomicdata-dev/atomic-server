import { Resource } from '@tomic/lib';
import { ReverseMapping } from './generateBaseObject.js';

export function generateSubjectToNameMapping(
  ontology: Resource,
  reverseMapping: ReverseMapping,
) {
  const properties = ontology.getArray(
    'https://atomicdata.dev/properties/properties',
  ) as string[];

  const lines = properties.map(prop => propLine(prop, reverseMapping));

  return `interface PropSubjectToNameMapping {
    ${lines.join('\n')}
  }`;
}

const propLine = (subject: string, reverseMapping: ReverseMapping) => {
  const name = reverseMapping[subject].split('.')[2];

  return `[${reverseMapping[subject]}]: '${name}',`;
};
