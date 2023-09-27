import { Resource, urls } from '@tomic/lib';
import { ReverseMapping } from './generateBaseObject.js';
import { store } from './store.js';
import { camelCaseify } from './utils.js';

export const generateClassExports = (
  ontology: Resource,
  reverseMapping: ReverseMapping,
): string => {
  const classes = ontology.getArray(urls.properties.classes) as string[];

  return classes
    .map(subject => {
      const res = store.getResourceLoading(subject);
      const objectPath = reverseMapping[subject];

      return createExportLine(res.title, objectPath);
    })
    .join('\n');
};

const createExportLine = (title: string, objectPath: string) =>
  `export type ${capitalize(title)} = typeof ${objectPath};`;

const capitalize = (str: string): string => {
  const camelCased = camelCaseify(str);

  return camelCased.charAt(0).toUpperCase() + camelCased.slice(1);
};
