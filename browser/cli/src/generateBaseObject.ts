import { Resource, type Core } from '@tomic/lib';
import { store } from './store.js';
import { camelCaseify, dedupe } from './utils.js';
import chalk from 'chalk';

export type ReverseMapping = Record<string, string>;

type BaseObject = {
  classes: Record<string, string>;
  properties: Record<string, string>;
};

export const generateBaseObject = async (
  ontology: Resource<Core.Ontology>,
): Promise<[string, ReverseMapping]> => {
  if (ontology.error) {
    throw ontology.error;
  }

  const classes = dedupe(ontology.props.classes ?? []);
  const properties = dedupe(ontology.props.properties ?? []);
  const name = camelCaseify(ontology.title);

  const baseObj = {
    classes: await listToObj(classes, 'classes'),
    properties: await listToObj(properties, 'properties'),
  };

  const objStr = `export const ${name} = {
    classes: ${recordToString(baseObj.classes)},
    properties: ${recordToString(baseObj.properties)},
  } as const`;

  return [objStr, createReverseMapping(name, baseObj)];
};

const listToObj = async (
  list: string[],
  type: string,
): Promise<Record<string, string>> => {
  const entries = await Promise.all(
    list.map(async subject => {
      const resource = await store.getResource(subject);

      return [camelCaseify(resource.title), subject];
    }),
  );

  // check for duplicates and throw an error if there are any.
  const duplicates = entries.filter(
    (entry, index) => entries.findIndex(e => e[0] === entry[0]) !== index,
  );

  if (duplicates.length > 0) {
    // eslint-disable-next-line no-console
    console.log(
      chalk.red(`ERROR: Found ${type} with the same name: `),
      duplicates.map(e => e[0]).join(', '),
    );

    // eslint-disable-next-line no-console
    console.log(
      chalk.red(
        'Properties with the same name will conflict in the generated ontology. Try to reuse properties where possible or rename the duplicate to prevent a conflict.',
      ),
    );

    process.exit(1);
  }

  return Object.fromEntries(entries);
};

const recordToString = (obj: Record<string, string>): string => {
  const innerSting = Object.entries(obj).reduce(
    (acc, [key, value]) => `${acc}\n\t${key}: '${value}',`,
    '',
  );

  return `{${innerSting}\n   }`;
};

const createReverseMapping = (
  ontologyTitle: string,
  obj: BaseObject,
): ReverseMapping => {
  const reverseMapping: ReverseMapping = {};

  for (const [name, subject] of Object.entries(obj.classes)) {
    reverseMapping[subject] = `${ontologyTitle}.classes.${name}`;
  }

  for (const [name, subject] of Object.entries(obj.properties)) {
    reverseMapping[subject] = `${ontologyTitle}.properties.${name}`;
  }

  return reverseMapping;
};
