import { core, Resource } from '@tomic/lib';
import { store } from './store.js';
import { camelCaseify, dedupe } from './utils.js';

export type ReverseMapping = Record<string, string>;

type BaseObject = {
  classes: Record<string, string>;
  properties: Record<string, string>;
};

export const generateBaseObject = async (
  ontology: Resource,
): Promise<[string, ReverseMapping]> => {
  if (ontology.error) {
    throw ontology.error;
  }

  const classes = dedupe(ontology.get(core.properties.classes)) as string[];
  const properties = dedupe(
    ontology.get(core.properties.properties),
  ) as string[];
  const name = camelCaseify(ontology.title);

  const baseObj = {
    classes: await listToObj(classes),
    properties: await listToObj(properties),
  };

  const objStr = `export const ${name} = {
    classes: ${recordToString(baseObj.classes)},
    properties: ${recordToString(baseObj.properties)},
  } as const`;

  return [objStr, createReverseMapping(name, baseObj)];
};

const listToObj = async (list: string[]): Promise<Record<string, string>> => {
  const entries = await Promise.all(
    list.map(async subject => {
      const resource = await store.getResource(subject);

      return [camelCaseify(resource.title), subject];
    }),
  );

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
