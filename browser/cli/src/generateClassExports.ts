import { Resource, urls } from '@tomic/lib';
import { atomicConfig } from './config.js';
import { ReverseMapping } from './generateBaseObject.js';
import { store } from './store.js';
import { camelCaseify } from './utils.js';

enum Inserts {
  NamespaceName = '{{1}}',
  NamespaceBody = '{{2}}',
}

const NAMESPACE_TEMPLATE = `
  // eslint-disable-next-line @typescript-eslint/no-namespace
  export namespace ${Inserts.NamespaceName} {
    ${Inserts.NamespaceBody}
  }
`;

export const generateClassExports = (
  ontology: Resource,
  reverseMapping: ReverseMapping,
): string => {
  const classes = ontology.getArray(urls.properties.classes) as string[];

  const body = classes
    .map(subject => {
      const res = store.getResourceLoading(subject);
      const objectPath = reverseMapping[subject];

      return createExportLine(res.title, objectPath);
    })
    .join('\n');

  if (atomicConfig.useNamespaces) {
    return NAMESPACE_TEMPLATE.replace(
      Inserts.NamespaceName,
      capitalize(ontology.title),
    ).replace(Inserts.NamespaceBody, body);
  } else {
    return body;
  }
};

const createExportLine = (title: string, objectPath: string) =>
  `export type ${capitalize(title)} = typeof ${objectPath};`;

const capitalize = (str: string): string => {
  const camelCased = camelCaseify(str);

  return camelCased.charAt(0).toUpperCase() + camelCased.slice(1);
};
