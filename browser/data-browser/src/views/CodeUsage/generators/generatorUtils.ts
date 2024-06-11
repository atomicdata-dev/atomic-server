export enum LangEnv {
  React = 'react',
  Other = 'other',
}

export type ImportItem = { name: string | string[]; file: string };

export const toCamelCase = (str: string) => {
  const converted = str.replace(/-([a-z])/g, g => {
    return g[1].toUpperCase();
  });

  return converted.charAt(0).toLowerCase() + converted.slice(1);
};

export const toPascaleCase = (str: string) => {
  return str.replace(/(^\w|-\w)/g, g => g.replace(/-/, '').toUpperCase());
};

export const includeOntologies = new Set([
  'https://atomicdata.dev/ontology/core',
  'https://atomicdata.dev/ontology/commit',
  'https://atomicdata.dev/ontology/collections',
  'https://atomicdata.dev/ontology/data-browser',
  'https://atomicdata.dev/ontology/server',
]);

/** Creates import statements based on the given ImportItems, import items that share the same filename will be merged */
export function renderImports(
  prefix: string,
  ...imports: Array<ImportItem | undefined>
): string;
export function renderImports(
  ...imports: Array<ImportItem | undefined>
): string;
export function renderImports(
  first: string | ImportItem | undefined,
  ...rest: Array<ImportItem | undefined>
): string {
  const prefix = typeof first === 'string' ? first : '';
  const imports = typeof first === 'string' ? rest : [first, ...rest];

  const importMap = imports.reduce(
    (acc, item) => {
      if (!item) {
        return acc;
      }

      const name = Array.isArray(item.name) ? item.name : [item.name];

      return {
        ...acc,
        [item.file]: Array.from(new Set([...(acc[item.file] ?? []), ...name])),
      };
    },
    {} as Record<string, string[]>,
  );

  const str = Object.entries(importMap)
    // Import libs first, then local files
    .sort(([file], _) => (file.startsWith('./') ? 1 : -1))
    // Create import statement strings
    .map(
      ([file, names]) =>
        `${prefix}import ${formatImportNames(prefix, names)} from '${file}';`,
    )
    .join('\n');

  return str ? `${str}\n` : '';
}

/** Formats the { varName } part of the import statement. If more than 3 vars are imported they will be split onto multiple lines */
const formatImportNames = (prefix: string, names: string[]): string => {
  if (names.length > 3) {
    return `{\n${prefix}  ${names.join(',\n  ' + prefix)},\n${prefix}}`;
  }

  return `{ ${names.join(', ')} }`;
};
