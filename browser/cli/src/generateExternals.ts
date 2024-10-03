import { Core, Datatype, Resource } from '@tomic/lib';
import { atomicConfig } from './config.js';
import { DatatypeToTSTypeMap } from './DatatypeToTSTypeMap.js';
import { store } from './store.js';
import { camelCaseify } from './utils.js';

enum Inserts {
  ModuleAlias = '{{1}}',
  BaseObjectProperties = '{{2}}',
  TypeMapping = '{{3}}',
  NameMapping = '{{4}}',
}

const TEMPLATE = `
/* -----------------------------------
* GENERATED WITH @tomic-cli
* -------------------------------- */

export const externals = {
  classes: {},
  properties: {
    ${Inserts.BaseObjectProperties}
  },
} as const;

declare module '${Inserts.ModuleAlias}' {
  interface PropTypeMapping {
    ${Inserts.TypeMapping}
  }

  interface PropSubjectToNameMapping {
    ${Inserts.NameMapping}
  }
}
`;

const generateTypeMapping = (properties: Resource<Core.Property>[]) => {
  const lines = properties.map(prop => {
    const type = DatatypeToTSTypeMap[prop.props.datatype as Datatype];

    return `["${prop.subject}"]: ${type};`;
  });

  return lines.join('\n');
};

const generateNameMapping = (properties: Resource<Core.Property>[]) => {
  const lines = properties.map(prop => {
    const name = camelCaseify(prop.props.shortname);

    return `["${prop.subject}"]: "${name}";`;
  });

  return lines.join('\n');
};

const generateBaseObjectProperties = (
  properties: Resource<Core.Property>[],
) => {
  const lines = properties.map(
    p => `${camelCaseify(p.props.shortname)}: '${p.subject}',`,
  );

  return lines.join('\n');
};

export const generateExternals = async (props: string[]) => {
  const properties: Resource<Core.Property>[] = await Promise.all(
    props.map(p => store.getResource<Core.Property>(p)),
  );

  const baseOjbectProperties = generateBaseObjectProperties(properties);
  const typeMapping = generateTypeMapping(properties);
  const nameMapping = generateNameMapping(properties);

  return TEMPLATE.replace(
    Inserts.ModuleAlias,
    atomicConfig.moduleAlias ?? '@tomic/lib',
  )
    .replace(Inserts.BaseObjectProperties, baseOjbectProperties)
    .replace(Inserts.TypeMapping, typeMapping)
    .replace(Inserts.NameMapping, nameMapping);
};
