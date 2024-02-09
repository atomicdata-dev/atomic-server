import { generateBaseObject } from './generateBaseObject.js';
import { generateClasses } from './generateClasses.js';
import { store } from './store.js';
import { camelCaseify } from './utils.js';
import { generatePropTypeMapping } from './generatePropTypeMapping.js';
import { generateSubjectToNameMapping } from './generateSubjectToNameMapping.js';
import { generateClassExports } from './generateClassExports.js';

import { atomicConfig } from './config.js';
import { PropertyRecord } from './PropertyRecord.js';
import { Core } from '@tomic/lib';

enum Inserts {
  MODULE_ALIAS = '{{1}}',
  BASE_OBJECT = '{{2}}',
  CLASS_EXPORTS = '{{3}}',
  CLASSES = '{{4}}',
  PROP_TYPE_MAPPING = '{{7}}',
  PROP_SUBJECT_TO_NAME_MAPPING = '{{8}}',
}

const TEMPLATE = `
/* -----------------------------------
* GENERATED WITH @tomic/cli
* For more info on how to use ontologies: https://github.com/atomicdata-dev/atomic-server/blob/develop/browser/cli/readme.md
* -------------------------------- */

import type { BaseProps } from '${Inserts.MODULE_ALIAS}'

${Inserts.BASE_OBJECT}

${Inserts.CLASS_EXPORTS}

declare module '${Inserts.MODULE_ALIAS}' {
  ${Inserts.CLASSES}

  ${Inserts.PROP_TYPE_MAPPING}

  ${Inserts.PROP_SUBJECT_TO_NAME_MAPPING}
}
`;

export const generateOntology = async (
  subject: string,
  propertyRecord: PropertyRecord,
): Promise<{
  filename: string;
  content: string;
}> => {
  const ontology = await store.getResourceAsync<Core.Ontology>(subject);

  const properties = ontology.props.properties ?? [];

  for (const prop of properties) {
    propertyRecord.repordPropertyDefined(prop);
  }

  const [baseObjStr, reverseMapping] = await generateBaseObject(ontology);
  const classesStr = generateClasses(ontology, reverseMapping, propertyRecord);
  const propertiesStr = generatePropTypeMapping(ontology, reverseMapping);
  const subToNameStr = generateSubjectToNameMapping(ontology, reverseMapping);
  const classExportsStr = generateClassExports(ontology, reverseMapping);

  const content = TEMPLATE.replaceAll(
    Inserts.MODULE_ALIAS,
    atomicConfig.moduleAlias ?? '@tomic/lib',
  )
    .replace(Inserts.BASE_OBJECT, baseObjStr)
    .replace(Inserts.CLASS_EXPORTS, classExportsStr)
    .replace(Inserts.CLASSES, classesStr)
    .replace(Inserts.PROP_TYPE_MAPPING, propertiesStr)
    .replace(Inserts.PROP_SUBJECT_TO_NAME_MAPPING, subToNameStr);

  return {
    filename: `${camelCaseify(ontology.title)}.ts`,
    content,
  };
};
