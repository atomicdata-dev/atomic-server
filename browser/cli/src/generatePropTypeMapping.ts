import { Datatype, Resource, type Core } from '@tomic/lib';
import { store } from './store.js';
import { ReverseMapping } from './generateBaseObject.js';
import { DatatypeToTSTypeMap } from './DatatypeToTSTypeMap.js';
import { dedupe } from './utils.js';

export const generatePropTypeMapping = (
  ontology: Resource<Core.Ontology>,
  reverseMapping: ReverseMapping,
): string => {
  const properties = dedupe(ontology.props.properties ?? []);

  const lines = properties
    .map(subject => generateLine(subject, reverseMapping))
    .join('\n');

  return `interface PropTypeMapping {
    ${lines}
  }`;
};

const generateLine = (subject: string, reverseMapping: ReverseMapping) => {
  const resource = store.getResourceLoading<Core.Property>(subject);
  const datatype = resource.props.datatype as Datatype;

  return `[${reverseMapping[subject]}]: ${DatatypeToTSTypeMap[datatype]}`;
};
