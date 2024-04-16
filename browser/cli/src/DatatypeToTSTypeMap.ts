import { Datatype } from '@tomic/lib';

export const DatatypeToTSTypeMap = {
  [Datatype.ATOMIC_URL]: 'string',
  [Datatype.RESOURCEARRAY]: 'string[]',
  [Datatype.BOOLEAN]: 'boolean',
  [Datatype.DATE]: 'string',
  [Datatype.TIMESTAMP]: 'number',
  [Datatype.INTEGER]: 'number',
  [Datatype.FLOAT]: 'number',
  [Datatype.STRING]: 'string',
  [Datatype.SLUG]: 'string',
  [Datatype.MARKDOWN]: 'string',
  [Datatype.UNKNOWN]: 'JSONValue',
};
