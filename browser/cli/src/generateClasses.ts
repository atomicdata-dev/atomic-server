import { type Core, type Resource } from '@tomic/lib';
import { store } from './store.js';
import { ReverseMapping } from './generateBaseObject.js';
import { PropertyRecord } from './PropertyRecord.js';
import { dedupe } from './utils.js';

export const generateClasses = (
  ontology: Resource<Core.Ontology>,
  reverseMapping: ReverseMapping,
  propertyRecord: PropertyRecord,
): string => {
  const classes = dedupe(ontology.props.classes ?? []);

  const classStringList = classes.map(subject => {
    return generateClass(subject, reverseMapping, propertyRecord);
  });

  const innerStr = classStringList.join('\n');

  return `interface Classes {
    ${innerStr}
  }`;
};

const generateClass = (
  subject: string,
  reverseMapping: ReverseMapping,
  propertyRecord: PropertyRecord,
): string => {
  const resource = store.getResourceLoading<Core.Class>(subject);

  const transformSubject = (str: string) => {
    const name = reverseMapping[str];

    if (!name) {
      return `'${str}'`;
    }

    return `typeof ${name}`;
  };

  const requires = resource.props.requires ?? [];
  const recommends = resource.props.recommends ?? [];

  for (const prop of [...requires, ...recommends]) {
    propertyRecord.reportPropertyUsed(prop);
  }

  return classString(
    reverseMapping[subject],
    requires.map(transformSubject),
    recommends.map(transformSubject),
  );
};

const classString = (
  key: string,
  requires: string[],
  recommends: string[],
): string => {
  return `[${key}]: {
    requires: BaseProps${
      requires.length > 0 ? ' | ' + requires.join(' | ') : ''
    };
    recommends: ${recommends.length > 0 ? recommends.join(' | ') : 'never'};
  };`;
};
