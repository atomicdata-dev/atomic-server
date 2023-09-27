import { Resource } from '@tomic/lib';
import { store } from './store.js';
import { ReverseMapping } from './generateBaseObject.js';

export const generateClasses = (
  ontology: Resource,
  reverseMapping: ReverseMapping,
): string => {
  const classes = ontology.get(
    'https://atomicdata.dev/properties/classes',
  ) as string[];
  const classStringList = classes.map(subject => {
    return generateClass(subject, reverseMapping);
  });

  const innerStr = classStringList.join('\n');

  return `interface Classes {
    ${innerStr}
  }`;
};

const generateClass = (
  subject: string,
  reverseMapping: ReverseMapping,
): string => {
  const resource = store.getResourceLoading(subject);

  const transformSubject = (str: string) => {
    const name = reverseMapping[str];

    if (!name) {
      return `'${str}'`;
    }

    return `typeof ${name}`;
  };

  const requires = (resource.get(
    'https://atomicdata.dev/properties/requires',
  ) ?? []) as string[];
  const recommends = (resource.get(
    'https://atomicdata.dev/properties/recommends',
  ) ?? []) as string[];

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
