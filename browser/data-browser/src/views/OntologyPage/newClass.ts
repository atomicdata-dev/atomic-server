import { Resource, Store, core } from '@tomic/react';

const DEFAULT_DESCRIPTION = 'Default description - Change me';

export const subjectForClass = (parent: Resource, shortName: string): string =>
  `${parent.subject}/class/${shortName}`;

export async function newClass(
  shortName: string,
  parent: Resource,
  store: Store,
): Promise<string> {
  const subject = subjectForClass(parent, shortName);

  const resource = await store.newResource({
    subject,
    parent: parent.subject,
    isA: core.classes.class,
    propVals: {
      [core.properties.shortname]: shortName,
      [core.properties.description]: DEFAULT_DESCRIPTION,
    },
  });

  await resource.save();

  parent.push(core.properties.classes, [subject]);

  await parent.save();

  return subject;
}
