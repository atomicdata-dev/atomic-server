import { Resource, Store, core } from '@tomic/react';

const DEFAULT_DESCRIPTION = 'Change me';

export const subjectForClass = (parent: Resource, shortName: string): string =>
  `${parent.getSubject()}/class/${shortName}`;

export async function newClass(
  shortName: string,
  parent: Resource,
  store: Store,
): Promise<string> {
  const subject = subjectForClass(parent, shortName);

  const resource = await store.newResource({
    subject,
    parent: parent.getSubject(),
    isA: core.classes.class,
    propVals: {
      [core.properties.shortname]: shortName,
      [core.properties.description]: DEFAULT_DESCRIPTION,
    },
  });

  await resource.save(store);

  parent.pushPropVal(core.properties.classes, [subject]);

  await parent.save(store);

  return subject;
}
