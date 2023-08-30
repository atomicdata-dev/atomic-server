import { Resource, Store, urls } from '@tomic/react';

const DEFAULT_DESCRIPTION = 'Change me';

export const subjectForClass = (parent: Resource, shortName: string): string =>
  `${parent.getSubject()}/class/${shortName}`;

export async function newClass(
  shortName: string,
  parent: Resource,
  store: Store,
): Promise<string> {
  const subject = subjectForClass(parent, shortName);
  const resource = store.getResourceLoading(subject, { newResource: true });

  await resource.addClasses(store, urls.classes.class);

  await resource.set(urls.properties.shortname, shortName, store);
  await resource.set(urls.properties.description, DEFAULT_DESCRIPTION, store);
  await resource.set(urls.properties.parent, parent.getSubject(), store);

  await resource.save(store);

  parent.pushPropVal(urls.properties.classes, [subject]);

  await parent.save(store);

  return subject;
}
