import { Resource, Store, core, type Core } from '@tomic/react';
import { sortSubjectList } from './sortSubjectList';

const DEFAULT_DESCRIPTION = 'Default description - Change me';

export const subjectForClass = (parent: Resource, shortName: string): string =>
  `${parent.subject}/class/${shortName}`;

export async function newClass(
  shortName: string,
  parent: Resource<Core.Ontology>,
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

  const classes = parent.props.classes ?? [];

  await parent.set(
    core.properties.classes,
    await sortSubjectList(store, [...classes, subject]),
  );

  await parent.save();

  return subject;
}
