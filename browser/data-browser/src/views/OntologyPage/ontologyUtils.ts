import { Datatype, Resource, Store, core, type Core } from '@tomic/react';
import { sortSubjectList } from './sortSubjectList';

const DEFAULT_DESCRIPTION = 'Change me';

/**
 * Preview of the subject the new class will get. For HTTP parents this matches
 * the actual subject; for DID parents the real subject is a fresh
 * `did:ad:{signature}` minted at save time, so the preview is informational
 * only. The server rejects `did:ad:{base64}/path` commits.
 */
export const subjectForClass = (parent: Resource, shortName: string): string =>
  `${parent.subject}/class/${shortName}`;

export async function newClass(
  shortName: string,
  parent: Resource<Core.Ontology>,
  store: Store,
): Promise<string> {
  const resource = await store.newResource({
    parent: parent.subject,
    isA: core.classes.class,
    propVals: {
      [core.properties.shortname]: shortName,
      [core.properties.description]: DEFAULT_DESCRIPTION,
    },
  });

  await resource.save();
  const subject = resource.subject;

  const classes = parent.props.classes ?? [];

  await parent.set(
    core.properties.classes,
    await sortSubjectList(store, [...classes, subject]),
  );

  await parent.save();

  return subject;
}

/**
 * Creates a content-addressed Property. Its ID derives from the ontology
 * (`parent`), `shortname` and `datatype`, so those must be chosen before this
 * is called and cannot change afterwards. Returns the existing Property when
 * the ontology already has one with the same shortname and datatype.
 */
export async function newProperty(
  shortname: string,
  parent: Resource,
  store: Store,
  datatype: Datatype = Datatype.STRING,
) {
  const resource = await store.newResource({
    parent: parent.subject,
    isA: core.classes.property,
    propVals: {
      [core.properties.shortname]: shortname,
      [core.properties.description]: 'a property',
      [core.properties.datatype]: datatype,
    },
    contentAddressedProperty: true,
  });

  if (resource.new) {
    await resource.save();
  }

  return resource.subject;
}
