import { Resource, Store, isString, dataBrowser, core } from '@tomic/react';

export function buildSideBarNewResourceHandler(store: Store) {
  // When a resource is saved add it to the parents subResources list if it's not already there.
  return async (resource: Resource) => {
    const parentSubject = resource.get(core.properties.parent);

    if (!isString(parentSubject)) {
      throw new Error(`Resource doesn't have a parent: ${resource.subject} `);
    }

    const parent = await store.getResource(parentSubject);
    const subResources = parent.getSubjects(
      dataBrowser.properties.subResources,
    );

    if (subResources.includes(resource.subject)) {
      return;
    }

    parent.push(dataBrowser.properties.subResources, [resource.subject]);

    await parent.save();
  };
}

export function buildSideBarRemoveResourceHandler(store: Store) {
  // When a resource is deleted remove it from the parents subResources list.
  return async (resource: Resource) => {
    const parentSubject = resource.get(core.properties.parent);

    if (!isString(parentSubject)) {
      throw new Error(`Resource doesn't have a parent: ${resource.subject} `);
    }

    const parent = await store.getResource(parentSubject);
    const subResources = parent.getSubjects(
      dataBrowser.properties.subResources,
    );

    if (subResources.length > 0) {
      await parent.set(
        dataBrowser.properties.subResources,
        subResources.filter(r => r !== resource.subject),
      );

      await parent.save();
    }
  };
}
