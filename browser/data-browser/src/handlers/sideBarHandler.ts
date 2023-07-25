import { Resource, Store, urls, isString } from '@tomic/react';

export function buildSideBarNewResourceHandler(store: Store) {
  // When a resource is saved add it to the parents subResources list if it's not already there.
  return async (resource: Resource) => {
    const parentSubject = resource.get(urls.properties.parent);

    if (!isString(parentSubject)) {
      throw new Error(
        `Resource doesn't have a parent: ${resource.getSubject()} `,
      );
    }

    const parent = await store.getResourceAsync(parentSubject);
    const subResources = parent.getSubjects(urls.properties.subResources);

    if (subResources.includes(resource.getSubject())) {
      return;
    }

    await parent.pushPropVal(
      urls.properties.subResources,
      resource.getSubject(),
    );

    await parent.save(store);
  };
}

export function buildSideBarRemoveResourceHandler(store: Store) {
  // When a resource is deleted remove it from the parents subResources list.
  return async (resource: Resource) => {
    const parentSubject = resource.get(urls.properties.parent);

    if (!isString(parentSubject)) {
      throw new Error(
        `Resource doesn't have a parent: ${resource.getSubject()} `,
      );
    }

    const parent = await store.getResourceAsync(parentSubject);
    const subResources = parent.getSubjects(urls.properties.subResources);

    await parent.set(
      urls.properties.subResources,
      subResources.filter(r => r !== resource.getSubject()),
      store,
    );

    parent.save(store);
  };
}
