// Sorry for the name of this
import { properties, Resource } from '@tomic/lib';
import { useEffect } from 'react';
import { useArray, useResource, useStore } from './index.js';

/** Creates a Collection and returns all children */
export const useChildren = (resource: Resource) => {
  const store = useStore();
  const childrenUrl = resource.getChildrenCollection();
  const childrenCollection = useResource(childrenUrl);
  const [children] = useArray(
    childrenCollection,
    properties.collection.members,
  );

  // Because collections are not invalidated serverside at the moment we need to fetch it on mount in order to show up to date data
  useEffect(() => {
    store.fetchResourceFromServer(childrenUrl);
  }, [store]);

  return children;
};
