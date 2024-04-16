// Sorry for the name of this
import { Resource } from '@tomic/lib';
import { useEffect, useState } from 'react';

/** Creates a Collection and returns all children */
export const useChildren = (resource: Resource) => {
  const [children, setChildren] = useState<string[]>([]);

  useEffect(() => {
    resource.getChildrenCollection().then(collection => {
      collection.getAllMembers().then(members => {
        setChildren(members);
      });
    });
  }, [resource]);

  return children;
};
