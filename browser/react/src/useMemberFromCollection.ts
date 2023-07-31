import { Collection, Resource, unknownSubject } from '@tomic/lib';
import { useEffect, useState } from 'react';
import { useResource } from './hooks.js';

/**
 * Gets a member from a collection by index. Handles pagination for you.
 */
export function useMemberFromCollection(
  collection: Collection,
  index: number,
): Resource {
  const [subject, setSubject] = useState(unknownSubject);
  const resource = useResource(subject);

  useEffect(() => {
    collection.getMemberWithIndex(index).then(setSubject);
  }, [collection, index]);

  return resource;
}
