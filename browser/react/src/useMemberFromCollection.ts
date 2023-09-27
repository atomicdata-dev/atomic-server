import {
  Collection,
  OptionalClass,
  Resource,
  unknownSubject,
} from '@tomic/lib';
import { useEffect, useState } from 'react';
import { useResource } from './hooks.js';

/**
 * Gets a member from a collection by index. Handles pagination for you.
 */
export function useMemberFromCollection<C extends OptionalClass = never>(
  collection: Collection,
  index: number,
): Resource<C> {
  const [subject, setSubject] = useState(unknownSubject);
  const resource = useResource(subject);

  useEffect(() => {
    collection.getMemberWithIndex(index).then(setSubject);
  }, [collection, index]);

  return resource;
}
