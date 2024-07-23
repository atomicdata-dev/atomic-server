import { type Resource, type Right, urls, RightType } from '@tomic/react';
import { useState, useEffect } from 'react';
import type { MergedRight } from './useRights';

export const useInheritedRights = (resource: Resource): MergedRight[] => {
  const [inheritedRights, setInheritedRights] = useState<MergedRight[]>([]);

  useEffect(() => {
    resource.getRights().then(allRights => {
      const rights = allRights
        .filter(r => r.setIn !== resource.subject)
        // Make sure the public agent is always the top of the list
        .toSorted(a => {
          return a.for === urls.instances.publicAgent ? -1 : 1;
        });

      setInheritedRights(toMergedRights(rights));
    });
  }, [resource]);

  return inheritedRights;
};

const buildKey = (right: Right) => `${right.for}::${right.setIn}`;

function toMergedRights(rights: Right[]): MergedRight[] {
  const rightsMap = new Map<string, MergedRight>();

  rights.forEach(right => {
    const key = buildKey(right);
    const existing = rightsMap.get(key) ?? {
      read: false,
      write: false,
      agentSubject: right.for,
      setIn: right.setIn,
    };

    existing.read ||= right.type === RightType.READ;
    existing.write ||= right.type === RightType.WRITE;

    rightsMap.set(key, existing);
  });

  return Array.from(rightsMap.values());
}
