import { ai, commits, core, unknownSubject, useCollection } from '@tomic/react';
import { useEffect, useState } from 'react';
import { usePrivateDriveSync } from './usePrivateDriveSync';

/** Live class query, independent of the drive's storage-folder pointer. */
export function useDriveChats(drive: string | undefined): string[] {
  const [subjects, setSubjects] = useState<string[]>([]);

  const { collection, ready, invalidateCollection } = useCollection(
    {
      property: core.properties.isA,
      value: ai.classes.aiChat,
      filters: [
        {
          property: 'https://atomicdata.dev/properties/drive',
          value: drive ?? unknownSubject,
        },
      ],
      drive: drive ?? unknownSubject,
      sort_by: commits.properties.createdAt,
      sort_desc: true,
    },
    { pageSize: 100 },
  );

  usePrivateDriveSync(drive, invalidateCollection);

  useEffect(() => {
    if (!ready || !drive) {
      setSubjects([]);

      return;
    }

    let cancelled = false;

    const extract = async () => {
      const members: string[] = [];

      for (let i = 0; i < collection.totalMembers; i++) {
        const member = await collection.getMemberWithIndex(i);

        if (member) {
          members.push(member);
        }
      }

      if (!cancelled) {
        setSubjects(members);
      }
    };

    extract();

    return () => {
      cancelled = true;
    };
  }, [collection, ready, drive]);

  return subjects;
}
