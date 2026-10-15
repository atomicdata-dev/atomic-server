// @wc-ignore-file
import { useEffect, useState } from 'react';
import {
  commits,
  core,
  dataBrowser,
  useCollection,
  useResource,
  useStore,
  useString,
} from '@tomic/react';
import { useChatLogRevision } from './useChatLog';
import { newestCommentTimes } from '../views/Drive/commentActivity';

/** How many of the newest threads in the Comments folder are read. */
export const RECENT_COMMENT_THREADS = 50;

const NO_MEMBERS: string[] = [];
const NONE: ReadonlyMap<string, number> = new Map();

/**
 * When the resources of a drive were last commented on (`about` -> ms): one
 * bounded read of the newest threads in the drive's Comments folder (ChatLog
 * pages, plus old Message resources). Reads the folder only if the drive
 * already has one and never creates it. Empty without a drive.
 *
 * Limit: threads are the newest by creation, so a comment added to a thread
 * that is older than the newest 50 is not seen.
 */
export function useRecentComments(
  drive: string | undefined,
): ReadonlyMap<string, number> {
  const store = useStore();
  const driveResource = useResource(drive);
  const [folder] = useString(
    driveResource,
    dataBrowser.properties.commentsFolder,
  );
  const { collection } = useCollection(
    {
      property: core.properties.parent,
      // Undefined value: the collection never asks the server.
      value: folder,
      sort_by: commits.properties.createdAt,
      sort_desc: true,
    },
    { pageSize: RECENT_COMMENT_THREADS },
  );
  const [members, setMembers] = useState<string[]>([]);
  const revision = useChatLogRevision(folder ? members : NO_MEMBERS);
  const [times, setTimes] = useState(NONE);

  useEffect(() => {
    if (!folder) return;

    let cancelled = false;

    void (async () => {
      await collection.waitForReady();
      const count = Math.min(RECENT_COMMENT_THREADS, collection.totalMembers);
      const found = await Promise.all(
        Array.from({ length: count }, (_, i) =>
          collection.getMemberWithIndex(i).catch(() => undefined),
        ),
      );

      if (!cancelled) {
        setMembers(found.filter((m): m is string => !!m));
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [collection, folder]);

  useEffect(() => {
    if (!folder || members.length === 0) return;

    let cancelled = false;

    void (async () => {
      const threads = await Promise.all(
        members.map(async member => {
          const resource = await store.getResource(member);

          if (resource.error) return {};

          const about = resource.get(dataBrowser.properties.about);
          const entries = resource.listChatLogEntries();
          const at = entries.length
            ? Math.max(...entries.map(({ entry }) => entry.c))
            : resource.getCreatedAt();

          return {
            about: typeof about === 'string' ? about : undefined,
            at,
          };
        }),
      );

      if (!cancelled) setTimes(newestCommentTimes(threads));
    })();

    return () => {
      cancelled = true;
    };
  }, [store, folder, members, revision]);

  return drive && folder && members.length > 0 ? times : NONE;
}
