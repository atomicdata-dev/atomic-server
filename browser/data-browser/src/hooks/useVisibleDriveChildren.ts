import {
  ai,
  dataBrowser,
  notifications,
  server,
  useChildren,
  useResource,
  useResources,
  useString,
} from '@tomic/react';
import { canonicalizeScheme } from '@tomic/lib';
import { useMemo } from 'react';
import { isHiddenFromChildLists } from '../helpers/hiddenFromChildLists';

/**
 * The children of a drive minus its schema plumbing, shared by the sidebar and
 * the drive page so both show the same set.
 *
 * Hidden: the default ontology (auto-created by `createDrive`, so users aren't
 * confronted with an "Ontology" they never made; it stays reachable via Drive
 * settings and class/property links), the Comments folder (comments are reached
 * through the Comments panel), the AI Chats folder (chats re-open through the AI
 * sidebar) the Inbox (opens from Notifications in the app menu) and the Trash folder
 * (reached from the account menu at the bottom of the sidebar).
 * Ontologies the user creates themselves still show. AI chats and Meetings
 * are hidden by class, and anything with an `about` (annotations such as
 * agent notes) is hidden too, wherever they sit (the AI sidebar and the meeting UI
 * reach them), which also covers legacy drives whose chats sit in a folder.
 *
 * `subjects` is the filtered list; `allSubjects` is what `useChildren`
 * returned, so callers can tell "nothing" from "only hidden resources".
 */
export function useVisibleDriveChildren(
  drive: string,
  options?: { limit?: number },
) {
  const driveResource = useResource(drive);
  const { subjects: allSubjects, loading, total } = useChildren(drive, options);
  const [defaultOntology] = useString(
    driveResource,
    server.properties.defaultOntology,
  );
  const [commentsFolder] = useString(
    driveResource,
    dataBrowser.properties.commentsFolder,
  );
  const [aiChatsFolder] = useString(driveResource, ai.properties.aiChatsFolder);
  const children = useResources(allSubjects);
  const [inbox] = useString(driveResource, notifications.properties.inbox);
  const [trashFolder] = useString(
    driveResource,
    dataBrowser.properties.trashFolder,
  );

  const subjects = useMemo(() => {
    const hidden = new Set(
      [defaultOntology, commentsFolder, aiChatsFolder, inbox, trashFolder]
        .filter((subject): subject is string => !!subject)
        .map(canonicalizeScheme),
    );

    return allSubjects.filter(subject => {
      if (hidden.has(canonicalizeScheme(subject))) return false;

      const child = children.get(subject);

      return !(
        child &&
        isHiddenFromChildLists(
          child.getClasses(),
          child.get(dataBrowser.properties.about) as string | undefined,
        )
      );
    });
  }, [
    allSubjects,
    children,
    defaultOntology,
    commentsFolder,
    aiChatsFolder,
    inbox,
    trashFolder,
  ]);

  return { subjects, allSubjects, loading, total };
}
