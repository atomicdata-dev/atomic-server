import {
  dataBrowser,
  isNotFound,
  isUnauthorized,
  useDrivePresence,
  useResources,
  useStore,
  type Store,
} from '@tomic/react';
import { canonicalizeScheme } from '@tomic/lib';
import { useMemo, useState, type JSX } from 'react';
import {
  FaComment,
  FaFileLines,
  FaFolder,
  FaPlus,
  FaTable,
  FaVideo,
} from 'react-icons/fa6';
import type { IconType } from 'react-icons';
import { styled } from 'styled-components';
import { Button } from '@components/Button';
import { Row } from '@components/Row';
import { ResourceRow, ResourceRowDescription } from '@views/ResourceRow';
import { PresenceAvatarMenu } from '@components/Presence/PresenceAvatarMenu';
import { useNewResourceUI } from '@components/forms/NewForm/useNewResourceUI';
import { getRecentResources } from '@helpers/recentResources';
import { useNewRoute } from '@helpers/useNewRoute';
import {
  toRelativeDateTime,
  toShortRelativeTime,
} from '@helpers/dates/relativeDate';
import { isHiddenFromChildLists } from '@helpers/hiddenFromChildLists';
import { useHiddenDriveSubjects } from '@hooks/useVisibleDriveChildren';
import { useRecentComments } from '@hooks/useRecentComments';
import { lastEditedAt } from './lastEditedAt';
import { mergeActivity, type ActivityRow } from './commentActivity';

export { lastEditedAt };

const MAX_PEOPLE = 6;
const ACTIVITY_VISIBLE = 10;

const QUICK_CREATE: { label: string; classSubject: string; Icon: IconType }[] =
  [
    {
      label: 'Document',
      classSubject: dataBrowser.classes.documentV2,
      Icon: FaFileLines,
    },
    { label: 'Table', classSubject: dataBrowser.classes.table, Icon: FaTable },
    {
      label: 'Folder',
      classSubject: dataBrowser.classes.folder,
      Icon: FaFolder,
    },
    {
      label: 'Meeting',
      classSubject: dataBrowser.classes.meeting,
      Icon: FaVideo,
    },
    {
      label: 'Chat room',
      classSubject: dataBrowser.classes.chatroom,
      Icon: FaComment,
    },
  ];

/** Shortcuts for the classes people create most. */
export function QuickCreateCards({ parent }: { parent: string }): JSX.Element {
  const createNewResource = useNewResourceUI();
  const navigateToNewRoute = useNewRoute(parent);

  return (
    <Row wrapItems gap='0.5rem' aria-label='Create'>
      <Button data-testid='drive-new-button' onClick={navigateToNewRoute}>
        <FaPlus /> <span>New</span>
      </Button>
      {QUICK_CREATE.map(({ label, classSubject, Icon }) => (
        <Button
          key={classSubject}
          subtle
          onClick={() => createNewResource(classSubject, parent)}
        >
          <Icon /> {label}
        </Button>
      ))}
    </Row>
  );
}

/** Avatars of the people currently on the drive, one per agent. */
export function DrivePeople(): JSX.Element | null {
  const presence = useDrivePresence();
  const agents = Array.from(new Set(presence.map(item => item.agent)));

  if (agents.length === 0) {
    return null;
  }

  return (
    <Row center gap='0.25rem' aria-label='Currently on this drive'>
      {agents.slice(0, MAX_PEOPLE).map(agent => (
        <PresenceAvatarMenu key={agent} agentSubject={agent} size='1.9rem' />
      ))}
      {agents.length > MAX_PEOPLE && (
        <small>+{agents.length - MAX_PEOPLE}</small>
      )}
    </Row>
  );
}

/** One full-width line per resource, with an optional quiet edit time. */
function ResourceLines({ items }: { items: ActivityRow[] }): JSX.Element {
  return (
    <Lines>
      {items.map(({ subject, at, kind }) => {
        const label = at
          ? `${kind === 'commented' ? 'Commented' : 'Edited'} ${toRelativeDateTime(new Date(at), true)}`
          : undefined;

        return (
          <li key={subject}>
            <ResourceRow
              clickable
              tabbable
              subject={subject}
              trailing={
                at ? (
                  <ResourceRowDescription
                    as='time'
                    dateTime={new Date(at).toISOString()}
                    title={label}
                    aria-label={label}
                  >
                    {toShortRelativeTime(new Date(at))}
                  </ResourceRowDescription>
                ) : undefined
              }
            />
          </li>
        );
      })}
    </Lines>
  );
}

export function ResourceList({
  subjects,
}: {
  subjects: string[];
}): JSX.Element {
  return <ResourceLines items={subjects.map(subject => ({ subject }))} />;
}

/**
 * Whether `subject` sits inside `drive`, judged from what is already in
 * memory (the root of its parent chain), so it costs no fetch. A chain that
 * ends at a resource we have not loaded is given the benefit of the doubt;
 * one that ends at a loaded, different root (another drive, an ontology's
 * Property or Class) is not part of this drive.
 */
export function belongsToDrive(
  store: Pick<Store, 'driveOfSubject' | 'resources'>,
  subject: string,
  drive: string,
): boolean {
  const root = store.driveOfSubject(subject);

  // `atomic:` and legacy `did:ad:` spell the same drive.
  if (
    canonicalizeScheme(root) === canonicalizeScheme(store.driveOfSubject(drive))
  ) {
    return true;
  }

  return !store.resources.has(root);
}

/**
 * What changed lately on this drive: its visible children plus the resources
 * opened here recently, newest edit first. Derived from data that is already
 * loaded for the tiles, so there is no log to write or query. Only the first
 * rows render; "Show all" renders the rest.
 */
export function ActivityFeed({
  subjects,
  drive,
}: {
  subjects: string[];
  drive: string;
}): JSX.Element {
  const store = useStore();
  const recent = useMemo(() => getRecentResources(drive), [drive]);
  const children = useMemo(() => new Set(subjects), [subjects]);
  const commented = useRecentComments(drive);
  const hidden = useHiddenDriveSubjects(drive);
  // Resources that were commented on are candidates too, unless the drive
  // keeps them out of sight (Comments folder, Trash, ...).
  const candidates = useMemo(
    () =>
      Array.from(
        new Set([
          ...subjects,
          ...recent,
          ...Array.from(commented.keys()).filter(
            subject => !hidden.has(canonicalizeScheme(subject)),
          ),
        ]),
      ),
    [subjects, recent, commented, hidden],
  );
  const resources = useResources(candidates, { allowIncomplete: true });
  const items = useMemo(() => {
    const edits: { subject: string; at?: number }[] = [];

    for (const [subject, resource] of resources) {
      // Only the drive's own children and recents that sit inside it. Recents
      // are recorded per current drive, but also hold whatever was opened
      // from elsewhere (other drives, ontology Properties and Classes).
      if (!children.has(subject) && !belongsToDrive(store, subject, drive)) {
        continue;
      }

      // AI chats, meetings and agent notes are reached elsewhere.
      if (
        isHiddenFromChildLists(
          resource.getClasses(),
          resource.get(dataBrowser.properties.about) as string | undefined,
        )
      ) {
        continue;
      }

      // Unreadable resources drop out here, and with them any comment on
      // them: their title never reaches the list.
      if (
        resource.loading ||
        isUnauthorized(resource.error) ||
        isNotFound(resource.error)
      ) {
        continue;
      }

      edits.push({ subject, at: lastEditedAt(resource) });
    }

    // Unknown edit time (legacy resource never edited here): listed after the
    // dated rows, without a made-up "Edited ..." caption.
    return mergeActivity(edits, commented);
  }, [resources, children, store, drive, commented]);
  const [showAll, setShowAll] = useState(false);
  const shown = showAll ? items : items.slice(0, ACTIVITY_VISIBLE);

  return (
    <section aria-label='Activity'>
      <SectionTitle>Activity</SectionTitle>
      {items.length === 0 ? (
        <p>Activity will show up here</p>
      ) : (
        <>
          <ResourceLines items={shown} />
          {items.length > ACTIVITY_VISIBLE && (
            <Button subtle onClick={() => setShowAll(!showAll)}>
              {showAll ? 'Show less' : 'Show all'}
            </Button>
          )}
        </>
      )}
    </section>
  );
}

export const SectionTitle = styled.h2`
  font-size: 0.85rem;
  font-weight: 650;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: ${p => p.theme.colors.textLight};
  margin: 0 0 0.75rem;
`;

const Lines = styled.ul`
  list-style: none;
  margin: 0;
  padding: 0;

  li {
    list-style: none;
    margin: 0;
    padding: 0.4rem 0;
  }
`;
