import {
  dataBrowser,
  isNotFound,
  isUnauthorized,
  useDrivePresence,
  useResources,
} from '@tomic/react';
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
import { toRelativeDateTime } from '@helpers/dates/relativeDate';
import { lastEditedAt } from './lastEditedAt';

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
function ResourceLines({
  items,
}: {
  items: { subject: string; at?: number }[];
}): JSX.Element {
  return (
    <Lines>
      {items.map(({ subject, at }) => (
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
                >
                  Edited {toRelativeDateTime(new Date(at), true)}
                </ResourceRowDescription>
              ) : undefined
            }
          />
        </li>
      ))}
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
  const [recent] = useState(() => getRecentResources(drive));
  const candidates = useMemo(
    () => Array.from(new Set([...subjects, ...recent])),
    [subjects, recent],
  );
  const resources = useResources(candidates, { allowIncomplete: true });
  const items = useMemo(() => {
    const out: { subject: string; at: number }[] = [];

    for (const [subject, resource] of resources) {
      const at = lastEditedAt(resource);

      if (
        at &&
        !isUnauthorized(resource.error) &&
        !isNotFound(resource.error)
      ) {
        out.push({ subject, at });
      }
    }

    return out.sort((a, b) => b.at - a.at);
  }, [resources]);
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
