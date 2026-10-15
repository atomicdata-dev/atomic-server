import {
  dataBrowser,
  isNotFound,
  isUnauthorized,
  useDrivePresence,
  useResource,
  useResources,
  useTitle,
} from '@tomic/react';
import { memo, useMemo, useState, type JSX } from 'react';
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
import { AtomicLink } from '@components/AtomicLink';
import { ResourceGlyph } from '@components/ResourceGlyph';
import { PresenceAvatarMenu } from '@components/Presence/PresenceAvatarMenu';
import { useNewResourceUI } from '@components/forms/NewForm/useNewResourceUI';
import { getRecentResources } from '@helpers/recentResources';
import { useNewRoute } from '@helpers/useNewRoute';
import { toRelativeDateTime } from '@helpers/dates/relativeDate';
import { lastEditedAt } from './lastEditedAt';

export { lastEditedAt };

const MAX_RECENT = 6;
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

/** Larger labelled shortcuts for the classes people create most. */
export function QuickCreateCards({ parent }: { parent: string }): JSX.Element {
  const createNewResource = useNewResourceUI();
  const navigateToNewRoute = useNewRoute(parent);

  return (
    <CardRow aria-label='Create'>
      <CreateCard
        $primary
        type='button'
        data-testid='drive-new-button'
        onClick={navigateToNewRoute}
      >
        <FaPlus />
        <span>New</span>
      </CreateCard>
      {QUICK_CREATE.map(({ label, classSubject, Icon }) => (
        <CreateCard
          key={classSubject}
          type='button'
          onClick={() => createNewResource(classSubject, parent)}
        >
          <Icon />
          <span>{label}</span>
        </CreateCard>
      ))}
    </CardRow>
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
    <People aria-label='Currently on this drive'>
      {agents.slice(0, MAX_PEOPLE).map(agent => (
        <PresenceAvatarMenu key={agent} agentSubject={agent} size='1.9rem' />
      ))}
      {agents.length > MAX_PEOPLE && <More>+{agents.length - MAX_PEOPLE}</More>}
    </People>
  );
}

/** Resources opened recently on this drive, newest first. Renders nothing when there are none. */
export function RecentlyOpened({
  drive,
}: {
  drive: string;
}): JSX.Element | null {
  const [recent] = useState(() =>
    getRecentResources(drive).slice(0, MAX_RECENT),
  );

  if (recent.length === 0) {
    return null;
  }

  return (
    <section>
      <SectionTitle>Recently opened</SectionTitle>
      <Tiles>
        {recent.map(subject => (
          <ResourceTile key={subject} subject={subject} />
        ))}
      </Tiles>
    </section>
  );
}

export function ResourceTiles({
  subjects,
}: {
  subjects: string[];
}): JSX.Element {
  return (
    <Tiles>
      {subjects.map(subject => (
        <ResourceTile key={subject} subject={subject} />
      ))}
    </Tiles>
  );
}

function ResourceTile({ subject }: { subject: string }): JSX.Element {
  const resource = useResource(subject, { allowIncomplete: true });
  const [title] = useTitle(resource);

  return (
    <Tile subject={subject} clean>
      <TileGlyph>
        <ResourceGlyph resource={resource} />
      </TileGlyph>
      <TileText>
        <TileTitle>{title}</TileTitle>
      </TileText>
    </Tile>
  );
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
        <ActivityHint>Activity will show up here</ActivityHint>
      ) : (
        <>
          <ActivityList>
            {shown.map(item => (
              <ActivityRow key={item.subject} {...item} />
            ))}
          </ActivityList>
          {items.length > ACTIVITY_VISIBLE && (
            <ShowAll type='button' onClick={() => setShowAll(!showAll)}>
              {showAll ? 'Show less' : 'Show all'}
            </ShowAll>
          )}
        </>
      )}
    </section>
  );
}

const ActivityRow = memo(function ActivityRow({
  subject,
  at,
}: {
  subject: string;
  at: number;
}): JSX.Element {
  const resource = useResource(subject, { allowIncomplete: true });
  const [title] = useTitle(resource);

  return (
    <ActivityItem>
      <ActivityText>
        <ActivityChip subject={subject} clean>
          <ResourceGlyph resource={resource} />
          <span>{title}</span>
        </ActivityChip>
      </ActivityText>
      <ActivityTime dateTime={new Date(at).toISOString()}>
        Edited {toRelativeDateTime(new Date(at), true)}
      </ActivityTime>
    </ActivityItem>
  );
});

export const SectionTitle = styled.h2`
  font-size: 0.85rem;
  font-weight: 650;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: ${p => p.theme.colors.textLight};
  margin: 0 0 0.75rem;
`;

const CardRow = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(5rem, 1fr));
  gap: 0.75rem;
`;

const CreateCard = styled.button<{ $primary?: boolean }>`
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.5rem;
  padding: 1rem 0.5rem;
  font: inherit;
  font-size: 0.9rem;
  cursor: pointer;
  color: ${p => (p.$primary ? p.theme.colors.bg : p.theme.colors.text1)};
  background: ${p => (p.$primary ? p.theme.colors.main : p.theme.colors.bg)};
  border: 1px ${p => (p.$primary ? 'solid' : 'dashed')}
    ${p => (p.$primary ? p.theme.colors.main : p.theme.colors.bg2)};
  font-weight: ${p => (p.$primary ? 600 : 400)};
  border-radius: ${p => p.theme.radius};
  transition:
    border-color 0.1s,
    color 0.1s,
    background-color 0.1s;

  svg {
    font-size: 1.4rem;
    color: ${p => (p.$primary ? p.theme.colors.bg : p.theme.colors.main)};
  }

  &:hover,
  &:focus-visible {
    border-style: solid;
    border-color: ${p => p.theme.colors.main};
    background: ${p =>
      p.$primary ? p.theme.colors.mainDark : p.theme.colors.mainSelectedBg};
    color: ${p => (p.$primary ? p.theme.colors.bg : p.theme.colors.main)};

    svg {
      color: ${p => (p.$primary ? p.theme.colors.bg : p.theme.colors.main)};
    }
  }
`;

const Tiles = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(15rem, 1fr));
  gap: 0.75rem;

  @media (max-width: 480px) {
    grid-template-columns: 1fr;
  }
`;

const Tile = styled(AtomicLink)`
  display: flex;
  align-items: center;
  gap: 0.85rem;
  min-width: 0;
  padding: 0.85rem 1rem;
  background: ${p => p.theme.colors.bg1};
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  color: ${p => p.theme.colors.text1};
  text-decoration: none;
  transition:
    border-color 0.1s,
    box-shadow 0.1s;

  &:hover,
  &:focus-visible {
    border-color: ${p => p.theme.colors.main};
    box-shadow: 0 0 0 1px ${p => p.theme.colors.main};
    color: ${p => p.theme.colors.text1};
  }
`;

const TileGlyph = styled.span`
  display: grid;
  place-items: center;
  flex-shrink: 0;
  width: 2.5rem;
  height: 2.5rem;
  font-size: 1.25rem;
  color: ${p => p.theme.colors.main};
  background: ${p => p.theme.colors.mainSelectedBg};
  border-radius: ${p => p.theme.radius};
`;

const TileText = styled.span`
  display: flex;
  flex-direction: column;
  min-width: 0;
`;

const TileTitle = styled.span`
  font-weight: 500;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
`;

const People = styled.span`
  display: inline-flex;
  align-items: center;

  & > *:not(:first-child) {
    margin-left: -0.4rem;
  }
`;

const More = styled.span`
  font-size: 0.8rem;
  color: ${p => p.theme.colors.textLight};
  margin-left: 0.3rem;
`;

const ActivityHint = styled.p`
  margin: 0;
  color: ${p => p.theme.colors.textLight};
`;

const ActivityList = styled.ul`
  list-style: none;
  margin: 0;
  padding: 0;
`;

const ActivityItem = styled.li`
  margin: 0;
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.4rem 0;
  min-width: 0;
`;

const ActivityText = styled.span`
  flex: 1;
  min-width: 0;
  overflow-wrap: anywhere;
`;

const ActivityChip = styled(AtomicLink)`
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  max-width: 100%;
  vertical-align: middle;
  padding: 0.1rem 0.5rem;
  background: ${p => p.theme.colors.bg1};
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: 999px;
  color: ${p => p.theme.colors.text1};
  text-decoration: none;

  svg {
    color: ${p => p.theme.colors.main};
    flex-shrink: 0;
  }

  &:hover,
  &:focus-visible {
    border-color: ${p => p.theme.colors.main};
    color: ${p => p.theme.colors.main};
  }
`;

const ActivityTime = styled.time`
  flex-shrink: 0;
  font-size: 0.8rem;
  color: ${p => p.theme.colors.textLight};
  white-space: nowrap;
`;

const ShowAll = styled.button`
  margin-top: 0.5rem;
  padding: 0;
  font: inherit;
  font-size: 0.85rem;
  color: ${p => p.theme.colors.main};
  background: none;
  border: none;
  cursor: pointer;
`;
