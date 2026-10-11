import { useEffect } from 'react';
import { driveDisplayName } from '../../helpers/driveDisplayName';
import { canonicalizeScheme } from '@tomic/lib';
import styled from 'styled-components';
import { useAccountDriveCatalog } from '../../hooks/useAccountDriveCatalog';
import { useDriveHostingStates } from '../../hooks/useDriveHostingStates';
import { Resource, core, server, useResources } from '@tomic/react';
import {
  FaCaretDown,
  FaGear,
  FaHouse,
  FaPlus,
  FaSquareCheck,
  FaRegCircle,
  FaCloud,
} from 'react-icons/fa6';
import { useSettings } from '../../helpers/AppSettings';
import { constructOpenURL } from '../../helpers/navigation';
import { useDriveHistory } from '../../hooks/useDriveHistory';
import { useDriveVisits } from '../../hooks/useDriveVisits';
import { useSavedDrives } from '../../hooks/useSavedDrives';
import { usePrivateDrive } from '../../hooks/usePrivateDrive';
import { paths } from '../../routes/paths';
import { type DropdownItem, DIVIDER, DropdownMenu } from '../Dropdown';
import { buildDefaultTrigger } from '../Dropdown/DefaultTrigger';
import type { DropdownTriggerComponent } from '../Dropdown/DropdownTrigger';
import { useNewResourceUI } from '../forms/NewForm/useNewResourceUI';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';

const MAX_SHOWN_DRIVES = 10;

const DefaultTrigger = buildDefaultTrigger(<FaCaretDown />, 'Switch Drive');

function getTitle(resource: Resource): string {
  return driveDisplayName(
    resource.get(core.properties.name) as string | undefined,
    resource.subject,
  );
}

/**
 * Quick-switch between the user's drives: private drive plus the 10 most recently
 * visited drives. The full lists live on the User Settings page.
 */
export function DriveSwitcher({
  Trigger = DefaultTrigger,
}: {
  Trigger?: DropdownTriggerComponent;
}) {
  const hosting = useDriveHostingStates();
  const badge = (subject: string) => (
    <HostingState>{hosting.states(subject)}</HostingState>
  );
  const navigate = useNavigateWithTransition();
  const { drive, setDrive, agent } = useSettings();
  const { privateDrive } = usePrivateDrive();
  const [savedDrives] = useSavedDrives();
  const [history, addToHistory] = useDriveHistory(savedDrives, 5);

  // The private drive leads the menu; keep it out of the lists below.
  const catalog = useAccountDriveCatalog(
    privateDrive ? [privateDrive, ...savedDrives] : savedDrives,
  );
  // Canonical spelling: the private drive can be `did:ad:` in one list and
  // `atomic:` in another, which showed it twice.
  const same = (a: string, b: string | undefined) =>
    !!b && canonicalizeScheme(a) === canonicalizeScheme(b);
  const myDrives = catalog.subjects.filter(
    subject => !same(subject, privateDrive),
  );
  const recentDrives = history.filter(
    subject =>
      !same(subject, privateDrive) &&
      !catalog.removed.some(removed => same(subject, removed)) &&
      !myDrives.some(mine => same(subject, mine)),
  );

  const [driveVisits, recordVisit] = useDriveVisits();

  // Record a visit whenever the active drive changes (also via links).
  useEffect(() => {
    if (drive) recordVisit(drive);
  }, [drive, recordVisit]);

  // One list: saved + recent drives, deduped, most recently visited first,
  // never visited ones after in their original order.
  const merged: string[] = [];

  for (const subject of [...myDrives, ...recentDrives]) {
    if (!merged.some(m => same(subject, m))) merged.push(subject);
  }

  const visitTime = (subject: string) =>
    driveVisits[canonicalizeScheme(subject)] ?? 0;
  // Array.prototype.sort is stable, so ties keep their original order.
  const shownDrives = merged
    .sort((a, b) => visitTime(b) - visitTime(a))
    .slice(0, MAX_SHOWN_DRIVES);

  const shownDrivesMap = useResources(shownDrives);

  const switchTo = (subject: string) => {
    setDrive(subject);
    addToHistory(subject);
    recordVisit(subject);
    navigate(constructOpenURL(subject));
  };

  const createNewResource = useNewResourceUI();

  const items: DropdownItem[] = [
    ...(privateDrive &&
    !catalog.removed.some(removed => same(privateDrive, removed))
      ? [
          {
            id: privateDrive,
            label: 'Private drive',
            helper: 'Switch to your personal drive.',
            suffix: badge(privateDrive),
            disabled: false,
            onClick: (): void => switchTo(privateDrive),
            icon: privateDrive === drive ? <FaSquareCheck /> : <FaHouse />,
          },
        ]
      : []),
    ...shownDrives.map(subject => {
      const resource = shownDrivesMap.get(subject);
      const label =
        resource && !resource.error
          ? getTitle(resource)
          : catalog.entries.find(e => e.drive_subject === subject)
              ?.drive_name || driveDisplayName(undefined, subject);

      return {
        id: subject,
        suffix: badge(subject),
        label,
        helper: `Switch to ${label}`,
        disabled: false,
        onClick: (): void => switchTo(subject),
        icon: subject === drive ? <FaSquareCheck /> : <FaRegCircle />,
      };
    }),
    DIVIDER,
    {
      id: 'new-drive',
      label: 'New Drive',
      icon: <FaPlus />,
      helper: 'Create a new drive',
      onClick: (): void =>
        createNewResource(server.classes.drive, agent?.subject ?? ''),
      disabled: !agent,
    },
    {
      id: 'manage-drives',
      label: 'View all drives',
      icon: <FaGear />,
      helper: 'View and organize all your drives.',
      onClick: (): void => {
        void navigate(paths.agentSettings);
      },
    },
    {
      id: 'drive-hosting',
      label: 'Storage and hosting',
      icon: <FaCloud />,
      helper:
        'Local stays on your devices. Vault is encrypted backup. Server hosts a readable copy. Remote is another connected server.',
      onClick: () =>
        navigate(`/app/sync?drive=${encodeURIComponent(drive ?? '')}`),
    },
  ];

  return (
    <DropdownMenu
      Trigger={Trigger}
      items={items}
      bindActive={active => {
        if (active) void hosting.refresh();
      }}
    />
  );
}

const HostingState = styled.span`
  margin-left: auto;
  font-size: 0.75rem;
  color: ${p => p.theme.colors.textLight};
  white-space: nowrap;
`;
