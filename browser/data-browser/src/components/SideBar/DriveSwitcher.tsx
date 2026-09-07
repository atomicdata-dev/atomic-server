import styled from 'styled-components';
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
import { useSavedDrives } from '../../hooks/useSavedDrives';
import { usePrivateDrive } from '../../hooks/usePrivateDrive';
import { paths } from '../../routes/paths';
import { type DropdownItem, DIVIDER, DropdownMenu } from '../Dropdown';
import { buildDefaultTrigger } from '../Dropdown/DefaultTrigger';
import type { DropdownTriggerComponent } from '../Dropdown/DropdownTrigger';
import { useNewResourceUI } from '../forms/NewForm/useNewResourceUI';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';

const DefaultTrigger = buildDefaultTrigger(<FaCaretDown />, 'Switch Drive');

function getTitle(resource: Resource): string {
  return (resource.get(core.properties.name) as string) ?? resource.subject;
}

/**
 * Quick-switch between the user's drives: private drive, My drives,
 * recently visited. Managing the lists lives on the User Settings page.
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
  const myDrives = savedDrives.filter(subject => subject !== privateDrive);
  const recentDrives = history.filter(subject => subject !== privateDrive);

  const myDrivesMap = useResources(myDrives);
  const recentDrivesMap = useResources(recentDrives);

  const switchTo = (subject: string) => {
    setDrive(subject);
    addToHistory(subject);
    navigate(constructOpenURL(subject));
  };

  const createNewResource = useNewResourceUI();

  const items: DropdownItem[] = [
    ...(privateDrive
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
    ...Array.from(myDrivesMap.entries())
      .filter(([_, resource]) => !resource.error)
      .map(([subject, resource]) => ({
        id: subject,
        suffix: badge(subject),
        label: getTitle(resource),
        helper: `Switch to ${getTitle(resource)}`,
        disabled: false,
        onClick: (): void => switchTo(subject),
        icon: subject === drive ? <FaSquareCheck /> : <FaRegCircle />,
      })),
    {
      id: 'new-drive',
      label: 'New Drive',
      icon: <FaPlus />,
      helper: 'Create a new drive',
      onClick: (): void =>
        createNewResource(server.classes.drive, agent?.subject ?? ''),
      disabled: !agent,
    },
    DIVIDER,
    ...Array.from(recentDrivesMap.entries()).map(([subject, resource]) => ({
      label: getTitle(resource),
      id: subject,
      suffix: badge(subject),
      helper: `Switch to ${getTitle(resource)}`,
      icon: subject === drive ? <FaSquareCheck /> : <FaRegCircle />,
      onClick: (): void => switchTo(subject),
      disabled: false,
    })),
    DIVIDER,
    {
      id: 'drive-hosting',
      label: 'Storage and hosting',
      icon: <FaCloud />,
      helper:
        'Local stays on your devices. Vault is encrypted backup. Server hosts a readable copy. Remote is another connected server.',
      onClick: () =>
        navigate(`/app/sync?drive=${encodeURIComponent(drive ?? '')}`),
    },
    {
      id: 'manage-drives',
      label: 'Manage drives',
      icon: <FaGear />,
      helper: 'View and organize all your drives.',
      onClick: (): void => {
        void navigate(paths.agentSettings);
      },
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
