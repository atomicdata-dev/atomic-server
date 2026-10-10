import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type JSX,
  type RefObject,
} from 'react';
import { styled } from 'styled-components';
import { SIDEBAR_BAR_HEIGHT, SIDEBAR_BAR_HEIGHT_TOUCH } from './SidebarCSSVars';
import {
  FaBell,
  FaCirclePlus,
  FaComment,
  FaGear,
  FaInfo,
  FaPlug,
  FaTrash,
  FaUser,
} from 'react-icons/fa6';
import { LuChevronsUpDown } from 'react-icons/lu';
import {
  core,
  dataBrowser,
  unknownSubject,
  useCanWrite,
  useCurrentAgent,
  useResource,
  useStore,
  useString,
} from '@tomic/react';
import { toast } from 'react-hot-toast';
import { useSettings } from '../../helpers/AppSettings';
import { constructOpenURL } from '../../helpers/navigation';
import { getOrCreateTrashFolder } from '../../helpers/standardLocations';
import { paths } from '../../routes/paths';
import { shortcuts } from '../../actions/shortcuts';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';
import { useInbox } from '../../hooks/useInbox';
import { DropdownMenu, type DropdownItem } from '../Dropdown';
import type { DropdownTriggerProps } from '../Dropdown/DropdownTrigger';
import { IconButton } from '../IconButton/IconButton';
import { ResourceGlyph } from '../ResourceGlyph';
import { useCombineRefs } from '../../hooks/useCombineRefs';
import { useFeedbackDialog } from './FeedbackButton';
import { OPEN_FEEDBACK_EVENT } from '../../actions/appMenuItems';
import {
  getSyncIcon,
  getSyncLabel,
  hasSyncWarning,
  useSyncStatus,
} from './syncStatus';
import {
  SideBarMenuRow,
  SideBarMenuRowIcon,
  SideBarMenuRowLabel,
} from './SideBarMenuItem';

// Non standard event type so we have to type it ourselfs for now.
type BeforeInstallPromptEvent = {
  preventDefault: () => void;
  prompt: () => Promise<{ outcome: 'accepted' | 'dismissed' }>;
};

export interface AccountMenuProps {
  /** Called after an item navigates somewhere. Used for closing the sidebar. */
  onItemClick: () => void;
}

interface AccountTriggerContextValue {
  /** Lets the feedback dialog return focus to the trigger when it closes. */
  triggerRef: RefObject<HTMLButtonElement | null>;
  unread: number;
}

const AccountTriggerContext = createContext<AccountTriggerContextValue>({
  triggerRef: { current: null },
  unread: 0,
});

/**
 * The bottom row of the sidebar: the current user, which opens a menu with
 * everything app-wide (profile, notifications, integrations, sync, feedback,
 * about), and a Settings button beside it.
 */
export function AccountMenu(props: AccountMenuProps): JSX.Element {
  const [agent] = useCurrentAgent();

  return agent ? (
    <SignedInAccountMenu {...props} />
  ) : (
    <AccountMenuRow {...props} unread={0} />
  );
}

/** Notifications only exist for a signed-in user, so only then read the inbox. */
function SignedInAccountMenu(props: AccountMenuProps): JSX.Element {
  const { unread } = useInbox();

  return <AccountMenuRow {...props} unread={unread} />;
}

function AccountMenuRow({
  onItemClick,
  unread,
}: AccountMenuProps & { unread: number }): JSX.Element {
  const [agent] = useCurrentAgent();
  const navigate = useNavigateWithTransition();
  const syncStatus = useSyncStatus();
  const triggerRef = useRef<HTMLButtonElement>(null);
  const feedback = useFeedbackDialog({ triggerRef });
  const [install, showInstallButton] = useInstallPrompt();
  const store = useStore();
  const { drive } = useSettings();
  const driveResource = useResource(drive);
  const [trashFolder] = useString(
    driveResource,
    dataBrowser.properties.trashFolder,
  );
  const agentCanWrite = useCanWrite(driveResource);

  // "Give feedback" in the More menu opens this menu's feedback dialog.
  // Error pages and dialogs have their own FeedbackButton and don't listen.
  const openFeedback = feedback.open;
  useEffect(() => {
    window.addEventListener(OPEN_FEEDBACK_EVENT, openFeedback);

    return () => window.removeEventListener(OPEN_FEEDBACK_EVENT, openFeedback);
  }, [openFeedback]);

  const goTo = (path: string) => () => {
    navigate(path);
    onItemClick();
  };

  // The Trash folder is created on first use. Until then the item is offered
  // to agents that can write the drive, and opening it creates the folder.
  // Read-only agents only see it once a Trash folder exists.
  const showTrash = !!trashFolder || agentCanWrite;

  const goToTrash = async () => {
    try {
      const trash = trashFolder ?? (await getOrCreateTrashFolder(store, drive));

      navigate(constructOpenURL(trash));
      onItemClick();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Could not open Trash');
    }
  };

  const unreadLabel =
    unread > 0 ? `Notifications, ${unread} unread` : undefined;

  // A warning icon leads to the banner that explains it.
  const goToSync = () => {
    if (hasSyncWarning(syncStatus)) {
      void navigate({ to: paths.sync, hash: 'sync-problem' });
      onItemClick();
    } else {
      goTo(paths.sync)();
    }
  };

  const items: DropdownItem[] = [
    agent
      ? {
          id: 'profile',
          label: 'Profile',
          icon: <FaUser />,
          helper: 'See and edit the current Agent / User',
          shortcut: shortcuts.userSettings,
          onClick: goTo(paths.agentSettings),
        }
      : {
          id: 'login',
          label: 'Login / New User',
          icon: <FaUser />,
          helper: 'Sign in, or create a new Agent / User',
          onClick: goTo(paths.agentSettings),
        },
    ...(agent
      ? [
          {
            id: 'notifications',
            label: 'Notifications',
            icon: <FaBell />,
            helper: unreadLabel ?? 'Messages, comments and replies for you',
            onClick: goTo(paths.notifications),
            suffix: unread > 0 && (
              <Count aria-label={unreadLabel}>
                {unread > 99 ? '99+' : unread}
              </Count>
            ),
          },
        ]
      : []),
    {
      id: 'integrations',
      label: 'Integrations',
      icon: <FaPlug />,
      helper: 'Discover published integrations',
      onClick: goTo(paths.integrations),
    },
    {
      id: 'sync',
      label: 'Sync',
      // The status is in the tooltip; hiding the icon's own title keeps the
      // item's accessible name "Sync".
      icon: <IconSlot aria-hidden>{getSyncIcon(syncStatus)}</IconSlot>,
      helper: getSyncLabel(syncStatus),
      onClick: goToSync,
    },
    ...(showTrash
      ? [
          {
            id: 'trash',
            label: 'Trash',
            icon: <FaTrash />,
            helper: 'Items you deleted from this drive',
            onClick: goToTrash,
          },
        ]
      : []),
    {
      id: 'feedback',
      label: 'Feedback',
      icon: <FaComment />,
      helper: 'Report a bug or suggest an improvement',
      onClick: feedback.open,
    },
    {
      id: 'about',
      label: 'About',
      icon: <FaInfo />,
      helper: 'Welcome page, tells about this app',
      onClick: goTo(paths.about),
    },
    ...(showInstallButton
      ? [
          {
            id: 'install-app',
            label: 'Install App',
            icon: <FaCirclePlus />,
            helper: 'Install app to desktop',
            onClick: install,
          },
        ]
      : []),
  ];

  return (
    <AccountTriggerContext value={{ triggerRef, unread }}>
      <Row data-testid='account-menu'>
        <DropdownMenu
          Trigger={AccountTrigger}
          items={items}
          searchable={false}
        />
        {/* Also in the menu; these are checked often enough for their own
         * button. All muted like the menu's items. */}
        {agent && (
          <BellWrap>
            <IconButton
              color='textLight'
              title={unreadLabel ?? 'Notifications'}
              aria-label={unreadLabel ?? 'Notifications'}
              data-testid='sidebar-notifications-button'
              onClick={goTo(paths.notifications)}
            >
              <FaBell />
            </IconButton>
            {unread > 0 && <BellDot aria-hidden />}
          </BellWrap>
        )}
        <IconButton
          color='textLight'
          title={`Sync: ${getSyncLabel(syncStatus)}`}
          aria-label='Sync'
          data-testid='sidebar-sync-button'
          onClick={goToSync}
        >
          {getSyncIcon(syncStatus)}
        </IconButton>
        <IconButton
          color='textLight'
          title='Settings'
          aria-label='Settings'
          data-testid='sidebar-settings-button'
          onClick={goTo(paths.appSettings)}
        >
          <FaGear />
        </IconButton>
      </Row>
      {feedback.dialog}
    </AccountTriggerContext>
  );
}

/** The user row: avatar and name. Opens the account menu. */
function AccountTrigger({
  onClick,
  menuId,
  isActive,
  ref,
  id,
}: DropdownTriggerProps): JSX.Element {
  const { triggerRef, unread } = useContext(AccountTriggerContext);
  const combinedRef = useCombineRefs([ref, triggerRef]);
  const [agent] = useCurrentAgent();
  const agentResource = useResource(agent?.subject ?? unknownSubject);
  // `useString`, not `agentResource.get(...)`: the resource object is stable
  // across renders, so the compiler caches a plain read of it and the row kept
  // the 'User' it first rendered, before the profile had loaded or after a
  // rename.
  const [agentName] = useString(agentResource, core.properties.name);
  const name = agent
    ? (agentName ?? (agentResource.loading ? '' : 'Signed in'))
    : 'Login / New User';

  return (
    <TriggerButton
      as='button'
      type='button'
      id={id}
      ref={combinedRef}
      onClick={onClick}
      aria-haspopup='menu'
      aria-expanded={isActive}
      aria-controls={menuId}
      title='Account and app menu'
      data-testid='account-menu-trigger'
      data-signed-in={agent ? 'true' : undefined}
    >
      <SideBarMenuRowIcon>
        {agent ? (
          // Your own avatar, by the same precedence every other resource
          // row uses (icon image > emoji > class icon). `fallbackIcon`
          // keeps the plain person glyph for agents without a picture.
          <AgentGlyphSlot aria-hidden>
            <ResourceGlyph resource={agentResource} fallbackIcon={FaUser} />
          </AgentGlyphSlot>
        ) : (
          <FaUser aria-hidden />
        )}
      </SideBarMenuRowIcon>
      <SideBarMenuRowLabel>{name}</SideBarMenuRowLabel>
      {unread > 0 && <UnreadDot aria-hidden />}
      <LuChevronsUpDown aria-hidden />
    </TriggerButton>
  );
}

/**
 * Offers "Install App" when the browser fires `beforeinstallprompt`. Returns
 * the install function and whether installing is possible.
 */
function useInstallPrompt(): [install: () => void, available: boolean] {
  const event = useRef<BeforeInstallPromptEvent | null>(null);
  const [available, setAvailable] = useState(false);

  const install = useCallback(() => {
    if (!event.current) {
      return;
    }

    event.current.prompt().then(result => {
      if (result.outcome === 'accepted') {
        setAvailable(false);
      }
    });
  }, []);

  useEffect(() => {
    const listener = (e: Event) => {
      e.preventDefault();
      setAvailable(true);
      event.current = e as unknown as BeforeInstallPromptEvent;
    };

    window.addEventListener('beforeinstallprompt', listener);

    return () => window.removeEventListener('beforeinstallprompt', listener);
  }, []);

  return [install, available];
}

const Row = styled.div`
  display: flex;
  min-height: ${SIDEBAR_BAR_HEIGHT};
  align-items: center;
  gap: 0.25rem;
  box-sizing: border-box;
  width: 100%;
  min-width: 0;
`;

const BellWrap = styled.span`
  position: relative;
  display: inline-flex;
`;

const BellDot = styled.span`
  position: absolute;
  top: 0.35rem;
  right: 0.35rem;
  width: 0.5rem;
  height: 0.5rem;
  border-radius: 50%;
  background: ${p => p.theme.colors.main};
  pointer-events: none;
`;

const TriggerButton = styled(SideBarMenuRow)`
  flex: 1;
  border: 0;
  font: inherit;
  cursor: pointer;
  gap: 0.25rem;
  padding-inline-end: 0.5rem;
  min-height: ${SIDEBAR_BAR_HEIGHT};

  @media (pointer: coarse) {
    min-height: ${SIDEBAR_BAR_HEIGHT_TOUCH};
  }

  &:focus-visible {
    outline: 2px solid ${p => p.theme.colors.main};
    outline-offset: -2px;
  }

  &[aria-expanded='true'] {
    background-color: ${p => p.theme.colors.bg1};
  }
`;

const IconSlot = styled.span`
  display: inline-flex;
`;

const UnreadDot = styled.span`
  flex-shrink: 0;
  width: 0.5rem;
  height: 0.5rem;
  border-radius: 50%;
  background: ${p => p.theme.colors.main};
`;

const Count = styled.span`
  flex-shrink: 0;
  min-width: 1.2rem;
  padding: 0 0.35rem;
  border-radius: 999px;
  background: ${p => p.theme.colors.main};
  color: white;
  font-size: 0.7rem;
  font-weight: 600;
  line-height: 1.2rem;
  text-align: center;
`;

/**
 * Sizes the avatar to the row rather than letting it inherit: `IconImg` is
 * `1.2em`, and `SideBarMenuRowIcon` only shrinks `svg` children, so an image
 * glyph would otherwise sit noticeably larger than the icons beside it.
 */
const AgentGlyphSlot = styled.span`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 0.9rem;
  line-height: 1;
`;
