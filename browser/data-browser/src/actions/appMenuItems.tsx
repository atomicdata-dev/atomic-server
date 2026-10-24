import {
  FaArrowsRotate,
  FaBell,
  FaCommentDots,
  FaGear,
  FaPlus,
  FaPowerOff,
  FaRightLeft,
  FaUser,
} from 'react-icons/fa6';
import { useSettings } from '../helpers/AppSettings';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { paths } from '../routes/paths';
import { useAISidebar } from '../components/AI/AISidebarContext';
import { useAISettings } from '../components/AI/AISettingsContext';
import { AIIcon } from '../components/AI/AIIcon';
import type { DropdownItem } from '../components/Dropdown';

/** Opens the sidebar's feedback dialog (the sidebar's AccountMenu listens). */
export const OPEN_FEEDBACK_EVENT = 'atomic-open-feedback';

/**
 * What the More menu offers that is not about the open resource.
 *
 * `create` are the two ways to start something new, shown in the More menu
 * of pages that are not a resource (settings, notifications), where a
 * resource's own actions do not apply. `find` are places in the app, the
 * "Go to" group of the More menu: hidden by default to keep the list short,
 * found through the filter. `maintenance` (restart) is hidden the same way.
 */
export function useAppMenuItems(): {
  create: DropdownItem[];
  find: DropdownItem[];
  maintenance: DropdownItem[];
} {
  const navigate = useNavigateWithTransition();
  const { drive, setSideBarLocked } = useSettings();
  const { setIsOpen } = useAISidebar();
  const { enableAI } = useAISettings();

  const create: DropdownItem[] = [
    { id: 'app-new', label: 'New', header: true, onClick: () => undefined },
    {
      id: 'app-new-resource',
      label: 'New resource',
      helper: 'Create a new resource in this drive.',
      icon: <FaPlus />,
      keywords: ['create', 'add'],
      onClick: () =>
        navigate({
          to: paths.new,
          search: { parentSubject: drive || undefined },
        } as never),
    },
    ...(enableAI
      ? [
          {
            id: 'app-new-ai-chat',
            label: 'New AI chat',
            helper: 'Open the assistant.',
            icon: <AIIcon />,
            keywords: ['assistant', 'ask'],
            onClick: () => setIsOpen(true),
          },
        ]
      : []),
  ];

  const find: DropdownItem[] = [
    {
      id: 'app-go-to',
      label: 'Go to',
      header: true,
      searchOnly: true,
      onClick: () => undefined,
    },
    {
      id: 'app-open-settings',
      label: 'Open settings',
      icon: <FaGear />,
      keywords: ['preferences', 'theme', 'language'],
      searchOnly: true,
      onClick: () => navigate(paths.appSettings),
    },
    {
      id: 'app-switch-drive',
      label: 'Switch drive',
      icon: <FaRightLeft />,
      keywords: ['workspace', 'drives'],
      searchOnly: true,
      onClick: () => {
        // The switcher lives in the sidebar header: show the sidebar, then
        // open it there.
        setSideBarLocked(true);
        requestAnimationFrame(() =>
          document
            .querySelector<HTMLElement>(
              '[data-testid="sidebar-drive-switcher"]',
            )
            ?.click(),
        );
      },
    },
    {
      id: 'app-sync-settings',
      label: 'Open sync settings',
      icon: <FaArrowsRotate />,
      keywords: ['sync', 'devices', 'backup', 'cloud', 'server'],
      searchOnly: true,
      onClick: () => navigate(paths.sync),
    },
    {
      id: 'app-user-settings',
      label: 'Open user settings',
      icon: <FaUser />,
      keywords: ['account', 'profile', 'agent'],
      searchOnly: true,
      onClick: () => navigate(paths.agentSettings),
    },
    {
      id: 'app-feedback',
      label: 'Give feedback',
      icon: <FaCommentDots />,
      keywords: ['bug', 'report', 'feedback'],
      searchOnly: true,
      onClick: () => window.dispatchEvent(new Event(OPEN_FEEDBACK_EVENT)),
    },
    {
      id: 'app-notifications',
      label: 'Show notifications',
      icon: <FaBell />,
      keywords: ['inbox', 'mentions'],
      searchOnly: true,
      onClick: () => navigate(paths.notifications),
    },
  ];

  const maintenance: DropdownItem[] = [
    {
      id: 'app-restart',
      label: 'Restart app',
      helper: 'Reload the whole app, as if you opened it again.',
      icon: <FaPowerOff />,
      keywords: ['reload', 'refresh', 'relaunch'],
      searchOnly: true,
      onClick: () => window.location.reload(),
    },
  ];

  return { create, find, maintenance };
}
