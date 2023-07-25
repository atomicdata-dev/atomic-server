import * as React from 'react';
import { dataURL, editURL } from '../helpers/navigation';
import { useHotkeys } from 'react-hotkeys-hook';
import { useNavigate } from 'react-router-dom';
import { useCurrentSubject } from '../helpers/useCurrentSubject';
import { Client } from '@tomic/react';
import { useSettings } from '../helpers/AppSettings';
import { paths } from '../routes/paths';

type Props = {
  children: React.ReactNode;
};

/** List of used keyboard shortcuts, mapped for OS */
export const shortcuts = {
  /** Edit current resource */
  edit: osCtrl('e'),
  /** Show data view for current resource */
  data: osCtrl('d'),
  /** Show home page */
  home: osCtrl('h'),
  /** Create a new resource */
  new: osCtrl('n'),
  /** Open user settings page */
  userSettings: osCtrl('u'),
  /** Open theme settings page */
  themeSettings: osCtrl('t'),
  /** Open keyboard shortcuts page */
  keyboardShortcuts: 'shift+/',
  /** Focus search bar */
  search: '/',
  /** Open resource menu */
  menu: osCtrl('m'),
  /** Locks the sidebar menu */
  sidebarToggle: '\\',
  /** Move line up (documents) */
  moveLineUp: osAlt('up'),
  /** Move line down (documents) */
  moveLineDown: osAlt('down'),
  /** Delete line (documents) */
  deleteLine: osAlt('backspace'),
};

function osCtrl(key: string): string {
  return navigator.platform.includes('Mac') ? `cmd+${key}` : `ctrl+${key}`;
}

function osAlt(key: string): string {
  return navigator.platform.includes('Mac') ? `option+${key}` : `alt+${key}`;
}

export function displayShortcut(shortcut: string): string {
  if (navigator.platform.includes('Mac')) {
    return shortcut
      .replace('cmd+', '⌘')
      .replace('option+', '⌥')
      .replace('shift+', '⇧')
      .replace('backspace', '⌫');
  }

  return shortcut;
}

/** App-wide keyboard events handler. */
function HotKeysWrapper({ children }: Props): JSX.Element {
  const navigate = useNavigate();
  const [subject] = useCurrentSubject();
  const { sideBarLocked, setSideBarLocked } = useSettings();

  useHotkeys(
    shortcuts.edit,
    e => {
      e.preventDefault();
      Client.isValidSubject(subject) && navigate(editURL(subject!));
    },
    {},
    [subject],
  );
  useHotkeys(
    shortcuts.data,
    e => {
      e.preventDefault();
      Client.isValidSubject(subject) && navigate(dataURL(subject!));
    },
    {},
    [subject],
  );
  useHotkeys(shortcuts.home, e => {
    e.preventDefault();
    navigate('/');
  });
  useHotkeys(shortcuts.new, e => {
    e.preventDefault();
    navigate(paths.new);
  });
  useHotkeys(shortcuts.userSettings, e => {
    e.preventDefault();
    navigate(paths.agentSettings);
  });
  useHotkeys(shortcuts.themeSettings, e => {
    e.preventDefault();
    navigate(paths.themeSettings);
  });
  useHotkeys(shortcuts.keyboardShortcuts, e => {
    e.preventDefault();
    navigate(paths.shortcuts);
  });
  useHotkeys(
    shortcuts.sidebarToggle,
    e => {
      e.preventDefault();
      setSideBarLocked(!sideBarLocked);
    },
    {},
    [sideBarLocked],
  );

  return <>{children}</>;
}

export default HotKeysWrapper;
