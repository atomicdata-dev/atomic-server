import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { FaPlusCircle } from 'react-icons/fa';
import { constructOpenURL } from '../../helpers/navigation';
import { useCurrentSubject } from '../../helpers/useCurrentSubject';
import { appMenuItems } from './menuItems';
import { SideBarHeader } from './SideBarHeader';
import { SideBarMenuItem } from './SideBarMenuItem';

// Non standard event type so we have to type it ourselfs for now.
type BeforeInstallPromptEvent = {
  preventDefault: () => void;
  prompt: () => Promise<{ outcome: 'accepted' | 'dismissed' }>;
};

export interface AppMenuProps {
  onItemClick: () => void;
}

export function AppMenu({ onItemClick }: AppMenuProps): JSX.Element {
  const event = useRef<BeforeInstallPromptEvent | null>(null);
  const [subject] = useCurrentSubject();
  const [showInstallButton, setShowInstallButton] = useState(false);

  const install = useCallback(() => {
    if (!event.current) {
      return;
    }

    event.current.prompt().then(result => {
      if (result.outcome === 'accepted') {
        setShowInstallButton(false);
      }
    });
  }, [event.current]);

  useEffect(() => {
    const listener = (e: BeforeInstallPromptEvent) => {
      e.preventDefault();
      setShowInstallButton(true);
      event.current = e;
    };

    //@ts-ignore
    window.addEventListener('beforeinstallprompt', listener);

    //@ts-ignore
    return () => window.removeEventListener('beforeinstallprompt', listener);
  }, []);

  const items = useMemo(() => {
    if (!showInstallButton) {
      return appMenuItems;
    }

    return [
      {
        icon: <FaPlusCircle />,
        label: 'Install App',
        helper: 'Install app to desktop',
        handleClickItem: install,
        path: constructOpenURL(subject ?? window.location.href),
      },
      ...appMenuItems,
    ];
  }, [appMenuItems, showInstallButton, subject]);

  return (
    <>
      <SideBarHeader>App</SideBarHeader>
      {items.map(p => (
        <SideBarMenuItem
          key={p.label}
          {...p}
          handleClickItem={p.handleClickItem ?? onItemClick}
        />
      ))}
    </>
  );
}
