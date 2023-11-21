import { useCallback, useEffect, useRef, useState } from 'react';
import {
  FaCog,
  FaInfo,
  FaKeyboard,
  FaPlusCircle,
  FaUser,
} from 'react-icons/fa';
import { constructOpenURL } from '../../helpers/navigation';
import { useCurrentSubject } from '../../helpers/useCurrentSubject';
import { SideBarMenuItem } from './SideBarMenuItem';
import { paths } from '../../routes/paths';
import { unknownSubject, useCurrentAgent, useResource } from '@tomic/react';

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
  const [agent] = useCurrentAgent();
  const agentResource = useResource(agent?.subject ?? unknownSubject);

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

  return (
    <section aria-label='App menu'>
      <SideBarMenuItem
        icon={<FaUser />}
        label={agent ? agentResource.title : 'Login'}
        helper='See and edit the current Agent / User (u)'
        path={paths.agentSettings}
        onClick={onItemClick}
      />
      <SideBarMenuItem
        icon={<FaCog />}
        label='Settings'
        helper='Edit the theme (t)'
        path={paths.themeSettings}
        onClick={onItemClick}
      />
      <SideBarMenuItem
        icon={<FaKeyboard />}
        label='Keyboard Shortcuts'
        helper='View the keyboard shortcuts (?)'
        path={paths.shortcuts}
        onClick={onItemClick}
      />
      <SideBarMenuItem
        icon={<FaInfo />}
        label='About'
        helper='Welcome page, tells about this app'
        path={paths.about}
        onClick={onItemClick}
      />
      {showInstallButton && (
        <SideBarMenuItem
          icon={<FaPlusCircle />}
          label='Install App'
          helper='Install app to desktop'
          path={constructOpenURL(subject ?? window.location.href)}
          onClick={install}
        />
      )}
    </section>
  );
}
