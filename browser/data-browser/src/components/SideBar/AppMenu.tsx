import { useCallback, useEffect, useRef, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { FaGear, FaInfo, FaCirclePlus, FaUser, FaPlug } from 'react-icons/fa6';
import { constructOpenURL } from '../../helpers/navigation';
import { useCurrentSubject } from '../../helpers/useCurrentSubject';
import { SideBarMenuItem } from './SideBarMenuItem';
import { paths } from '../../routes/paths';
import {
  core,
  unknownSubject,
  useCurrentAgent,
  useResource,
} from '@tomic/react';
import { FeedbackMenuItem } from './FeedbackMenuItem';
import { SyncMenuItem } from './SyncMenuItem';
import { ResourceGlyph } from '../ResourceGlyph';
import { DemoExitMenuItem } from '../DemoExitButton';

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
  }, []);

  useEffect(() => {
    const listener = (e: Event) => {
      e.preventDefault();
      setShowInstallButton(true);
      event.current = e as unknown as BeforeInstallPromptEvent;
    };

    window.addEventListener('beforeinstallprompt', listener);

    return () => window.removeEventListener('beforeinstallprompt', listener);
  }, []);

  return (
    <AppMenuSection aria-label='App menu'>
      <SideBarMenuItem
        icon={
          agent ? (
            // Your own avatar, by the same precedence every other resource
            // row uses (icon image > emoji > class icon). `fallbackIcon`
            // keeps the plain person glyph for agents without a picture.
            <AgentGlyphSlot aria-hidden>
              <ResourceGlyph resource={agentResource} fallbackIcon={FaUser} />
            </AgentGlyphSlot>
          ) : (
            <FaUser />
          )
        }
        label={
          agent
            ? (agentResource.get(core.properties.name) ?? 'User Settings')
            : 'Login / New User'
        }
        helper='See and edit the current Agent / User (u)'
        path={paths.agentSettings}
        onClick={onItemClick}
      />
      <SideBarMenuItem
        icon={<FaGear />}
        label='Settings'
        helper='Change client settings (t)'
        path={paths.appSettings}
        onClick={onItemClick}
      />
      <SideBarMenuItem
        icon={<FaPlug />}
        label='Integrations'
        helper='Discover published integrations'
        path={paths.integrations}
        onClick={onItemClick}
      />
      <SyncMenuItem onClick={onItemClick} />
      <FeedbackMenuItem />
      <SideBarMenuItem
        icon={<FaInfo />}
        label='About'
        helper='Welcome page, tells about this app'
        path={paths.about}
        onClick={onItemClick}
      />
      {showInstallButton && (
        <SideBarMenuItem
          icon={<FaCirclePlus />}
          label='Install App'
          helper='Install app to desktop'
          path={constructOpenURL(subject ?? window.location.href)}
          onClick={install}
        />
      )}
      <DemoExitMenuItem onItemClick={onItemClick} />
    </AppMenuSection>
  );
}

const AppMenuSection = styled.section`
  box-sizing: border-box;
  width: 100%;
  min-width: 0;
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
