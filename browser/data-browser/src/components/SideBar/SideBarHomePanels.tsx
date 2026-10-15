import { core, urls } from '@tomic/react';
import type { JSX } from 'react';
import { useSettings } from '../../helpers/AppSettings';
import { usePrivateDriveList } from '../../hooks/usePrivateDriveList';
import { SideBarPanel } from './SideBarPanel';
import { SharedWithMeLink } from './SharedWithMeLink';
import { MessagesPanel } from './MessagesPanel';
import { Panel, usePanelList } from './usePanelList';

interface SideBarHomePanelsProps {
  onItemClick: () => void;
}

/**
 * The per-user "home index" panels — Messages, Favorites and Shared-with-me —
 * read from the user's PRIVATE DRIVE (see {@link usePrivateDriveList}). Rendered in the
 * sidebar's bottom-pinned area (above the account menu) rather than scrolling with
 * the active drive's tree, since they are cross-drive and not part of the
 * current drive's contents.
 */
export function SideBarHomePanels({
  onItemClick,
}: SideBarHomePanelsProps): JSX.Element | null {
  const { agent } = useSettings();
  const { enabledPanels } = usePanelList();
  const [favorites] = usePrivateDriveList(urls.properties.favorites);
  const [sharedWithMe] = usePrivateDriveList(core.properties.sharedWithMe);

  if (!agent) {
    return null;
  }

  return (
    <>
      {enabledPanels.has(Panel.Messages) && (
        <MessagesPanel onItemClick={onItemClick} />
      )}
      {enabledPanels.has(Panel.Favorites) && favorites.length > 0 && (
        <SideBarPanel
          title='Favorites'
          panel={Panel.Favorites}
          heightStorageKey='favoritesPanelHeight'
          data-testid='favorites'
        >
          {favorites.map((subject: string) => (
            <SharedWithMeLink
              key={subject}
              subject={subject}
              onClick={onItemClick}
              data-testid='favorite-item'
            />
          ))}
        </SideBarPanel>
      )}
      {enabledPanels.has(Panel.SharedWithMe) && sharedWithMe.length > 0 && (
        <SideBarPanel
          title='Shared with me'
          panel={Panel.SharedWithMe}
          heightStorageKey='sharedWithMePanelHeight'
          data-testid='shared-with-me'
        >
          {sharedWithMe.map((subject: string) => (
            <SharedWithMeLink
              key={subject}
              subject={subject}
              onClick={onItemClick}
              data-testid='shared-with-me-item'
            />
          ))}
        </SideBarPanel>
      )}
    </>
  );
}
