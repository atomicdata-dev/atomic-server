import { useEffect } from 'react';
import { dataBrowser, properties, useString } from '@tomic/react';
import { LoaderInline } from '../components/Loader';
import { useRightPanel } from '../components/RightPanel/RightPanelContext';
import { constructOpenURL } from '../helpers/navigation';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import type { ResourcePageProps } from './ResourcePage';

/**
 * A page of a chat log has nothing to show of its own: opening one (a copied
 * link to a message points at it) goes to the chat it belongs to, or to the
 * item it comments on with the comments open.
 */
export function ChatLogPage({ resource }: ResourcePageProps) {
  const [parent] = useString(resource, properties.parent);
  const [about] = useString(resource, dataBrowser.properties.about);
  const navigate = useNavigateWithTransition();
  const { setPanelOpen } = useRightPanel();
  const target = about ?? parent;

  useEffect(() => {
    if (!target) return;

    navigate(constructOpenURL(target));

    if (about) setPanelOpen('comments', true);
  }, [target, about, navigate, setPanelOpen]);

  return <LoaderInline>Opening the chat...</LoaderInline>;
}
