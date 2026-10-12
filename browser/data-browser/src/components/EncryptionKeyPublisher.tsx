import { useEffect } from 'react';
import { RequestCancelledError, useStore } from '@tomic/react';
import { useSettings } from '../helpers/AppSettings';
import { ensureEncryptionKey } from '../helpers/conversations/conversations';

/**
 * Publishes the signed-in agent's `encryptionKey` once per session, so others
 * can start an encrypted conversation with them. Renders nothing. Someone who
 * never opens the app has no key, and the app says so to whoever tries to
 * message them.
 */
export function EncryptionKeyPublisher() {
  const store = useStore();
  const { agent } = useSettings();

  useEffect(() => {
    if (!agent?.subject || store.isLocalOnlySubject(agent.subject)) return;

    let cancelled = false;
    // Not on the boot path: the first screen needs the network more.
    const timer = setTimeout(() => {
      if (cancelled) return;
      ensureEncryptionKey(store, agent).catch(error => {
        // A cancelled request means the page, agent or drive changed under
        // us. The effect runs again for the new one; nothing failed.
        if (error instanceof RequestCancelledError) return;

        console.warn('Could not publish the encryption key:', error);
      });
    }, 2000);

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [store, agent]);

  return null;
}
