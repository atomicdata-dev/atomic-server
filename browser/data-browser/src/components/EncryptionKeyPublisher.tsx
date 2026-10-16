import { useEffect } from 'react';
import { useStore } from '@tomic/react';
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

    const publish = () => {
      if (cancelled) return;
      ensureEncryptionKey(store, agent).catch(error =>
        console.warn('Could not publish the encryption key:', error),
      );
    };

    // Not on the boot path: the first screen needs the network more. Offline
    // it would only fail on the chunks it imports, so wait for the network.
    const timer = setTimeout(() => {
      if (navigator.onLine === false) {
        window.addEventListener('online', publish, { once: true });
      } else {
        publish();
      }
    }, 2000);

    return () => {
      cancelled = true;
      clearTimeout(timer);
      window.removeEventListener('online', publish);
    };
  }, [store, agent]);

  return null;
}
