import { useCallback, useSyncExternalStore } from 'react';
import { Agent, StoreEvents } from '@tomic/lib';
import { useStore } from './index.js';

/**
 * A hook for using and adjusting the Agent in the store.
 */
export const useCurrentAgent = (): [
  Agent | undefined,
  (agent?: Agent) => void,
] => {
  const store = useStore();

  const subscribe = useCallback(
    (callback: () => void) => store.on(StoreEvents.AgentChanged, callback),
    [store],
  );

  const agent = useSyncExternalStore(subscribe, store.getAgent);

  return [agent, store.setAgent];
};
