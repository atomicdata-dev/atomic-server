import { useEffect } from 'react';
import {
  isNotFound,
  isUnauthorized,
  StoreEvents,
  useStore,
  useResourceSnapshot,
} from '@tomic/react';
import { useRightPanel } from './RightPanelContext';
import type { RightPanelId } from './panelState';

/** A loading/offline resource may recover; a missing/inaccessible target cannot. */
export function panelTargetAvailable(subject?: string, error?: Error): boolean {
  return !!subject && !(error && (isNotFound(error) || isUnauthorized(error)));
}

export function useContextualPanel(
  panel: RightPanelId,
  subject?: string,
): boolean {
  const { activePanel, setPanelOpen } = useRightPanel();
  const store = useStore();
  const { error } = useResourceSnapshot(
    activePanel === panel ? subject : undefined,
  );
  const available = panelTargetAvailable(subject, error);
  useEffect(() => {
    if (activePanel === panel && !available) setPanelOpen(panel, false);
  }, [activePanel, available, panel, setPanelOpen]);
  useEffect(() => {
    if (activePanel !== panel || !subject) return;

    // Deletion evicts the resource; it need not produce a fetch/error snapshot.
    return store.on(StoreEvents.ResourceRemoved, removed => {
      if (store.normalizeSubject(removed) === store.normalizeSubject(subject)) {
        setPanelOpen(panel, false);
      }
    });
  }, [store, activePanel, panel, subject, setPanelOpen]);

  return activePanel === panel && available;
}
