import { useCallback, useMemo } from 'react';
import { useLocalStorage } from '../../hooks/useLocalStorage';

export enum Panel {
  Ontologies = 'ontologies',
  AIChats = 'aichats',
  Messages = 'messages',
  Favorites = 'favorites',
  SharedWithMe = 'sharedwithme',
}

/** Panels that start hidden and are switched on in settings. */
const OPT_IN: Panel[] = [Panel.Ontologies, Panel.AIChats];

/** Panels that are visible until someone hides them. */
const OPT_OUT: Panel[] = [Panel.Messages, Panel.Favorites, Panel.SharedWithMe];

export const usePanelList = (): {
  enabledPanels: Set<Panel>;
  enablePanel: (panel: Panel) => void;
  disablePanel: (panel: Panel) => void;
} => {
  // Opted-in panels (the original list, so existing preferences survive).
  const [optedIn, setOptedIn] = useLocalStorage<Panel[]>(
    'atomic.sidebar-panels',
    [Panel.AIChats],
  );
  // Panels the person hid; everything else in OPT_OUT shows.
  const [hidden, setHidden] = useLocalStorage<Panel[]>(
    'atomic.sidebar-hidden-panels',
    [],
  );

  const enablePanel = useCallback(
    (panel: Panel) => {
      if (OPT_OUT.includes(panel)) {
        setHidden(hidden.filter(p => p !== panel));
      } else if (!optedIn.includes(panel)) {
        setOptedIn([...optedIn, panel]);
      }
    },
    [optedIn, hidden, setOptedIn, setHidden],
  );

  const disablePanel = useCallback(
    (panel: Panel) => {
      if (OPT_OUT.includes(panel)) {
        if (!hidden.includes(panel)) setHidden([...hidden, panel]);
      } else if (optedIn.includes(panel)) {
        setOptedIn(optedIn.filter(p => p !== panel));
      }
    },
    [optedIn, hidden, setOptedIn, setHidden],
  );

  const enabledPanels = useMemo(
    () =>
      new Set<Panel>([
        ...optedIn.filter(p => OPT_IN.includes(p)),
        ...OPT_OUT.filter(p => !hidden.includes(p)),
      ]),
    [optedIn, hidden],
  );

  return { enabledPanels, enablePanel, disablePanel };
};
