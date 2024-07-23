export enum Panel {
  Ontologies = 'ontologies',
}

import { useCallback, useMemo } from 'react';
import { useLocalStorage } from '../../hooks/useLocalStorage';

export const usePanelList = (): {
  enabledPanels: Set<Panel>;
  enablePanel: (panel: Panel) => void;
  disablePanel: (panel: Panel) => void;
} => {
  const [enabledPanels, setEnabledPanels] = useLocalStorage<Panel[]>(
    'sidebar-panels',
    [],
  );

  const enablePanel = useCallback(
    (panel: Panel) => {
      if (!enabledPanels.includes(panel)) {
        setEnabledPanels([...enabledPanels, panel]);
      }
    },
    [enabledPanels, setEnabledPanels],
  );

  const disablePanel = useCallback(
    (panel: Panel) => {
      if (enabledPanels.includes(panel)) {
        setEnabledPanels(enabledPanels.filter(p => p !== panel));
      }
    },
    [enabledPanels, setEnabledPanels],
  );

  const enabledPanelsSet = useMemo(
    () => new Set(enabledPanels),
    [enabledPanels],
  );

  return {
    enabledPanels: enabledPanelsSet,
    enablePanel,
    disablePanel,
  };
};
