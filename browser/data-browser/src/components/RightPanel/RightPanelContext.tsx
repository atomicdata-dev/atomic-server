import { useMediaQuery } from '../../hooks/useMediaQuery';
import { useSettings } from '../../helpers/AppSettings';
import { useMobilePanelHistory } from './useMobilePanelHistory';
import { RIGHT_PANEL_OVERLAY_BREAKPOINT } from './layout';
import React, {
  useCallback,
  useContext,
  createContext,
  useEffect,
  useLayoutEffect,
  useState,
} from 'react';

import {
  closePanelState,
  emptyPanelState,
  updatePanelState,
  type RightPanelId,
} from './panelState';

export type { RightPanelId } from './panelState';

/**
 * Manages which panel occupies the right side of the screen. Panels are
 * mutually exclusive: opening one closes the other.
 */
const RightPanelContext = createContext<{
  activePanel: RightPanelId | null;
  setPanelOpen: (
    panel: RightPanelId,
    action: React.SetStateAction<boolean>,
    /** Only for `comments`: the resource the panel is about. */
    commentSubject?: string,
  ) => void;
  togglePanel: (panel: RightPanelId) => void;
  closePanel: (panel: RightPanelId) => void;
  selectedMeeting: string | undefined;
  openMeetingPanel: (subject: string) => void;
  /** See `PanelState.commentSubject`: the resource the comments panel is
   *  about, or `undefined` when it is about the page itself. */
  commentSubject: string | undefined;
  /** Opens (or, for the thread already shown, closes) the comments panel for a
   *  resource inside the page, such as a table row. */
  toggleCommentsFor: (subject: string) => void;
  /** Aims the comments panel back at the page's own resource. */
  clearCommentTarget: () => void;
}>({
  activePanel: null,
  setPanelOpen: () => {},
  togglePanel: () => {},
  closePanel: () => {},
  selectedMeeting: undefined,
  openMeetingPanel: () => {},
  commentSubject: undefined,
  toggleCommentsFor: () => {},
  clearCommentTarget: () => {},
});

export const useRightPanel = () => useContext(RightPanelContext);

export const RightPanelProvider: React.FC<
  React.PropsWithChildren<{ scope: string }>
> = ({ children, scope }) => {
  // Open panels are transient context, not a browser preference. Persisting only
  // the panel ID resurrected empty meeting drawers after a new session.
  const [state, setState] = useState(() => emptyPanelState(scope));
  const current = state.scope === scope ? state : emptyPanelState(scope);
  if (state.scope !== scope) setState(current);
  const { activePanel, selectedMeeting, commentSubject } = current;
  const { setSideBarLocked } = useSettings();
  const overlay = useMediaQuery(
    `(max-width: ${RIGHT_PANEL_OVERLAY_BREAKPOINT - 1}px)`,
  );

  useLayoutEffect(() => {
    if (overlay && activePanel) setSideBarLocked(false);
  }, [overlay, activePanel, setSideBarLocked]);

  useEffect(() => {
    try {
      window.localStorage.removeItem('atomic.rightPanel.active');
    } catch {
      // Panel state also works when browser storage is unavailable.
    }
  }, []);

  const setPanelOpen = useCallback(
    (
      panel: RightPanelId,
      action: React.SetStateAction<boolean>,
      target?: string,
    ) => {
      setState(previous =>
        updatePanelState(previous, scope, panel, action, target),
      );
    },
    [scope],
  );

  const mobile = useMediaQuery('(max-width: 600px)', false);
  useMobilePanelHistory(mobile && activePanel === 'ai', () =>
    setPanelOpen('ai', false),
  );

  const togglePanel = useCallback(
    (panel: RightPanelId) => setPanelOpen(panel, open => !open),
    [setPanelOpen],
  );

  const closePanel = useCallback(
    (panel: RightPanelId) => {
      setState(previous => closePanelState(previous, scope, panel));
    },
    [scope],
  );

  const toggleCommentsFor = useCallback(
    (subject: string) => {
      setState(previous =>
        updatePanelState(previous, scope, 'comments', open => !open, subject),
      );
    },
    [scope],
  );

  const clearCommentTarget = useCallback(() => {
    setState(previous =>
      previous.scope === scope && previous.commentSubject !== undefined
        ? { ...previous, commentSubject: undefined }
        : previous,
    );
  }, [scope]);

  const openMeetingPanel = useCallback(
    (subject: string) => {
      setState(previous =>
        previous.scope === scope
          ? {
              scope,
              activePanel: 'followSession',
              selectedMeeting: subject,
            }
          : previous,
      );
    },
    [scope],
  );

  return (
    <RightPanelContext.Provider
      value={{
        activePanel,
        setPanelOpen,
        togglePanel,
        closePanel,
        selectedMeeting,
        openMeetingPanel,
        commentSubject,
        toggleCommentsFor,
        clearCommentTarget,
      }}
    >
      {children}
    </RightPanelContext.Provider>
  );
};
