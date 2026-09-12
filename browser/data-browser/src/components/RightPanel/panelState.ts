export type RightPanelId = 'ai' | 'comments' | 'followSession';
export type PanelState = {
  scope: string;
  activePanel: RightPanelId | null;
  selectedMeeting?: string;
};
export const emptyPanelState = (scope: string): PanelState => ({
  scope,
  activePanel: null,
});

export function updatePanelState(
  previous: PanelState,
  scope: string,
  panel: RightPanelId,
  action: boolean | ((open: boolean) => boolean),
): PanelState {
  // Ignore callbacks from a meeting/account operation started in an old scope.
  if (previous.scope !== scope) return previous;
  const current = previous;
  const isOpen = current.activePanel === panel;
  const open = typeof action === 'function' ? action(isOpen) : action;
  const activePanel = open ? panel : isOpen ? null : current.activePanel;

  return {
    scope,
    activePanel,
    selectedMeeting:
      activePanel === 'followSession' ? current.selectedMeeting : undefined,
  };
}
