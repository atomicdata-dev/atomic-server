import React, { useCallback, useContext, useState, createContext } from 'react';

import type { AIMessageContext } from '../../chunks/AI/types';
import { useRightPanel } from '../RightPanel/RightPanelContext';

/**
 * A question to put to the assistant on someone else's behalf, from anywhere
 * in the app — "this app just threw, fix it" being the case it was built for.
 */
export interface AIAsk {
  /** Sent as the first message of a new chat. */
  prompt: string;
  /** Attached to it, so the assistant can read what the question is about. */
  context?: AIMessageContext[];
}

export const AISidebarContext = createContext<{
  isOpen: boolean;
  setIsOpen: React.Dispatch<React.SetStateAction<boolean>>;
  contextItems: AIMessageContext[];
  setContextItems: React.Dispatch<React.SetStateAction<AIMessageContext[]>>;
  /** Opens the panel on a new chat and asks. */
  askAI: (ask: AIAsk) => void;
  pendingAsk: AIAsk | undefined;
  clearPendingAsk: () => void;
}>({
  isOpen: false,
  setIsOpen: () => {},
  contextItems: [],
  setContextItems: () => {},
  askAI: () => {},
  pendingAsk: undefined,
  clearPendingAsk: () => {},
});

export const useAISidebar = () => {
  return useContext(AISidebarContext);
};

/**
 * Open state lives in the shared RightPanelContext so the AI sidebar and the
 * Comments panel are mutually exclusive. This provider keeps the boolean
 * isOpen/setIsOpen API the AI components already use.
 */
export const AISidebarContextProvider: React.FC<React.PropsWithChildren> = ({
  children,
}) => {
  const { activePanel, setPanelOpen } = useRightPanel();
  const isOpen = activePanel === 'ai';

  const setIsOpen = useCallback<React.Dispatch<React.SetStateAction<boolean>>>(
    action => setPanelOpen('ai', action),
    [setPanelOpen],
  );

  const [contextItems, setContextItems] = useState<AIMessageContext[]>([]);
  // Held here rather than delivered directly, because the sidebar may not be
  // mounted yet when the ask is made — the caller opens it in the same breath.
  const [pendingAsk, setPendingAsk] = useState<AIAsk>();

  const askAI = useCallback(
    (ask: AIAsk) => {
      setPendingAsk(ask);
      setPanelOpen('ai', true);
    },
    [setPanelOpen],
  );

  const clearPendingAsk = useCallback(() => setPendingAsk(undefined), []);

  return (
    <AISidebarContext.Provider
      value={{
        isOpen,
        setIsOpen,
        contextItems,
        setContextItems,
        askAI,
        pendingAsk,
        clearPendingAsk,
      }}
    >
      {children}
    </AISidebarContext.Provider>
  );
};

export function newContextItem<T extends AIMessageContext>(
  item: Omit<T, 'id'>,
): T {
  return {
    ...item,
    id: crypto.randomUUID() as string,
  } as T;
}
