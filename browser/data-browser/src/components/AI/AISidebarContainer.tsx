import React, { Suspense, useEffect, useState } from 'react';
import { useAISidebar } from './AISidebarContext';
import { ChatLoadingIndicator } from './ChatLoadingIndicator';
import { RightPanel } from '../RightPanel/RightPanel';

const AISidebar = React.lazy(() => import('@chunks/AI/AISidebar'));

export const AISidebarContainer: React.FC = () => {
  const { isOpen } = useAISidebar();
  // Unmounting on close threw away the conversation: the chat's messages are
  // component state, and a chat is only re-found afterwards if you happen to be
  // on the resource it was started about. Mount on first open and keep it —
  // the panel hides it with width and overflow, so nothing renders anyway.
  const [everOpened, setEverOpened] = useState(isOpen);

  useEffect(() => {
    if (isOpen) setEverOpened(true);
  }, [isOpen]);

  return (
    <RightPanel isOpen={isOpen} testId='ai-sidebar'>
      <Suspense fallback={<ChatLoadingIndicator />}>
        {everOpened && <AISidebar />}
      </Suspense>
    </RightPanel>
  );
};
