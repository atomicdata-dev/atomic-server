import { Button } from '@components/Button';
import { useAISidebar } from '@components/AI/AISidebarContext';
import { newAutomationAssistantAsk } from './automationAssistant';

export function NewAutomation({
  drive,
  connections,
  workspace,
  onStart,
}: {
  drive: string;
  connections: string[];
  workspace?: string;
  onStart?: () => void;
}) {
  const { askAI } = useAISidebar();

  return (
    <Button
      onClick={() => {
        onStart?.();
        askAI(newAutomationAssistantAsk(drive, connections, workspace));
      }}
    >
      New automation
    </Button>
  );
}
