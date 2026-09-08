import { Button } from '@components/Button';
import { useAISidebar } from '@components/AI/AISidebarContext';
import { newAutomationAssistantAsk } from './automationAssistant';

export function NewAutomation({
  drive,
  connections,
}: {
  drive: string;
  connections: string[];
}) {
  const { askAI } = useAISidebar();

  return (
    <Button
      onClick={() => askAI(newAutomationAssistantAsk(drive, connections))}
    >
      New automation
    </Button>
  );
}
