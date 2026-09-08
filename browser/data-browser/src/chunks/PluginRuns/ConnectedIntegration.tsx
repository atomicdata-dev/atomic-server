import { Card } from '@components/Card';
import { Column } from '@components/Row';
import { Button } from '@components/Button';
import { useAISidebar } from '@components/AI/AISidebarContext';
import { newAutomationAssistantAsk } from './automationAssistant';
import { ResourceInline } from '../../views/ResourceInline/ResourceInline';
import { useIntegrationConnection } from './IntegrationConnection';

export function ConnectedIntegration({
  subject,
  drive,
}: {
  subject: string;
  drive: string;
}) {
  const definition = useIntegrationConnection(subject, drive);
  const { askAI } = useAISidebar();

  return (
    <Card data-connection={subject}>
      <Column gap='0.75rem'>
        <ResourceInline subject={subject} />
        {definition?.events.length ? (
          <Button
            subtle
            onClick={() => askAI(newAutomationAssistantAsk(drive, [subject]))}
          >
            Create automation
          </Button>
        ) : null}
      </Column>
    </Card>
  );
}
