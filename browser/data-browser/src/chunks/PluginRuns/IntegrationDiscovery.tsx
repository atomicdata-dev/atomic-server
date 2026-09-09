import { lazy, Suspense } from 'react';
import { Card } from '@components/Card';
import { Column } from '@components/Row';
import { Button } from '@components/Button';
import { Dialog, useDialog } from '@components/Dialog';
import { IntegrationEvidence } from './IntegrationEvidence';

const NotionSetup = lazy(() =>
  import('./ConnectNotion').then(m => ({ default: m.ConnectNotion })),
);

const ClockifySetup = lazy(() =>
  import('./ConnectClockify').then(m => ({ default: m.ConnectClockify })),
);

const MT940Setup = lazy(() =>
  import('./ImportMT940').then(m => ({ default: m.ImportMT940 })),
);

export function bundledIntegrations() {
  return [
    {
      id: 'mt940' as const,
      name: 'Bank statements',
      icon: '🏦',
      description:
        'Import bank transactions from bunq and other MT940 exports.',
      capabilities:
        'Preview exact amounts, dates, account references and original descriptions in a Bank transactions table.',
      events: 'Upload a statement when you need it. No bank token required.',
      limitation:
        'MT940 files only, up to 500 transactions and 512 KB. No payment initiation or live bank sync. Bank-specific formats may need additional support.',
      keywords:
        'bank bunq banking finance accounting statement mt940 import swift',
    },
    {
      id: 'clockify' as const,
      name: 'Clockify',
      icon: '⏱️',
      description: 'Bring your completed work into the Time Tracker.',
      capabilities:
        'Import completed entries with project and person links, start/end times and billable flags.',
      events:
        'Review imports before applying them. This first version does not sync changes back.',
      limitation:
        'Your entries only; up to 31 days. No active timers, updates, deletions, tags, task links, rates or custom fields.',
      keywords: 'clockify time tracking timesheet projects billable import',
    },
    {
      id: 'notion' as const,
      name: 'Notion',
      icon: '📓',
      description: 'Work with your Notion database in Atomic.',
      capabilities:
        'Sync supported row fields, property names and table or board views.',
      events: 'Start automations from newly discovered rows.',
      limitation:
        'Formatted text, relations, formulas and filtered views need additional mappings.',
      keywords: 'notion database table board rows knowledge tasks automation',
    },
  ];
}

export function IntegrationDiscovery({
  entry,
  drive,
  workspace,
}: {
  entry: ReturnType<typeof bundledIntegrations>[number];
  drive?: string;
  workspace?: string;
}) {
  const [dialog, show, , isOpen] = useDialog();

  return (
    <Card data-integration={entry.id}>
      <Column gap='0.75rem'>
        <h2>
          <span aria-hidden>{entry.icon}</span> {entry.name}
        </h2>
        <p>{entry.description}</p>
        <p>{entry.capabilities}</p>
        <p>{entry.events}</p>
        <details>
          <summary>Supported scope</summary>
          <p>{entry.limitation}</p>
          <p>
            Experimental integration. Preview proposed changes before approving
            them.
          </p>
        </details>
        {workspace && (entry.id === 'notion' || entry.id === 'mt940') && (
          <p>This integration creates a new workspace for its imported data.</p>
        )}
        <IntegrationEvidence id={entry.id} />
        <Button disabled={!drive} onClick={show}>
          Set up connection
        </Button>
      </Column>
      <Dialog {...dialog} width='38rem'>
        <Dialog.Title>
          <h2>
            <span aria-hidden>{entry.icon}</span> {entry.name}
          </h2>
        </Dialog.Title>
        <Dialog.Content>
          <Suspense fallback={<p>Loading setup…</p>}>
            {isOpen &&
              drive &&
              (entry.id === 'mt940' ? (
                <MT940Setup drive={drive} />
              ) : entry.id === 'clockify' ? (
                <ClockifySetup drive={drive} workspace={workspace} />
              ) : (
                <NotionSetup drive={drive} />
              ))}
          </Suspense>
        </Dialog.Content>
      </Dialog>
    </Card>
  );
}
