import { Suspense, type ComponentType } from 'react';
import { Card } from '@components/Card';
import { Column } from '@components/Row';
import { Button } from '@components/Button';
import { Dialog, useDialog } from '@components/Dialog';
import { IntegrationEvidence } from './IntegrationEvidence';
import { integrationRegistry } from '@localthought/atomic-integrations';
import { ImportMT940 } from './ImportMT940';

const externalSetup = new Map(
  integrationRegistry.map(({ id, Component }) => [
    id,
    Component as ComponentType<{ drive: string; workspace?: string }>,
  ]),
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
    ...integrationRegistry.filter(
      entry => 'description' in entry,
    ),
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
        {workspace &&
          (('createsWorkspace' in entry && entry.createsWorkspace) ||
            entry.id === 'mt940') && (
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
            {isOpen && drive && entry.id === 'mt940' && (
              <ImportMT940 drive={drive} />
            )}
            {isOpen &&
              drive &&
              entry.id !== 'mt940' &&
              (() => {
                const Setup = externalSetup.get(entry.id);
                return Setup ? (
                  <Setup drive={drive} workspace={workspace} />
                ) : null;
              })()}
          </Suspense>
        </Dialog.Content>
      </Dialog>
    </Card>
  );
}
