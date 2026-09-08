import { ResourceInline } from '../../../views/ResourceInline/ResourceInline';
import { useEffect, useState } from 'react';
import { useStore } from '@tomic/react';
import {
  integrationActionProposals,
  approveIntegrationAction,
  cancelIntegrationAction,
  type ActionProposal,
} from '@tomic/lib';
import { Button } from '@components/Button';
import { Column, Row } from '@components/Row';

/** Re-fetch the host proposal: conversation text is never the approval payload. */
export function IntegrationActionReview({
  drive,
  plugin,
  id,
}: {
  drive: string;
  plugin: string;
  id: string;
}) {
  const store = useStore();
  const [proposal, setProposal] = useState<ActionProposal>();
  const [status, setStatus] = useState('Loading proposal…');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    setProposal(undefined);
    setStatus('Loading proposal…');
    setError('');
    integrationActionProposals(store, { drive, plugin })
      .then(items => {
        if (!active) return;
        setProposal(items.find(p => p.id === id && !p.archived));
        setStatus(
          'This proposal is no longer awaiting review. Check the integration history for its outcome.',
        );
      })
      .catch(e => {
        if (active) setError(String(e));
      });

    return () => {
      active = false;
    };
  }, [store, drive, plugin, id]);

  const act = async (approve: boolean) => {
    setBusy(true);
    setError('');

    try {
      if (approve) {
        const receipt = await approveIntegrationAction(
          store,
          { drive, plugin },
          id,
        );
        setStatus(JSON.stringify(receipt, null, 2));
      } else {
        await cancelIntegrationAction(store, { drive, plugin }, id);
        setStatus('Proposal cancelled.');
      }

      setProposal(undefined);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Column gap='0.75rem'>
      <ResourceInline subject={plugin} />
      {proposal ? (
        <>
          <h3>{proposal.title}</h3>
          <p>Review this external action before approving it.</p>
          <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
            {JSON.stringify(proposal.intent, null, 2)}
          </pre>
          <Row wrapItems>
            <Button disabled={busy} onClick={() => act(true)}>
              Approve action
            </Button>
            <Button subtle disabled={busy} onClick={() => act(false)}>
              Cancel action
            </Button>
          </Row>
        </>
      ) : (
        <pre style={{ whiteSpace: 'pre-wrap' }} aria-live='polite'>
          {status}
        </pre>
      )}
      {error && <p role='alert'>{error}</p>}
    </Column>
  );
}
