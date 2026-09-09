import { useEffect, useState } from 'react';
import { signRequest, useStore } from '@tomic/react';
import { Button } from '@components/Button';
import { Column, Row } from '@components/Row';
import { Card } from '@components/Card';
interface TriggerInfo {
  queuedEvents: number;
  query: { filters: Array<{ property: string; value: string | null }> };
  onEnter: boolean;
  onLeave: boolean;
  autoApply: unknown | null;
  pendingVerdict: string | null;
  lastError: string | null;
}

export function PluginTrigger({
  plugin,
  drive,
  onReview,
}: {
  plugin: string;
  drive: string;
  onReview: (verdict: string) => void;
}): React.JSX.Element | null {
  const store = useStore();
  const [trigger, setTrigger] = useState<TriggerInfo | null>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const endpoint = `${store.getServerUrl()}/plugin-trigger`;
  useEffect(() => {
    let active = true;

    const load = async () => {
      const url = `${endpoint}?drive=${encodeURIComponent(drive)}&plugin=${encodeURIComponent(plugin)}`;
      const response = await fetch(url, {
        headers: await signRequest(url, store.getAgent()!, {}),
      });
      if (!response.ok) throw new Error(await response.text());
      const result = await response.json();
      if (active) setTrigger(result);
    };

    const refresh = () =>
      void load().catch(e => {
        if (active) setError(String(e));
      });
    refresh();
    const timer = setInterval(refresh, 2000);

    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [store, endpoint, drive, plugin]);

  const update = async (enabled: boolean) => {
    if (!trigger) return;
    setBusy(true);
    setError(undefined);

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          ...(await signRequest(endpoint, store.getAgent()!, {})),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          drive,
          plugin,
          filters: trigger.query.filters.map(f => ({
            property: f.property,
            value: f.value,
          })),
          onEnter: trigger.onEnter,
          onLeave: trigger.onLeave,
          autoApply: enabled,
        }),
      });
      if (!response.ok) throw new Error(await response.text());
      setTrigger(await response.json());
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  if (!trigger) return error ? <Card role='alert'>{error}</Card> : null;

  return (
    <Column gap='0.5rem'>
      <h2>Automation</h2>
      {trigger.queuedEvents > 0 && (
        <p>
          {trigger.queuedEvents} events queued. They remain saved while waiting
          for review.
        </p>
      )}
      <p>
        {trigger.autoApply
          ? 'Runs automatically when matching records are added.'
          : 'Test a sample and review its changes, then enable automatic execution. Until then, the next event waits for review.'}
      </p>
      <Row gap='0.5rem'>
        {trigger.pendingVerdict && (
          <Button subtle onClick={() => onReview(trigger.pendingVerdict!)}>
            Review pending event
          </Button>
        )}
        <Button disabled={busy} onClick={() => update(!trigger.autoApply)}>
          {trigger.autoApply ? 'Require review' : 'Enable automatic execution'}
        </Button>
      </Row>
      {(error || trigger.lastError) && (
        <Card role='alert'>{error || trigger.lastError}</Card>
      )}
    </Column>
  );
}
