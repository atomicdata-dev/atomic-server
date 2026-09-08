import { useEffect, useState } from 'react';
import {
  findSchema,
  pluginSchema,
  useStore,
  type Resource,
} from '@tomic/react';
import { Card } from '@components/Card';
import { Column } from '@components/Row';
import { Button } from '@components/Button';
import { TextAreaStyled } from '@components/forms/InputStyles';
import { styled } from 'styled-components';
import { setPluginSource } from './runScript';
import { useAISidebar } from '@components/AI/AISidebarContext';
import { automationAssistantAsk } from './automationAssistant';

export function useAutomationTrigger(subject: string, drive: string) {
  const store = useStore();
  const [trigger, setTrigger] = useState<{
    event: string;
    name?: string;
    integration?: string;
  } | null>();
  useEffect(() => {
    let active = true;

    const load = async () => {
      const schema = await findSchema(store, drive, pluginSchema());
      const resource = await store.getResource(subject);
      const property = schema.properties?.['automation-trigger'];
      const raw = property ? resource.get(property) : undefined;
      const value = typeof raw === 'string' ? JSON.parse(raw) : raw;
      if (active)
        setTrigger(
          value && typeof value === 'object' && 'event' in value
            ? (value as { event: string; name?: string; integration?: string })
            : null,
        );
    };

    void load().catch(() => {
      if (active) setTrigger(null);
    });
    const unsubscribe = store.subscribe(
      subject,
      () => void load().catch(() => undefined),
    );

    return () => {
      active = false;
      unsubscribe();
    };
  }, [store, subject, drive]);

  return trigger;
}

export function AutomationWorkspace({
  resource,
  drive,
  source,
  eventName,
  integration,
  eventId,
  onTest,
}: {
  resource: Resource;
  drive: string;
  source?: string;
  eventName: string;
  integration?: string;
  eventId: string;
  onTest: () => void;
}) {
  const store = useStore();
  const { askAI } = useAISidebar();
  const [request, setRequest] = useState('');
  const [draft, setDraft] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const code = draft ?? source ?? '';

  const saveAndTest = async () => {
    setBusy(true);
    setError(undefined);

    try {
      await setPluginSource(store, resource.subject, drive, code);
      setDraft(undefined);
      onTest();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <Column gap='0.75rem'>
        <h2>Build with the Atomic assistant</h2>
        <p>When: {eventName}</p>
        <p>
          Describe the behavior you want. The assistant can update this
          automation and help test it before you enable it.
        </p>
        <label htmlFor='automation-refinement'>
          What would you like to change?
        </label>
        <TextAreaStyled
          id='automation-refinement'
          value={request}
          onChange={event => setRequest(event.target.value)}
        />
        <Button
          disabled={
            !integration ||
            !request.trim() ||
            busy ||
            (draft !== undefined && draft !== source)
          }
          onClick={() => {
            if (integration)
              askAI(
                automationAssistantAsk(request, resource.subject, integration, {
                  id: eventId,
                  name: eventName,
                  description:
                    /* @wc-ignore */
                    'Use the saved trigger and integration definition.',
                  filters: [],
                }),
              );
          }}
        >
          Ask Atomic assistant
        </Button>
        <details>
          <summary>View or edit JavaScript</summary>
          <Column gap='0.75rem'>
            <label htmlFor='automation-code'>Automation JavaScript</label>
            <Editor
              id='automation-code'
              spellCheck={false}
              value={code}
              onChange={e => setDraft(e.target.value)}
              disabled={source === undefined || busy}
            />
          </Column>
        </details>
        <h3>Test before enabling</h3>
        <p>
          Save your code and run it against a matching record. Review proposed
          changes before applying them. If no record matches, sync one first.
        </p>
        <Button
          disabled={source === undefined || busy || !code.trim()}
          onClick={saveAndTest}
        >
          {busy ? 'Saving…' : 'Save and test sample'}
        </Button>
        {error && <p role='alert'>{error}</p>}
      </Column>
    </Card>
  );
}

const Editor = styled(TextAreaStyled)`
  font-family: monospace;
  min-height: 24rem;
  width: 100%;
  resize: vertical;
  line-height: 1.5;
  border-color: ${p => p.theme.colors.bg2};
`;
