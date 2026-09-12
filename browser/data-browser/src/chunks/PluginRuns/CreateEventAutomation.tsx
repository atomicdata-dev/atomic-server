import { useState } from 'react';
import {
  dataBrowser,
  signRequest,
  useStore,
  ensureSchema,
  pluginSchema,
} from '@tomic/react';
import { Button } from '@components/Button';
import { Column } from '@components/Row';
import { BasicSelect } from '@components/forms/BasicSelect';
import { InputStyled, TextAreaStyled } from '@components/forms/InputStyles';
import { useAISidebar } from '@components/AI/AISidebarContext';
import { automationAssistantAsk } from './automationAssistant';
import { ResourceInline } from '../../views/ResourceInline/ResourceInline';
import { useNavigateWithTransition } from '@hooks/useNavigateWithTransition';
import { constructOpenURL } from '@helpers/navigation';
import { createPlugin } from './runScript';
import {
  eventAutomationSource,
  type IntegrationEvent,
} from './integrationAutomation';

/** No action-specific forms: behavior belongs to the script, not its trigger. */
export function CreateEventAutomation({
  drive,
  plugin,
  events,
}: {
  drive: string;
  plugin: string;
  events: IntegrationEvent[];
}) {
  const store = useStore();
  const { askAI } = useAISidebar();
  const [request, setRequest] = useState('');
  const navigate = useNavigateWithTransition();
  const [eventId, setEventId] = useState(events[0]?.id ?? '');
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  if (events.length === 0) return null;
  const selected = events.find(event => event.id === eventId);

  const create = async (withAssistant = false) => {
    if (!selected) return;
    setBusy(true);
    setError(undefined);

    try {
      const subject = await createPlugin(
        store,
        { drive, parent: drive },
        name.trim() || selected.name,
        eventAutomationSource(selected),
        {},
      );
      const script = await store.getResource(subject);
      const schema = await ensureSchema(store, drive, pluginSchema());
      await script.set(schema.properties['automation-integrations'], [plugin]);
      await script.set(schema.properties['automation-trigger'], {
        integration: plugin,
        event: selected.id,
        name: selected.name,
      });
      await script.set(dataBrowser.properties.emoji, '⚡');
      await script.save();
      const url = `${store.getServerUrl()}/plugin-trigger`;
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          ...(await signRequest(url, store.getAgent()!, {})),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          drive,
          plugin: subject,
          filters: selected.filters,
          onEnter: true,
          onLeave: false,
          autoApply: false,
        }),
      });
      if (!response.ok) throw new Error(await response.text());
      navigate(constructOpenURL(subject));
      if (withAssistant)
        askAI(automationAssistantAsk(request, subject, plugin, selected));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Column gap='0.75rem'>
        <h2>Automations</h2>
        <p>
          Let the Atomic assistant help build and test an automation. Your
          integration can keep syncing without one.
        </p>
        <ResourceInline subject={plugin} />
        <label htmlFor='integration-event'>Event</label>
        <BasicSelect
          id='integration-event'
          value={eventId}
          onChange={e => setEventId(e.target.value)}
          disabled={busy}
        >
          {events.map(event => (
            <option key={event.id} value={event.id}>
              {event.name}
            </option>
          ))}
        </BasicSelect>
        <p>{selected?.description}</p>
        <label htmlFor='automation-request'>
          What would you like to automate?
        </label>
        <TextAreaStyled
          id='automation-request'
          value={request}
          onChange={event => setRequest(event.target.value)}
          disabled={busy}
          placeholder='Describe what should happen and when.'
        />
        <Button
          disabled={busy || !selected || !request.trim()}
          onClick={() => create(true)}
        >
          {busy ? 'Creating automation…' : 'Build with Atomic assistant'}
        </Button>
      </Column>
      <details>
        <summary>Advanced: write JavaScript yourself</summary>
        <Column gap='0.75rem'>
          <label htmlFor='automation-name'>Automation name</label>
          <InputStyled
            id='automation-name'
            value={name}
            placeholder={selected?.name}
            onChange={event => setName(event.target.value)}
            disabled={busy}
          />
          <p>
            The next screen opens an editable JavaScript starter. Automatic
            execution stays off until you enable it.
          </p>
          <Button disabled={busy || !selected} onClick={() => create()}>
            {busy ? 'Creating automation…' : 'Create automation'}
          </Button>
        </Column>
      </details>
      {error && <p role='alert'>{error}</p>}
    </>
  );
}
