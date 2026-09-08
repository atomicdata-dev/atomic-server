import { ActionActivity } from './ActionActivity';
import { useEffect, useState } from 'react';
import { useStore } from '@tomic/react';
import {
  listIntegrationActions,
  callIntegrationAction,
  integrationActionProposals,
  approveIntegrationAction,
  cancelIntegrationAction,
  type IntegrationTool,
  type ActionProposal,
} from '@tomic/lib';
import { Button } from '@components/Button';
import { Card } from '@components/Card';
import { Column } from '@components/Row';
import { BasicSelect } from '@components/forms/BasicSelect';
import { InputStyled } from '@components/forms/InputStyles';
import { styled } from 'styled-components';

export function IntegrationActions({
  drive,
  plugin,
}: {
  drive: string;
  plugin: string;
}) {
  const store = useStore();
  const [tools, setTools] = useState<IntegrationTool[]>([]);
  const [proposals, setProposals] = useState<ActionProposal[]>([]);
  const [action, setAction] = useState('');
  const [args, setArgs] = useState<Record<string, string>>({});
  const [result, setResult] = useState<string>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [completed, setCompleted] = useState<string[]>([]);
  const selected = tools.find(t => t.name === action);
  useEffect(() => {
    let active = true;

    const load = async () => {
      const [catalog, pending] = await Promise.all([
        listIntegrationActions(store, { drive, plugin }),
        integrationActionProposals(store, { drive, plugin }),
      ]);

      if (active) {
        setTools(catalog.tools);
        setProposals(pending);
      }
    };

    const refresh = () =>
      void load().catch(e => {
        if (active) setError(String(e));
      });
    refresh();
    const timer = setInterval(refresh, 5000);

    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [store, drive, plugin]);

  const invoke = async () => {
    if (!selected) return;
    setBusy(true);
    setError(undefined);
    setResult(undefined);

    try {
      const values: Record<string, unknown> = {};

      for (const [key, field] of Object.entries(
        selected.inputSchema.properties,
      )) {
        const value = args[key];
        if (
          value === undefined ||
          (value === '' && !selected.inputSchema.required?.includes(key))
        )
          continue;
        values[key] =
          field.type === 'integer'
            ? Number(value)
            : field.type === 'boolean'
              ? value === 'true'
              : value;
      }

      const response = await callIntegrationAction(
        store,
        { drive, plugin },
        action,
        values,
        crypto.randomUUID(),
      );
      if (response.status === 'needs_review')
        setProposals(previous => [
          ...previous.filter(p => p.id !== response.proposal.id),
          response.proposal,
        ]);
      else setResult(response.result.body);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const approve = async (id: string) => {
    setBusy(true);
    setError(undefined);

    try {
      const receipt = await approveIntegrationAction(
        store,
        { drive, plugin },
        id,
      );
      setCompleted(previous => [...previous, id]);
      setResult(receipt.body);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  if (!tools.length && !proposals.length)
    return error ? <p role='alert'>{error}</p> : null;

  return (
    <Column gap='0.75rem'>
      <h2>Actions</h2>
      <p>
        Use this integration once, without creating an automation. Writes wait
        for your review.
      </p>
      <label htmlFor='integration-action'>Action</label>
      <BasicSelect
        id='integration-action'
        value={action}
        onChange={e => {
          setAction(e.target.value);
          setArgs({});
        }}
        disabled={busy}
      >
        <option value=''>Choose an action</option>
        {tools.map(t => (
          <option key={t.name} value={t.name}>
            {t.title}
          </option>
        ))}
      </BasicSelect>
      <p>{selected?.description}</p>
      {selected &&
        Object.entries(selected.inputSchema.properties)
          .sort(
            ([a], [b]) =>
              Number(selected.inputSchema.required?.includes(b) ?? false) -
              Number(selected.inputSchema.required?.includes(a) ?? false),
          )
          .map(([key, field]) => (
            <Column key={key} gap='0.25rem'>
              <label htmlFor={`action-input-${key}`}>{key}</label>
              <p>{field.description}</p>
              {field.type === 'boolean' ? (
                <BasicSelect
                  id={`action-input-${key}`}
                  value={args[key] ?? ''}
                  onChange={e => setArgs({ ...args, [key]: e.target.value })}
                >
                  <option value=''>Choose a value</option>
                  <option value='true'>True</option>
                  <option value='false'>False</option>
                </BasicSelect>
              ) : (
                <InputStyled
                  id={`action-input-${key}`}
                  type={field.type === 'integer' ? 'number' : 'text'}
                  value={args[key] ?? ''}
                  onChange={e => setArgs({ ...args, [key]: e.target.value })}
                  disabled={busy}
                />
              )}
            </Column>
          ))}
      <Button disabled={busy || !selected} onClick={invoke}>
        {selected?.annotations.readOnlyHint
          ? 'Read from integration'
          : 'Prepare for review'}
      </Button>
      {proposals
        .filter(p => !completed.includes(p.id))
        .map(p => (
          <Card key={p.id}>
            <Column gap='0.5rem'>
              <h3>{p.title}</h3>
              <p>Destination: {p.intent.url}</p>
              <dl>
                {Object.entries(p.arguments).map(([name, value]) => (
                  <div key={name}>
                    <dt>{name}</dt>
                    <dd>{String(value)}</dd>
                  </div>
                ))}
              </dl>
              <details>
                <summary>Exact request</summary>
                <Output>
                  {p.intent.method} {p.intent.url}
                  {'\n'}
                  {p.intent.body}
                </Output>
              </details>
              <Button disabled={busy} onClick={() => approve(p.id)}>
                Approve action
              </Button>
              <Button
                disabled={busy}
                onClick={async () => {
                  try {
                    await cancelIntegrationAction(
                      store,
                      { drive, plugin },
                      p.id,
                    );
                    setProposals(previous =>
                      previous.filter(v => v.id !== p.id),
                    );
                  } catch (e) {
                    setError(String(e));
                  }
                }}
              >
                Cancel action
              </Button>
            </Column>
          </Card>
        ))}
      <ActionActivity drive={drive} plugin={plugin} tools={tools} />
      {result && (
        <details open>
          <summary>Result</summary>
          <Output>{result}</Output>
        </details>
      )}
      {error && <p role='alert'>{error}</p>}
    </Column>
  );
}

const Output = styled.pre`
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  max-height: 20rem;
  overflow: auto;
`;
