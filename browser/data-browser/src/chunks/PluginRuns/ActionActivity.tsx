import { ActionConsumers } from './ActionConsumers';
import { ActionHistoryCleanup } from './ActionHistoryCleanup';
import { useEffect, useState } from 'react';
import { useStore } from '@tomic/react';
import {
  findSchema,
  pluginSchema,
  readConnectionSubjects,
  integrationActionHistoryPage,
  integrationActionGrants,
  setIntegrationActionGrant,
  inspectActionRecovery,
  confirmActionRecovery,
  type ActionHistoryEntry,
  type ActionGrant,
  type IntegrationTool,
} from '@tomic/lib';
import { Button } from '@components/Button';
import { Card } from '@components/Card';
import { Column } from '@components/Row';
import { BasicSelect } from '@components/forms/BasicSelect';
import { InputStyled } from '@components/forms/InputStyles';
import { ResourceInline } from '../../views/ResourceInline/ResourceInline';

export function ActionActivity({
  drive,
  plugin,
  tools,
}: {
  drive: string;
  plugin: string;
  tools: IntegrationTool[];
}) {
  const store = useStore();
  const target = { drive, plugin };
  const [pageCount, setPageCount] = useState(1);
  const [hasMore, setHasMore] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [entries, setEntries] = useState<ActionHistoryEntry[]>([]);
  useEffect(() => {
    setPageCount(1);
    setEntries([]);
    setHasMore(false);
  }, [drive, plugin]);
  const [grants, setGrants] = useState<ActionGrant[]>([]);
  const [callers, setCallers] = useState<{ subject: string; name: string }[]>(
    [],
  );
  const [caller, setCaller] = useState('');
  const [action, setAction] = useState('');
  const [mode, setMode] = useState<'review' | 'automatic'>('review');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    let loading = false;

    const readHistory = async () => {
      const pageEntries: ActionHistoryEntry[] = [];
      let cursor: string | undefined;

      for (let page = 0; page < pageCount; page++) {
        const result = await integrationActionHistoryPage(
          store,
          target,
          cursor,
        );
        pageEntries.push(...result.entries);
        cursor = result.nextCursor ?? undefined;
        if (!cursor) break;
      }

      return { entries: pageEntries, hasMore: !!cursor };
    };

    const load = async () => {
      const [history, permissions] = await Promise.all([
        readHistory(),
        integrationActionGrants(store, target),
      ]);
      const schema = await findSchema(store, drive, pluginSchema());
      const property = schema.properties?.['automation-integrations'];
      const subjects = property
        ? await readConnectionSubjects(store, drive, property, plugin)
        : [];
      const resources = await Promise.all(
        subjects.map(async subject => {
          const r = await store.getResource(subject);

          return { subject, name: r.title };
        }),
      );

      if (active) {
        setEntries(history.entries);
        setHasMore(history.hasMore);
        setGrants(permissions);
        setCallers(resources);
      }
    };

    const refresh = () => {
      if (loading) return;
      loading = true;
      setLoadingHistory(true);
      void load()
        .catch(e => {
          if (active) setError(String(e));
        })
        .finally(() => {
          loading = false;
          if (active) setLoadingHistory(false);
        });
    };

    refresh();
    const timer = setInterval(refresh, 5000);

    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [store, drive, plugin, pageCount]);

  const grant = async (
    c: string,
    a: string,
    m: 'review' | 'automatic' | 'revoke',
  ) => {
    setBusy(true);
    setError(undefined);

    try {
      await setIntegrationActionGrant(store, target, c, a, m);
      setGrants(await integrationActionGrants(store, target));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Column gap='0.75rem'>
      <details>
        <summary>Action history</summary>
        <p>
          Actions are shown newest first. Uncertain writes stay here until you
          check their outcome.
        </p>
        <Column>
          {entries
            .filter(e => e.state !== 'pending' || e.proposal.origin)
            .map(entry => (
              <Card key={entry.proposal.id}>
                <Column gap='0.5rem'>
                  <h3>{entry.proposal.title}</h3>
                  <p>{stateLabel(entry.state)}</p>
                  <Column>
                    {entry.proposal.archived && (
                      <p>
                        Action details archived. This action ID remains
                        reserved.
                      </p>
                    )}
                  </Column>
                  <p>{new Date(entry.proposal.created_at).toLocaleString()}</p>
                  {entry.proposal.origin && (
                    <ResourceInline subject={entry.proposal.origin.caller} />
                  )}
                  <Column>
                    {entry.proposal.origin && (
                      <ActionConsumers
                        drive={drive}
                        plugin={plugin}
                        id={entry.proposal.id}
                      />
                    )}
                  </Column>
                  {Object.entries(entry.proposal.arguments).map(([k, v]) => (
                    <p key={k}>
                      {k}: {String(v)}
                    </p>
                  ))}
                  {entry.receipt && (
                    <details>
                      <summary>Provider result</summary>
                      <pre
                        style={{
                          whiteSpace: 'pre-wrap',
                          overflowWrap: 'anywhere',
                          maxHeight: '20rem',
                          overflow: 'auto',
                        }}
                      >
                        {entry.receipt.body}
                      </pre>
                    </details>
                  )}
                  {entry.resolution && (
                    <p>
                      Confirmed after checking the provider:{' '}
                      {entry.resolution.evidence}
                    </p>
                  )}
                  {entry.state === 'uncertain' && (
                    <RecoverAction
                      drive={drive}
                      plugin={plugin}
                      entry={entry}
                      tools={tools}
                      onResolved={() =>
                        setEntries(previous =>
                          previous.map(e =>
                            e.proposal.id === entry.proposal.id
                              ? { ...e, state: 'completed' }
                              : e,
                          ),
                        )
                      }
                    />
                  )}
                </Column>
              </Card>
            ))}
        </Column>
        <Column>
          {hasMore && (
            <Button
              disabled={loadingHistory}
              onClick={() => setPageCount(n => n + 1)}
            >
              Load more actions
            </Button>
          )}
        </Column>
        {!entries.some(e => e.state !== 'pending') && (
          <p>No completed actions yet.</p>
        )}
      </details>
      <ActionHistoryCleanup
        key={`${drive}/${plugin}`}
        drive={drive}
        plugin={plugin}
      />
      <details>
        <summary>Automation action permissions</summary>
        <p>
          Permissions apply to this connection, action and exact automation code
          for 30 days. Changes need a new review. Sync settings are independent.
        </p>
        <label htmlFor='action-caller'>Automation</label>
        <BasicSelect
          id='action-caller'
          value={caller}
          onChange={e => setCaller(e.target.value)}
        >
          <option value=''>Choose an automation</option>
          {callers.map(c => (
            <option key={c.subject} value={c.subject}>
              {c.name}
            </option>
          ))}
        </BasicSelect>
        <label htmlFor='grant-action'>Allowed action</label>
        <BasicSelect
          id='grant-action'
          value={action}
          onChange={e => setAction(e.target.value)}
        >
          <option value=''>Choose an action</option>
          {tools.map(t => (
            <option key={t.name} value={t.name}>
              {t.title}
            </option>
          ))}
        </BasicSelect>
        <label htmlFor='action-mode'>Write approval</label>
        <BasicSelect
          id='action-mode'
          value={mode}
          onChange={e => setMode(e.target.value as typeof mode)}
        >
          <option value='review'>Review each write</option>
          <option value='automatic'>Allow automatic writes</option>
        </BasicSelect>
        {mode === 'automatic' && (
          <p>
            This automation may send this action without asking each time, using
            the inputs its approved code supplies.
          </p>
        )}
        <Button
          disabled={busy || !caller || !action}
          onClick={() => grant(caller, action, mode)}
        >
          Save action permission
        </Button>
        {grants.map(g => (
          <Card key={`${g.origin.caller}:${g.action}`}>
            <ResourceInline subject={g.origin.caller} />
            <p>
              {g.action} —{' '}
              {g.mode === 'automatic'
                ? 'Automatic writes allowed'
                : 'Writes require review'}
            </p>
            <p>Expires: {new Date(g.expires_at).toLocaleString()}</p>
            <Button
              disabled={busy}
              onClick={() => grant(g.origin.caller, g.action, 'revoke')}
            >
              Revoke permission
            </Button>
          </Card>
        ))}
      </details>
      {error && <p role='alert'>{error}</p>}
    </Column>
  );
}

function stateLabel(state: ActionHistoryEntry['state']) {
  switch (state) {
    case 'completed':
      return 'Completed';
    case 'uncertain':
      return 'Outcome unknown — check the provider before continuing';
    case 'failed':
      return 'Provider returned an error — action was not retried';
    case 'cancelled':
      return 'Cancelled';
    case 'expired':
      return 'Review expired';
    case 'stale':
      return 'Connection changed — prepare a new action';
    default:
      return 'Waiting for review';
  }
}

function RecoverAction({
  drive,
  plugin,
  entry,
  tools,
  onResolved,
}: {
  drive: string;
  plugin: string;
  entry: ActionHistoryEntry;
  tools: IntegrationTool[];
  onResolved: () => void;
}) {
  const store = useStore();
  const [action, setAction] = useState('');
  const [args, setArgs] = useState<Record<string, string>>({});
  const [evidence, setEvidence] = useState('');
  const [result, setResult] = useState<string>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const selected = tools.find(t => t.name === action);
  const key = entry.proposal.id;

  const inspect = async () => {
    setBusy(true);
    setError(undefined);
    setResult(undefined);

    try {
      const values: Record<string, unknown> = {};

      for (const [name, field] of Object.entries(
        selected?.inputSchema.properties ?? {},
      )) {
        if (args[name] === undefined || args[name] === '') continue;
        values[name] =
          field.type === 'integer'
            ? Number(args[name])
            : field.type === 'boolean'
              ? args[name] === 'true'
              : args[name];
      }

      const candidate = await inspectActionRecovery(
        store,
        { drive, plugin },
        key,
        action,
        values,
        evidence,
      );
      setResult(candidate.receipt.body);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const confirm = async () => {
    setBusy(true);

    try {
      await confirmActionRecovery(store, { drive, plugin }, key);
      onResolved();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <details>
      <summary>Check and recover</summary>
      <Column gap='0.5rem'>
        <p>
          Find the created record in the connected app. Look it up below, then
          confirm only if it is the result of this action. This never sends the
          write again.
        </p>
        <label htmlFor={`recover-${key}`}>Provider lookup</label>
        <BasicSelect
          id={`recover-${key}`}
          value={action}
          onChange={e => {
            setAction(e.target.value);
            setArgs({});
            setResult(undefined);
          }}
        >
          <option value=''>Choose a read action</option>
          {tools
            .filter(t => t.annotations.readOnlyHint)
            .map(t => (
              <option key={t.name} value={t.name}>
                {t.title}
              </option>
            ))}
        </BasicSelect>
        <Column>
          {selected &&
            Object.entries(selected.inputSchema.properties).map(
              ([name, field]) => (
                <Column key={name}>
                  <label htmlFor={`recover-${key}-${name}`}>
                    {field.description}
                  </label>
                  <InputStyled
                    id={`recover-${key}-${name}`}
                    value={args[name] ?? ''}
                    onChange={e => {
                      setArgs({ ...args, [name]: e.target.value });
                      setResult(undefined);
                    }}
                  />
                </Column>
              ),
            )}
        </Column>
        <label htmlFor={`evidence-${key}`}>
          How does this record match the action?
        </label>
        <InputStyled
          id={`evidence-${key}`}
          value={evidence}
          onChange={e => {
            setEvidence(e.target.value);
            setResult(undefined);
          }}
        />
        <Button
          disabled={busy || !selected || !evidence.trim()}
          onClick={inspect}
        >
          Look up provider result
        </Button>
        {result && (
          <Column>
            <pre
              style={{
                whiteSpace: 'pre-wrap',
                maxHeight: '20rem',
                overflow: 'auto',
              }}
            >
              {result}
            </pre>
            <Button disabled={busy} onClick={confirm}>
              I verified this is the action result
            </Button>
          </Column>
        )}
        {error && <p role='alert'>{error}</p>}
      </Column>
    </details>
  );
}
