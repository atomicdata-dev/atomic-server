import { useEffect, useId, useRef, useState } from 'react';
import { useCurrentAgent, useStore } from '@tomic/react';
import { validateSetupArguments, type SetupArguments } from '@tomic/lib';
import { Button } from '../Button';
import { Column } from '../Row';
import Field from '../forms/Field';
import { Input, ErrMessage } from '../forms/InputStyles';
import { Checkbox } from '../forms/Checkbox';
import { BasicSelect } from '../forms/BasicSelect';
import { ExternalLink } from '../ExternalLink';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';
import { constructOpenURL } from '../../helpers/navigation';
import { getAppSetup } from './registry';
import { setupError } from './setupError';
import type { SetupChoice } from './types';

interface AppSetupFormProps {
  app: string;
  drive: string;
  workspace?: string;
  initial?: SetupArguments;
  onConnected?: () => void;
}

/** Credentials and pending submissions belong to one account and destination. */
export function AppSetupForm(props: AppSetupFormProps) {
  const store = useStore();
  const [agent] = useCurrentAgent();
  const identity = JSON.stringify([
    store.getServerUrl(),
    agent?.subject,
    props.drive,
    props.app,
    props.workspace,
  ]);

  return <SetupFormSession key={identity} {...props} />;
}

function SetupFormSession({
  app,
  drive,
  workspace,
  initial = {},
  onConnected,
}: AppSetupFormProps) {
  const adapter = getAppSetup(app);
  const store = useStore();
  const [agent] = useCurrentAgent();
  const navigate = useNavigateWithTransition();
  const id = useId();
  const [args, setArgs] = useState<SetupArguments>(() => ({
    ...adapter.defaults?.(workspace),
    ...validateSetupArguments(adapter.declaration, initial, true),
  }));
  const [credential, setCredential] = useState('');
  const [choices, setChoices] = useState<Record<string, SetupChoice[]>>({});
  const [loading, setLoading] = useState(true);
  const [loadFailed, setLoadFailed] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [uncertain, setUncertain] = useState(false);
  const running = useRef(false);
  const session = useRef(0);
  const properties = adapter.declaration.inputSchema.properties;

  useEffect(() => {
    const current = ++session.current;
    setLoading(true);
    setLoadFailed(false);
    setError('');
    const lookups = [
      ...new Set(
        Object.values(properties).flatMap(f =>
          f['x-atomic'] ? [f['x-atomic'].lookup] : [],
        ),
      ),
    ];
    Promise.all(
      lookups.map(
        async key =>
          [key, await adapter.choices(key, { store, drive })] as const,
      ),
    )
      .then(entries => {
        if (current === session.current) {
          setChoices(Object.fromEntries(entries));
          setLoading(false);
        }
      })
      .catch(() => {
        if (current === session.current) {
          setLoadFailed(true);
          setError('Could not load setup choices. Close setup and try again.');
          setLoading(false);
        }
      });

    return () => {
      session.current++;
    };
  }, [adapter, store, drive, agent?.subject, properties]);

  const connect = async () => {
    if (running.current || loading || loadFailed || uncertain) return;
    let validated: SetupArguments;

    try {
      validated = validateSetupArguments(adapter.declaration, args);
      if (adapter.prepare) validated = adapter.prepare(validated);

      for (const [key, field] of Object.entries(properties)) {
        const lookup = field['x-atomic'];
        const value = validated[key];
        if (
          lookup &&
          value &&
          !choices[lookup.lookup]?.some(c => c.value === value)
        )
          throw new Error('Choose an available destination.');
      }

      if (adapter.credential && !credential.trim())
        throw new Error('Enter the credential to continue.');
    } catch (e) {
      setError(String(e));

      return;
    }

    running.current = true;
    setBusy(true);
    setError('');
    const current = session.current;
    let installationStarted = false;

    try {
      await adapter.preflight?.({ store, drive });
      if (current !== session.current) return;
      installationStarted = true;
      const result = await adapter.connect(validated, credential.trim(), {
        store,
        drive,
      });
      if (current !== session.current) return;
      setCredential('');
      onConnected?.();
      navigate(constructOpenURL(result.subject));
    } catch (e) {
      if (current !== session.current) return;
      // Existing installers may have created resources before an error. Never auto-retry.
      setCredential('');
      setUncertain(installationStarted);
      setError(
        installationStarted
          ? `${setupError(e, credential.trim())}. Setup did not finish. Check your integrations for a partially created connection before starting again.`
          : setupError(e, credential.trim()),
      );
    } finally {
      running.current = false;
      if (current === session.current) setBusy(false);
    }
  };

  return (
    <form
      onSubmit={e => {
        e.preventDefault();
        void connect();
      }}
    >
      <Column gap='1rem'>
        <p>{adapter.declaration.description}</p>
        {Object.entries(properties).map(([key, field]) => {
          const fieldId = `${id}-${key}`;
          const lookup = field['x-atomic'];

          return (
            <Field key={key} fieldId={fieldId} label={field.title ?? key}>
              {lookup ? (
                <BasicSelect
                  id={fieldId}
                  value={String(args[key] ?? '')}
                  disabled={busy || loading || uncertain}
                  onChange={e =>
                    setArgs(previous => ({
                      ...previous,
                      [key]: e.target.value,
                    }))
                  }
                >
                  <option value=''>
                    {loading
                      ? 'Loading…'
                      : (lookup.emptyLabel ?? 'Choose an option')}
                  </option>
                  {(choices[lookup.lookup] ?? []).map(choice => (
                    <option key={choice.value} value={choice.value}>
                      {choice.label}
                    </option>
                  ))}
                </BasicSelect>
              ) : field.type === 'boolean' ? (
                <Checkbox
                  id={fieldId}
                  checked={args[key] === true}
                  disabled={busy || uncertain}
                  onChange={value =>
                    setArgs(previous => ({
                      ...previous,
                      [key]: value,
                    }))
                  }
                />
              ) : (
                <Input
                  id={fieldId}
                  type={field.type === 'integer' ? 'number' : 'text'}
                  value={String(args[key] ?? '')}
                  disabled={busy || uncertain}
                  required={adapter.declaration.inputSchema.required?.includes(
                    key,
                  )}
                  onChange={e => {
                    const value = e.target.value;
                    setArgs(previous => ({
                      ...previous,
                      [key]: field.type === 'integer' ? Number(value) : value,
                    }));
                  }}
                />
              )}
              <small>{field.description}</small>
            </Field>
          );
        })}
        {adapter.credential && (
          <Field fieldId={`${id}-credential`} label={adapter.credential.label}>
            {adapter.credential.link && (
              <ExternalLink to={adapter.credential.link(args)}>
                {adapter.credential.linkLabel}
              </ExternalLink>
            )}
            <Input
              id={`${id}-credential`}
              type='password'
              autoComplete='off'
              value={credential}
              disabled={busy || uncertain}
              required
              onChange={e => setCredential(e.target.value)}
            />
            <small>{adapter.credential.description}</small>
          </Field>
        )}
        {error && <ErrMessage role='alert'>{error}</ErrMessage>}
        <Button
          type='submit'
          disabled={busy || loading || uncertain || loadFailed}
          loading={busy ? 'Connecting…' : undefined}
        >
          {busy ? 'Connecting…' : adapter.declaration.title}
        </Button>
      </Column>
    </form>
  );
}
