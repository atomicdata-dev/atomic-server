import { useCallback, useEffect, useState } from 'react';
import { styled } from 'styled-components';
import toast from 'react-hot-toast';
import { FaKey, FaTrash } from 'react-icons/fa6';
import { signRequest, useStore, type Resource } from '@tomic/react';
import { Button } from '@components/Button';
import { Column, Row } from '@components/Row';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';

/**
 * Credentials a plugin may spend.
 *
 * The value is write-only everywhere, including here: once stored there is no
 * request that returns it, so this shows what a person needs in order to decide
 * whether to revoke — the origins it goes to, and whether it has ever been
 * used — and nothing else.
 */

interface SecretInfo {
  name: string;
  origins: string[];
  createdAt: number;
  lastUsedAt: number | null;
  useCount: number;
}

interface SecretsView {
  declaredOrigins: string[];
  secrets: SecretInfo[];
}

interface PluginSecretsProps {
  plugin: Resource;
  drive: string;
}

export function PluginSecrets({
  plugin,
  drive,
}: PluginSecretsProps): React.JSX.Element {
  const store = useStore();
  const [view, setView] = useState<SecretsView>();
  const [name, setName] = useState('');
  const [value, setValue] = useState('');
  const [busy, setBusy] = useState(false);

  const { subject } = plugin;
  const endpoint = `${store.getServerUrl()}/plugin-secret`;
  const params = `drive=${encodeURIComponent(drive)}&plugin=${encodeURIComponent(subject)}`;

  const secrets = view?.secrets;
  const declaredOrigins = view?.declaredOrigins;

  const load = useCallback(async () => {
    const result = await request(store, `${endpoint}?${params}`, {
      method: 'GET',
    });

    setView(
      result.ok
        ? (result.body as SecretsView)
        : { declaredOrigins: [], secrets: [] },
    );
  }, [store, endpoint, params]);

  useEffect(() => {
    void load();
  }, [load]);

  const add = useCallback(async () => {
    setBusy(true);

    const result = await request(store, endpoint, {
      method: 'POST',
      body: JSON.stringify({
        drive,
        plugin: subject,
        name,
        value,
        origins: declaredOrigins ?? [],
      }),
    });

    setBusy(false);

    if (!result.ok) {
      toast.error(result.error);

      return;
    }

    // Clear it from the page as soon as it is stored: there is nowhere to read
    // it back from, so leaving it in an input only risks it being seen.
    setName('');
    setValue('');
    setView(result.body as SecretsView);
    toast.success(`Stored ${name}`);
  }, [store, endpoint, drive, subject, name, value, declaredOrigins]);

  const remove = useCallback(
    async (secretName: string) => {
      const result = await request(
        store,
        `${endpoint}?${params}&name=${encodeURIComponent(secretName)}`,
        { method: 'DELETE' },
      );

      if (!result.ok) {
        toast.error(result.error);

        return;
      }

      setView(result.body as SecretsView);
    },
    [store, endpoint, params],
  );

  const originCount = declaredOrigins?.length ?? 0;
  const canAdd =
    name.length > 0 && value.length > 0 && originCount > 0 && !busy;

  return (
    <Column>
      <h3>
        <Row gap='0.5ch' center>
          <FaKey />
          Secrets
        </Row>
      </h3>

      {originCount === 0 ? (
        <Muted>
          This plugin declares no origins, so it cannot send a credential
          anywhere. Add <code>network.origins</code> to its manifest first.
        </Muted>
      ) : (
        <Muted>
          Sent only to {declaredOrigins?.join(', ')}. Stored on the server and
          never shown again — the plugin uses it as{' '}
          <code>secret:&lt;name&gt;</code> and never sees the value.
        </Muted>
      )}

      {secrets?.map(secret => (
        <SecretRow key={secret.name}>
          <Row center justify='space-between'>
            <Column gap='0.1rem'>
              <strong>{secret.name}</strong>
              <Muted>{describe(secret)}</Muted>
            </Column>
            <Button
              subtle
              title={`Revoke ${secret.name}`}
              onClick={() => remove(secret.name)}
            >
              <FaTrash />
            </Button>
          </Row>
        </SecretRow>
      ))}

      {secrets?.length === 0 && <Muted>No secrets stored.</Muted>}

      <Row gap='0.5rem' center>
        <InputWrapper>
          <InputStyled
            placeholder='name'
            value={name}
            onChange={e => setName(e.target.value)}
          />
        </InputWrapper>
        <InputWrapper>
          <InputStyled
            type='password'
            placeholder='value'
            autoComplete='off'
            value={value}
            onChange={e => setValue(e.target.value)}
          />
        </InputWrapper>
        <Button disabled={!canAdd} onClick={add}>
          {busy ? 'Storing…' : 'Store'}
        </Button>
      </Row>
    </Column>
  );
}

function describe(secret: SecretInfo): string {
  const used =
    secret.useCount === 0
      ? 'never used'
      : `used ${secret.useCount} time${secret.useCount === 1 ? '' : 's'}, last ${new Date(
          secret.lastUsedAt!,
        ).toLocaleDateString()}`;

  return `${secret.origins.join(', ')} — ${used}`;
}

type RequestResult = { ok: true; body: unknown } | { ok: false; error: string };

/**
 * A signed request to the secrets endpoint.
 *
 * Shaped as a result rather than an exception because the React Compiler cannot
 * compile try/catch inside a component, and every caller here is one.
 */
async function request(
  store: ReturnType<typeof useStore>,
  url: string,
  init: RequestInit,
): Promise<RequestResult> {
  const agent = store.getAgent();

  if (!agent) return { ok: false, error: 'Not signed in' };

  try {
    // The server checks write rights on the plugin, so the request has to say
    // who is asking.
    const headers = await signRequest(url, agent, {});
    const response = await fetch(url, {
      ...init,
      headers: { ...headers, 'Content-Type': 'application/json' },
    });

    if (!response.ok) {
      return {
        ok: false,
        error: `${response.status} ${await response.text()}`,
      };
    }

    return { ok: true, body: await response.json() };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

const Muted = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.9rem;
`;

const SecretRow = styled.div`
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  padding: 0.5rem;
`;
