import { useCallback, useEffect, useState } from 'react';
import { styled } from 'styled-components';
import toast from 'react-hot-toast';
import { FaCheck, FaKey, FaTrash } from 'react-icons/fa6';
import { signRequest, useStore, type DeclaredSecret } from '@tomic/react';
import { Button } from '@components/Button';
import { Column, Row } from '@components/Row';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';

/**
 * The credentials a plugin asked for.
 *
 * Driven by the plugin's own declaration, so the name and origin are not typed
 * a second time into a form that nothing checks against the code. A slot says
 * which credential it wants and where it will be sent; you supply the value.
 *
 * The value is write-only everywhere, here included: once stored no request
 * returns it, so a filled slot shows only that it is filled and whether it has
 * ever been used.
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
  plugin: string;
  drive: string;
  /** What the plugin's source says it needs. */
  declared: DeclaredSecret[];
}

export function PluginSecrets({
  plugin,
  drive,
  declared,
}: PluginSecretsProps): React.JSX.Element | null {
  const store = useStore();
  const [stored, setStored] = useState<SecretInfo[]>();

  const endpoint = `${store.getServerUrl()}/plugin-secret`;
  const params = `drive=${encodeURIComponent(drive)}&plugin=${encodeURIComponent(plugin)}`;

  const load = useCallback(async () => {
    const result = await request(store, `${endpoint}?${params}`, {
      method: 'GET',
    });

    setStored(result.ok ? (result.body as SecretsView).secrets : []);
  }, [store, endpoint, params]);

  useEffect(() => {
    void load();
  }, [load]);

  const store_ = useCallback(
    async (secret: DeclaredSecret, value: string) => {
      const result = await request(store, endpoint, {
        method: 'POST',
        body: JSON.stringify({
          drive,
          plugin,
          name: secret.name,
          value,
          // From the declaration, so what is stored is what the plugin says it
          // needs — there is nothing to keep in sync.
          origins: [secret.origin],
        }),
      });

      if (!result.ok) {
        toast.error(result.error);

        return false;
      }

      setStored((result.body as SecretsView).secrets);
      toast.success(`Stored ${secret.name}`);

      return true;
    },
    [store, endpoint, drive, plugin],
  );

  const revoke = useCallback(
    async (name: string) => {
      const result = await request(
        store,
        `${endpoint}?${params}&name=${encodeURIComponent(name)}`,
        { method: 'DELETE' },
      );

      if (!result.ok) {
        toast.error(result.error);

        return;
      }

      setStored((result.body as SecretsView).secrets);
    },
    [store, endpoint, params],
  );

  const byName = new Map((stored ?? []).map(s => [s.name, s]));
  // Anything stored that the plugin no longer asks for. Still shown, because a
  // credential nobody mentions is exactly the one worth revoking.
  const orphans = (stored ?? []).filter(
    s => !declared.some(d => d.name === s.name),
  );

  if (declared.length === 0 && orphans.length === 0) return null;

  return (
    <Column gap='0.5rem'>
      <SectionTitle>
        <Row gap='0.5ch' center>
          <FaKey aria-hidden />
          Secrets
        </Row>
      </SectionTitle>

      {declared.map(secret => (
        <SecretSlot
          key={secret.name}
          secret={secret}
          stored={byName.get(secret.name)}
          onStore={value => store_(secret, value)}
          onRevoke={() => revoke(secret.name)}
        />
      ))}

      {orphans.map(secret => (
        <Slot key={secret.name}>
          <Row center justify='space-between'>
            <Column gap='0.1rem'>
              <strong>{secret.name}</strong>
              <Muted>
                No longer asked for by this plugin — {describeUse(secret)}
              </Muted>
            </Column>
            <Button subtle onClick={() => revoke(secret.name)}>
              <FaTrash aria-hidden /> Revoke
            </Button>
          </Row>
        </Slot>
      ))}
    </Column>
  );
}

function SecretSlot({
  secret,
  stored,
  onStore,
  onRevoke,
}: {
  secret: DeclaredSecret;
  stored?: SecretInfo;
  onStore: (value: string) => Promise<boolean>;
  onRevoke: () => void;
}): React.JSX.Element {
  const [value, setValue] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = useCallback(async () => {
    setBusy(true);
    const ok = await onStore(value);
    setBusy(false);

    // Cleared as soon as it is stored: there is nowhere to read it back from,
    // so leaving it on screen only risks it being seen.
    if (ok) setValue('');
  }, [onStore, value]);

  return (
    <Slot>
      <Column gap='0.35rem'>
        <Row center justify='space-between'>
          <Column gap='0.1rem'>
            <strong>{secret.description ?? secret.name}</strong>
            <Muted>
              Sent only to <code>{secret.origin}</code>. The plugin uses it as{' '}
              <code>secret:{secret.name}</code> and never sees the value.
            </Muted>
          </Column>
          {stored && (
            <Row gap='0.5rem' center>
              <Stored>
                <FaCheck aria-hidden /> Stored
              </Stored>
              <Button subtle onClick={onRevoke} title={`Revoke ${secret.name}`}>
                <FaTrash aria-hidden />
              </Button>
            </Row>
          )}
        </Row>

        {stored ? (
          <Muted>{describeUse(stored)}</Muted>
        ) : (
          <Row gap='0.5rem' center>
            <GrowingInput>
              <InputStyled
                type='password'
                autoComplete='off'
                placeholder={`Paste the value for ${secret.name}`}
                value={value}
                onChange={e => setValue(e.target.value)}
              />
            </GrowingInput>
            <Button disabled={value.length === 0 || busy} onClick={submit}>
              {busy ? 'Storing…' : 'Store'}
            </Button>
          </Row>
        )}
      </Column>
    </Slot>
  );
}

function describeUse(secret: SecretInfo): string {
  if (secret.useCount === 0) return 'never used';

  return `used ${secret.useCount} time${secret.useCount === 1 ? '' : 's'}, last ${new Date(
    secret.lastUsedAt!,
  ).toLocaleDateString()}`;
}

type RequestResult = { ok: true; body: unknown } | { ok: false; error: string };

/**
 * A signed request, shaped as a result rather than an exception: the React
 * Compiler cannot compile try/catch inside a component and every caller is one.
 */
async function request(
  store: ReturnType<typeof useStore>,
  url: string,
  init: RequestInit,
): Promise<RequestResult> {
  const agent = store.getAgent();

  if (!agent) return { ok: false, error: 'Not signed in' };

  try {
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

const SectionTitle = styled.h2`
  font-size: 1.1rem;
  margin: 0;
`;

const Muted = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.9rem;
`;

const Stored = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.9rem;
  white-space: nowrap;
`;

const Slot = styled.div`
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  padding: 0.75rem;
`;

const GrowingInput = styled(InputWrapper)`
  flex: 1;
`;
