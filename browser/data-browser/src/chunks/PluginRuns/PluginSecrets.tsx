import { useCallback, useEffect, useState } from 'react';
import { styled } from 'styled-components';
import toast from 'react-hot-toast';
import { FaCheck, FaKey, FaTrash } from 'react-icons/fa6';
import {
  errorMessageFromResponse,
  signRequest,
  useStore,
  type DeclaredSecret,
} from '@tomic/react';
import { Button } from '@components/Button';
import { Column, Row } from '@components/Row';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { BasicSelect } from '@components/forms/BasicSelect';

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
  /** What the plugin's `manifest` export says it needs. */
  declared: DeclaredSecret[];
  /**
   * Names its source actually spends. A plugin that writes
   * `secret:x` without declaring it still needs `x`, and the author who forgot
   * is the one who cannot find where to enter it.
   */
  mentioned: string[];
  /** Origins its source requests, used when it did not declare one. */
  candidateOrigins: string[];
}

export function PluginSecrets({
  plugin,
  drive,
  declared,
  mentioned,
  candidateOrigins,
}: PluginSecretsProps): React.JSX.Element {
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

  // Undeclared but spent: offered anyway, asking for the origin the
  // declaration would have named.
  const undeclared = mentioned.filter(
    name => !declared.some(d => d.name === name),
  );

  // Stored but neither declared nor spent. Still shown: a credential nothing
  // mentions is exactly the one worth revoking.
  const orphans = (stored ?? []).filter(
    s => !declared.some(d => d.name === s.name) && !mentioned.includes(s.name),
  );

  const nothingToShow =
    declared.length === 0 && undeclared.length === 0 && orphans.length === 0;

  return (
    <Column gap='0.5rem'>
      <SectionTitle>
        <Row gap='0.5ch' center>
          <FaKey aria-hidden />
          Secrets
        </Row>
      </SectionTitle>

      {nothingToShow && (
        <Muted>
          This plugin asks for no credentials. To use one, have it declare what
          it needs —{' '}
          <code>
            export const manifest = {'{'} secrets: [{'{'} name, origin {'}'}]{' '}
            {'}'}
          </code>{' '}
          — or reference <code>secret:&lt;name&gt;</code> in a header and a slot
          will appear here.
        </Muted>
      )}

      {declared.map(secret => (
        <SecretSlot
          key={secret.name}
          secret={secret}
          stored={byName.get(secret.name)}
          onStore={value => store_(secret, value)}
          onRevoke={() => revoke(secret.name)}
        />
      ))}

      {undeclared.map(name => (
        <UndeclaredSlot
          key={name}
          name={name}
          candidateOrigins={candidateOrigins}
          stored={byName.get(name)}
          onStore={(value, origin) => store_({ name, origin }, value)}
          onRevoke={() => revoke(name)}
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

/**
 * A secret the source spends without declaring.
 *
 * Where it may be sent is read from the URLs the plugin requests, so the usual
 * case is one field — a value — with the origin stated rather than typed. It is
 * only a question when the source asks more than one origin, or builds its URLs
 * at runtime, and in both cases guessing would be worse than asking.
 */
function UndeclaredSlot({
  name,
  candidateOrigins,
  stored,
  onStore,
  onRevoke,
}: {
  name: string;
  candidateOrigins: string[];
  stored?: SecretInfo;
  onStore: (value: string, origin: string) => Promise<boolean>;
  onRevoke: () => void;
}): React.JSX.Element {
  const [value, setValue] = useState('');
  const [chosen, setChosen] = useState(candidateOrigins[0] ?? '');
  const [busy, setBusy] = useState(false);

  const only = candidateOrigins.length === 1 ? candidateOrigins[0] : undefined;
  const origin = only ?? chosen;

  const submit = useCallback(async () => {
    setBusy(true);
    const ok = await onStore(value, origin);
    setBusy(false);

    if (ok) setValue('');
  }, [onStore, value, origin]);

  return (
    <Slot>
      <Column gap='0.35rem'>
        <Row center justify='space-between'>
          <Column gap='0.1rem'>
            <strong>{name}</strong>
            <Muted>
              {only ? (
                <>
                  Used as <code>secret:{name}</code>, sent only to{' '}
                  <code>{only}</code>. Undeclared, so this was read from the
                  URLs it requests.
                </>
              ) : candidateOrigins.length > 1 ? (
                <>
                  Used as <code>secret:{name}</code>. This plugin requests
                  several origins — pick the one this credential belongs to.
                </>
              ) : (
                <>
                  Used as <code>secret:{name}</code>. Its URLs are built at run
                  time, so say which origin it may be sent to.
                </>
              )}
            </Muted>
          </Column>
          {stored && (
            <Row gap='0.5rem' center>
              <Stored>
                <FaCheck aria-hidden /> Stored
              </Stored>
              <Button subtle onClick={onRevoke} title={`Revoke ${name}`}>
                <FaTrash aria-hidden />
              </Button>
            </Row>
          )}
        </Row>

        {stored ? (
          <Muted>
            {stored.origins.join(', ')} — {describeUse(stored)}
          </Muted>
        ) : (
          <Row gap='0.5rem' center>
            <GrowingInput>
              <InputStyled
                type='password'
                autoComplete='off'
                placeholder={`Value for ${name}`}
                value={value}
                onChange={e => setValue(e.target.value)}
              />
            </GrowingInput>
            {candidateOrigins.length > 1 && (
              <BasicSelect
                value={chosen}
                onChange={e => setChosen(e.target.value)}
              >
                {candidateOrigins.map(candidate => (
                  <option key={candidate} value={candidate}>
                    {candidate}
                  </option>
                ))}
              </BasicSelect>
            )}
            {candidateOrigins.length === 0 && (
              <GrowingInput>
                <InputStyled
                  placeholder='https://api.example.com'
                  value={chosen}
                  onChange={e => setChosen(e.target.value)}
                />
              </GrowingInput>
            )}
            <Button
              disabled={value.length === 0 || origin.length === 0 || busy}
              onClick={submit}
            >
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
        error: errorMessageFromResponse(await response.text(), response.status),
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
