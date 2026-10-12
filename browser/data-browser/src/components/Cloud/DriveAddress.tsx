import { useEffect, useState, type FormEvent } from 'react';
import { styled } from 'styled-components';
import { Button } from '../Button';
import { CARD_ACTIONS_GAP, CARD_SUB_FONT } from '../cardSurface';
import { openExternal } from '../../helpers/openExternal';
import { isRunningInTauri } from '../../helpers/tauri';
import {
  checkAliasAvailability,
  listAliases,
  releaseAlias,
  renameAlias,
  reserveAlias,
  type AliasAvailability,
  type DomainAlias,
} from '../../helpers/managed/aliases';

/**
 * A workspace's public web address, such as `ontola.atomic.place`.
 *
 * Mirrors the account portal's drive address: a debounced availability check
 * while typing (the portal owns the reserved and taken names), a confirmation
 * before releasing, and "Setting up" while a reserved name is not routing yet.
 * Renders nothing until the list has loaded, and nothing when the portal has
 * no address routes: a missing feature is not an error worth showing.
 */
export function DriveAddress({ drive }: { drive: string }) {
  const [alias, setAlias] = useState<DomainAlias | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [editing, setEditing] = useState(false);
  const [label, setLabel] = useState('');
  const [check, setCheck] = useState<AliasAvailability | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  // The fixed part of the address (`.atomic.place`). The portal renders it, so
  // this is the only place the namespace is known; remembered because the
  // check result is gone while someone is editing their name.
  // Until the portal answers, assume the hosted namespace, so the field reads
  // as the address it will become.
  const [suffix, setSuffix] = useState('.atomic.place');
  const inputId = 'drive-address-input';

  useEffect(() => {
    const controller = new AbortController();

    listAliases(controller.signal)
      .then(all => {
        if (!controller.signal.aborted) {
          const mine = all.find(a => a.drive_subject === drive) ?? null;

          setAlias(mine);
          if (mine) setSuffix(mine.host.slice(mine.label.length));
          setLoaded(true);
        }
      })
      // Unreachable, signed out, or no such route yet: show nothing.
      .catch(() => undefined);

    return () => controller.abort();
  }, [drive]);

  // Either nothing is held yet, or the holder asked to change it.
  const picking = !alias || editing;

  // Debounced, and checked by the portal, which owns the reserved and taken
  // names. A copy in the client would drift.
  useEffect(() => {
    const wanted = label.trim();

    if (!picking || !wanted) return;

    const controller = new AbortController();
    const timer = setTimeout(() => {
      checkAliasAvailability(wanted, controller.signal)
        .then(result => {
          if (!controller.signal.aborted) {
            setCheck(result);
            setSuffix(result.host.slice(result.label.length));
          }
        })
        .catch(() => {
          if (!controller.signal.aborted) setCheck(null);
        });
    }, 300);

    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [label, picking]);

  async function submit(event: FormEvent) {
    event.preventDefault();

    const wanted = label.trim();

    if (!wanted || busy) return;

    setBusy(true);
    setError('');

    try {
      const next = alias
        ? await renameAlias(alias.label, wanted)
        : await reserveAlias(wanted, drive);

      setAlias(next);
      setSuffix(next.host.slice(next.label.length));
      setEditing(false);
      setLabel('');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not save that address.');
    }

    setBusy(false);
  }

  async function release() {
    if (!alias) return;

    if (
      !window.confirm(
        `Release ${alias.host}? Links to it stop working, and the name becomes available for anyone else to take.`,
      )
    ) {
      return;
    }

    setBusy(true);
    setError('');

    try {
      await releaseAlias(alias.label);
      setAlias(null);
      setEditing(false);
    } catch (e) {
      setError(
        e instanceof Error ? e.message : 'Could not release that address.',
      );
    }

    setBusy(false);
  }

  function startEditing() {
    setLabel(alias?.label ?? '');
    setError('');
    setEditing(true);
  }

  function stopEditing() {
    setEditing(false);
    setLabel('');
    setError('');
  }

  if (!loaded) return null;

  // Only the answer for what is in the box now; an older one is stale.
  const current =
    check && check.label.toLowerCase() === label.trim().toLowerCase()
      ? check
      : null;
  const canSubmit = !busy && !!label.trim() && (current?.available ?? false);
  const url = alias ? `https://${alias.host}` : '';
  const hint = !label.trim()
    ? ''
    : current
      ? current.available
        ? 'Available.'
        : (current.reason ?? 'Not available.')
      : 'Checking…';

  return (
    <Wrapper data-testid='drive-address'>
      {!picking && alias && (
        <>
          <Current>
            <Label>Web address</Label>
            <a
              data-testid='drive-address-link'
              href={url}
              target={isRunningInTauri() ? undefined : '_blank'}
              rel='noreferrer'
              onClick={e => {
                e.preventDefault();
                void openExternal(url);
              }}
            >
              {alias.host}
            </a>
            {!alias.applied_at && (
              <Muted data-testid='drive-address-pending'>Setting up</Muted>
            )}
            <Button subtle onClick={startEditing} disabled={busy}>
              Change address
            </Button>
            <Button subtle onClick={release} disabled={busy}>
              Release
            </Button>
          </Current>
        </>
      )}

      {picking && (
        <form onSubmit={submit}>
          <Label as='label' htmlFor={inputId}>
            {alias ? 'New web address' : 'Web address'}
          </Label>
          <InputRow>
            <Field>
              <Input
                id={inputId}
                value={label}
                onChange={e => setLabel(e.target.value)}
                autoCapitalize='none'
                autoCorrect='off'
                spellCheck={false}
                placeholder='name'
                aria-describedby={`${inputId}-status`}
                disabled={busy}
              />
              <Suffix aria-hidden>{suffix}</Suffix>
            </Field>
            <Button type='submit' disabled={!canSubmit}>
              {busy ? 'Saving…' : alias ? 'Change' : 'Claim'}
            </Button>
            {alias && (
              <Button subtle onClick={stopEditing} disabled={busy}>
                Cancel
              </Button>
            )}
          </InputRow>
          {hint && (
            <Hint
              id={`${inputId}-status`}
              role='status'
              $bad={!!current && !current.available}
            >
              {hint}
            </Hint>
          )}
          {error && (
            <Hint role='alert' $bad>
              {error}
            </Hint>
          )}
        </form>
      )}
    </Wrapper>
  );
}

const Wrapper = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
  min-width: 0;
  font-size: ${CARD_SUB_FONT};

  form {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 0.35rem;
  }
`;

const Current = styled.div`
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.25rem 0.6rem;
  min-width: 0;

  a {
    color: ${p => p.theme.colors.main};
    overflow-wrap: anywhere;
  }
`;

const Label = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: ${CARD_SUB_FONT};
`;

const Muted = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: ${CARD_SUB_FONT};
`;

const InputRow = styled.div`
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: ${CARD_ACTIONS_GAP};
  min-width: 0;
`;

// One box reading as the whole address: the name is typed, the namespace is
// fixed text after it.
const Field = styled.div`
  display: flex;
  align-items: center;
  min-width: 0;
  max-width: 20rem;
  flex: 1 1 12rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  background: ${p => p.theme.colors.bg};
  padding-right: 0.6rem;

  &:focus-within {
    border-color: ${p => p.theme.colors.main};
  }
`;

const Input = styled.input`
  flex: 1;
  min-width: 3rem;
  border: none;
  outline: none;
  padding: 0.4rem 0 0.4rem 0.6rem;
  font-size: ${CARD_SUB_FONT};
  background: transparent;
  color: ${p => p.theme.colors.text};
  text-align: right;
`;

const Suffix = styled.span`
  color: ${p => p.theme.colors.textLight};
  white-space: nowrap;
`;

const Hint = styled.p<{ $bad?: boolean }>`
  margin: 0;
  color: ${p => (p.$bad ? p.theme.colors.alert : p.theme.colors.textLight)};
  font-size: ${CARD_SUB_FONT};
`;
