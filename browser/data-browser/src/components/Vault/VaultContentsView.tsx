import { useEffect, useState } from 'react';
import { useStore } from '@tomic/react';
import { styled } from 'styled-components';
import { AtomicLink } from '../AtomicLink';
import { Button } from '../Button';
import { SizeMap } from '../SizeMap';
import { Row } from '../Row';
import { formatBytes } from '../../helpers/formatBytes';
import {
  inspectVaultContents,
  type VaultContents,
} from '../../helpers/managed/vaultContents';
import type { VaultEnrollment } from '../../helpers/managed/vault';

type Scan =
  | { status: 'idle' }
  | { status: 'reading'; done: number; total: number }
  | { status: 'error'; message: string }
  | { status: 'ready'; contents: VaultContents };

/** Reads encrypted copies, never imports them into the live workspace. */
export function VaultContentsView({
  enrollment,
  accountId,
}: {
  enrollment: VaultEnrollment;
  accountId: string;
}) {
  const store = useStore();
  const signer = store.getAgent();
  const [request, setRequest] = useState(0);
  const [scan, setScan] = useState<Scan>({ status: 'idle' });
  const [selected, setSelected] = useState<string | null>(null);
  useEffect(() => {
    if (!request || !signer) return;
    const controller = new AbortController();
    const { signal } = controller;
    void inspectVaultContents(
      enrollment,
      accountId,
      signer,
      signal,
      (done, total) => {
        if (!signal.aborted) setScan({ status: 'reading', done, total });
      },
    ).then(
      contents => {
        if (!signal.aborted) setScan({ status: 'ready', contents });
      },
      error => {
        if (!signal.aborted)
          setScan({
            status: 'error',
            message: error instanceof Error ? error.message : String(error),
          });
      },
    );

    return () => controller.abort();
  }, [request, signer, enrollment, accountId]);
  const contents = scan.status === 'ready' ? scan.contents : null;
  const current =
    contents?.items.find(item => item.id === selected) ?? contents?.items[0];

  return (
    <section aria-label='Backup contents'>
      <h3>What is inside this backup?</h3>
      <p>
        Inspect saved documents and file references on this device. This
        downloads the encrypted resource packs; attached file bodies are
        measured from the storage inventory.
      </p>
      <Row wrapItems>
        <Button
          disabled={!signer || scan.status === 'reading'}
          onClick={() => {
            setScan({ status: 'reading', done: 0, total: 0 });
            setSelected(null);
            setRequest(value => value + 1);
          }}
        >
          Inspect contents
        </Button>
        {scan.status === 'reading' && (
          <Button
            subtle
            onClick={() => {
              setRequest(0);
              setScan({ status: 'idle' });
            }}
          >
            Stop inspection
          </Button>
        )}
      </Row>
      {!signer && <p>Unlock your identity to inspect encrypted contents.</p>}
      {scan.status === 'reading' && (
        <p role='status'>
          Inspecting {scan.done} of {scan.total} backup objects…
        </p>
      )}
      {scan.status === 'error' && <p role='alert'>{scan.message}</p>}
      {contents && (
        <>
          <h3>
            {formatBytes(contents.storedBytes)} in {contents.objects} stored
            objects
          </h3>
          <p>
            Each tile counts actual bytes in retained copies: Loro updates plus
            signed commit records for a document, or stored file bytes. Repeated
            copies count each time. Shared format and encryption bytes are shown
            separately.
          </p>
          <p>
            Names and file references come from saved copies. This is not a list
            of currently live items, and the sizes are not estimates of what
            deleting an item would free.
          </p>
          {contents.unreadable > 0 && (
            <p role='status'>
              {contents.unreadable} objects could not be inspected. Their full
              sizes remain visible as unreadable objects.
            </p>
          )}
          <SizeMap
            testId='vault-contents'
            onSelect={id => setSelected(id)}
            items={contents.items.map(item => ({
              id: item.id,
              value: item.id,
              label: item.name,
              bytes: item.bytes,
              colour:
                item.kind === 'file'
                  ? '#1f9d8a'
                  : item.kind === 'resource'
                    ? '#3b6fe0'
                    : '#7b4fd6',
            }))}
          />
          {current && (
            <Selected aria-label='Selected backup item'>
              <h4>
                {current.name} · {formatBytes(current.bytes)}
              </h4>
              {current.kind === 'resource' && (
                <p>
                  {current.copies} saved entries ·{' '}
                  {formatBytes(current.updateBytes)} Loro updates ·{' '}
                  {formatBytes(current.envelopeBytes)} signed commit records
                </p>
              )}
              {current.error && <p>{current.error}</p>}
              {current.subjects.map(subject => (
                <p key={subject}>
                  <AtomicLink subject={subject}>
                    Open item in workspace
                  </AtomicLink>
                </p>
              ))}
              {current.subjects.length > 0 && (
                <p>
                  Use the item’s menu to delete the document or file. That
                  deletion syncs to other devices. Its saved copies stay in the
                  backup until the retention policy or backup cleanup removes
                  them.
                </p>
              )}
            </Selected>
          )}
          <details>
            <summary>All items by size</summary>
            <ItemList>
              {contents.items.map(item => (
                <li key={item.id}>
                  <button type='button' onClick={() => setSelected(item.id)}>
                    {item.name} · {formatBytes(item.bytes)}
                  </button>
                </li>
              ))}
            </ItemList>
          </details>
        </>
      )}
    </section>
  );
}

const Selected = styled.section`
  margin: 1rem 0;
  padding: 1rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  overflow-wrap: anywhere;
`;
const ItemList = styled.ul`
  button {
    color: ${p => p.theme.colors.main};
    background: transparent;
    border: 0;
    text-align: start;
    cursor: pointer;
    font: inherit;
    overflow-wrap: anywhere;
  }
`;
