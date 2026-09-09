import { WorkspaceLoading } from './WorkspaceLoading';
import { useEffect, useState } from 'react';
import { styled } from 'styled-components';
import { invoke } from '@tauri-apps/api/core';
import { useStore } from '@tomic/react';
import { Button } from '../../components/Button';
import { Column, Row } from '../../components/Row';
import { InputStyled } from '../../components/forms/InputStyles';
import { normalizeServerUrl } from '../../helpers/serverUrl';
import { fetchManagedInfo } from '../../helpers/managedServer';
import {
  reopenRestoredDrive,
  deviceHasDriveData,
} from '../../helpers/driveData';

const UNAUTHORIZED = 'Unauthorized';

interface WorkspacePeer {
  nodeId: string;
  name?: string;
}

/** Discovery inspects access; fetching requires the button below. */
export function DiscoverWorkspace({
  drive,
  onConnected,
}: {
  drive: string;
  onConnected: (drive: string) => void;
}) {
  const store = useStore();
  const [peer, setPeer] = useState<WorkspacePeer>();
  const [phase, setPhase] = useState<'searching' | 'ready' | 'fetching'>(
    'searching',
  );
  const [error, setError] = useState('');
  const [address, setAddress] = useState('');
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let cancelled = false;
    setPeer(undefined);
    setError('');
    setPhase('searching');
    void invoke<WorkspacePeer>('discover_workspace', { drive })
      .then(found => {
        if (!cancelled) {
          setPeer(found);
          setPhase('ready');
        }
      })
      .catch(e => {
        if (!cancelled) {
          setError(String(e));
          setPhase('ready');
        }
      });

    return () => {
      cancelled = true;
    };
  }, [drive, attempt]);

  async function findAtAddress() {
    const url = normalizeServerUrl(address);
    if (!url) return;
    setPhase('searching');
    setPeer(undefined);
    setError('');

    try {
      const info = await fetchManagedInfo(url);
      if (!info.nodeId)
        throw new Error('That address did not return a device pairing ID.');
      setPeer(
        await invoke<WorkspacePeer>('discover_workspace', {
          drive,
          nodeId: info.nodeId,
        }),
      );
    } catch (e) {
      setError(String(e));
    }

    setPhase('ready');
  }

  async function fetchWorkspace() {
    if (!peer) return;
    setPhase('fetching');
    setError('');

    try {
      await invoke('fetch_workspace', { drive, nodeId: peer.nodeId });

      if (!(await deviceHasDriveData(store, drive, { refresh: true }))) {
        throw new Error(
          'The connection finished, but your workspace is not available here yet.',
        );
      }

      await reopenRestoredDrive(store, drive);
      onConnected(drive);
    } catch (e) {
      setError(String(e));
      setPhase('ready');
    }
  }

  return phase === 'searching' || phase === 'fetching' ? (
    <WorkspaceLoading stage={phase === 'searching' ? 'discovery' : 'fetch'} />
  ) : (
    <Panel>
      <div role='status' aria-live='polite'>
        {peer ? (
          <>
            <h3>We found your workspace</h3>
            <p>
              <strong>{peer.name || peer.nodeId.slice(0, 12)}</strong>
            </p>
            <p>Fetch a copy to this device so you can open it here.</p>
          </>
        ) : (
          <p>We couldn’t find a reachable device with your workspace.</p>
        )}
      </div>
      {error && (
        <div role='alert'>
          <p>
            {error.includes(UNAUTHORIZED)
              ? 'A device was found, but this account cannot read the workspace there.'
              : 'We could not check your workspace. Try again or enter its address below.'}
          </p>
          <details>
            <summary>Connection details</summary>
            <p>{error}</p>
          </details>
        </div>
      )}
      {peer ? (
        <Button
          type='button'
          onClick={fetchWorkspace}
          disabled={phase !== 'ready'}
        >
          Fetch workspace
        </Button>
      ) : (
        <Button subtle onClick={() => setAttempt(n => n + 1)}>
          Search again
        </Button>
      )}
      <form
        onSubmit={e => {
          e.preventDefault();
          void findAtAddress();
        }}
      >
        <Column gap='0.5rem'>
          <label htmlFor='workspace-address'>
            Address where your workspace lives
          </label>
          <Row gap='0.5rem'>
            <InputStyled
              id='workspace-address'
              placeholder='your-server.example'
              value={address}
              onChange={e => setAddress(e.target.value)}
            />
            <Button
              type='submit'
              subtle
              disabled={!address.trim() || phase !== 'ready'}
            >
              Look here
            </Button>
          </Row>
        </Column>
      </form>
    </Panel>
  );
}

const Panel = styled.section`
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  font-size: 0.9rem;
  p,
  h3 {
    margin: 0;
  }
  h3 {
    font-size: 1rem;
  }
  details {
    color: ${p => p.theme.colors.textLight};
  }
  summary {
    cursor: pointer;
  }
  input {
    min-width: 0;
    width: 100%;
  }
`;
