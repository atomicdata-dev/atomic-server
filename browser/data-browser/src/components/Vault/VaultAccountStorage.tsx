import { useEffect, useState } from 'react';
import { Link } from '@tanstack/react-router';
import { styled } from 'styled-components';
import { Main } from '../Main';
import { SizeMap } from '../SizeMap';
import { VaultContentsView } from './VaultContentsView';
import { VaultStorage } from './VaultStorage';
import { requireStorageAccount } from '../../helpers/managed/vaultContents';
import { ContainerWide } from '../Containers';
import { Button } from '../Button';
import { Column, Row } from '../Row';
import { formatBytes } from '../../helpers/formatBytes';
import { paths } from '../../routes/paths';
import {
  onManagedLogout,
  onManagedSessionChanged,
} from '../../helpers/managed/session';
import {
  downloadVaultStorageReport,
  loadVaultStorageReport,
  workspaceBytes,
  type VaultStorageReport,
  type WorkspaceStorage,
} from '../../helpers/managed/vaultStorageReport';

type ReportState =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; report: VaultStorageReport };

/** Account-wide metadata inspection, separate from the current server's resource map. */
export function VaultAccountStorage() {
  const [state, setState] = useState<ReportState>({ status: 'loading' });
  const [refresh, setRefresh] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  useEffect(() => {
    let controller = new AbortController();

    const clear = () => {
      controller.abort();
      setState({ status: 'loading' });
      setSelected(null);
    };

    const load = () => {
      clear();
      controller = new AbortController();
      const { signal } = controller;
      void loadVaultStorageReport(signal).then(
        report => {
          if (!signal.aborted) setState({ status: 'ready', report });
        },
        error => {
          if (!signal.aborted)
            setState({
              status: 'error',
              message: error instanceof Error ? error.message : String(error),
            });
        },
      );
    };

    const visible = () => {
      if (document.visibilityState === 'visible') load();
    };

    const offLogout = onManagedLogout(() => {
      clear();
      setState({
        status: 'error',
        message: 'Sign in to your account to inspect Cloud Vault storage.',
      });
    });
    const offSession = onManagedSessionChanged(load);
    window.addEventListener('focus', load);
    document.addEventListener('visibilitychange', visible);
    load();

    return () => {
      controller.abort();
      offLogout();
      offSession();
      window.removeEventListener('focus', load);
      document.removeEventListener('visibilitychange', visible);
    };
  }, [refresh]);
  const report = state.status === 'ready' ? state.report : null;
  const current =
    report?.workspaces.find(row => row.enrollment.id === selected) ??
    report?.workspaces[0];

  return (
    <Main>
      <ContainerWide>
        <h1>Cloud Vault storage</h1>
        <p>
          Compare all workspaces backed up to your account. Each workspace has
          its own storage allowance.
        </p>
        <p>
          <Link to={paths.sync}>Back to sync settings</Link> ·{' '}
          <Link to={paths.storage} search={{}}>
            Current server storage
          </Link>
        </p>
        <Row wrapItems>
          <Button
            subtle
            onClick={() => setRefresh(value => value + 1)}
            disabled={state.status === 'loading'}
          >
            Refresh
          </Button>
          {report && (
            <Button subtle onClick={() => downloadVaultStorageReport(report)}>
              Download diagnostic report
            </Button>
          )}
        </Row>
        {state.status === 'loading' && (
          <p role='status'>Reading storage metadata…</p>
        )}
        {state.status === 'error' && <p role='alert'>{state.message}</p>}
        {report && (
          <>
            <p>{report.account}</p>
            <h2 data-testid='vault-account-total'>
              {formatBytes(report.total_bytes)} across{' '}
              {report.workspaces.length} workspaces
            </h2>
            <Muted>
              Encrypted backup objects, including retained copies and edit
              history. The server storage map measures a different copy of your
              data.
            </Muted>
            {report.workspaces.some(row => row.error) && (
              <p role='status'>
                Some details could not be read. Those workspaces keep their last
                listed usage in the total.
              </p>
            )}
            {report.workspaces.length === 0 && (
              <p>No workspaces are backed up to this account.</p>
            )}
            {report.total_bytes > 0 && (
              <SizeMap
                testId='vault-account'
                onSelect={id => setSelected(id)}
                items={report.workspaces.map((row, index) => ({
                  id: row.enrollment.id,
                  value: row.enrollment.id,
                  label:
                    row.enrollment.drive_name || row.enrollment.drive_subject,
                  bytes: workspaceBytes(row),
                  colour: ['#3b6fe0', '#7b4fd6', '#1f9d8a', '#d9822b'][
                    index % 4
                  ],
                }))}
              />
            )}
            <WorkspaceList aria-label='Workspace storage comparison'>
              {report.workspaces.map(row => (
                <li key={row.enrollment.id}>
                  <WorkspaceButton
                    type='button'
                    aria-pressed={current === row}
                    onClick={() => setSelected(row.enrollment.id)}
                  >
                    <Spread>
                      <strong>
                        {row.enrollment.drive_emoji}{' '}
                        {row.enrollment.drive_name ||
                          row.enrollment.drive_subject}
                      </strong>
                      <span>{formatBytes(workspaceBytes(row))}</span>
                    </Spread>
                    <Spread>
                      <span>
                        {row.enrollment.last_backup_at
                          ? `Last backup ${new Date(row.enrollment.last_backup_at * 1000).toLocaleString()}`
                          : 'No confirmed backup yet'}
                      </span>
                      <span>
                        {row.enrollment.status === 'suspended'
                          ? 'Paused'
                          : row.enrollment.status === 'active'
                            ? 'Active'
                            : row.enrollment.status}
                      </span>
                    </Spread>
                  </WorkspaceButton>
                </li>
              ))}
            </WorkspaceList>
            {current && (
              <WorkspaceDetails
                key={current.enrollment.id}
                row={current}
                accountId={report.accountId}
                onChanged={() => setRefresh(value => value + 1)}
              />
            )}
            <Muted>
              The diagnostic report includes workspace names, identifiers and
              object metadata; it contains no keys or download links. Content
              inspection decrypts saved copies locally and does not restore them
              into your workspace.
            </Muted>
          </>
        )}
      </ContainerWide>
    </Main>
  );
}

function WorkspaceDetails({
  row,
  accountId,
  onChanged,
}: {
  row: WorkspaceStorage;
  accountId: string;
  onChanged: () => void;
}) {
  const [showCleanup, setShowCleanup] = useState(false);
  const { enrollment, usage, objects } = row;
  const quota = usage?.quota_bytes ?? enrollment.quota_bytes;
  const largest = objects
    ?.toSorted((a, b) => b.size_bytes - a.size_bytes)
    .slice(0, 10);
  const confirmedBytes = objects?.reduce(
    (sum, object) => sum + object.size_bytes,
    0,
  );

  return (
    <DetailSection aria-label='Selected workspace storage'>
      <h2>{enrollment.drive_name || enrollment.drive_subject}</h2>
      <Muted>{enrollment.drive_subject}</Muted>
      <p>
        {quota > 0
          ? `${formatBytes(workspaceBytes(row))} of ${formatBytes(quota)} for this workspace`
          : `${formatBytes(workspaceBytes(row))} used · allowance unavailable`}
      </p>
      <VaultContentsView enrollment={enrollment} accountId={accountId} />
      <h3>Remove backup data</h3>
      <p>
        Backup cleanup removes copies that the current backup no longer needs.
        To remove a document or file from the workspace itself, open it from the
        contents map and use its existing delete action.
      </p>
      {showCleanup ? (
        <VaultStorage
          drivePseudonym={enrollment.drive_pseudonym}
          showAccountLink={false}
          beforeWrite={() => requireStorageAccount(accountId)}
          onClose={() => setShowCleanup(false)}
          onChanged={onChanged}
        />
      ) : (
        <Button subtle onClick={() => setShowCleanup(true)}>
          Manage backup storage
        </Button>
      )}
      {row.error && (
        <p role='status'>Some details are unavailable: {row.error}</p>
      )}
      {usage && (
        <Column>
          {usage.by_kind.map(category => (
            <Spread key={category.kind}>
              <span>
                {kindName(category.kind)} · {category.objects} objects
              </span>
              <strong>{formatBytes(category.bytes)}</strong>
            </Spread>
          ))}
          <Spread>
            <span>Uploads in progress</span>
            <span>{formatBytes(usage.pending_bytes)}</span>
          </Spread>
          <Spread>
            <span>Usage outside the object ledger</span>
            <span>{formatBytes(usage.unaccounted_bytes)}</span>
          </Spread>
          <p>
            {formatBytes(usage.reclaimable_bytes)} can be freed under the
            current retention policy. Another{' '}
            {formatBytes(usage.undo_window_bytes)} is retained for recovery of
            recent deletions. These amounts are part of the total above.
          </p>
        </Column>
      )}
      {objects && (
        <>
          <p>
            {objects.length} confirmed objects ·{' '}
            {formatBytes(confirmedBytes ?? 0)} in the listed inventory
          </p>
          <Muted>
            The list and usage are read separately; a backup or cleanup in
            progress can make their totals differ. Object metadata cannot
            establish which content is duplicated or no longer needed.
          </Muted>
          {largest && largest.length > 0 && (
            <details>
              <summary>Largest backup objects</summary>
              <ObjectList>
                {largest.map(object => (
                  <li key={object.object_id}>
                    <Spread>
                      <span>{kindName(object.kind)}</span>
                      <strong>{formatBytes(object.size_bytes)}</strong>
                    </Spread>
                    <Muted>{object.object_key}</Muted>
                  </li>
                ))}
              </ObjectList>
            </details>
          )}
        </>
      )}
      <Link to={paths.sync} search={{ drive: enrollment.drive_subject }}>
        Open this workspace’s sync settings
      </Link>
    </DetailSection>
  );
}

function kindName(kind: string) {
  switch (kind) {
    case 'pack':
      return 'Saved edits';
    case 'checkpoint':
    case 'checkpoint_image':
      return 'Snapshots';
    case 'blob':
      return 'Files and images';
    case 'index':
      return 'Search index';
    case 'dictionary':
      return 'Compression data';
    default:
      return kind;
  }
}

const Muted = styled.p`
  color: ${p => p.theme.colors.textLight};
  overflow-wrap: anywhere;
`;
const WorkspaceList = styled.ul`
  && {
    margin: 1rem 0;
    padding: 0;
    padding-inline-start: 0;
  }
  li {
    list-style: none;
    margin: 0;
  }
  display: grid;
  gap: 0.7rem;
`;
const Spread = styled.div`
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 0.5rem;
  overflow-wrap: anywhere;
`;
const WorkspaceButton = styled.button`
  width: 100%;
  text-align: start;
  padding: 0.9rem;
  cursor: pointer;
  color: ${p => p.theme.colors.text};
  background: ${p => p.theme.colors.bg};
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  font: inherit;
  &[aria-pressed='true'] {
    outline: 2px solid ${p => p.theme.colors.main};
  }
`;
const DetailSection = styled.section`
  padding: 0.5rem 0;
  margin: 1.5rem 0;
  overflow-wrap: anywhere;
`;
const ObjectList = styled.ol`
  padding-left: 1.5rem;
  li {
    margin: 0.75rem 0;
  }
`;
