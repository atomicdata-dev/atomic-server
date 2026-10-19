import { useCallback, useEffect, useId, useState } from 'react';
import { styled } from 'styled-components';
import { Button } from '../Button';
import { CARD_SUB_FONT } from '../cardSurface';
import { formatBytes } from '../../helpers/formatBytes';
import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useDialog,
} from '../Dialog';
import {
  ConfirmationDialog,
  ConfirmationDialogTheme,
} from '../ConfirmationDialog';
import { formatTimeAgo } from '../../helpers/formatTimeAgo';
import {
  type CompactResult,
  deleteVaultSnapshot,
  freeUpVaultStorage,
  getVaultUsage,
  removeVaultDeviceHistory,
  type VaultDeviceUsage,
  type VaultFreeUpResult,
  type VaultHistoryUsage,
  type VaultSnapshotUsage,
  type VaultUsage,
} from '../../helpers/managed/vault';

/**
 * What a drive's Cloud Vault storage is made of, and what can be freed.
 *
 * The host is blind, so the breakdown is by kind of object rather than by file
 * or note. Two amounts are kept apart on purpose: what is safe to free (old
 * history nothing needs) and what is only kept so a recent deletion can be
 * undone. The second is never freed without a separate, explicit choice.
 */
export function VaultStorage({
  drivePseudonym,
  onChanged,
  onClose,
  busy: parentBusy = false,
  suspended = false,
  onCompact,
  currentDevice = null,
}: {
  drivePseudonym: string;
  /** A backup, restore or other pass is running somewhere else in the row. */
  busy?: boolean;
  /** A suspended vault refuses new uploads, and compressing needs one. */
  suspended?: boolean;
  /**
   * Take a fresh full checkpoint, then free what it replaced. Resolves to null
   * when it failed; the host reports why.
   */
  onCompact?: (includeUndoWindow: boolean) => Promise<CompactResult | null>;
  /** This device's public key, to mark its row among the devices. */
  currentDevice?: string | null;
  /** Called after storage was freed, so the host can refresh its numbers. */
  onChanged?: () => void;
  /** Called once the dialog has closed. The row's "Manage storage" action opens it. */
  onClose: () => void;
}) {
  const titleId = useId();
  const [dialogProps, showDialog, close] = useDialog({
    bindShow: open => {
      if (!open) onClose();
    },
  });
  const [usage, setUsage] = useState<VaultUsage | null>(null);
  const [working, setWorking] = useState(false);
  const busy = working || parentBusy;
  const [confirmDiscard, setConfirmDiscard] = useState(false);
  const [removeDevice, setRemoveDevice] = useState<VaultDeviceUsage | null>(
    null,
  );
  const [deleteSnapshot, setDeleteSnapshot] =
    useState<VaultSnapshotUsage | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Reading can fail for reasons that are nobody's fault (the account does not
  // have this yet), so it is a muted note, not an error.
  const [readNote, setReadNote] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setUsage(await getVaultUsage(drivePseudonym));
    } catch (e) {
      setReadNote(
        e instanceof Error ? e.message : 'Could not read storage use.',
      );
    }
  }, [drivePseudonym]);

  useEffect(() => {
    void load();
  }, [load]);

  // Rendered only while open, so it opens as it mounts.
  useEffect(() => {
    showDialog();
  }, []);

  const free = (includeUndoWindow: boolean) =>
    manage(
      () => freeUpVaultStorage(drivePseudonym, includeUndoWindow),
      'Could not free storage.',
    );

  /** Remove one device's history or one snapshot, report it, refresh usage. */
  async function manage(
    action: () => Promise<VaultFreeUpResult>,
    failure: string,
  ) {
    setWorking(true);
    setMessage(null);
    setError(null);

    try {
      const result = await action();

      setMessage(
        result.bytes_reclaimed > 0
          ? `Freed ${formatBytes(result.bytes_reclaimed)}.`
          : 'Nothing to free.',
      );
      await load();
      onChanged?.();
    } catch (e) {
      setError(e instanceof Error ? e.message : failure);
    } finally {
      setWorking(false);
    }
  }

  async function compact(includeUndoWindow: boolean) {
    if (!onCompact) return;

    setWorking(true);
    setMessage(null);
    setError(null);

    try {
      // The host owns the busy state and the error text for this one: it runs
      // a backup pass, which can fail for reasons only it can name.
      const result = await onCompact(includeUndoWindow);

      if (result) {
        setMessage(
          result.freed.bytes_reclaimed > 0
            ? `Freed ${formatBytes(result.freed.bytes_reclaimed)}. The new snapshot uses ${formatBytes(result.checkpointBytes)}.`
            : 'Nothing to free.',
        );
      }

      await load();
    } finally {
      setWorking(false);
    }
  }

  const segments = usage ? buildSegments(usage) : [];
  const history = usage?.history;
  const historyRows = history ? historyRowsFor(history) : [];
  const devices = history?.devices;
  const snapshots = usage?.snapshots;

  return (
    <Dialog {...dialogProps} labelledBy={titleId} width='34rem'>
      <DialogTitle>
        <h1 id={titleId}>Storage in Cloud Vault</h1>
      </DialogTitle>
      <DialogContent data-testid='vault-storage'>
        <Body>
          {readNote && !usage && (
            <Muted data-testid='vault-storage-note'>{readNote}</Muted>
          )}
          {error && (
            <ErrorText data-testid='vault-storage-error'>{error}</ErrorText>
          )}
          {!usage && !error && !readNote && (
            <Muted>Reading what is stored…</Muted>
          )}
          {usage && (
            <>
              <Total data-testid='vault-storage-total'>
                {formatBytes(usage.used_bytes)} of{' '}
                {formatBytes(usage.quota_bytes)} used
              </Total>
              <Bar
                role='img'
                data-testid='vault-storage-bar'
                aria-label={segments
                  .map(s => `${s.label}: ${formatBytes(s.bytes)}`)
                  .join(', ')}
              >
                {segments.map(s => (
                  <Segment
                    key={s.id}
                    data-testid={`vault-bar-${s.id}`}
                    $color={s.color}
                    style={{ flexGrow: s.bytes, flexBasis: 0 }}
                    title={`${s.label}: ${formatBytes(s.bytes)}`}
                  />
                ))}
              </Bar>
              <Legend>
                {segments.map(s => (
                  <LegendItem key={s.id} data-testid={`vault-storage-${s.id}`}>
                    <Dot $color={s.color} aria-hidden />
                    <span>
                      <strong>{s.label}</strong>
                      {s.count !== undefined && <> · {countText(s)}</>} ·{' '}
                      {formatBytes(s.bytes)}
                      <Hint>{s.hint}</Hint>
                    </span>
                  </LegendItem>
                ))}
              </Legend>
              {(usage.pending_bytes > 0 || usage.unaccounted_bytes > 0) && (
                <Muted>
                  {usage.pending_bytes > 0 &&
                    `Uploads in progress: ${formatBytes(usage.pending_bytes)}. `}
                  {usage.unaccounted_bytes > 0 &&
                    `Leftovers, cleaned up automatically: ${formatBytes(usage.unaccounted_bytes)}.`}
                </Muted>
              )}

              {historyRows.length > 0 && (
                <Explain data-testid='vault-history-explain'>
                  <strong>What the change history holds</strong>
                  <ul>
                    {historyRows.map(r => (
                      <li key={r.id} data-testid={`vault-history-${r.id}`}>
                        <span>
                          {r.label}
                          <Hint>{r.hint}</Hint>
                        </span>
                        <Amount>{formatBytes(r.bytes)}</Amount>
                      </li>
                    ))}
                  </ul>
                  {devices && devices.length > 0 && (
                    <Hint>
                      Each browser or app&apos;s share is listed below, where
                      you can remove it.
                    </Hint>
                  )}
                </Explain>
              )}

              {snapshots && snapshots.length > 0 && (
                <Section data-testid='vault-snapshots'>
                  <strong>Snapshots</strong>
                  <ul>
                    {snapshots.map(snap => (
                      <li
                        key={snap.id}
                        data-testid={`vault-snapshot-${snap.id}`}
                      >
                        <span>
                          {new Date(snap.created_at * 1000).toLocaleDateString(
                            undefined,
                            { dateStyle: 'medium' },
                          )}
                          <Hint>{formatBytes(snap.bytes)}</Hint>
                        </span>
                        {snap.is_latest ? (
                          <Muted>Always kept</Muted>
                        ) : (
                          <Button
                            subtle
                            data-testid={`vault-snapshot-delete-${snap.id}`}
                            onClick={() => setDeleteSnapshot(snap)}
                            disabled={busy}
                          >
                            Delete
                          </Button>
                        )}
                      </li>
                    ))}
                  </ul>
                  {snapshots.length === 1 && (
                    <Hint data-testid='vault-snapshots-only-latest'>
                      Older snapshots are removed automatically.
                    </Hint>
                  )}
                </Section>
              )}

              {devices && devices.length > 0 && (
                <Section data-testid='vault-devices'>
                  <strong>Browsers and apps backing up here</strong>
                  <Hint as='p'>
                    Every browser or app you signed in on sends its own changes
                    to this backup. Old or unused ones can pile up.
                  </Hint>
                  <ul>
                    {devices.map(d => (
                      <li
                        key={d.device_pubkey}
                        data-testid={`vault-device-${d.device_pubkey}`}
                      >
                        <span>
                          {deviceLabel(d.device_pubkey)}
                          {currentDevice === d.device_pubkey && (
                            <> · This browser</>
                          )}
                          <Hint>
                            {formatBytes(d.pack_bytes)}
                            {d.last_activity_at
                              ? ` · last active ${formatTimeAgo(new Date(d.last_activity_at * 1000))}`
                              : ''}
                          </Hint>
                        </span>
                        <Button
                          subtle
                          data-testid={`vault-device-remove-${d.device_pubkey}`}
                          onClick={() => setRemoveDevice(d)}
                          disabled={busy}
                        >
                          Remove its history…
                        </Button>
                      </li>
                    ))}
                  </ul>
                </Section>
              )}

              {onCompact && historyBytes(usage) > 0 && (
                <Actions data-testid='vault-history'>
                  <Hint as='p'>
                    Compressing takes a fresh snapshot of the backup and frees
                    the changes it covers. Your workspace is not touched, and
                    recently deleted items stay recoverable.
                  </Hint>
                  <ButtonRow>
                    <Button
                      data-testid='vault-compress'
                      onClick={() => void compact(false)}
                      disabled={busy || suspended}
                    >
                      Compress history
                    </Button>
                    {discardGain(usage) > 0 && (
                      <DiscardButton
                        data-testid='vault-discard-history'
                        subtle
                        onClick={() => setConfirmDiscard(true)}
                        disabled={busy || suspended}
                      >
                        Discard history…
                      </DiscardButton>
                    )}
                  </ButtonRow>
                  {(busy || suspended) && (
                    <Muted data-testid='vault-history-disabled'>
                      {suspended
                        ? 'Backups are paused, so the backup cannot be compressed.'
                        : 'Wait for the current backup to finish.'}
                    </Muted>
                  )}
                </Actions>
              )}

              {!onCompact && usage.reclaimable_bytes > 0 && (
                <Actions>
                  <span data-testid='vault-storage-reclaimable'>
                    {formatBytes(usage.reclaimable_bytes)} of old history and
                    unused files can be removed. Nothing you can see is lost.
                  </span>
                  <ButtonRow>
                    <Button
                      data-testid='vault-free-up'
                      onClick={() => free(false)}
                      disabled={busy}
                    >
                      {busy ? 'Freeing…' : 'Free up space'}
                    </Button>
                  </ButtonRow>
                </Actions>
              )}

              {!onCompact && usage.undo_window_bytes > 0 && (
                <Actions>
                  <span data-testid='vault-storage-undo'>
                    {formatBytes(usage.undo_window_bytes)} is kept only so
                    recently deleted items can be brought back. Freeing it means
                    those cannot be restored.
                  </span>
                  <ButtonRow>
                    <Button
                      data-testid='vault-free-up-undo'
                      subtle
                      onClick={() => free(true)}
                      disabled={busy}
                    >
                      Free it anyway
                    </Button>
                  </ButtonRow>
                </Actions>
              )}

              {usage.reclaimable_bytes === 0 &&
                usage.undo_window_bytes === 0 &&
                historyBytes(usage) === 0 && (
                  <Muted data-testid='vault-storage-nothing'>
                    Nothing extra is stored. This is what your workspace needs.
                  </Muted>
                )}
            </>
          )}
          <div aria-live='polite'>
            {message && (
              <Message data-testid='vault-storage-message'>{message}</Message>
            )}
          </div>
        </Body>
        {usage && (
          <ConfirmationDialog
            show={confirmDiscard}
            bindShow={setConfirmDiscard}
            title='Discard backup history?'
            confirmLabel='Discard history'
            theme={ConfirmationDialogTheme.Alert}
            onConfirm={() => void compact(true)}
          >
            <p data-testid='vault-discard-warning'>
              {`The backup will keep only its newest snapshot, and about ${formatBytes(discardGain(usage))} will be freed.`}
            </p>
            <p>
              Older backup copies are removed, and so is the edit history of the
              backup: it keeps only the current state of every item. Restoring
              from it brings back your workspace as it is now, without its
              version history. Items you deleted recently can no longer be
              recovered from the backup. Your devices keep their own edit
              history and your workspace is not changed.
            </p>
            <p>This cannot be undone.</p>
          </ConfirmationDialog>
        )}
        <ConfirmationDialog
          show={removeDevice !== null}
          bindShow={open => {
            if (!open) setRemoveDevice(null);
          }}
          title='Remove the saved history of this browser or app?'
          confirmLabel='Remove history'
          theme={ConfirmationDialogTheme.Alert}
          onConfirm={() => {
            const target = removeDevice;

            if (target) {
              void manage(
                () =>
                  removeVaultDeviceHistory(
                    drivePseudonym,
                    target.device_pubkey,
                  ),
                'Could not remove the history.',
              );
            }
          }}
        >
          <p data-testid='vault-remove-warning'>
            {removeDevice
              ? `About ${formatBytes(removeDevice.pack_bytes)} of saved history from ${deviceLabel(removeDevice.device_pubkey)} will be removed.`
              : ''}
          </p>
          <p>
            This deletes the changes it sent to your backup. Edits made only
            there, and never synced anywhere else, are lost. Your workspace and
            your other browsers are not touched.
          </p>
          <p>This cannot be undone.</p>
        </ConfirmationDialog>
        <ConfirmationDialog
          show={deleteSnapshot !== null}
          bindShow={open => {
            if (!open) setDeleteSnapshot(null);
          }}
          title='Delete this snapshot?'
          confirmLabel='Delete snapshot'
          theme={ConfirmationDialogTheme.Alert}
          onConfirm={() => {
            const target = deleteSnapshot;

            if (target) {
              void manage(
                () => deleteVaultSnapshot(drivePseudonym, target.id),
                'Could not delete the snapshot.',
              );
            }
          }}
        >
          <p data-testid='vault-delete-warning'>
            {deleteSnapshot
              ? `This snapshot uses ${formatBytes(deleteSnapshot.bytes)}. The newest snapshot and your workspace are not touched.`
              : ''}
          </p>
          <p>This cannot be undone.</p>
        </ConfirmationDialog>
      </DialogContent>
      <DialogActions>
        <Button subtle onClick={() => close()} data-testid='vault-storage-hide'>
          Close
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/** A short, recognisable form of a device key. */
function deviceLabel(pubkey: string): string {
  return pubkey.slice(0, 8);
}

type Segment = {
  id: 'snapshots' | 'history' | 'files' | 'other';
  label: string;
  hint: string;
  count?: number;
  bytes: number;
  color: string;
};

/**
 * The bar's pieces, from the usage rows.
 *
 * A snapshot is one `checkpoint` object. `checkpoint_image` objects are chunks
 * of a snapshot's image (they carry the same `checkpoint_n` plus a chunk
 * index), so they add to its size but not to the count. If only chunks exist,
 * the chunks are all there is to count.
 */
function buildSegments(usage: VaultUsage): Segment[] {
  const sum = (kinds: string[], field: 'bytes' | 'objects') =>
    usage.by_kind
      .filter(r => kinds.includes(r.kind))
      .reduce((total, r) => total + r[field], 0);
  const known = ['checkpoint', 'checkpoint_image', 'pack', 'blob'];
  const snapshotCount =
    sum(['checkpoint'], 'objects') || sum(['checkpoint_image'], 'objects');
  const packs = sum(['pack'], 'objects');
  const files = sum(['blob'], 'objects');
  const other = usage.by_kind
    .filter(r => !known.includes(r.kind))
    .reduce((total, r) => total + r.bytes, 0);

  const all: Segment[] = [
    {
      id: 'snapshots',
      label: 'Snapshots',
      hint: 'Full copies that restore fast',
      count: snapshotCount,
      bytes: sum(['checkpoint', 'checkpoint_image'], 'bytes'),
      color: COLOR_SNAPSHOTS,
    },
    {
      id: 'history',
      label: 'Change history',
      hint: 'Every edit since a snapshot',
      count: packs,
      bytes: sum(['pack'], 'bytes'),
      color: COLOR_HISTORY,
    },
    {
      id: 'files',
      label: 'Files and images',
      hint: 'Uploads attached to your pages',
      count: files,
      bytes: sum(['blob'], 'bytes'),
      color: COLOR_FILES,
    },
    {
      id: 'other',
      label: 'Other',
      hint: 'Search index and supporting data',
      bytes: other,
      color: COLOR_OTHER,
    },
  ];

  return all.filter(
    s => s.bytes > 0 || s.id === 'snapshots' || s.id === 'history',
  );
}

function countText(s: Segment): React.ReactNode {
  if (s.id === 'history') {
    return s.count === 1 ? <>{s.count} pack</> : <>{s.count} packs</>;
  }

  if (s.id === 'files') {
    return s.count === 1 ? <>{s.count} file</> : <>{s.count} files</>;
  }

  return s.count;
}

type HistoryRow = { id: string; label: string; hint: string; bytes: number };

/** The change packs, split into why each is still there. Zero rows are hidden. */
function historyRowsFor(h: VaultHistoryUsage): HistoryRow[] {
  const rows: HistoryRow[] = [
    {
      id: 'tip',
      label:
        h.lanes === 1
          ? 'Latest changes from 1 browser or app'
          : `Latest changes from each of ${h.lanes} browsers and apps`,
      hint: 'Always kept',
      bytes: h.tip_bytes,
    },
    {
      id: 'uncovered',
      label: 'Changes not in a snapshot yet',
      hint: 'The next backup from that browser or app adds them',
      bytes: h.uncovered_bytes,
    },
    {
      id: 'undo',
      label: 'Kept so deleted items can be recovered',
      hint: 'Dropped by Discard history',
      bytes: h.in_undo_window_bytes,
    },
    {
      id: 'freeable',
      label: 'Can be freed now',
      hint: 'Compress history removes this',
      bytes: h.freeable_bytes,
    },
  ];

  return rows.filter(r => r.bytes > 0);
}

/** What discarding history would free: old history plus the undo window. */
function discardGain(usage: VaultUsage): number {
  return usage.reclaimable_bytes + usage.undo_window_bytes;
}

/** Bytes in the backup's change chain and old snapshots: what compressing can replace. */
function historyBytes(usage: VaultUsage): number {
  return (
    usage.reclaimable_bytes +
    usage.undo_window_bytes +
    usage.by_kind
      .filter(row => row.kind === 'pack')
      .reduce((sum, row) => sum + row.bytes, 0)
  );
}

const COLOR_SNAPSHOTS = 'var(--vs-snapshots)';
const COLOR_HISTORY = 'var(--vs-history)';
const COLOR_FILES = 'var(--vs-files)';
const COLOR_OTHER = 'var(--vs-other)';

const Body = styled.div`
  --vs-snapshots: ${p => p.theme.colors.main};
  --vs-history: ${p => p.theme.colors.warning};
  --vs-files: ${p => p.theme.colors.success};
  --vs-other: ${p => p.theme.colors.textLight};
  display: flex;
  flex-direction: column;
  gap: 0.8rem;
  font-size: ${CARD_SUB_FONT};

  p {
    margin: 0;
  }
`;

const Total = styled.strong`
  font-size: 1.1rem;
`;

const Muted = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: ${CARD_SUB_FONT};
`;

const Hint = styled.span`
  display: block;
  margin: 0;
  color: ${p => p.theme.colors.textLight};
  font-size: ${CARD_SUB_FONT};
`;

const Message = styled.p`
  margin: 0;
  padding: 0.5rem 0.7rem;
  border-radius: ${p => p.theme.radius};
  background: ${p => p.theme.colors.bg1};
`;

// Gaps between segments, not only hue, tell them apart.
const Bar = styled.div`
  display: flex;
  gap: 2px;
  height: 14px;
  border-radius: 7px;
  overflow: hidden;
  background: ${p => p.theme.colors.bg1};
`;

const Segment = styled.div<{ $color: string }>`
  background: ${p => p.$color};
  min-width: 4px;
`;

const Legend = styled.ul`
  list-style: none;
  margin: 0;
  padding: 0;
  padding-inline-start: 0;
  margin-inline-start: 0;
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
`;

const LegendItem = styled.li`
  margin: 0;
  list-style: none;
  display: flex;
  gap: 0.6rem;
  align-items: flex-start;
`;

const Dot = styled.span<{ $color: string }>`
  flex: none;
  width: 0.8rem;
  height: 0.8rem;
  margin-top: 0.2rem;
  border-radius: 50%;
  background: ${p => p.$color};
`;

const Explain = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
  padding: 0.7rem 0.8rem;
  border-radius: ${p => p.theme.radius};
  background: ${p => p.theme.colors.bg1};

  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    padding-inline-start: 0;
    margin-inline-start: 0;
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
  }

  li {
    margin: 0;
    list-style: none;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
  }
`;

const Section = styled(Explain)`
  button {
    flex: none;
    white-space: nowrap;
  }
`;

const Amount = styled.span`
  flex: none;
  font-variant-numeric: tabular-nums;
`;

const Actions = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.6rem;
`;

const ButtonRow = styled.div`
  display: flex;
  flex-wrap: wrap;
  gap: 0.6rem;
`;

const DiscardButton = styled(Button)`
  --button-text-color: ${p => p.theme.colors.alert};
  --button-border-color: ${p => p.theme.colors.alert};
  --button-text-color-hover: ${p => p.theme.colors.alertLight};
  --button-border-color-hover: ${p => p.theme.colors.alertLight};
`;

const ErrorText = styled.p`
  margin: 0;
  color: ${p => p.theme.colors.alert};
`;
