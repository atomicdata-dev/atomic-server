import { FaRotateLeft } from 'react-icons/fa6';
import { styled } from 'styled-components';
import { Button } from '../Button';
import { useEffect, useRef } from 'react';
import { useStore } from '@tomic/react';
import { useDriveVault } from '../../helpers/managed/useDriveVault';
import type { UseVaultBackup } from '../../helpers/managed/useVaultBackup';

import type { JSX } from 'react';

/**
 * "Restore from Cloud Vault", for a drive this device cannot open.
 *
 * Rendered on the error page, because that is where a second browser lands
 * when it is sent to a drive it has never held: "Could not open did:ad:… —
 * resource not available locally". The connect-device step makes the same
 * offer at sign-in, but not everyone arrives through sign-in — a bookmark, a
 * shared link, or a session that outlived its data all end up here instead.
 *
 * With `autoStart` it restores by itself (see the effect below); otherwise the
 * button waits for a click. Shows nothing unless the vault holds a backup of exactly this drive, so on a
 * self-hosted server or for a subject that is not a backed-up drive the page
 * is unchanged.
 */
export function VaultRestoreAction({
  subject,
  vault: given,
  autoStart = false,
}: {
  subject: string;
  /** The caller's own {@link useDriveVault}, when it needs the state too. */
  vault?: UseVaultBackup;
  /**
   * Restore as soon as this renders. Only for a caller that already knows the
   * drive is unavailable (DriveUnavailable); the generic error page must not,
   * or any error on a backed-up subject would trigger a restore.
   */
  autoStart?: boolean;
}): JSX.Element | null {
  const store = useStore();
  // A caller that passed its own vault does not need a second one.
  const own = useDriveVault(given ? null : subject);
  const vault = given ?? own;
  const startedFor = useRef<string | null>(null);
  const canRestore = canRestoreFromVault(vault);
  const signedIn = !!store.getAgent();
  const { busy, error, restore } = vault;

  // Someone who lands on a drive with a backup wants the drive, not a choice.
  // Once per subject: after a failure the button below offers the retry, so a
  // persistent failure cannot become a loop.
  useEffect(() => {
    if (!autoStart || !canRestore || !signedIn || busy || error) return;

    if (startedFor.current === subject) return;

    startedFor.current = subject;
    void restore();
  }, [autoStart, canRestore, signedIn, busy, error, restore, subject]);

  if (!canRestore) return null;

  const failed = !busy && !!error;

  return (
    <Offer data-testid='vault-restore-offer'>
      <p>This drive has an encrypted backup in Cloud Vault.</p>
      {error && (
        <ErrorText role='alert'>
          {/ClientDb/.test(error)
            ? "This device's storage isn't responding. Close other atomic.place windows or tabs, then try again."
            : error}
        </ErrorText>
      )}
      {busy && (
        <p role='status'>
          {vault.restoreProgress !== null
            ? `Restoring this drive… ${Math.round(vault.restoreProgress * 100)}%`
            : 'Restoring this drive…'}
        </p>
      )}
      {(failed || !busy) && (
        <Button
          data-testid='vault-restore-now'
          onClick={restore}
          disabled={busy}
        >
          <FaRotateLeft /> {failed ? 'Try again' : 'Restore from Cloud Vault'}
        </Button>
      )}
    </Offer>
  );
}

/** True when the vault holds a backup this device can restore. */
export function canRestoreFromVault(vault: UseVaultBackup): boolean {
  return (
    vault.status.state === 'on' && vault.status.details.confirmed_objects > 0
  );
}

const Offer = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  align-items: flex-start;
`;

const ErrorText = styled.p`
  color: ${p => p.theme.colors.alert};
  margin: 0;
`;
