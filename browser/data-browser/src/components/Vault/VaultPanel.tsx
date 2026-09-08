import { styled } from 'styled-components';
import { FaLock, FaRotateLeft, FaCloudArrowUp } from 'react-icons/fa6';
import {
  cardSurface,
  CardIcon,
  CARD_ACTIONS_GAP,
  CARD_BODY_GAP,
  CARD_SUB_FONT,
  CARD_TITLE_FONT,
} from '../cardSurface';
import { Button } from '../Button';
import { PRODUCT_NAME } from '../../helpers/managed/product';
import type { UseVaultBackup } from '../../helpers/managed/useVaultBackup';

/**
 * Cloud Vault controls for one drive.
 *
 * Presentational: every decision lives in `useVaultBackup`, so this can be
 * dropped anywhere a drive is in view without dragging state with it.
 *
 * The copy is deliberate about which tier this is. Cloud Vault is *blind* —
 * encrypted backup we cannot read — while Cloud Server stores queryable state we
 * can. `OSS_STRATEGY.md` calls out that headlining "we can't read your data"
 * and then selling a tier that can is how a trust pitch gets lost, so the two
 * must never be described in the same words.
 */
export function VaultPanel({
  vault,
  onRestored,
  embedded = false,
  offerUrl,
  onOfferClick,
}: {
  vault: UseVaultBackup;
  /** Called after a successful restore, so the host can refresh its view. */
  onRestored?: () => void;
  /**
   * Render as a row inside a surface the host already drew, rather than as a
   * card of its own. Nesting a card in a card reads as two things when this is
   * one service listed under an account.
   */
  embedded?: boolean;
  /**
   * Where to read what this tier costs. Shown only while the vault is off:
   * once it is on, the price is a question for the account page, not for a
   * panel whose job is the state of one drive's backup.
   */
  offerUrl?: string | null;
  /**
   * Opening the link is the host's business. A plain anchor is wrong in the
   * desktop app, where Tauri intercepts a new window natively and the shell
   * refuses it; the host already knows how to open one properly.
   */
  onOfferClick?: (url: string) => void;
}) {
  const { status, busy, error, restoreProgress } = vault;

  // Still settling. Bounded — the hook gives up on `loading` rather than
  // sitting in it — but the bound is seconds, not a frame, so rendering
  // nothing meant the row appeared out of nowhere and shoved the rest of the
  // account card down with it. Hold the space and say what is happening.
  if (status.state === 'loading') {
    return (
      <Panel
        data-testid='vault-panel'
        data-vault-state='loading'
        $embedded={embedded}
      >
        <CardIcon>
          <FaLock />
        </CardIcon>
        <Body>
          <Title>Cloud Vault</Title>
          <Sub>Checking this workspace’s backup…</Sub>
        </Body>
      </Panel>
    );
  }

  // "Cannot say" is not "off": offering an enable button when we could not
  // even ask would turn a missing session into a confusing failure on click.
  //
  // But it is not nothing either. Rendering null here meant a device that
  // could never run the vault looked exactly like one where the feature does
  // not exist — no panel, no reason, nothing to act on. Say what is missing
  // and leave the decision to the reader.
  if (status.state === 'unavailable') {
    return (
      <Panel
        data-testid='vault-panel'
        data-vault-state='unavailable'
        $embedded={embedded}
      >
        <CardIcon>
          <FaLock />
        </CardIcon>
        <Body>
          <Title>Cloud Vault</Title>
          <Sub data-testid='vault-unavailable-reason'>{status.reason}</Sub>
        </Body>
      </Panel>
    );
  }

  async function handleRestore() {
    const outcome = await vault.restore();

    if (outcome) onRestored?.();
  }

  if (status.state === 'off') {
    return (
      <Panel
        data-testid='vault-panel'
        data-vault-state='off'
        $embedded={embedded}
      >
        {/* Neutral: an offer is not a service. Blue on this page means "on",
            so a vault that is off must not wear it, or the row's own answer
            contradicts its glyph. */}
        <CardIcon>
          <FaLock />
        </CardIcon>
        <Body>
          <Title>Cloud Vault</Title>
          <Sub>
            Keep an encrypted copy of this workspace in {PRODUCT_NAME}. It is
            sealed on this device, so we store it without being able to read it.
          </Sub>
          {error && <ErrorText data-testid='vault-error'>{error}</ErrorText>}
          <Actions>
            <Button
              data-testid='vault-enable'
              onClick={vault.enable}
              disabled={busy}
            >
              {busy ? 'Setting up…' : 'Turn on Cloud Vault'}
            </Button>
            {offerUrl && (
              <OfferLink
                data-testid='vault-offer'
                href={offerUrl}
                rel='noreferrer'
                onClick={e => {
                  if (!onOfferClick) return;

                  e.preventDefault();
                  onOfferClick(offerUrl);
                }}
              >
                See plans
              </OfferLink>
            )}
          </Actions>
        </Body>
      </Panel>
    );
  }

  const { enrollment, details } = status;
  const suspended = enrollment.status !== 'active';

  return (
    <Panel
      data-testid='vault-panel'
      data-vault-state={suspended ? 'suspended' : 'on'}
      $accent={!embedded}
      $embedded={embedded}
    >
      <CardIcon $tone='provider'>
        <FaLock />
      </CardIcon>
      <Body>
        <Title>Cloud Vault is on</Title>
        {/* The object count is an attribute as well as prose: a test asserting
            that a second backup actually stored something should read the
            number, not parse a sentence that is free to be reworded. */}
        <Sub
          data-testid='vault-summary'
          data-vault-objects={details.confirmed_objects}
          data-vault-bytes={enrollment.used_bytes}
        >
          {/* Name where it goes, in the state the user actually sits in. The
              off-state copy says "in {PRODUCT_NAME}" and then the on-state used
              to drop it, so the one screen you see every day never mentioned
              that your data leaves the device at all. Sealed or not, who is
              holding it is not a detail to infer. */}
          {details.confirmed_objects === 0
            ? `Nothing has been backed up to ${PRODUCT_NAME} yet.`
            : `${details.confirmed_objects} encrypted object${
                details.confirmed_objects === 1 ? '' : 's'
              } · ${formatBytes(enrollment.used_bytes)} stored in ${PRODUCT_NAME}.`}
          {enrollment.last_backup_at
            ? ` Last backup ${formatWhen(enrollment.last_backup_at)}.`
            : ''}
        </Sub>

        {suspended && (
          <ErrorText data-testid='vault-suspended'>
            Backups are paused. You can still restore what is already stored.
          </ErrorText>
        )}

        {error && <ErrorText data-testid='vault-error'>{error}</ErrorText>}

        {restoreProgress !== null && (
          <Sub data-testid='vault-restore-progress'>
            Restoring… {Math.round(restoreProgress * 100)}%
          </Sub>
        )}

        <Actions>
          <Button
            data-testid='vault-backup-now'
            onClick={vault.backupNow}
            disabled={busy || suspended}
          >
            <FaCloudArrowUp /> <span>{busy ? 'Working…' : 'Back up now'}</span>
          </Button>
          <Button
            data-testid='vault-restore'
            subtle
            onClick={handleRestore}
            disabled={busy}
          >
            <FaRotateLeft /> <span>Restore</span>
          </Button>
          <Button
            data-testid='vault-disable'
            subtle
            onClick={vault.disable}
            disabled={busy}
          >
            Turn off
          </Button>
        </Actions>
      </Body>
    </Panel>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;

  const units = ['KB', 'MB', 'GB'];
  let value = bytes / 1024;
  let unit = 0;

  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }

  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

/** Unix seconds → a phrase, because an ISO timestamp answers a question nobody asked. */
function formatWhen(unixSeconds: number): string {
  const minutes = Math.floor((Date.now() / 1000 - unixSeconds) / 60);

  if (minutes < 1) return 'just now';

  if (minutes < 60) return `${minutes} min ago`;

  const hours = Math.floor(minutes / 60);

  if (hours < 24) return `${hours}h ago`;

  return `${Math.floor(hours / 24)}d ago`;
}

// This panel sits in the Sync page's list of cards, so it uses that list's
// surface and type scale rather than its own. It used to set padding and gap
// from `theme.size(2)` (8px) while the cards around it used 0.9rem (14.4px),
// and left its body text at the inherited 1rem against their 0.82rem — close
// enough to look like a mistake rather than a distinction.
const Panel = styled.div<{ $accent?: boolean; $embedded?: boolean }>`
  ${cardSurface}
  border-color: ${p => (p.$accent ? p.theme.colors.main : undefined)};
  background: ${p => (p.$accent ? `${p.theme.colors.main}0a` : undefined)};

  /* Inside the provider card the surrounding card already supplies the
     surface and the accent, so drawing them again would box one service
     inside another box. */
  ${p =>
    p.$embedded &&
    `
      border: none;
      background: none;
      padding: 0;
    `}
`;

const Body = styled.div`
  display: flex;
  flex-direction: column;
  gap: ${CARD_BODY_GAP};
  min-width: 0;
`;

const Title = styled.h3`
  margin: 0;
  font-size: ${CARD_TITLE_FONT};
  font-weight: 600;
`;

const Sub = styled.p`
  margin: 0;
  color: ${p => p.theme.colors.textLight};
  font-size: ${CARD_SUB_FONT};
`;

const ErrorText = styled.p`
  margin: 0;
  color: ${p => p.theme.colors.alert};
  font-size: ${CARD_SUB_FONT};
`;

const OfferLink = styled.a`
  align-self: center;
  color: ${p => p.theme.colors.main};
  font-size: ${CARD_SUB_FONT};
  text-decoration: underline;

  &:hover,
  &:focus-visible {
    color: ${p => p.theme.colors.mainDark};
  }
`;

const Actions = styled.div`
  display: flex;
  flex-wrap: wrap;
  gap: ${CARD_ACTIONS_GAP};
  margin-top: ${CARD_ACTIONS_GAP};
`;
