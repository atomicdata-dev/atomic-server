import { ServiceGroup, ServiceSection } from '@tomic/service-ui';
import '@tomic/service-ui/styles.css';
import { Checkbox } from '../components/forms/Checkbox';
import {
  readKnownPeers,
  writeKnownPeers,
  type KnownPeer,
} from '../helpers/knownPeers';
import { resumePeerLinks } from '../helpers/browserPeerSync';
import { syncSummary, showSavedServer } from '../helpers/syncPresentation';
import { driveBillingUrl } from '../helpers/driveBillingUrl';
import { reportUserFacingFailure } from '../helpers/sentry';
import {
  deriveNodeStatuses,
  currentDriveSync,
  driveHostedByNode,
  currentDriveValue,
  hasHostedDriveConnection,
  shouldAutoEnroll,
  type ScopedDriveValue,
  type NodeStatus,
} from '../helpers/driveSyncStatus';
import { BrowserPeerPanel } from '../components/BrowserPeerPanel';
import { HostingPaymentRequiredError } from '../helpers/managed/enrollment';
import { DiscoverWorkspace } from '../views/getting-started/DiscoverWorkspace';
import {
  Fragment,
  useEffect,
  useRef,
  useState,
  type JSX,
  type MouseEvent,
  type ReactNode,
} from 'react';
import { createRoute, Link } from '@tanstack/react-router';
import toast from 'react-hot-toast';
import {
  StoreEvents,
  type StoreSyncStatus,
  type CommitLogEntry,
  useStore,
  useProperty,
  truncateUrl,
  Datatype,
  isAtomicIdentifier,
  nodeId as parseNodeId,
  nodeSubject,
} from '@tomic/react';
import { styled, keyframes, css, type DefaultTheme } from 'styled-components';
import {
  cardSurface,
  CardIcon,
  CARD_SUB_FONT,
  CARD_TITLE_FONT,
} from '../components/cardSurface';
import { openExternal } from '../helpers/openExternal';
import { formatBytes } from '../helpers/formatBytes';
import { AICreditsService } from '../components/Vault/AICreditsService';
import {
  FaLaptop,
  FaServer,
  FaCheck,
  FaArrowsRotate,
  FaQuestion,
  FaCircleExclamation,
  FaCloud,
  FaMobileScreenButton,
  FaCloudArrowUp,
  FaKey,
} from 'react-icons/fa6';
import { Button } from '../components/Button';
import { VaultPanel } from '../components/Vault/VaultPanel';
import {
  ServiceRow,
  ServiceRows,
  type ServiceStanding,
  type ServiceTone,
} from '../components/Cloud/ServiceRow';
import { CloudServerDetails } from '../components/Cloud/CloudServerDetails';
import { SyncProblemBanner } from '../components/SyncProblemBanner';
import { describeSyncProblem } from '../helpers/syncProblem';
import { isErrorReportingEnabled, reportSyncProblem } from '../helpers/sentry';
import { LinkProviderPanel } from '../components/Vault/LinkProviderPanel';
import { isDeviceLinked } from '../helpers/managed/deviceLink';
import {
  getManagedAccount,
  type ManagedAccount,
} from '../helpers/managed/session';
import {
  managedFetch,
  getRememberedManagedPortalUrl,
  safePortalUrl,
} from '../helpers/managed/api';
import {
  envelopeWrapperKinds,
  getRecoverySecret,
  isAssistedRecoveryAvailable,
  readCachedBackups,
  sameAgent,
} from '../helpers/managed/recovery';
import { useDriveVault } from '../helpers/managed/useDriveVault';
import { ContainerNarrow } from '../components/Containers';
import { Main } from '../components/Main';
import { Card } from '../components/Card';
import {
  fetchManagedInfo,
  type ManagedInfo,
  EMPTY_NODE_INFO,
  fetchNodeDriveUsage,
  forgetServerPeer,
  type NodeDriveUsage,
} from '../helpers/managedServer';
import { isOriginWithoutNode } from '../helpers/originNode';
import { getDriveUsage } from '../helpers/managedUsage';
import { sameOrigin, serverLabel } from '../helpers/serverUrl';
import { ResourceInline } from '../views/ResourceInline';
import { AtomicLink } from '../components/AtomicLink';
import { formatTimeAgo } from '../helpers/formatTimeAgo';
import { getLocalServerOrigin, isRunningInTauri } from '../helpers/tauri';
import { deviceHasDriveData } from '../helpers/driveData';
import { ConnectDevice, focusConnectDevice } from '../components/ConnectDevice';
import {
  decodePairingEnvelope,
  PairingEnvelopeError,
  PAIRING_URI_PREFIX,
  signRequest,
} from '@tomic/lib';
import { isClientDbEnabled, setClientDbEnabled } from '../helpers/clientDbMode';
import { PRODUCT_NAME } from '../helpers/managed/product';
import {
  enableCloudSyncForDrive,
  ensureManagedSession,
  driveHasCloudEnrollment,
  isCloudSyncAvailable,
  getManagedPortalUrl,
} from '../helpers/managed/cloudSync';
import { appRoute } from './RootRoutes';
import { pathNames, paths } from './paths';
import { useSettings } from '../helpers/AppSettings';
import { serverURLStorage } from '../helpers/serverURLStorage';

export const SyncRoute = createRoute({
  path: pathNames.sync,
  validateSearch: (search): { drive?: string } => ({
    drive:
      typeof search.drive === 'string' && isAtomicIdentifier(search.drive)
        ? search.drive
        : undefined,
  }),
  component: () => <SyncPage />,
  getParentRoute: () => appRoute,
});

function nodeDidToRaw(nodeDid: string): string | undefined {
  const raw = parseNodeId(nodeDid)?.split(':')[0];

  return raw && /^[0-9a-f]{64}$/i.test(raw) ? raw.toLowerCase() : undefined;
}

function rawToNodeDid(raw: string): string {
  return nodeSubject(raw);
}

function StatusIcon({ status }: { status: NodeStatus }) {
  switch (status) {
    case 'synced':
      return <FaCheck />;
    case 'syncing':
      return <FaArrowsRotate />;
    case 'unsynced':
      return <FaCircleExclamation />;
    case 'offline':
      return <FaQuestion />;
    case 'unknown':
      return <FaQuestion />;
  }
}

/** Connected and answering usage for this drive, but no finished sync is
 *  recorded here yet: not "In sync", and no longer just "Connecting…". */
function serverStatusLabel(status: NodeStatus, answersUsage: boolean): string {
  return status === 'unknown' && answersUsage
    ? 'Connected'
    : statusLabel(status);
}

function statusLabel(status: NodeStatus): string {
  switch (status) {
    case 'synced':
      return 'In sync';
    case 'syncing':
      return 'Syncing…';
    case 'unsynced':
      return 'Changes pending';
    case 'offline':
      return 'Offline';
    case 'unknown':
      return 'Connecting…';
  }
}

type ServerCardProps = {
  server: string;
  status: StoreSyncStatus;
  managedInfo: ManagedInfo;
  cloudHosted: boolean;
  cloudEnrolled: boolean | null;
  /** Sync status of the server actually in use. */
  serverStatus: NodeStatus;
  hasWorkingLocalStore: boolean;
  nodeUsage: NodeDriveUsage | null;
  quotaBytes: number | null;
  serverNodeId: string | null;
  onSwitch: (server: string) => void;
  onRemove: (server: string) => void;
};

/**
 * Props for an anchor that leaves the app for the browser.
 *
 * `openExternal` rather than a bare `target='_blank'`: in the desktop app Tauri
 * intercepts a new-window request natively, before a click handler could cancel
 * it, and hands it to `shell.open`, which is denied there and fails on Android
 * regardless. The href stays real either way, so this is still a link to
 * assistive tech and to "copy link address".
 *
 * Shared because there are now several of these on one page, and the version
 * that forgot the handler was silently a dead link in the app.
 */
function externalLinkProps(url: string) {
  return {
    href: url,
    target: isRunningInTauri() ? undefined : '_blank',
    rel: 'noreferrer',
    onClick: (e: MouseEvent) => {
      e.preventDefault();
      void openExternal(url);
    },
  };
}

/**
 * One server, as a card.
 *
 * Rendered in two places, which is why it is a component: a managed node is no
 * longer listed among the devices, because it is one of the provider's
 * services and belongs inside the account card. Both places want the same
 * content — status, usage, node id, the way to disconnect — and one renderer
 * is what stops the two copies drifting.
 *
 * At module scope with every input passed in, even though all of them are to
 * hand in `SyncPage`. A component declared inside another component is a fresh
 * type on every parent render, so React remounts the subtree rather than
 * updating it — which for this card means throwing away a live connection's
 * DOM on every keystroke elsewhere on the page.
 */
function ServerCard({
  server,
  status,
  managedInfo,
  cloudHosted,
  cloudEnrolled,
  serverStatus,
  hasWorkingLocalStore,
  nodeUsage,
  quotaBytes,
  serverNodeId,
  onSwitch,
  onRemove,
}: ServerCardProps) {
  const store = useStore();
  const [syncChange, setSyncChange] = useState<{
    drive: string;
    next: boolean;
  } | null>(null);
  const [syncError, setSyncError] = useState<{
    drive: string;
    message: string;
  } | null>(null);
  const isSelectedServer =
    sameOrigin(server, status.serverUrl) && !!status.drive;
  const localOnlyDrive =
    isSelectedServer && !!status.drive && store.isLocalOnlyDrive(status.drive);
  const isActive =
    isSelectedServer && !!status.drive && store.isLiveSyncedDrive(status.drive);
  // A managed node that does not host this drive refuses every push. Syncing
  // can never finish, so say why instead of "Connecting…", and let the person
  // turn sync off even though the server will not answer.
  const refusedByServer =
    isSelectedServer && store.isDriveRefusedByServer(status.drive);
  const showWorkspaceSyncToggle =
    isSelectedServer &&
    !isRunningInTauri() &&
    !isOriginWithoutNode(server) &&
    (refusedByServer ||
      (isCloudSyncAvailable(managedInfo) && cloudEnrolled === false));
  const isCloud = isActive && cloudHosted;
  // A managed node admits a drive it does not host for a short bootstrap window,
  // so first sync can finish while the enrollment propagates. In that window
  // the connection looks healthy ("In sync") for a drive the node will refuse
  // minutes later. The node says so itself via `/drive-usage`.
  const hostingPending =
    isActive &&
    !isCloud &&
    !refusedByServer &&
    managedInfo.managed &&
    cloudEnrolled === false &&
    nodeUsage?.enrolled === false;
  const serverHostname = status.serverUrl
    ? new URL(status.serverUrl).hostname
    : undefined;
  const driveSync = isActive ? currentDriveSync(status) : undefined;
  const syncedAgo = driveSync
    ? formatTimeAgo(new Date(driveSync.timestamp))
    : null;
  const usedBytes = nodeUsage
    ? nodeUsage.blobBytes + nodeUsage.loroBytes
    : null;
  /**
   * What is true of the server in use, as whole phrases joined by a dot.
   *
   * Assembled here rather than written inline in the JSX for two reasons.
   * Interpolated text placed directly inside a `&&` guard extracts wrong —
   * wuchale keeps the leading literal and drops the arguments, so at runtime
   * the lookup wants more placeholders than the catalogue entry has and the
   * line renders as `[i18n-404:…]`. And a translator given a whole phrase can
   * reorder it, which is the whole point; given `resources ·` and ` of ` they
   * cannot.
   *
   * Each phrase has to start with a capital or a placeholder: wuchale's
   * default heuristic drops script-scope strings with a lower-case beginning,
   * on the reasoning that those are usually identifiers rather than prose. A
   * dropped string is not an error, it is simply never translated — which is
   * the quiet failure, so it is worth knowing about.
   */
  const facts: ReactNode[] = [];

  // A Cloud Server's resource count, space and storage link live on its row in
  // the plan card, where the portal shows them too. The device card keeps what
  // is true of the device.
  if (nodeUsage && usedBytes !== null && !isCloud) {
    facts.push(`${nodeUsage.resourceCount.toLocaleString()} resources`);

    const usedText = quotaBytes
      ? `${formatBytes(usedBytes)} of ${formatBytes(quotaBytes)}`
      : formatBytes(usedBytes);

    // The link to the size map sits right behind the space count.
    facts.push(
      isActive ? (
        <span key='space'>
          {usedText}{' '}
          <ManagedLink
            as={Link}
            to={paths.storage}
            data-testid='storage-map-link'
          >
            (see where space goes)
          </ManagedLink>
        </span>
      ) : (
        usedText
      ),
    );
  }

  // Shown next to the "in use" line at the top of the card.
  const syncedFact = driveSync
    ? syncedAgo
      ? `Synced ${syncedAgo}`
      : 'Synced just now'
    : null;

  async function toggleWorkspaceSync(next: boolean) {
    const drive = status.drive;
    if (!drive || syncChange) return;
    setSyncChange({ drive, next });
    setSyncError(null);

    try {
      if (next) {
        await store.promoteLocalDrive(drive);
      } else {
        await store.makeDriveLocal(drive);
        resumePeerLinks(store);
      }
    } catch (error) {
      setSyncError({
        drive,
        message:
          error instanceof Error
            ? error.message
            : 'Could not change drive sync.',
      });
    } finally {
      setSyncChange(null);
    }
  }

  return (
    <SyncCard
      active={isActive}
      icon={isCloud ? <FaCloud /> : <FaServer />}
      iconTone={isCloud ? 'provider' : 'neutral'}
      title={isCloud ? 'Cloud Server' : serverLabel(server)}
      status={
        localOnlyDrive
          ? { tone: 'unknown', label: 'Drive sync off' }
          : refusedByServer
            ? { tone: 'offline', label: 'Not hosted here' }
            : hostingPending
              ? { tone: 'unsynced', label: 'Not hosted yet' }
              : isActive
                ? {
                    tone: serverStatus,
                    label: serverStatusLabel(serverStatus, !!nodeUsage),
                  }
                : { tone: 'unknown', label: 'Not connected' }
      }
      controls={
        isSelectedServer ? (
          status.serverConnected ? (
            // Without a working local store (embedded node or ready OPFS
            // cache), the server is the only data source — disconnecting
            // would leave the app with no data at all.
            !localOnlyDrive && (
              <NodeAction
                onClick={() => store.disconnect()}
                disabled={!hasWorkingLocalStore}
                title={
                  hasWorkingLocalStore
                    ? undefined
                    : 'Local storage is off, so this server is the only data source. Enable local storage below to work disconnected.'
                }
              >
                Disconnect
              </NodeAction>
            )
          ) : (
            <NodeAction
              onClick={() => store.reconnect().catch(e => store.notifyError(e))}
            >
              Reconnect
            </NodeAction>
          )
        ) : (
          <NodeAction onClick={() => onSwitch(server)}>Switch</NodeAction>
        )
      }
      subtitle={
        isActive
          ? isCloud
            ? serverHostname
            : ['Always-on · in use', hostingPending ? null : syncedFact]
                .filter(Boolean)
                .join(' · ')
          : 'Always-on device'
      }
      facts={isActive ? facts : undefined}
      // A node id identifies this server's node, so it belongs on the server —
      // not buried in Developer.
      nodeId={
        !isCloud && isActive && serverNodeId
          ? rawToNodeDid(serverNodeId)
          : undefined
      }
      footer={
        !isSelectedServer ? (
          // Removing the server you're using would strand the app.
          <NodeActionSubtle onClick={() => onRemove(server)}>
            Remove
          </NodeActionSubtle>
        ) : undefined
      }
    >
      {refusedByServer && (
        <ConnError role='alert'>
          <FaCircleExclamation aria-hidden />
          <span>
            This server doesn’t host this drive, so it refuses its changes. Set
            up Cloud Server to sync it here, or turn off sync to keep it on this
            device only.
          </span>
        </ConnError>
      )}
      {hostingPending && (
        <ConnError role='status'>
          <FaCircleExclamation aria-hidden />
          <span>
            Cloud Server isn’t on for this drive. This server only accepts it
            for a short while; after that it stops syncing. Set up Cloud Server
            to keep it here, or turn off sync to keep it on this device only.
          </span>
        </ConnError>
      )}
      {showWorkspaceSyncToggle && (
        <WorkspaceSyncRow>
          <WorkspaceSyncControl>
            <Checkbox
              id='workspace-server-sync'
              checked={!localOnlyDrive}
              disabled={
                syncChange !== null ||
                (!status.serverConnected && !refusedByServer) ||
                !hasWorkingLocalStore
              }
              onChange={next => void toggleWorkspaceSync(next)}
            />
            <label htmlFor='workspace-server-sync'>
              Sync this drive with this server
            </label>
          </WorkspaceSyncControl>
          <ConnMeta>
            Off stops server sync for this drive on this browser. The server’s
            existing copy and other devices are unchanged; browser sync can
            still connect open browsers.
          </ConnMeta>
          {syncChange && syncChange.drive === status.drive && (
            <ConnMeta role='status'>
              {syncChange.next
                ? 'Starting server sync…'
                : 'Checking local copy…'}
            </ConnMeta>
          )}
          {syncError && syncError.drive === status.drive && (
            <ConnError role='alert'>{syncError.message}</ConnError>
          )}
        </WorkspaceSyncRow>
      )}
      {/* Status details belong to the server actually in use. */}
      {isActive && !status.serverConnected && status.serverConnectionError && (
        <ConnError role='alert'>
          <FaCircleExclamation aria-hidden />
          <span>{status.serverConnectionError}</span>
        </ConnError>
      )}
    </SyncCard>
  );
}

/**
 * One device or server in the sync list.
 *
 * There were four of these assembled by hand — the server in use, two kinds of
 * peer, and this device — sharing the styled pieces but not a shape. They drifted:
 * the same "Disconnect" verb sat top-right on one card and bottom-left on
 * another, telemetry lived in the subtitle on peers and in a facts line on the
 * server, and the node-id copy was written three times, once without the error
 * handling the other two had.
 *
 * So the differences between the cards are data now, and the arrangement is
 * decided once. Two slots, by what the control DOES rather than where it looks
 * best per card:
 *   - `controls` change the connection (Disconnect, Sync now, Switch) and sit
 *     beside the status they act on;
 *   - `footer` leaves or leads away from it (Remove, Manage account).
 */
interface SyncCardProps {
  icon: ReactNode;
  iconTone?: 'provider' | 'neutral';
  title: ReactNode;
  /** Tooltip for the title, where the title is a short name for a long id. */
  titleHint?: string;
  status?: { tone: NodeStatus; label: ReactNode };
  controls?: ReactNode;
  subtitle?: ReactNode;
  /** What is true of this connection, joined by dots. Empty entries drop out,
   *  so callers can build the list conditionally without filtering. */
  facts?: ReactNode[];
  /** Anything between the facts and the node id, such as errors. */
  children?: ReactNode;
  /** Rendered as a click-to-copy row. Pass the full `did:ad:node:…`. */
  nodeId?: string;
  footer?: ReactNode;
  active?: boolean;
  /** The standalone spacing "This device" uses; the list cards sit tighter. */
  spacious?: boolean;
}

function SyncCard({
  icon,
  iconTone,
  title,
  titleHint,
  status,
  controls,
  subtitle,
  facts,
  children,
  nodeId,
  footer,
  active,
  spacious,
}: SyncCardProps): JSX.Element {
  const store = useStore();
  const shown = (facts ?? []).filter(f => !!f);

  return (
    <ConnCard $active={active} $spacious={spacious}>
      <CardIcon $tone={iconTone}>{icon}</CardIcon>
      <ConnBody>
        <ConnTopRow>
          <ConnTitle title={titleHint}>{title}</ConnTitle>
          {(status || controls) && (
            <ConnTopRight>
              {status && (
                <StatusPill $status={status.tone}>
                  {/* Drawn from the tone rather than passed in: the server card
                      had an icon and the peer cards did not, for no reason
                      anyone chose. */}
                  <StatusIcon status={status.tone} />
                  {status.label}
                </StatusPill>
              )}
              {controls}
            </ConnTopRight>
          )}
        </ConnTopRow>

        {subtitle && <ConnSub>{subtitle}</ConnSub>}

        {children}

        {shown.length > 0 && (
          <ConnMeta>
            {shown.map((fact, i) => (
              <Fragment key={i}>
                {i > 0 && ' · '}
                {fact}
              </Fragment>
            ))}
          </ConnMeta>
        )}

        {nodeId && (
          <NodeIdRow>
            <NodeIdLabel>Node ID</NodeIdLabel>
            <NodeIdValue
              title={`Copy ${nodeId}`}
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(nodeId);
                  toast.success('Node ID copied');
                } catch (e) {
                  // Written three ways before this, one of them swallowing the
                  // rejection: a denied clipboard looked like a dead button.
                  store.notifyError(e as Error);
                }
              }}
            >
              {nodeId}
            </NodeIdValue>
          </NodeIdRow>
        )}

        {footer && <ConnActions>{footer}</ConnActions>}
      </ConnBody>
    </ConnCard>
  );
}

/**
 * Keeps the previous object when a poll brought nothing new. `managedInfo` is a
 * dependency of the effects that ask the portal about the account and this
 * drive's enrollment, so a fresh object every five seconds made the page repeat
 * `/api/me` and `/api/sync-enrollments` for as long as it stayed open.
 */
function sameInfo(prev: ManagedInfo, next: ManagedInfo): ManagedInfo {
  return JSON.stringify(prev) === JSON.stringify(next) ? prev : next;
}

function SyncPage() {
  const store = useStore();
  const [status, setStatus] = useState<StoreSyncStatus>(() =>
    store.getSyncStatus(),
  );
  const [commitLog, setCommitLog] = useState<CommitLogEntry[]>(() =>
    store.getCommitLog(),
  );
  const [wsDebug, setWsDebug] = useState(
    () => localStorage.getItem('ws-debug') === '1',
  );
  const [clientDbOn, setClientDbOn] = useState(() => isClientDbEnabled());
  const { setServer, setDrive, baseURL } = useSettings();
  const { drive: requestedDrive } = SyncRoute.useSearch();
  const [hostedCopy, setHostedCopy] = useState<{
    drive: string;
    origin: string;
  } | null>(null);
  const hostedCopyOrigin =
    hostedCopy && hostedCopy.drive === status.drive ? hostedCopy.origin : null;
  useEffect(() => {
    if (requestedDrive && requestedDrive !== store.getDrive())
      setDrive(requestedDrive);
  }, [requestedDrive, setDrive, store]);
  const [knownServers, setKnownServers] = useState<string[]>(() =>
    serverURLStorage.getKnownServers(),
  );

  // New servers are persisted by `setServer` (through `serverURLStorage`), and
  // AppSettings registers the current origin on mount — neither can reach this
  // state, so without re-reading, a server you just added only shows up after a
  // reload. `baseURL` changes on every add and switch, which is the signal.
  useEffect(() => {
    setKnownServers(serverURLStorage.getKnownServers());
  }, [baseURL]);

  const [localNodeId, setLocalNodeId] = useState<string | null>(null);
  const [syncRetrying, setSyncRetrying] = useState(false);
  const [peerSyncing, setPeerSyncing] = useState(false);
  const [peerSyncResult, setPeerSyncResult] = useState<string | null>(null);
  const [promoting, setPromoting] = useState(false);
  // Cloud Server (SaaS) hosting state for the active drive. `null` = not yet
  // known / not applicable; `false` = eligible but not enrolled (show the CTA);
  // `true` = already enrolled (hide it).
  const [cloudEnrollment, setCloudEnrollment] =
    useState<ScopedDriveValue<boolean> | null>(null);
  // Only what THIS account has enrolled. Hosting belongs to the drive, so a
  // member who isn't the subscriber (or isn't signed in) can't learn it here;
  // `cloudEnrolled` below folds in what the node itself says about the drive.
  const accountEnrolled = currentDriveValue(
    cloudEnrollment,
    status.drive,
    status.serverUrl,
  );
  const [cloudBusy, setCloudBusy] = useState(false);
  // Why the automatic Cloud Server start failed, so the row can say so and
  // offer a retry instead of sitting on "Moving…" forever.
  const [autoEnrollError, setAutoEnrollError] = useState<string | null>(null);
  // The drive this page already tried to start Cloud Server for by itself.
  // Once per drive per visit: a failure gets a button, not a loop.
  const autoEnrollTried = useRef<string | null>(null);
  // Resolved in an effect rather than read off a Resource during render: the
  // React Compiler memoizes on the proxy identity, so a resource that finishes
  // loading would never re-render this.
  const [driveMissing, setDriveMissing] = useState(false);
  const [knownPeers, setKnownPeers] = useState<KnownPeer[]>(readKnownPeers);

  // What the server in use says about itself, read from its `/server` resource:
  // its node id and version, plus whether it is a managed node and where its
  // dashboard lives. The managed flag and portal URL are the ONLY things the
  // FOSS data-browser knows about "being managed" — self-hosted servers report
  // `managed:false` and no portal link is shown; anything plan/billing-specific
  // lives behind the link, on the operator's portal.
  const [managedInfo, setManagedInfo] = useState<ManagedInfo>(EMPTY_NODE_INFO);
  // Which server `managedInfo` was actually read from; `EMPTY_NODE_INFO` is
  // also what an unanswered poll looks like.
  const [managedInfoServer, setManagedInfoServer] = useState<string | null>(
    null,
  );

  // Cloud Vault. Assembling its prerequisites (wasm key ops, this install's
  // lane id, the signing agent) lives in the hook, which the wiped-device
  // onboarding screen uses too — both have to agree about whether a vault
  // exists for this drive.
  const vault = useDriveVault(status.drive ?? null);

  /**
   * Does this client need to link before it can reach the provider at all?
   *
   * True only when nothing is linked yet and `/api/me` says there is no
   * session — the state a self-hosted, desktop or Android client starts in,
   * and never the state of a browser served from the provider's own site.
   *
   * Deliberately not gated on the vault's own status: the vault reports
   * `unavailable` only once it has an agent, a drive and its wasm keys to ask
   * with. A fresh install has none of those and sits at `loading`, so gating
   * on it hid the one control that could have fixed the situation.
   */
  const [needsProviderLink, setNeedsProviderLink] = useState(false);

  /**
   * The provider account this client is signed in to, if any.
   *
   * Kept rather than reduced to a boolean because the account is what earns a
   * link back to the portal, and that relationship exists independently of any
   * managed node: Cloud Vault is blind backup and needs no hosting, so a user
   * can be signed in with nothing managed in sight.
   */
  const [managedAccount, setManagedAccount] = useState<ManagedAccount | null>(
    null,
  );

  const [subscriptionStatus, setSubscriptionStatus] = useState<string | null>(
    null,
  );
  const [serverAccessGranted, setServerAccessGranted] = useState(false);
  /**
   * Who made this drive's plan: `stripe` when the account paid for it, `grant`
   * when an operator added it by hand. Unknown from a control plane that does
   * not say yet, which is treated like a grant: asking once too often is
   * cheaper than hosting a readable copy nobody agreed to.
   */
  const [subscriptionSource, setSubscriptionSource] = useState<string | null>(
    null,
  );

  useEffect(() => {
    setSubscriptionStatus(null);
    setSubscriptionSource(null);
    setServerAccessGranted(false);
    if (!managedAccount || !status.drive) return;
    const drive = status.drive;
    const controller = new AbortController();
    managedFetch(`/billing/subscription?${new URLSearchParams({ drive })}`, {
      credentials: 'include',
      signal: controller.signal,
    })
      .then(async response => {
        if (!response.ok || response.status === 204) return;
        const subscription = await response.json();

        if (!controller.signal.aborted) {
          setServerAccessGranted(
            typeof subscription.server_access?.quota_bytes === 'number' &&
              subscription.server_access.quota_bytes > 0,
          );
          setSubscriptionStatus(
            subscription.plan === 'server' ? subscription.status : 'free',
          );
          setSubscriptionSource(
            typeof subscription.source === 'string'
              ? subscription.source
              : null,
          );
        }
      })
      .catch(() => {
        /* Unknown is not an unpaid subscription. */
      });

    return () => controller.abort();
  }, [managedAccount, status.drive]);

  /**
   * Where this account's encrypted backup actually is.
   *
   * Three answers, not two, because a backup on this device is not the thing
   * this row promises. `stored` means the control plane holds the sealed
   * envelope, which is what lets an email get you back in on hardware you do
   * not own yet. `device-only` means the sealed copy is in this browser and
   * nowhere else: a passkey still unlocks it here, and a lost laptop still
   * loses the account. Settings reads that local copy too, so a two-state
   * answer here had the two pages contradicting each other in plain sight.
   *
   * `passkey-only` is stored, but the only thing that opens it is a passkey.
   * That is the default onboarding leaves behind, and it is the case this row
   * used to describe as "this email gets you back in on a new device" — while
   * a browser the passkey never synced to (Firefox next to Safari, say)
   * offered nothing but a field for the agent secret. Nothing was lost, but
   * the promise was not kept, so the row must not be drawn as covered.
   *
   * `null` until asked, and on failure — "we could not check" is not "you have
   * none", and telling someone their recovery is missing when the control
   * plane was merely unreachable is the one wrong answer this row can give.
   */
  const [recoveryState, setRecoveryState] = useState<{
    account: ManagedAccount;
    value:
      | 'stored'
      | 'sign-in-not-on'
      | 'passkey-only'
      | 'device-only'
      | 'none'
      | null;
  } | null>(null);
  const recoveryBackup =
    recoveryState?.account === managedAccount
      ? (recoveryState?.value ?? null)
      : null;

  useEffect(() => {
    if (!managedAccount) return;

    const setRecoveryBackup = (
      value: NonNullable<typeof recoveryState>['value'],
    ) => setRecoveryState({ account: managedAccount, value });

    let cancelled = false;

    void (async () => {
      try {
        const stored = await getRecoverySecret();

        if (cancelled) return;

        if (stored) {
          const { hasPasskey, hasCode, hasAccount } =
            envelopeWrapperKinds(stored);

          if (hasAccount) {
            setRecoveryBackup('stored');

            return;
          }

          // A backup from before assisted recovery: signing in does not open
          // it yet, which is the whole promise of this row. Settings adds the
          // key with one passkey prompt or the code.
          const assisted =
            !managedAccount.assisted_recovery_off &&
            (await isAssistedRecoveryAvailable().catch(() => false));

          if (cancelled) return;

          setRecoveryBackup(
            assisted
              ? 'sign-in-not-on'
              : hasPasskey && !hasCode
                ? 'passkey-only'
                : 'stored',
          );

          return;
        }

        // Nothing on the server. Before calling that "no backup", ask whether
        // this browser is holding one, because that is the copy the settings
        // page reports and the difference between the two is exactly what the
        // reader needs told.
        const agentSubject = store.getAgent()?.subject;
        const cached = readCachedBackups();
        const mine = agentSubject
          ? cached.some(entry => sameAgent(entry.agent_subject, agentSubject))
          : cached.length > 0;

        setRecoveryBackup(mine ? 'device-only' : 'none');
      } catch {
        if (!cancelled) setRecoveryBackup(null);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [managedAccount, store]);

  useEffect(() => {
    let cancelled = false;

    let generation = 0;

    const refreshAccount = async () => {
      const requestGeneration = ++generation;
      // Asked even when this device is already linked. The link only settles
      // *how* this client authenticates; it says nothing about who, and the
      // portal link needs the account itself.
      const linked = isDeviceLinked();

      try {
        const account = await getManagedAccount();

        if (cancelled || requestGeneration !== generation) return;

        setManagedAccount(account);
        setNeedsProviderLink(!linked && account === null);
      } catch {
        // Unreachable control plane. Offering to link is the useful answer —
        // the alternative is a Sync page that silently omits backup with no
        // way to ask for it.
        if (!cancelled && requestGeneration === generation) {
          setManagedAccount(null);
          setNeedsProviderLink(!linked);
        }
      }
    };

    const onFocus = () => void refreshAccount();

    void refreshAccount();
    window.addEventListener('focus', onFocus);
    const unsubscribe = store.on(StoreEvents.AgentChanged, onFocus);

    return () => {
      cancelled = true;
      unsubscribe();
      window.removeEventListener('focus', onFocus);
    };
  }, [status.drive, store]);

  useEffect(() => {
    const serverUrl = status.serverUrl;

    if (!serverUrl) {
      setManagedInfo(EMPTY_NODE_INFO);

      return;
    }

    let cancelled = false;

    const poll = () =>
      fetchManagedInfo(serverUrl).then(info => {
        if (cancelled) return;

        setManagedInfo(prev => sameInfo(prev, info));
        setManagedInfoServer(serverUrl);
      });

    void poll();

    // Re-poll so a device connecting or dropping shows up without a reload —
    // `peer/live` is a moment-to-moment fact, not a one-time read. Version and
    // node id don't change, so this is cheap and idempotent.
    const timer = setInterval(poll, 5000);

    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [status.serverUrl]);

  // Re-read per server, never carried across a switch: a node id belongs to one
  // node, so a stale one on a server card would lie about who you're talking to.
  const serverNodeId = managedInfo.nodeId
    ? (nodeDidToRaw(managedInfo.nodeId) ?? null)
    : null;

  // Resource count + bytes from the connected node's `/drive-usage` — generic,
  // works on any atomic-server (self-hosted included). Signed with the agent
  // because the endpoint enforces read access to the drive.
  const [nodeUsageState, setNodeUsageState] =
    useState<ScopedDriveValue<NodeDriveUsage> | null>(null);
  const nodeUsage = currentDriveValue(
    nodeUsageState,
    status.drive,
    status.serverUrl,
  );

  // Hosting belongs to the drive: a member sees it whether or not their own
  // account pays for it, or is signed in at all.
  const hostedByNode = driveHostedByNode({
    managed: managedInfo.managed,
    liveSyncedDrive: !!status.drive && store.isLiveSyncedDrive(status.drive),
    refusedByServer: store.isDriveRefusedByServer(status.drive),
    status,
    resourceCount: nodeUsage?.resourceCount,
    enrolled: nodeUsage?.enrolled,
  });
  const cloudEnrolled = hostedByNode ? true : accountEnrolled;

  // Sign in with a secret on a fresh device and you get the identity but none
  // of the data. Detect that so the page can lead with "pair a device".
  useEffect(() => {
    const drive = status.drive;

    if (!drive || !store.getAgent()) {
      setDriveMissing(false);

      return;
    }

    let cancelled = false;

    deviceHasDriveData(store, drive).then(present => {
      if (!cancelled) {
        setDriveMissing(!present);
      }
    });

    return () => {
      cancelled = true;
    };
  }, [status.drive, store]);

  useEffect(() => {
    const drive = status.drive;
    const serverUrl = status.serverUrl;
    const agent = store.getAgent();

    // A local-only drive isn't on the server — asking for its usage 500s.
    if (
      !drive ||
      !serverUrl ||
      !agent ||
      cloudBusy ||
      store.isLocalOnlyDrive(drive)
    ) {
      setNodeUsageState(null);

      return;
    }

    let cancelled = false;
    fetchNodeDriveUsage(serverUrl, drive, agent)
      .then(usage => {
        if (!cancelled)
          setNodeUsageState(
            usage ? { drive, server: serverUrl, value: usage } : null,
          );
      })
      .catch(() => {
        if (!cancelled) setNodeUsageState(null);
      });

    return () => {
      cancelled = true;
    };
  }, [
    status.drive,
    status.serverUrl,
    status.lastDriveSync?.timestamp,
    cloudBusy,
    store,
  ]);

  // Plan quota — managed nodes only, from the control plane. Billing stays a
  // managed concern; the usage numbers above are generic to every node.
  const [quotaBytes, setQuotaBytes] = useState<number | null>(null);

  useEffect(() => {
    const drive = status.drive;

    if (!managedInfo.portalUrl || !drive || store.isLocalOnlyDrive(drive)) {
      setQuotaBytes(null);

      return;
    }

    let cancelled = false;
    getDriveUsage(drive)
      .then(info => {
        if (!cancelled) setQuotaBytes(info?.quotaBytes ?? null);
      })
      .catch(() => {
        if (!cancelled) setQuotaBytes(null);
      });

    return () => {
      cancelled = true;
    };
  }, [managedInfo.portalUrl, status.drive]);

  useEffect(() => {
    // Absolute origin, not a bare path: inside the Tauri webview a bare
    // `/server` resolves against `tauri.localhost` (the bundled assets), not
    // the embedded atomic-server — so the node identity (and the whole pairing
    // UI it gates) would never load on desktop/mobile.
    fetchManagedInfo(getLocalServerOrigin())
      .then(info => {
        if (!info.nodeId) return;

        const raw = nodeDidToRaw(info.nodeId);

        if (!raw) return;

        setLocalNodeId(raw);
      })
      .catch(() => {});
  }, []);

  // Does the active drive already have a Cloud Server enrollment? Drives the
  // Cloud Server CTA below. Skips entirely when no control plane is
  // reachable (pure self-hosted), so the CTA never shows there.
  useEffect(() => {
    const drive = status.drive;

    if (!drive || !isCloudSyncAvailable(managedInfo)) {
      setCloudEnrollment(null);

      return;
    }

    let cancelled = false;
    driveHasCloudEnrollment(drive)
      .then(has => {
        if (!cancelled)
          setCloudEnrollment({ drive, server: status.serverUrl, value: has });
      })
      .catch(() => {
        if (!cancelled) setCloudEnrollment(null);
      });

    return () => {
      cancelled = true;
    };
  }, [status.drive, status.serverUrl, managedInfo, managedAccount]);

  useEffect(() => {
    const refresh = () => setStatus(store.getSyncStatus());
    const unsubConnection = store.on(StoreEvents.ConnectionChanged, refresh);
    const unsubSync = store.on(StoreEvents.SyncStatusChanged, next =>
      setStatus(next),
    );
    const unsubCommitLog = store.on(StoreEvents.CommitLogChanged, next =>
      setCommitLog(next),
    );
    const unsubDrive = store.on(StoreEvents.DriveChanged, refresh);
    const unsubServer = store.on(StoreEvents.ServerURLChanged, refresh);

    return () => {
      unsubConnection();
      unsubSync();
      unsubCommitLog();
      unsubDrive();
      unsubServer();
    };
  }, [store]);

  const nodes = deriveNodeStatuses(status);

  // Whose code to show. Inside the Tauri shell this app is itself a node, so
  // it shows its own. A browser tab is not a node and never will be — but the
  // always-on device it is signed in to is one, and that is the device another
  // of yours should reach. Either way a code is a node id, and a node id needs
  // no address, port or certificate to dial: that is the point of Iroh.
  const isNode = isRunningInTauri();
  const pairNodeId = isNode ? localNodeId : serverNodeId;
  // A local-only drive (the demo, or any drive made offline) is a normal
  // drive the sync engine was simply told to skip — not a special code path.
  // When the active drive is local-only the "syncs with N places" story is a
  // lie for it, so the page leads with an honest, drive-specific state + the
  // option to start syncing it.
  const localOnlyDrive = !!status.drive && store.isLocalOnlyDrive(status.drive);
  // Whether this device holds a usable copy of the data on its own: the
  // embedded node (Tauri) or an enabled AND actually-running OPFS cache.
  // `clientDbOn` alone isn't enough — the toggle only takes effect after a
  // reload, and the worker can park in server-only mode (lock contention,
  // insecure context), in which case the server is still the only source.
  const hasWorkingLocalStore =
    isNode || (clientDbOn && status.clientDbReady && !status.clientDbError);
  const serverHostname = status.serverUrl
    ? new URL(status.serverUrl).hostname
    : undefined;
  const embeddedActive =
    isNode &&
    (serverHostname === 'localhost' || serverHostname === '127.0.0.1');
  // Show a server connection card whenever the active server isn't this
  // device's own embedded one (browser: always; Tauri: only a real remote) —
  // and is a server at all. The hosted build's shared origin is not (see
  // `originNode.ts`): counting it made a free-tier drive "sync with 1
  // other device" and call moving it to Cloud Server "a migration".
  const showServerConn =
    !!status.serverUrl &&
    !!status.drive &&
    store.isLiveSyncedDrive(status.drive) &&
    !embeddedActive &&
    !isOriginWithoutNode(status.serverUrl);
  const pairedPeers = isNode ? knownPeers : [];
  // A browser is not a node, so it cannot pair with a device itself. But the
  // server it reads from can — and reports who, over `/server`. So a phone
  // paired with your server shows up here, as the server sees it. These are
  // display-only: reaching them is the server's job, not this tab's.
  const serverPeers =
    !isNode && showServerConn ? (managedInfo.peers ?? []) : [];
  const connectionCount =
    (showServerConn ? 1 : 0) + pairedPeers.length + serverPeers.length;

  // Every known server, in one stable list — the active one is *styled*, not
  // moved. Rendering the active server as its own card above the rest made the
  // list reshuffle on every switch, which is disorienting. In the Tauri shell
  // the embedded localhost is "This device", not a connection, so it's excluded
  // there (same rule as `embeddedActive`).
  const connectionServers = knownServers.filter(server => {
    if (!isNode) {
      return true;
    }

    try {
      const { hostname } = new URL(server);

      return hostname !== 'localhost' && hostname !== '127.0.0.1';
    } catch {
      return false;
    }
  });

  // The source server copies remote drives in full; enrollment alone is not sync.
  const showCloudBackup =
    isCloudSyncAvailable(managedInfo) &&
    cloudEnrolled !== null &&
    !driveMissing;

  /**
   * Why Cloud Server can't be switched on from here, or null when it can.
   *
   * The row itself is unconditional once an account is known: a service that
   * vanishes when it is off cannot be discovered, and "is this on?" is exactly
   * the question this card exists to answer. But most of the reasons it can't
   * be enabled right now are about *this device* rather than about the
   * product, and saying which one is the difference between a page that reads
   * as broken and one that reads as informative.
   *
   * The order matters: each line assumes the ones above it are false. `null`
   * here is the same condition as `showCloudBackup`, by construction.
   */
  function cloudServerBlocker(): string | null {
    if (!status.drive) {
      return 'Open a drive to see whether it can be hosted.';
    }

    if (driveMissing) {
      return 'This device doesn’t have this drive yet. Pair the device that does, and you can host it from here.';
    }

    if (!isCloudSyncAvailable(managedInfo)) {
      return `${serverHostname ?? 'This server'} doesn’t offer hosting, so it can’t be switched on from here.`;
    }

    if (cloudEnrolled === null) {
      // The enrollment list needs a portal session. Without one the answer
      // never arrives, so say what would get it instead of waiting forever.
      return managedAccount
        ? 'Checking whether this drive is hosted…'
        : `Sign in to ${PRODUCT_NAME} to see whether this drive is hosted.`;
    }

    if (!isAtomicIdentifier(status.drive)) {
      return 'This drive uses a legacy server address. Cloud Server requires a portable DID drive.';
    }

    return null;
  }

  /** Evaluated once: three JSX call sites want the same answer. */
  const cloudServerBlocked = cloudServerBlocker();

  function summaryLine(): string {
    return syncSummary({
      missing: driveMissing,
      local: hasWorkingLocalStore,
      serverSync: showServerConn,
      hosting: cloudEnrolled,
      managed: isCloudSyncAvailable(managedInfo),
      vaultOn: vault.status.state === 'on',
    });
  }

  const cloudHosted = hasHostedDriveConnection(
    !!status.drive && store.isLiveSyncedDrive(status.drive),
    managedInfo.managed,
    cloudEnrolled,
    nodeUsage?.resourceCount,
  );

  /** The provider's own node, when this drive is on one. */
  const managedServer =
    connectionServers.find(server => isManagedServer(server)) ?? null;

  /** Is this one of ours? Mirrors `isCloud` inside the card renderer. */
  function isManagedServer(server: string): boolean {
    return sameOrigin(server, status.serverUrl) && cloudHosted;
  }

  /**
   * A sales-page link for one tier, carrying what it would apply to.
   *
   * The portal only lists prices today, but buying a tier is per drive (that is
   * how Cloud Server placement and Cloud Vault storage are both costed), so a
   * checkout will need to know which drive and which agent it is selling to.
   * Both identifiers are already on this page and both are public DIDs — the
   * agent's *secret* never leaves the device — so passing them costs nothing
   * now and saves the round trip later. Unknown values are omitted rather than
   * sent empty.
   */
  function tierOfferUrl(portalUrl: string, tier: 'vault' | 'server'): string {
    const url = new URL(portalUrl);
    url.searchParams.set('tier', tier);

    if (status.drive) url.searchParams.set('drive', status.drive);

    const agentSubject = store.getAgent()?.subject;

    if (agentSubject) url.searchParams.set('agent', agentSubject);

    url.hash = 'pricing';

    return url.toString();
  }

  /**
   * Where to send someone who holds an account.
   *
   * Same sources as the Cloud Server CTA, then the control plane a managed
   * node named earlier in this install's life. That fallback is what makes the
   * link work on a device whose active node is unmanaged — a desktop app on
   * its own embedded node, say — without inventing a URL for a node that has
   * never heard of a portal.
   */
  const accountPortalUrl =
    safePortalUrl(
      getManagedPortalUrl(managedInfo) ?? getRememberedManagedPortalUrl(),
    ) ?? null;

  async function promoteDrive() {
    if (!status.drive || promoting) return;
    setPromoting(true);

    try {
      await store.promoteLocalDrive(status.drive);
    } catch (e) {
      store.notifyError(e as Error);
    } finally {
      setPromoting(false);
    }
  }

  /**
   * Enroll this drive with Cloud Server and point this device at it.
   *
   * `auto` is the run nobody clicked: a paid plan, or an enrollment this
   * device has not caught up with. It must not open a sign-in window or leave
   * for checkout on its own, so those cases become an error on the row.
   */
  async function backupToCloud({ auto = false }: { auto?: boolean } = {}) {
    const drive = status.drive;
    const agent = store.getAgent();
    // Enrollment is keyed on the agent's subject: without one there is no
    // identity to attach the backup to.
    const agentSubject = agent?.subject;

    if (!drive || !agentSubject || cloudBusy) return;

    setCloudBusy(true);

    try {
      const args = {
        store,
        drive,
        agentSubject,
        setServer,
        managedInfo,
        hostingConsentAccepted: true,
        sourceServer:
          !localOnlyDrive &&
          status.serverUrl &&
          !isOriginWithoutNode(status.serverUrl)
            ? status.serverUrl
            : undefined,
      };
      let result = await enableCloudSyncForDrive(args);

      if (!result.ok && auto) {
        setAutoEnrollError(
          `Sign in to your ${PRODUCT_NAME} account to start Cloud Server.`,
        );

        return;
      }

      if (!result.ok) {
        // No account/session yet. Open the portal (in-app window on desktop,
        // popup on web) so the user signs in / creates an account there; it
        // shares our cookie jar, so once done we just retry — no token handoff.
        if (!result.portalUrl) {
          reportUserFacingFailure('Cloud Server setup: no portal configured', {
            drive,
            server: status.serverUrl,
          });
          toast.error(
            `No ${PRODUCT_NAME} portal is configured for this server.`,
          );

          return;
        }

        const signedIn = await ensureManagedSession(result.portalUrl);

        if (!signedIn) {
          toast(`Sign-in wasn’t completed — hosting setup was cancelled.`);

          return;
        }

        result = await enableCloudSyncForDrive(args);

        if (!result.ok) {
          reportUserFacingFailure('Cloud Server setup failed after sign-in', {
            drive,
            server: status.serverUrl,
            reason: result.reason,
          });
          toast.error(`Could not set up Cloud Server.`);

          return;
        }
      }

      setCloudEnrollment({
        drive: status.drive!,
        server: status.serverUrl,
        value: true,
      });
      if (result.replicated)
        setHostedCopy({ drive, origin: result.httpOrigin });

      // A manual run shows its result in the connection card. The automatic
      // run nobody clicked is announced.
      if (auto) {
        toast.success(
          result.replicated
            ? 'Cloud Server received this drive. Your source server is still connected.'
            : 'Connected to Cloud Server. Syncing this drive…',
        );
      }
    } catch (e) {
      // The manual path ends in `store.notifyError`, which Sentry already
      // gets. The automatic one only fills an inline message.
      if (auto && !(e instanceof HostingPaymentRequiredError)) {
        reportUserFacingFailure('Cloud Server setup failed on its own', {
          drive,
          server: status.serverUrl,
          error: e instanceof Error ? e.message : String(e),
        });
      }

      if (auto) {
        setAutoEnrollError(
          e instanceof HostingPaymentRequiredError
            ? 'This drive’s plan does not include Cloud Server yet.'
            : e instanceof Error
              ? e.message
              : 'Could not start Cloud Server.',
        );
      } else if (e instanceof HostingPaymentRequiredError) {
        if (!accountPortalUrl) {
          store.notifyError(
            new Error(
              `No ${PRODUCT_NAME} portal is configured for this server.`,
            ),
          );

          return;
        }

        const billingUrl = new URL('/billing', accountPortalUrl);
        billingUrl.searchParams.set('drive', drive);

        if (isRunningInTauri()) {
          await openExternal(billingUrl.toString());
        } else {
          window.location.assign(billingUrl.toString());
        }
      } else {
        store.notifyError(e as Error);
      }
    } finally {
      setCloudBusy(false);
    }
  }

  const cloudTier: CloudTier =
    managedServer || hostedCopyOrigin
      ? 'server'
      : vault.status.state === 'on'
        ? 'vault'
        : 'local';
  const planActive =
    subscriptionStatus === 'active' || subscriptionStatus === 'trialing';
  /**
   * Cloud Server should just work for a drive whose owner paid for it (the
   * checkout already said what hosting means), and for a drive that is
   * enrolled but that this device has not switched to yet. Either way there is
   * nothing left for the person to decide, so no button.
   */
  const autoEnroll =
    !managedServer &&
    !hostedCopyOrigin &&
    !cloudServerBlocked &&
    !!managedAccount &&
    // The account's own enrollment: a member of someone else's hosted drive
    // has nothing to start.
    shouldAutoEnroll({
      accountEnrolled,
      nodeInfoLoaded: managedInfoServer === status.serverUrl,
      currentServerManaged: managedInfo.managed,
      paidPlanActive: planActive && subscriptionSource === 'stripe',
    });
  /**
   * The one case that still asks: a plan that was not bought, such as Cloud
   * Server added by hand by an operator. Hosting stores the drive readable on
   * our servers, so it waits for the owner's word.
   */
  const needsHostingConsent =
    !managedServer &&
    !hostedCopyOrigin &&
    !cloudServerBlocked &&
    cloudEnrolled === false &&
    (serverAccessGranted || (planActive && subscriptionSource !== 'stripe'));

  useEffect(() => {
    const drive = status.drive;

    if (!autoEnroll || !drive || cloudBusy) return;

    if (autoEnrollTried.current === drive) return;

    autoEnrollTried.current = drive;
    setAutoEnrollError(null);
    void backupToCloud({ auto: true });
  }, [autoEnroll, status.drive, cloudBusy]);

  /** Point the app at `server` and reconnect. `setServer` runs through
   * `store.setServerUrl`, which reopens the WebSocket — the connection card
   * then reflects the new server's status. */
  function switchToServer(server: string) {
    if (server === baseURL) {
      return;
    }

    try {
      setServer(server);
    } catch (e) {
      store.notifyError(e as Error);
    }
  }

  /**
   * Cloud Server's row, as one state. Each state fills the same slots of
   * `ServiceRow`, so the row only ever changes what it says, never its shape.
   */
  const serverRow: {
    state: 'on' | 'copied' | 'moving' | 'failed' | 'offered' | 'off';
    standing: ServiceStanding | null;
    status: { tone: ServiceTone; text: ReactNode } | null;
    details?: ReactNode;
    actions: ReactNode;
  } = (() => {
    // Hosting belongs to the drive, but the plan belongs to whoever pays for
    // it. Unknown (not yet loaded, or no session) counts as not paying: a
    // member should never be offered another account's controls.
    const paysForDrive =
      subscriptionStatus !== null && subscriptionStatus !== 'free';
    const managePlan = paysForDrive && accountPortalUrl && status.drive && (
      <Button
        subtle
        data-testid='cloud-server-manage'
        onClick={() =>
          void openExternal(driveBillingUrl(accountPortalUrl, status.drive))
        }
      >
        Manage plan
      </Button>
    );

    if (managedServer) {
      const tone = nodes.server;

      return {
        state: 'on',
        standing: 'current',
        status: {
          tone:
            tone === 'synced'
              ? 'ok'
              : tone === 'offline'
                ? 'error'
                : tone === 'unknown'
                  ? 'muted'
                  : 'busy',
          text: `${serverStatusLabel(tone, !!nodeUsage)} · ${serverHostname ?? managedServer}`,
        },
        details: status.drive ? (
          <CloudServerDetails
            key={status.drive}
            drive={status.drive}
            usage={nodeUsage}
            quotaBytes={quotaBytes}
            signedIn={!!managedAccount}
            managed={paysForDrive}
            managedBy={nodeUsage?.managedBy}
          />
        ) : undefined,
        actions: managePlan,
      };
    }

    if (hostedCopyOrigin) {
      return {
        state: 'copied',
        standing: 'current',
        status: {
          tone: 'waiting',
          text: 'This drive is on Cloud Server. This device still syncs with its old server.',
        },
        actions: (
          <>
            <Button onClick={() => switchToServer(hostedCopyOrigin)}>
              Use Cloud Server
            </Button>
            {managePlan}
          </>
        ),
      };
    }

    if (autoEnroll && autoEnrollError) {
      return {
        state: 'failed',
        standing: 'current',
        status: { tone: 'error', text: autoEnrollError },
        actions: (
          <>
            <Button
              onClick={() => {
                setAutoEnrollError(null);
                void backupToCloud();
              }}
              disabled={cloudBusy}
            >
              {cloudBusy ? 'Trying again…' : 'Try again'}
            </Button>
            {managePlan}
          </>
        ),
      };
    }

    if (autoEnroll || cloudBusy) {
      return {
        state: 'moving',
        standing: 'current',
        status: {
          tone: 'busy',
          text: 'Moving this drive to Cloud Server. It switches on by itself; you can keep working.',
        },
        actions: managePlan,
      };
    }

    if (needsHostingConsent) {
      return {
        state: 'offered',
        standing: 'offered',
        status: {
          tone: 'waiting',
          text:
            serverAccessGranted || subscriptionSource === 'grant'
              ? `${PRODUCT_NAME} added Cloud Server to this drive. It waits for your consent.`
              : 'This drive’s plan includes Cloud Server. It waits for your consent.',
        },
        actions: (
          <Button
            data-testid='cloud-server-accept'
            onClick={() => void backupToCloud()}
            disabled={cloudBusy}
          >
            Turn on Cloud Server
          </Button>
        ),
      };
    }

    return {
      state: 'off',
      standing: null,
      status: cloudServerBlocked
        ? { tone: 'muted', text: cloudServerBlocked }
        : null,
      actions:
        !cloudServerBlocked && accountPortalUrl && status.drive ? (
          <Button
            data-testid='cloud-server-upgrade'
            onClick={() =>
              void openExternal(driveBillingUrl(accountPortalUrl, status.drive))
            }
          >
            Upgrade to Cloud Server
          </Button>
        ) : undefined,
    };
  })();

  function savePeers(peers: KnownPeer[]) {
    setKnownPeers(peers);
    writeKnownPeers(peers);
  }

  async function disconnectServerPeer(nodeId: string) {
    const agent = store.getAgent();
    const serverUrl = status.serverUrl;

    if (!agent || !serverUrl) return;

    // Drop it locally right away so the card disappears; the server forgets the
    // reconnect entry and closes the live connection. A refetch reconciles.
    setManagedInfo(prev => ({
      ...prev,
      peers: (prev.peers ?? []).filter(p => p.nodeId !== nodeId),
    }));

    const ok = await forgetServerPeer(serverUrl, nodeId, agent);

    if (!ok) {
      setPeerSyncResult('Error: could not disconnect that device');
    }

    fetchManagedInfo(serverUrl).then(setManagedInfo);
  }

  async function syncWithPeer(input: string) {
    if (!input || !status.drive) return;

    // A pasted atomic://pair link is routing sugar for the same thing: pull
    // the node identity out of the envelope.
    let nodeDid = input;

    if (input.startsWith(PAIRING_URI_PREFIX)) {
      try {
        nodeDid = decodePairingEnvelope(input).node;
      } catch (e) {
        setPeerSyncResult(
          `Error: ${e instanceof PairingEnvelopeError ? e.message : e}`,
        );

        return;
      }
    }

    const rawNodeId = nodeDidToRaw(nodeDid);

    if (!rawNodeId) {
      setPeerSyncResult('Error: Expected atomic:node:<node-id>');

      return;
    }

    const canonicalNodeDid = rawToNodeDid(rawNodeId);

    // The node only dials a peer for an agent with write rights on the drive,
    // so the request is signed — there is nothing to send without one.
    const agent = store.getAgent();

    if (!agent) {
      setPeerSyncResult('Error: Sign in before syncing with another device');

      return;
    }

    setPeerSyncing(true);
    setPeerSyncResult(null);

    try {
      const syncUrl = `${getLocalServerOrigin()}/iroh-sync`;
      const headers = await signRequest(syncUrl, agent, {
        'Content-Type': 'application/json',
      });
      const res = await fetch(syncUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify({ nodeId: canonicalNodeDid, drive: status.drive }),
      });
      // A refusal (401/403) may not carry JSON; still say what happened.
      const data = await res
        .json()
        .catch(() => ({ error: `${res.status} ${res.statusText}`.trim() }));

      if (data.error) {
        setPeerSyncResult(`Error: ${data.error}`);
      } else {
        // `peerName` is the remote's self-reported HELLO label. New servers
        // populate it; older builds return null. Fall back to the truncated
        // Node DID so the entry always has *something* to display.
        const peerName: string | undefined =
          typeof data.peerName === 'string' && data.peerName.trim()
            ? data.peerName.trim()
            : undefined;
        const didFallback = `${nodeSubject(rawNodeId).slice(0, 20)}...`;
        // Say what moved in each direction. A pass that sends 49 and receives 1
        // is not "1 resource synced", and reporting it that way hides whether
        // the link works at all.
        const received: number =
          typeof data.count === 'number' ? data.count : 0;
        const sent: number = typeof data.pushed === 'number' ? data.pushed : 0;
        const withWhom = peerName ? ` with ${peerName}` : '';
        const msg =
          received === 0 && sent === 0
            ? `Already up to date${withWhom}`
            : `Synced${withWhom} — sent ${sent}, received ${received}`;
        setPeerSyncResult(msg);

        const existing = knownPeers.findIndex(
          p => nodeDidToRaw(p.nodeId) === rawNodeId,
        );
        const entry: KnownPeer = {
          nodeId: canonicalNodeDid,
          label: peerName ?? didFallback,
          lastSync: new Date().toISOString(),
        };

        if (existing >= 0) {
          const updated = [...knownPeers];
          updated[existing] = entry;
          savePeers(updated);
        } else {
          savePeers([...knownPeers, entry]);
        }
      }
    } catch (e) {
      setPeerSyncResult(`Error: ${e}`);
    }

    setPeerSyncing(false);
  }

  function removePeer(nodeId: string) {
    savePeers(knownPeers.filter(p => p.nodeId !== nodeId));
  }

  function removeServer(server: string) {
    serverURLStorage.removeKnownServer(server);
    setKnownServers(serverURLStorage.getKnownServers());
  }

  // Why this drive is not syncing, if it is not. A local-only drive is
  // not supposed to be, so it has nothing to explain.
  const syncProblemInput = {
    status,
    refusedByServer: store.isDriveRefusedByServer(status.drive),
    entries: store.outbox.pending(),
    serverName: serverLabel(status.serverUrl ?? ''),
    driveOf: (subject: string) => store.driveOfSubject(subject),
  };
  const syncProblem = localOnlyDrive
    ? null
    : describeSyncProblem(syncProblemInput);
  const syncProblemKey = syncProblem?.key;
  const syncProblemOurs = syncProblem?.cause === 'ours';
  const syncProblemReported = syncProblem?.reported ?? true;
  const syncProblemDetail = syncProblem?.detail;

  // A commit that keeps failing is already reported by the outbox. Everything
  // else we own is reported here, once.
  useEffect(() => {
    if (syncProblemKey && syncProblemOurs && !syncProblemReported) {
      reportSyncProblem({
        key: syncProblemKey,
        server: status.serverUrl,
        detail: syncProblemDetail,
      });
    }
  }, [
    syncProblemKey,
    syncProblemOurs,
    syncProblemReported,
    syncProblemDetail,
    status.serverUrl,
  ]);

  // A drive the server refuses may be one nobody hosts; the app then moves it
  // to browser-only when the refusal is seen again. The refusal that triggered
  // the first look may have come too early, so re-arm the drive's parked
  // changes once per visit to hand the app another chance.
  const rearmedRefusedDrive = useRef<string | null>(null);
  const refusedDrive =
    !localOnlyDrive &&
    status.drive &&
    store.isDriveRefusedByServer(status.drive)
      ? status.drive
      : undefined;

  useEffect(() => {
    if (!refusedDrive || rearmedRefusedDrive.current === refusedDrive) return;

    rearmedRefusedDrive.current = refusedDrive;

    for (const entry of store.outbox.pending()) {
      if (
        entry.blocked &&
        store.driveOfSubject(entry.subject) === refusedDrive
      ) {
        store.outbox.markDirty(entry.subject);
      }
    }
  }, [refusedDrive, store]);

  async function tryAgainSync() {
    if (syncRetrying) return;

    setSyncRetrying(true);

    // A parked change is only sent again after a fresh signal. Reconnecting
    // repeats the drive handshake, which also retries a refused sync.
    for (const entry of store.outbox.pending()) {
      if (entry.blocked) store.outbox.markDirty(entry.subject);
    }

    try {
      await store.reconnect();
    } catch (e) {
      store.notifyError(e as Error);
    }

    setSyncRetrying(false);
  }

  return (
    <Main>
      <ContainerNarrow>
        <h1>Sync</h1>
        <Lead>{summaryLine()}</Lead>
        {syncProblem && (
          <SyncProblemBanner
            problem={syncProblem}
            notified={isErrorReportingEnabled()}
            retrying={syncRetrying}
            onTryAgain={() => void tryAgainSync()}
          />
        )}
        {/* Everything our paid services own, in one card.

            These used to be loose entries in the Devices list, on the reasoning
            that a person does not think of "this device", "the backup" and "the
            hosted drive" as different kinds of thing — they are all places
            the same data lives. True as far as it goes, but it left no answer to
            a different question the page is also asked: which of this is a
            product I am paying for, and where do I go to manage it. Grouping
            under the account answers that without returning to the old stack of
            free-floating offer cards, because this is one card, not three.

            Gated on a portal being known at all, so a self-hosted node with no
            control plane renders none of it. That URL comes from a managed
            node, a build-time override, or one a node named earlier — never
            from anything hardcoded here. */}
        {/* Everything our paid services own, in one card.

            The top is the account, not a service: whose services these are,
            who is signed in and whether email recovery is set up, with the
            way out to the portal. Below it, the drive's place on one ladder:
            on this device, then Cloud Vault (encrypted backup we cannot read),
            then Cloud Server (hosting on top of that backup). Cloud Server is
            the step up from Cloud Vault, not a second product next to it.

            Gated on a portal being known at all, so a self-hosted node with no
            control plane renders none of it. That URL comes from a managed
            node, a build-time override, or one a node named earlier, never
            from anything hardcoded here. */}
        {accountPortalUrl && (
          <ProviderCard data-testid='provider-card'>
            <ProviderHeader>
              <CardIcon $tone='provider'>
                <FaCloud />
              </CardIcon>
              <AccountBody>
                <AccountLabel>{PRODUCT_NAME}</AccountLabel>
                <AccountEmail data-testid='provider-account'>
                  {managedAccount
                    ? recoveryBackup === 'stored'
                      ? `${managedAccount.email} · Email recovery on`
                      : managedAccount.email
                    : 'Not signed in'}
                </AccountEmail>
              </AccountBody>
              {/* Signed in, the dashboard rather than the portal root, which
                  is the marketing page. Signed out, `/signin` both creates an
                  account and returns to an existing one. */}
              <ManagedLink
                data-testid='provider-portal-link'
                {...externalLinkProps(
                  managedAccount
                    ? `${accountPortalUrl}/dashboard`
                    : `${accountPortalUrl}/signin`,
                )}
              >
                {managedAccount ? 'Manage account →' : 'Sign in →'}
              </ManagedLink>
            </ProviderHeader>

            {/* Only when it needs you: signed out, or no backup that gets you
                back in on a new device. Set up, it is one phrase in the
                header; unknown, the header just shows the account. */}
            {(!managedAccount ||
              recoveryBackup === 'none' ||
              recoveryBackup === 'device-only' ||
              recoveryBackup === 'sign-in-not-on' ||
              recoveryBackup === 'passkey-only') && (
              <ProviderService data-testid='recovery-row'>
                <CardIcon
                  $tone={
                    managedAccount && recoveryBackup === 'stored'
                      ? 'provider'
                      : 'neutral'
                  }
                >
                  <FaKey />
                </CardIcon>
                <ConnBody>
                  <ConnTitle>Email recovery</ConnTitle>
                  <ConnSub>
                    {!managedAccount
                      ? `Sign in to your ${PRODUCT_NAME} account to check email recovery. Signing in to this drive with a passkey or secret does not by itself connect your cloud account.`
                      : recoveryBackup === null
                        ? `Signed in as ${managedAccount.email}.`
                        : recoveryBackup === 'stored'
                          ? `${managedAccount.email}. We hold your key sealed, so this email gets you back in on a new device.`
                          : recoveryBackup === 'sign-in-not-on'
                            ? `${managedAccount.email}. We hold your key sealed, but signing in does not open it yet. Confirm once with your passkey or recovery code to turn that on.`
                            : recoveryBackup === 'passkey-only'
                              ? `${managedAccount.email}. We hold your key sealed, but only your passkey opens it. A browser your passkey has not synced to cannot get you back in — a recovery code would.`
                              : recoveryBackup === 'device-only'
                                ? `${managedAccount.email}. Your backup is sealed in this browser and nowhere else, so it unlocks here but a new device could not get you back in.`
                                : `${managedAccount.email}. No recovery backup stored, so losing every device loses this drive.`}
                  </ConnSub>
                  {/* Signed out, the account itself is the missing piece, and it
                      is made in the portal: on a device that cannot hold our
                      cookie the sign-in is approved from a browser anyway.

                      Signed in with nothing stored, the flow is in settings,
                      where the rest of account recovery already lives. It asks
                      for the agent secret, which this page has no business
                      collecting in a status row, and it cannot avoid asking: the
                      key is non-extractable in the browser, so the copy the user
                      saved at setup is the only one that can still be sealed.

                      Nothing to press once it is on. Rotating a code or reading
                      the secret back are settings' business, and this row's job
                      is answering whether you are covered. */}
                  {!managedAccount ? (
                    <ConnActions>
                      <LearnMore
                        {...externalLinkProps(`${accountPortalUrl}/signin`)}
                      >
                        Sign in to check recovery
                      </LearnMore>
                    </ConnActions>
                  ) : recoveryBackup === 'none' ||
                    recoveryBackup === 'device-only' ||
                    recoveryBackup === 'sign-in-not-on' ||
                    recoveryBackup === 'passkey-only' ? (
                    <ConnActions>
                      <LearnMoreLink
                        to={paths.agentSettings}
                        data-testid='recovery-row-action'
                      >
                        {recoveryBackup === 'device-only'
                          ? 'Store it with ' + PRODUCT_NAME
                          : recoveryBackup === 'sign-in-not-on'
                            ? 'Turn it on'
                            : recoveryBackup === 'passkey-only'
                              ? 'Add a recovery code'
                              : 'Set up email recovery'}
                      </LearnMoreLink>
                    </ConnActions>
                  ) : null}
                </ConnBody>
              </ProviderService>
            )}

            {/* The plan as steps: Cloud Vault, then Cloud Server on top of
                it. Both are the same `ServiceRow`, so they read the same way:
                name and standing, what it is, what you get, how it is doing,
                what you can do. Where the drive's data syncs is the Devices
                list's business, further down. */}
            <PlanLabelRow data-testid='cloud-tier' data-tier={cloudTier}>
              <PlanLabel>Your plan</PlanLabel>
              <LearnMore
                {...externalLinkProps(tierOfferUrl(accountPortalUrl, 'server'))}
              >
                See plans
              </LearnMore>
            </PlanLabelRow>
            <ServiceRows>
              <VaultPanel
                vault={vault}
                included={serverRow.standing === 'current'}
                onRestored={() => window.location.reload()}
              />
              <ServiceRow
                data-testid='cloud-server-row'
                data-state={serverRow.state}
                kind='server'
                title='Cloud Server'
                standing={serverRow.standing}
                tagline='Everything in Cloud Vault, plus a hosted drive on atomic.place, always online. Our servers process what you put here.'
                points={[
                  'Shareable links and API access',
                  'Search across everything',
                  'No need for another device to be awake',
                ]}
                status={serverRow.status}
                details={serverRow.details}
                notice={
                  serverRow.state === 'offered' ? (
                    <>
                      <strong>Before you turn it on:</strong> unlike Cloud
                      Vault, Cloud Server stores a readable, unencrypted copy of
                      this drive on our servers, so we can run search, shareable
                      links and the API for it. Your sharing permissions still
                      control who else sees it, and you can turn it off at any
                      time.
                    </>
                  ) : undefined
                }
                actions={serverRow.actions}
              />
            </ServiceRows>
            {/* Credits belong to the account, not to a plan or a drive: shown
                with or without a Cloud Server, only while signed in. */}
            {managedAccount && <ProviderAICredits />}
          </ProviderCard>
        )}

        {/* A failed read gives no evidence about copies on other devices. */}
        {driveMissing && (
          <LocalDriveNotice>
            <CardIcon>
              <FaMobileScreenButton />
            </CardIcon>
            <ConnBody>
              <ConnTitle>This drive could not be read on this device</ConnTitle>
              {isNode && status.drive ? (
                <DiscoverWorkspace
                  key={status.drive}
                  drive={status.drive}
                  onConnected={() => setDriveMissing(false)}
                />
              ) : (
                <>
                  <ConnSub>
                    {/* Either code below brings it over: this device's when it is a
                    node, otherwise the server's — the other device scans it and
                    syncs the drive somewhere this one can read. */}
                    {pairNodeId
                      ? 'If another device has this drive, scan the code below to connect it.'
                      : 'If another device has this drive, you can connect it.'}
                  </ConnSub>
                  <ConnActions>
                    {!pairNodeId && (
                      <Button onClick={focusConnectDevice}>
                        Connect a device
                      </Button>
                    )}
                  </ConnActions>
                </>
              )}
            </ConnBody>
          </LocalDriveNotice>
        )}

        {/* Cloud Vault first: it is what a managed account gets by default, and
            it is the promise we can make unconditionally — blind encrypted
            backup we cannot read. It hides itself entirely when we cannot
            determine its status, so a missing session never renders a dead
            button. */}

        {/* A local-only drive (demo, or any drive made offline) isn't synced.
            Offer to promote it to a normal synced drive on the connected
            server — the same reconcile a regular drive uses, no special path. */}
        {localOnlyDrive && !driveMissing && !showCloudBackup && (
          <LocalDriveNotice>
            {/* Nothing is synced yet, which is the whole point of the notice,
                so the glyph stays neutral. The button carries the invitation. */}
            <CardIcon>
              <FaCloudArrowUp />
            </CardIcon>
            <ConnBody>
              <ConnTitle>Only on this device</ConnTitle>
              <ConnSub>
                This drive hasn’t been synced. It’s safe here, but not backed up
                and not on your other devices.
              </ConnSub>
              <ConnActions>
                <Button
                  onClick={promoteDrive}
                  disabled={promoting || !status.serverConnected}
                >
                  {promoting ? 'Syncing…' : 'Sync this drive'}
                </Button>
              </ConnActions>
              {!status.serverConnected && (
                <ConnMeta>Connect a device below first.</ConnMeta>
              )}
            </ConnBody>
          </LocalDriveNotice>
        )}

        <Section id='sync-devices'>
          <SectionTitle>Devices</SectionTitle>

          {/* Devices only. The hosted services moved up into the provider
              card, which is a narrower split than the one this list was
              built to avoid: that earlier layout scattered them as separate
              offer cards, where they are now one card under the account that
              pays for them. What is left here is an inventory of places this
              drive physically lives. */}
          {/* This device — always the source of truth for local-first data. */}
          <SyncCard
            spacious
            icon={<FaLaptop />}
            title='This device'
            footer={<BrowserPeerPanel drive={status.drive ?? undefined} />}
            subtitle={
              driveMissing
                ? 'Local copy unavailable'
                : isNode
                  ? status.lastDriveSync
                    ? `${status.lastDriveSync.count.toLocaleString()} resources · stored locally`
                    : 'Embedded server · stored locally'
                  : clientDbOn
                    ? 'Cached locally · works offline'
                    : 'Server-only · no local cache'
            }
            nodeId={isNode && localNodeId ? localNodeId : undefined}
          />

          {/* A client that cannot hold the provider's cookie — a self-hosted
              origin, or the desktop and Android apps on tauri://localhost — has
              to link before any of the vault works.

              Gated on whether this client has a session, not on what the vault
              says. The vault reports `unavailable` only once it has an agent, a
              drive and its wasm keys to ask with; a fresh install has none of
              those and sits at `loading` forever, so gating on the vault hid the
              one control that could have fixed it. */}
          {needsProviderLink && (
            <LinkProviderPanel
              portalUrl={getManagedPortalUrl(managedInfo)}
              onLinked={() => window.location.reload()}
            />
          )}

          {localOnlyDrive && connectionCount > 0 && (
            <ConnNote>These sync your other drives — not this drive.</ConnNote>
          )}

          {/* About *other* devices specifically. This device and any cloud
              services are listed above, so the old "not syncing anywhere"
              wording now sat under entries proving otherwise. */}
          {!driveMissing &&
            connectionCount === 0 &&
            connectionServers.length === 0 && (
              <EmptyConnections>
                <p>No other devices yet — your data is safe on this one.</p>
                <p>
                  {isNode
                    ? 'Pair another device to sync directly, or connect an always-on one to reach your data from anywhere.'
                    : 'Connect an always-on device to back up your data and reach it from anywhere.'}
                </p>
              </EmptyConnections>
            )}

          {/* Every server, Cloud Server included, in one stable list; the
              active one is marked, not moved. The plan card above answers
              "what am I paying for"; this list answers "where does this drive
              sync", for ours and everyone else's alike. */}
          {connectionServers
            .filter(
              server =>
                isManagedServer(server) ||
                showSavedServer({
                  managed: isCloudSyncAvailable(managedInfo),
                  activeForDrive:
                    (showServerConn ||
                      (localOnlyDrive && cloudEnrolled === false)) &&
                    sameOrigin(server, status.serverUrl),
                }),
            )
            .map(server => (
              <ServerCard
                key={server}
                server={server}
                status={status}
                managedInfo={managedInfo}
                cloudHosted={cloudHosted}
                cloudEnrolled={cloudEnrolled}
                serverStatus={nodes.server}
                hasWorkingLocalStore={hasWorkingLocalStore}
                nodeUsage={nodeUsage}
                quotaBytes={quotaBytes}
                serverNodeId={serverNodeId}
                onSwitch={switchToServer}
                onRemove={removeServer}
              />
            ))}

          {/* Paired devices (Iroh peers).

              Status comes from THIS device's own server rather than the local
              `atomic-peers` record: that record only updates when the user
              presses "Sync now", so it reported "synced 5 hours ago" about a
              link that was live and exchanging data. The server knows whether
              the peer is connected right now and when it last synced. */}
          {pairedPeers.map(peer => {
            const reported = serverPeers.find(
              p => nodeDidToRaw(p.nodeId) === nodeDidToRaw(peer.nodeId),
            );
            const lastSynced = reported?.lastSeen ?? peer.lastSync;

            return (
              <SyncCard
                key={peer.nodeId}
                icon={<FaMobileScreenButton />}
                title={peer.label}
                titleHint={peer.nodeId}
                status={{
                  tone: reported?.live ? 'synced' : 'unknown',
                  label: reported?.live ? 'Connected' : 'Paired',
                }}
                controls={
                  <NodeAction
                    onClick={() => syncWithPeer(peer.nodeId)}
                    disabled={peerSyncing}
                  >
                    {peerSyncing ? 'Syncing…' : 'Sync now'}
                  </NodeAction>
                }
                subtitle='Paired device'
                facts={[
                  lastSynced
                    ? `Synced ${formatTimeAgo(new Date(lastSynced)) ?? 'just now'}`
                    : 'Not synced yet',
                  // Only what this side actually counted — the accepting node
                  // answers frames through the engine and does not tally what
                  // it served, and a fabricated 0 would be the same lie this
                  // is meant to remove.
                  reported?.lastSent !== undefined &&
                    `sent ${reported.lastSent}`,
                  reported?.lastReceived !== undefined &&
                    `received ${reported.lastReceived}`,
                ]}
                footer={
                  <NodeActionSubtle onClick={() => removePeer(peer.nodeId)}>
                    Remove
                  </NodeActionSubtle>
                }
              />
            );
          })}

          {/* Devices paired with the server this browser reads from — a phone
              that scanned the code. The server reports them; this tab only
              shows them. */}
          {serverPeers.map(peer => {
            const raw = nodeDidToRaw(peer.nodeId);
            const name =
              peer.deviceName ?? (raw ? `${raw.slice(0, 12)}…` : peer.nodeId);

            return (
              <SyncCard
                key={peer.nodeId}
                icon={<FaMobileScreenButton />}
                title={name}
                titleHint={peer.nodeId}
                status={{
                  tone: peer.live ? 'synced' : 'unknown',
                  label: peer.live ? 'Connected' : 'Offline',
                }}
                controls={
                  <NodeAction onClick={() => disconnectServerPeer(peer.nodeId)}>
                    Disconnect
                  </NodeAction>
                }
                subtitle={`Paired with ${serverLabel(status.serverUrl ?? '')}`}
                facts={[
                  // "Connected" only says a socket is open. Say when data last
                  // actually moved, so a link that is up but carrying nothing
                  // is distinguishable from a healthy one.
                  peer.lastSeen
                    ? `Synced ${formatTimeAgo(new Date(peer.lastSeen)) ?? 'just now'}`
                    : 'Not synced yet',
                  // What that sync moved. Deliberately the last pass, not a
                  // lifetime total — see `KnownPeer::last_sent`.
                  !!peer.lastSeen &&
                    (peer.lastSent !== undefined ||
                      peer.lastReceived !== undefined) &&
                    `sent ${peer.lastSent ?? 0}, received ${peer.lastReceived ?? 0}`,
                ]}
                nodeId={peer.nodeId}
              />
            );
          })}

          {peerSyncResult && (
            <PeerSyncResult $error={peerSyncResult.startsWith('Error')}>
              {peerSyncResult}
            </PeerSyncResult>
          )}
        </Section>

        {/* Pairing is the point of this page on a peer node, so it's shown
            outright rather than hidden behind a button: the code is routing
            only, and safe to leave on screen. The section itself always
            renders, in the same place, because adding a device is always
            possible; only the "show this device" half is gated. */}
        <ConnectDevice
          pairNodeDid={pairNodeId ? rawToNodeDid(pairNodeId) : null}
          showPairing={
            !!pairNodeId &&
            (isNode ||
              (showServerConn &&
                (!isCloudSyncAvailable(managedInfo) || cloudEnrolled === true)))
          }
          canTakeCode={isNode}
          serverName={serverLabel(status.serverUrl ?? '')}
          onAddServer={setServer}
        />

        {/* Developer: diagnostics + advanced toggles, tucked away. */}
        <DevDetails>
          <DevSummary>Developer</DevSummary>

          <DevGrid>
            {/* Node ID now lives on the server card / "This device" — it's
                node identity, not a developer detail. */}
            <DevRow>
              <DetailLabel>Local database</DetailLabel>
              <LocalDbControl
                enabled={clientDbOn}
                attached={status.clientDbAttached}
                ready={status.clientDbReady}
                error={status.clientDbError}
                onToggle={next => {
                  setClientDbEnabled(next);
                  setClientDbOn(next);
                }}
              />
            </DevRow>
            <DevRow>
              <DetailLabel>WebSocket debug</DetailLabel>
              <DetailValue>
                <DebugToggle
                  type='checkbox'
                  checked={wsDebug}
                  onChange={e => {
                    setWsDebug(e.target.checked);
                    store.setWebSocketDebug(e.target.checked);
                  }}
                />
                <span>{wsDebug ? 'Logging to console' : 'Off'}</span>
              </DetailValue>
            </DevRow>
          </DevGrid>

          <DevActivityTitle>
            <span>Recent activity</span>
            {status.pendingDirtyCount > 0 && (
              <PendingCount>{status.pendingDirtyCount} unsynced</PendingCount>
            )}
          </DevActivityTitle>
          {commitLog.length > 0 ? (
            <LogList>
              {commitLog.map((entry, i) => (
                <CommitCard
                  key={`${entry.id}-${i}`}
                  highlight={entry.status === 'failed'}
                >
                  <LogHeader>
                    <LogHeaderLeft>
                      <StatusBadge $status={entry.status}>
                        {entry.status}
                      </StatusBadge>
                      <Direction>
                        {entry.direction === 'outgoing' ? '\u2191' : '\u2193'}{' '}
                        {entry.direction}
                      </Direction>
                      {entry.destroy && <DestroyBadge>destroy</DestroyBadge>}
                    </LogHeaderLeft>
                    {/* `entry.commitId` is a `did:ad:commit:` receipt, not a
                        fetchable resource (content commits are not stored), so
                        the timestamp is plain text. */}
                    <TimeText
                      title={new Date(entry.timestamp).toLocaleString()}
                    >
                      {formatTimeAgo(new Date(entry.timestamp)) ?? 'just now'}
                    </TimeText>
                  </LogHeader>

                  <LogSubjectRow>
                    <LogSubject>
                      <ResourceInline subject={entry.subject} />
                    </LogSubject>
                    <LogSummaryText>{entry.summary}</LogSummaryText>
                  </LogSubjectRow>

                  <CommitPropertyList entry={entry} />

                  {entry.error && <ErrorText>{entry.error}</ErrorText>}
                  {/* A failed upload that can never land (its parent or drive
                      is gone) otherwise retries forever and keeps "Changes
                      pending" up. Discarding drops only the queued upload;
                      the copy on this device stays. */}
                  {entry.status === 'failed' &&
                    entry.direction === 'outgoing' &&
                    store.outbox.hasPending(entry.subject) && (
                      <DiscardRow>
                        <Button
                          subtle
                          onClick={() => {
                            if (
                              window.confirm(
                                'Stop uploading this change? It stays on this device but will not reach the server.',
                              )
                            ) {
                              store.outbox.discard(entry.subject);
                              setCommitLog(store.getCommitLog());
                            }
                          }}
                        >
                          Discard upload
                        </Button>
                      </DiscardRow>
                    )}
                </CommitCard>
              ))}
            </LogList>
          ) : (
            <Muted>No activity recorded in this session yet.</Muted>
          )}
        </DevDetails>
      </ContainerNarrow>
    </Main>
  );
}

type LocalDbStatus = 'disabled' | 'initializing' | 'ready' | 'error';

function localDbStatus(args: {
  enabled: boolean;
  attached: boolean;
  ready: boolean;
  error?: string;
}): LocalDbStatus {
  if (!args.enabled) return 'disabled';
  if (args.error) return 'error';
  if (!args.attached || !args.ready) return 'initializing';

  return 'ready';
}

function LocalDbControl({
  enabled,
  attached,
  ready,
  error,
  onToggle,
}: {
  enabled: boolean;
  attached: boolean;
  ready: boolean;
  error?: string;
  onToggle: (next: boolean) => void;
}) {
  const state = localDbStatus({ enabled, attached, ready, error });
  const label: Record<LocalDbStatus, string> = {
    disabled: 'Disabled (server-only)',
    initializing: 'Initializing...',
    ready: 'Ready — WASM + OPFS',
    error: 'Error',
  };
  const noteIfToggled = enabled !== attached ? ' (reload to apply)' : '';

  return (
    <LocalDbStack>
      <LocalDbRow>
        <DebugToggle
          type='checkbox'
          checked={enabled}
          onChange={e => onToggle(e.target.checked)}
          aria-label='Enable local WASM DB'
        />
        <StatusDot $state={state} aria-hidden />
        <LocalDbLabel>
          {label[state]}
          {noteIfToggled}
        </LocalDbLabel>
      </LocalDbRow>
      {state === 'error' && error && <LocalDbError>{error}</LocalDbError>}
    </LocalDbStack>
  );
}

function PropertyName({ propertyURL }: { propertyURL: string }) {
  const property = useProperty(propertyURL);
  const label = property.loading
    ? 'loading...'
    : property.error
      ? truncateUrl(propertyURL, 10, true)
      : property.shortname;

  return (
    <AtomicLink subject={propertyURL}>
      <PropLabel>{label}</PropLabel>
    </AtomicLink>
  );
}

/**
 * Renders a commit-log property value with type-aware formatting:
 *   - ResourceArray  → comma-separated <ResourceInline> links
 *   - AtomicURL      → single <ResourceInline>
 *   - everything else → text via {@link formatValue}
 *
 * Falls back to text rendering while the property's datatype is still
 * loading or errors out, so a slow / missing property metadata fetch
 * doesn't blank the row.
 */
function PropertyValueDisplay({
  propertyURL,
  value,
}: {
  propertyURL: string;
  value: unknown;
}) {
  const property = useProperty(propertyURL);

  if (value === null) {
    return <PropertyValue>{formatValue(value)}</PropertyValue>;
  }

  if (
    !property.loading &&
    !property.error &&
    property.datatype === Datatype.RESOURCEARRAY &&
    Array.isArray(value)
  ) {
    return (
      <PropertyValue>
        {value.map((subject, i) => (
          <span key={`${i}-${String(subject)}`}>
            {i > 0 && ', '}
            {typeof subject === 'string' ? (
              <ResourceInline subject={subject} />
            ) : (
              String(subject)
            )}
          </span>
        ))}
      </PropertyValue>
    );
  }

  if (
    !property.loading &&
    !property.error &&
    property.datatype === Datatype.ATOMIC_URL &&
    typeof value === 'string'
  ) {
    return (
      <PropertyValue>
        <ResourceInline subject={value} />
      </PropertyValue>
    );
  }

  return <PropertyValue>{formatValue(value)}</PropertyValue>;
}

function formatValue(value: unknown): string {
  // The store flags removed properties by passing `null` through the
  // commit-log diff; surface that explicitly so the user can tell a
  // property-removal commit apart from one setting an empty string.
  if (value === null) {
    return '(removed)';
  }

  if (typeof value === 'string') {
    return value.length > 200 ? value.slice(0, 200) + '...' : value;
  }

  if (Array.isArray(value)) {
    return `[${value.length} items]`;
  }

  return JSON.stringify(value);
}

// --- Styled components ---

const Lead = styled.p`
  color: ${p => p.theme.colors.textLight};
  margin-bottom: 2rem;
`;

/**
 * The account strip under the lead line.
 *
 * Wears the same accent as an active connection card rather than a style of
 * its own: everything on this page that is backed by the provider account
 * reads blue, so a glance separates "this is yours and local" from "this
 * involves your account".
 */
const ProviderCard = styled(ServiceGroup)`
  --service-accent: ${p => p.theme.colors.main};
  --service-muted: ${p => p.theme.colors.textLight};
  --service-text: ${p => p.theme.colors.text};
  --service-neutral: ${p => p.theme.colors.bg1};
  ${cardSurface}
  flex-direction: column;
  align-items: stretch;
  gap: 0;
  padding: 0;
  margin-bottom: 2rem;
  border-color: ${p => p.theme.colors.main};
  background: ${p => `${p.theme.colors.main}0a`};
`;

const ProviderHeader = styled.div`
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.9rem 1rem;
`;

/**
 * One service under the account header.
 *
 * Separated by a rule rather than by gaps between cards: these belong to the
 * account above them, and whitespace alone made them read as neighbours of it
 * instead of contents.
 */
/* The same row look as ProviderService, for a row that is its own
   component. */
const providerRowCss = css`
  display: flex;
  align-items: flex-start;
  gap: 0.9rem;
  padding: 0.9rem 1rem;
  border-top: 1px solid ${p => `${p.theme.colors.main}33`};
  min-width: 0;
`;

const ProviderAICredits = styled(AICreditsService)`
  ${providerRowCss}
`;

type CloudTier = 'local' | 'vault' | 'server';

const PlanLabelRow = styled.div`
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 0.75rem;
  padding: 0.9rem 1rem 0.2rem;
  border-top: 1px solid ${p => `${p.theme.colors.main}33`};
`;

const PlanLabel = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
`;

const ProviderService = styled(ServiceSection)`
  display: flex;
  align-items: flex-start;
  gap: 0.9rem;
  padding: 0.9rem 1rem;
  border-top: 1px solid ${p => `${p.theme.colors.main}33`};
  min-width: 0;

  /* A connection row is one ellipsised line because a server origin has no
     useful second line. These rows explain a service, so their text wraps —
     otherwise the recovery row trails off mid-sentence. */
  p,
  span {
    overflow: visible;
    text-overflow: clip;
    white-space: normal;
  }
`;

const AccountBody = styled.div`
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
`;

const AccountLabel = styled.span`
  font-size: ${CARD_TITLE_FONT};
  font-weight: 600;
`;

const AccountEmail = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: ${CARD_SUB_FONT};
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

const Section = styled.section`
  margin-bottom: 2rem;
`;

const SectionTitle = styled.h2`
  font-size: 1.1rem;
  margin-bottom: 0.8rem;
`;

const NodeAction = styled.button`
  background: none;
  border: none;
  color: ${p => p.theme.colors.main};
  cursor: pointer;
  font-size: 0.8rem;
  padding: 0.2rem 0;

  &:hover {
    text-decoration: underline;
  }

  &:disabled {
    color: ${p => p.theme.colors.textLight};
    cursor: default;
    text-decoration: none;
  }
`;

/** Secondary / destructive actions (Remove). Muted so the card's primary
 *  action — the one beside the status pill — stays the obvious thing to click. */
const NodeActionSubtle = styled(NodeAction)`
  color: ${p => p.theme.colors.textLight};

  &:hover {
    color: ${p => p.theme.colors.alert};
  }
`;

const ManagedLink = styled.a`
  color: ${p => p.theme.colors.main};
  font-size: 0.8rem;
  text-decoration: none;
  margin-top: 0.15rem;

  &:hover {
    text-decoration: underline;
  }
`;

const Muted = styled.p`
  color: ${p => p.theme.colors.textLight};
`;

const statusColor = (status: NodeStatus, theme: DefaultTheme) => {
  switch (status) {
    case 'synced':
      return theme.colors.main;
    case 'syncing':
      return theme.colors.main;
    case 'unsynced':
      return theme.colors.warning;
    case 'offline':
      return theme.colors.alert;
    case 'unknown':
      return theme.colors.textLight;
  }
};

const spin = keyframes`
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
`;

const PendingCount = styled.span`
  font-size: 0.8rem;
  font-weight: 600;
  color: ${p => p.theme.colors.warning};
  margin-left: 0.5rem;
`;

// --- Connection cards ---

const cardBase = cardSurface;

/** The "This device" card. Same surface as the rest of the list — it is one
 *  of the devices, not a different kind of object. */
const NodeIdRow = styled.div`
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
  margin-top: 0.35rem;
  font-size: 0.75rem;
`;

const NodeIdLabel = styled.span`
  color: ${p => p.theme.colors.textLight};
  flex-shrink: 0;
`;

const NodeIdValue = styled.button`
  font-family: monospace;
  font-size: 0.75rem;
  color: ${p => p.theme.colors.text};
  background: none;
  border: none;
  padding: 0;
  cursor: pointer;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  min-width: 0;

  &:hover {
    color: ${p => p.theme.colors.main};
    text-decoration: underline;
  }
`;

/**
 * One device or server card. `$active` marks the server in use with a neutral
 * emphasis. The list order is stable across switches, so that accent is the
 * only thing that changes: a reshuffling list is far harder to follow than a
 * highlighted row.
 *
 * Every device looks like this, Cloud Server included. The provider's blue
 * belongs to the plan card above, which is where it is bought and managed.
 */
const ConnCard = styled.div<{
  $active?: boolean;
  $spacious?: boolean;
}>`
  ${cardBase}
  margin-bottom: ${p => (p.$spacious ? '1.5rem' : '0.6rem')};
  border-color: ${p => (p.$active ? p.theme.colors.textLight : undefined)};
`;

/** A call to action, but still one of the cards in this list. The button
 *  inside it is the affordance; a second accent surface was just noise. */
const LocalDriveNotice = styled.div`
  ${cardBase}
  margin-bottom: 1.5rem;
`;

const ConnNote = styled.p`
  margin: 0 0 0.6rem;
  color: ${p => p.theme.colors.textLight};
  font-size: 0.82rem;
`;

const ConnBody = styled.div`
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
`;

const WorkspaceSyncRow = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  margin-top: 0.5rem;
`;

const WorkspaceSyncControl = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
`;

const ConnTopRow = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
  min-width: 0;
`;

/** Status and the one thing you'd do about it, together: "Offline · Reconnect",
 *  "Not connected · Switch". The state and its remedy read as one unit rather
 *  than the action being stranded at the bottom of the card. */
const ConnTopRight = styled.div`
  display: flex;
  align-items: center;
  gap: 0.6rem;
  flex-shrink: 0;
`;

const ConnTitle = styled.span`
  font-weight: 600;
  font-size: 0.95rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  min-width: 0;
`;

const ConnSub = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.82rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

const ConnMeta = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.8rem;
  margin-top: 0.3rem;
`;

const ConnError = styled.div`
  display: inline-flex;
  align-items: flex-start;
  gap: 0.35rem;
  margin-top: 0.3rem;
  color: ${p => p.theme.colors.alert};
  font-size: 0.8rem;
  line-height: 1.25;

  svg {
    flex-shrink: 0;
    margin-top: 0.12rem;
  }
`;

const ConnActions = styled.div`
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-top: 0.5rem;
  flex-wrap: wrap;
`;

/** A link, styled as one. The primary action next to it is the button. */
const learnMoreLook = css`
  color: ${p => p.theme.colors.main};
  font-size: ${CARD_SUB_FONT};
  text-decoration: underline;

  &:hover,
  &:focus-visible {
    color: ${p => p.theme.colors.mainDark};
  }
`;

const LearnMore = styled.a`
  ${learnMoreLook}
`;

/** The same, for somewhere inside the app: a real route, not an `openExternal`. */
const LearnMoreLink = styled(Link)`
  ${learnMoreLook}
`;

const StatusPill = styled.span<{ $status: NodeStatus }>`
  flex-shrink: 0;
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
  font-size: 0.75rem;
  font-weight: 600;
  color: ${p => statusColor(p.$status, p.theme)};
  padding: 0.15rem 0.55rem;
  border-radius: 1rem;
  background: ${p => statusColor(p.$status, p.theme)}1c;

  svg {
    font-size: 0.65rem;
    ${p =>
      p.$status === 'syncing' &&
      css`
        animation: ${spin} 1s linear infinite;
      `}
  }
`;

const EmptyConnections = styled.div`
  padding: 1rem 1.1rem;
  border-radius: ${p => p.theme.radius};
  background: ${p => p.theme.colors.bg1};
  margin-bottom: 0.8rem;

  p {
    margin: 0;
    color: ${p => p.theme.colors.textLight};
    font-size: 0.88rem;
  }

  p + p {
    margin-top: 0.4rem;
  }
`;

// --- Developer disclosure ---

const DevDetails = styled.details`
  margin-top: 2.5rem;
  border-top: 1px solid ${p => p.theme.colors.bg2};
  padding-top: 1rem;
`;

const DevSummary = styled.summary`
  cursor: pointer;
  color: ${p => p.theme.colors.textLight};
  font-size: 0.9rem;
  font-weight: 600;
  user-select: none;

  &:hover {
    color: ${p => p.theme.colors.text};
  }
`;

const DevGrid = styled.div`
  display: grid;
  gap: 0.4rem;
  margin-top: 1rem;
`;

const DevRow = styled.div`
  display: grid;
  grid-template-columns: 9rem minmax(0, 1fr);
  gap: 0.8rem;
  align-items: center;
  padding: 0.5rem 0.8rem;
  border-radius: ${p => p.theme.radius};
  background: ${p => p.theme.colors.bg1};
  min-width: 0;
`;

const DevActivityTitle = styled.h3`
  font-size: 0.95rem;
  margin: 1.5rem 0 0.8rem;
`;

const DetailLabel = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.9rem;
`;

const DetailValue = styled.span`
  font-size: 0.9rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  min-width: 0;
`;

// --- Activity log ---

const LogList = styled.div`
  display: grid;
  gap: 0.6rem;
`;

const CommitCard = styled(Card)`
  display: grid;
  gap: 0.5rem;
  overflow: hidden;
  min-width: 0;
`;

const LogHeader = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.6rem;
`;

const LogHeaderLeft = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
`;

/** The properties a logged commit changed, diffed when shown. */
function CommitPropertyList({ entry }: { entry: CommitLogEntry }) {
  const store = useStore();
  const propertySummaries = store.getCommitPropertySummaries(entry);

  if (!propertySummaries || propertySummaries.length === 0) return null;

  return (
    <PropertyList>
      {propertySummaries.map((ps, j) => (
        <PropertyRow
          key={`${ps.property}-${j}`}
          data-change-type={ps.changeType}
        >
          <span aria-hidden='true'>
            {ps.changeType === 'changed' ? '+' : '−'}
          </span>
          <PropertyName propertyURL={ps.property} />
          <PropertyValueDisplay propertyURL={ps.property} value={ps.value} />
        </PropertyRow>
      ))}
    </PropertyList>
  );
}

const StatusBadge = styled.span<{ $status: CommitLogEntry['status'] }>`
  font-size: 0.8rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  padding: 0.15rem 0.4rem;
  border-radius: ${p => p.theme.radius};
  background: ${p => {
    switch (p.$status) {
      case 'failed':
        return p.theme.colors.warning + '22';
      case 'sent':
        return p.theme.colors.main + '22';
      case 'pending':
        // Same amber tone the previous PendingCount used.
        return '#d4960044';
      default:
        return p.theme.colors.bg2;
    }
  }};
  color: ${p => {
    switch (p.$status) {
      case 'failed':
        return p.theme.colors.warning;
      case 'sent':
        return p.theme.colors.main;
      case 'pending':
        return '#d49600';
      default:
        return p.theme.colors.textLight;
    }
  }};
`;

const Direction = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.85rem;
`;

const TimeText = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8rem;
`;

const LogSubjectRow = styled.div`
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
  min-width: 0;
`;

const LogSubject = styled.div`
  font-weight: 600;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  min-width: 0;
`;

const LogSummaryText = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.85rem;
  white-space: nowrap;
  flex-shrink: 0;
`;

const PropertyList = styled.div`
  display: grid;
  gap: 0.3rem;
  padding: 0.5rem;
  border-radius: ${p => p.theme.radius};
  background: ${p => p.theme.colors.bg1};
`;

const PropertyRow = styled.div`
  display: grid;
  grid-template-columns: 1ch minmax(6rem, auto) minmax(0, 1fr);
  gap: 0.6rem;
  align-items: baseline;

  & > span[aria-hidden='true']:first-child {
    font-weight: 700;
    text-align: center;
    font-size: 0.85rem;
  }

  &[data-change-type='unchanged'] {
    opacity: 0.55;
  }
  &[data-change-type='removed'] {
    text-decoration: line-through;
    color: ${p => p.theme.colors.textLight};
  }
  &[data-change-type='changed'] > span[aria-hidden='true']:first-child {
    color: ${p => p.theme.colors.main};
  }
  &[data-change-type='removed'] > span[aria-hidden='true']:first-child {
    color: ${p => p.theme.colors.alert};
  }
`;

const PropLabel = styled.span`
  font-weight: 600;
  font-size: 0.85rem;
  color: ${p => p.theme.colors.textLight};
`;

const PropertyValue = styled.span`
  font-size: 0.9rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  min-width: 0;
`;

const DestroyBadge = styled.span`
  font-size: 0.8rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  padding: 0.15rem 0.4rem;
  border-radius: ${p => p.theme.radius};
  background: ${p => p.theme.colors.warning}22;
  color: ${p => p.theme.colors.warning};
`;

const DiscardRow = styled.div`
  display: flex;
  justify-content: flex-end;
  margin-top: 0.5rem;
`;

const ErrorText = styled.div`
  color: ${p => p.theme.colors.warning};
  white-space: pre-wrap;
  font-size: 0.9rem;
`;

const DebugToggle = styled.input`
  margin-right: 0.5rem;
  cursor: pointer;
`;

// These are spans (not divs) so they render legally inside <DetailValue>,
// which is itself a <span>. Using flex on a span still works fine.
const LocalDbStack = styled.span`
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
  min-width: 0;
`;

const LocalDbRow = styled.span`
  display: flex;
  align-items: center;
  gap: 0.1rem;
`;

const LocalDbLabel = styled.span`
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

const LocalDbError = styled.span`
  color: ${p => p.theme.colors.warning};
  white-space: pre-wrap;
  font-size: 0.85rem;
  display: block;
`;

const StatusDot = styled.span<{ $state: LocalDbStatus }>`
  display: inline-block;
  width: 0.55rem;
  height: 0.55rem;
  margin-right: 0.4rem;
  border-radius: 50%;
  background: ${p => {
    switch (p.$state) {
      case 'ready':
        return p.theme.colors.main;
      case 'error':
        return p.theme.colors.warning;
      case 'initializing':
        return p.theme.colors.textLight;
      case 'disabled':
      default:
        return p.theme.colors.bg2;
    }
  }};
  flex-shrink: 0;
`;

const PeerSyncResult = styled.div<{ $error: boolean }>`
  font-size: 0.8rem;
  margin-top: 0.3rem;
  color: ${p => (p.$error ? p.theme.colors.warning : p.theme.colors.main)};
`;
