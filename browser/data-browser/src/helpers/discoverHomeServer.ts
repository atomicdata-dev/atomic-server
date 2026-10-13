import {
  decodeB64,
  decodeGenesisCert,
  identifierBody,
  resolveDriveOrigins,
  verifyGenesisCert,
} from '@tomic/lib';
import { serverURLStorage } from './serverURLStorage';
import { isRunningInTauri } from './tauri';

/** Resolving (6 s), probing (5 s) and verifying (4 s) share one deadline. */
const DISCOVERY_DEADLINE_MS = 14_000;
/** The record is public and anyone may add to it: look at a few, not all. */
const MAX_CANDIDATES = 3;
const VERIFY_TIMEOUT_MS = 4_000;
const GENESIS_PROPERTY = 'https://atomicdata.dev/properties/genesis';
const MAX_DRIVE_BYTES = 256 * 1024;

/**
 * Whether `origin` serves the drive's own genesis certificate and it verifies
 * against the DID. The DID is the genesis signature, so this is
 * self-certifying: nobody without the drive owner's key can produce a
 * certificate that signs to it, wherever they host it. A node that merely
 * answers `/server`, or serves some other drive, does not pass.
 *
 * A plain anonymous GET of `/genesis`, which serves only that certificate
 * (never the drive's content, so it works for private drives), no redirects.
 * A server without the route, or without the drive, counts as not verified.
 */
export async function serverServesGenesis(
  origin: string,
  drive: string,
  timeoutMs = VERIFY_TIMEOUT_MS,
): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const signature = identifierBody(drive);

    if (!signature) return false;

    const res = await fetch(
      `${origin}/genesis?subject=${encodeURIComponent(drive)}`,
      {
        headers: { Accept: 'application/ad+json' },
        credentials: 'omit',
        redirect: 'error',
        signal: controller.signal,
      },
    );

    if (!res.ok) return false;

    const text = await res.text();

    if (text.length > MAX_DRIVE_BYTES) return false;

    const encoded = (JSON.parse(text) as Record<string, unknown> | null)?.[
      GENESIS_PROPERTY
    ];

    if (typeof encoded !== 'string' || !encoded) return false;

    return await verifyGenesisCert(
      decodeGenesisCert(decodeB64(encoded)),
      signature,
    );
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

type DiscoveryStore = {
  getServerUrl(): string | undefined;
  setServerUrl(url: string): void;
  unregisterLocalOnlyDrive(drive: string): void;
  waitForServerConnected(timeoutMs: number): Promise<boolean>;
};

/** The parts that touch the network or the device, replaceable in a test. */
export type DiscoveryDeps = {
  /** The server was picked by the person, never inferred. */
  wasExplicitlyChosen: () => boolean;
  /** The app runs in the desktop shell with a node of its own. */
  hasEmbeddedNode: () => boolean;
  /** Whether the server in use already serves this drive. */
  hasDriveData: (drive: string) => Promise<boolean>;
  resolveOrigins: (drive: string) => Promise<string[]>;
  /** The origin serves the drive's genesis and it verifies against the DID. */
  verifyGenesis: (origin: string, drive: string) => Promise<boolean>;
};

const defaultDeps = (
  hasDriveData: DiscoveryDeps['hasDriveData'],
): DiscoveryDeps => ({
  wasExplicitlyChosen: () => serverURLStorage.wasExplicitlyChosen(),
  hasEmbeddedNode: () => isRunningInTauri(),
  hasDriveData,
  resolveOrigins: drive => resolveDriveOrigins(drive),
  verifyGenesis: (origin, drive) => serverServesGenesis(origin, drive),
});

function sameOrigin(a: string | undefined, b: string): boolean {
  try {
    return !!a && new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}

/**
 * After a secret sign-in on a device that knows no server for the person's
 * drive, ask pkarr which servers announced it and move the app to the first
 * one that serves the drive's verified genesis. No account and no typed address are involved:
 * the drive DID is enough to find the record.
 *
 * Does nothing (returns `false`) when
 *  - the person chose a server themselves, or the desktop shell runs its own,
 *  - the server in use already has the drive (an already restored session
 *    must not be switched),
 *  - pkarr names no origin that serves a genesis that verifies
 *    against the DID (the record is public; naming a server proves nothing),
 *  - or anything fails or takes longer than the deadline.
 *
 * It never throws and never connects after the deadline has passed, so a slow
 * lookup cannot move a session that carried on without it.
 */
export async function discoverHomeServer(
  store: DiscoveryStore,
  drive: string,
  persistServer: (url: string) => void,
  deps: DiscoveryDeps,
  deadlineMs = DISCOVERY_DEADLINE_MS,
): Promise<boolean> {
  if (deps.wasExplicitlyChosen() || deps.hasEmbeddedNode()) return false;

  let expired = false;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const lookup = async (): Promise<string | undefined> => {
    if (await deps.hasDriveData(drive)) return undefined;

    // Deduped and capped: anyone who knows the DID can add names to the record.
    const origins = [...new Set(await deps.resolveOrigins(drive))]
      .filter(origin => !sameOrigin(store.getServerUrl(), origin))
      .slice(0, MAX_CANDIDATES);

    // Check together so one dead origin does not eat the whole deadline, but
    // keep the announced order when several pass. A genesis certificate that
    // verifies against the DID already proves the origin is a node holding
    // this drive, so no separate `/server` probe is needed.
    const ok = await Promise.all(
      origins.map(origin => deps.verifyGenesis(origin, drive)),
    );

    return origins.find((_, i) => ok[i]);
  };

  try {
    const origin = await Promise.race([
      lookup().catch(() => undefined),
      new Promise<undefined>(resolve => {
        timer = setTimeout(() => {
          expired = true;
          resolve(undefined);
        }, deadlineMs);
      }),
    ]);

    // Re-check: the person may have chosen a server while we were asking.
    if (!origin || expired || deps.wasExplicitlyChosen()) return false;

    store.unregisterLocalOnlyDrive(drive);
    store.setServerUrl(origin);
    persistServer(origin);
    await store.waitForServerConnected(3_000);

    return true;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
    expired = true;
  }
}

/**
 * {@link discoverHomeServer} with the real network and device behind it.
 * The server found is remembered as an inferred choice, not an explicit one:
 * it is not sticky, and a device's own embedded node still outranks it later.
 * `setBaseURL` moves the app's state to it.
 */
export function discoverHomeServerForApp(
  store: DiscoveryStore,
  drive: string,
  setBaseURL: (url: string) => void,
  hasDriveData: DiscoveryDeps['hasDriveData'],
  deps: Partial<DiscoveryDeps> = {},
): Promise<boolean> {
  return discoverHomeServer(
    store,
    drive,
    origin => {
      setBaseURL(origin);
      serverURLStorage.set(origin, false);
    },
    { ...defaultDeps(hasDriveData), ...deps },
  );
}
