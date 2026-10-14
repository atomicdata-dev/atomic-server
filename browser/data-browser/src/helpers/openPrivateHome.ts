import { core, type Store } from '@tomic/lib';
import { deviceHasDriveData } from './driveData';
import { isOriginWithoutNode } from './originNode';
import { restoreFromVault } from './managed/vaultAutoBackup';
import { withDeadline } from './withDeadline';

const pending = new WeakMap<
  Store,
  Map<string, Promise<'existing' | 'created' | undefined>>
>();

/** Recover before creating; only the current identity's own home may be created. */
export function openPrivateHome(
  store: Store,
  subject: string,
  recoveryAttempted = false,
): Promise<'existing' | 'created' | undefined> {
  let homes = pending.get(store);

  if (!homes) {
    homes = new Map();
    pending.set(store, homes);
  }

  const key = `${store.getAgent()?.subject}:${subject}`;
  const existing = homes.get(key);
  if (existing) return existing;
  const opening = prepare(store, subject, recoveryAttempted).finally(() =>
    homes.delete(key),
  );
  homes.set(key, opening);

  return opening;
}

async function prepare(
  store: Store,
  subject: string,
  recoveryAttempted: boolean,
): Promise<'existing' | 'created' | undefined> {
  const agent = store.getAgent();
  if (!agent || (await store.privateDriveSubject()) !== subject) return;
  if (await deviceHasDriveData(store, subject)) return 'existing';

  if (!recoveryAttempted) {
    await withDeadline(
      restoreFromVault(store, subject),
      8_000,
      undefined,
    ).catch(() => undefined);
    if (await deviceHasDriveData(store, subject)) return 'existing';
  }

  const name = agent.subject
    ? await ownerName(store, agent.subject)
    : undefined;

  // A sign-out or another sign-in during recovery must not create that
  // identity's home on behalf of the new session.
  if (store.getAgent() !== agent) return;
  // No literal for the unnamed case: `ensurePrivateDrive` already defaults it,
  // inside the library. `undefined` is how a default parameter is asked for, so
  // the title stays one call. `InvitePage` leaves the name out too.
  //
  // The named case is kept away from the extractor on purpose. Left alone it
  // becomes a catalog lookup, and this runs during boot: the catalog is not
  // always loaded yet, and a home created in that window is titled
  // `[i18n-404:845]` — permanently, since the title is written into the
  // resource. Observed on a second device, not reasoned about. The message it
  // would look up is `{0}'s Drive`, whose es, fr and de entries are all empty,
  // so translating it here buys nothing and risks that. `NewIdentitySection`
  // composes the same title from a component, where the catalog is up.
  await store.ensurePrivateDrive(
    name ? /* @wc-ignore */ `${name}'s Drive` : undefined,
    { localOnly: isOriginWithoutNode(store.getServerUrl()) },
  );

  return 'created';
}

/**
 * The owner's own name, as the Agent resource carries it.
 *
 * A title only lands while the drive is being created: `ensurePrivateDrive`
 * returns an existing home untouched, so a name that arrives a moment later
 * never reaches it. A returning session may not have read its Agent yet, so
 * this is worth a fetch, but not worth holding the user out of their
 * workspace for, hence the budget and the silent fallback to the default.
 */
async function ownerName(
  store: Store,
  agentSubject: string,
): Promise<string | undefined> {
  // Everything inside the guard, not just the promise: `withDeadline` swallows
  // a rejection, but `getResource` can also throw before there is a promise to
  // swallow. A name is a nicety and creating the home is not, so nothing here
  // may be the reason someone is left without one.
  try {
    return await withDeadline<string | undefined>(
      readName(store, agentSubject),
      2_000,
      undefined,
    );
  } catch {
    return undefined;
  }
}

/**
 * The name on the Agent resource, asking the server once when the copy in hand
 * does not carry one.
 *
 * Signing in on a new device reads the Agent before the store finished
 * assembling the identity, so what it caches is the view the server gives a
 * stranger: `read`, `isA` and `publicKey`, and no name. It is a ready resource
 * with no error, so nothing about it looks wrong, and every later reader gets
 * that copy. Asked again, now signed in, the server answers with the profile.
 * Same cache and same remedy as `deviceHasDriveData`'s `refresh`.
 *
 * A name that is genuinely not set costs one request that finds nothing, which
 * is the same request the app makes moments later anyway.
 */
async function readName(
  store: Store,
  agentSubject: string,
): Promise<string | undefined> {
  const cached = await store.getResource(agentSubject);
  const name = trimmed(cached?.get(core.properties.name));

  if (name) return name;

  return trimmed(
    (await store.fetchResourceFromServer(agentSubject))?.get(
      core.properties.name,
    ),
  );
}

function trimmed(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}
