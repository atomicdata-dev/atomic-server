import { canViewAccess } from '@helpers/extensions/viewPolicy';
import type { Store } from '@tomic/react';
import type { ProxyHost } from '@helpers/proxyConnections';
import { parseViewQuery, runViewQuery } from '@helpers/extensions/viewQuery';
import { ViewChanges } from '@helpers/extensions/viewApply';
import { parseViewSearch, runViewSearch } from '@helpers/extensions/viewSearch';
import {
  core,
  destinationTablesFor,
  errorMessageFromResponse,
  findSchema,
  pluginSchema,
  signRequest,
} from '@tomic/react';

/**
 * Answers the data requests an app's view makes.
 *
 * The view runs in a null-origin frame and has no rights of its own, so every
 * read goes through this page's store — which means it sees exactly what the
 * signed-in person sees, no more.
 *
 * Writes are confined to the app's own subtree. "May this app write its own
 * data" needs no permission dialog; "may this app write your calendar" does,
 * and that is a grant (B4) rather than something to wave through here in the
 * meantime.
 */

export interface HostRequest {
  __atomic: true;
  id: number | string;
  op: string;
  subject?: string;
  property?: string;
  value?: string;
  parent?: string;
  isA?: string[];
  propVals?: Record<string, unknown>;
  /** `save`: properties the view removed, sent apart from `propVals`. */
  remove?: string[];
  // `proxyCapability` / `proxyConnections`
  platform?: string;
  connectionId?: string;
  /** The frame's own Ed25519 public key, base64url. */
  publicKey?: string;
  /** `getMany`: the subjects to read, in order. Checked, since the frame sends it. */
  subjects?: unknown;
}

/**
 * How many subjects one `getMany` may ask for. Enough for a page of rows in
 * one round trip, and a bound on what a frame can make this page load at once.
 */
export const MAX_GET_MANY = 100;

export interface HostReply {
  id: number | string;
  result?: unknown;
  error?: string;
}

export function isHostRequest(data: unknown): data is HostRequest {
  return (
    typeof data === 'object' &&
    data !== null &&
    (data as HostRequest).__atomic === true &&
    (typeof (data as HostRequest).id === 'number' ||
      typeof (data as HostRequest).id === 'string')
  );
}

/**
 * Whether `subject` is the app or something under it.
 *
 * Bounded rather than exhaustive: a cycle in a parent chain would otherwise
 * hang the frame's request, and twelve levels is far deeper than any app's own
 * data goes.
 */
export async function isWithinApp(
  store: Store,
  subject: string,
  app: string,
): Promise<boolean> {
  return canViewAccess(store, subject, { kind: 'app', root: app }, 'write');
}

export async function handleRequest(
  store: Store,
  app: string,
  drive: string,
  request: HostRequest,
  /** The table this app is a view of, when it is being used as one. */
  table?: string,
  /**
   * This app's integration-proxy access, as the signed-in user grants it.
   * Absent where the host cannot (no signed-in agent, or a host without it).
   */
  proxy?: ProxyHost,
  /** This frame's `apply` and `undo` history. */
  changes?: ViewChanges,
): Promise<unknown> {
  switch (request.op) {
    case 'apply':
      if (!changes) throw new Error('This host cannot apply changes.');

      return await changes.apply(
        (request as unknown as { intents?: unknown }).intents,
      );

    case 'undo':
      if (!changes) throw new Error('This host cannot undo changes.');

      return await changes.undo();

    case 'app':
      return app;

    case 'data': {
      // The table it was pointed at, if any, and its own otherwise. So one
      // app can be its own thing on its own page and a view of someone
      // else's rows on a table tab, without knowing which it is.
      const resource = await store.getResource(app);
      const schema = await findSchema(store, drive, pluginSchema());
      const own = schema.properties?.['app-data']
        ? (resource.get(schema.properties['app-data']) as string | undefined)
        : undefined;
      const subject = table ?? own;

      if (!subject) return undefined;

      // The row class comes off the table rather than the app: a table already
      // names what its rows are, and duplicating that on the app would be two
      // places to disagree.
      const tableResource = await store.getResource(subject);
      // A table an importer's Set up created together with others (a
      // manifest `destination.tables`): its siblings, by the keys the
      // manifest declared, so a view of transactions can find statements.
      const tables = await destinationTablesFor(store, drive, subject);

      return {
        table: subject,
        rowClass: tableResource.get(core.properties.classtype) as
          | string
          | undefined,
        ...(tables ? { tables } : {}),
      };
    }

    case 'get':
      return readForApp(store, required(request.subject, 'subject'));

    // Many `get`s in one round trip: each subject is read exactly as `get`
    // reads it, through this person's store, so it sees what they see and
    // their own writes. One that cannot be read is reported in its place
    // rather than failing the rest.
    case 'getMany': {
      const subjects = request.subjects;

      if (
        !Array.isArray(subjects) ||
        !subjects.every(s => typeof s === 'string' && s !== '')
      )
        throw new Error('getMany takes an array of subjects');

      if (subjects.length > MAX_GET_MANY)
        throw new Error(
          `getMany reads at most ${MAX_GET_MANY} subjects at a time; ask in batches`,
        );

      return Promise.all(
        (subjects as string[]).map(async subject => {
          try {
            const { propVals, ...rest } = await readForApp(store, subject);

            return { ...rest, props: propVals, loading: false };
          } catch (e) {
            return { subject, error: (e as Error).message };
          }
        }),
      );
    }

    case 'query':
      // A collection, not `search`. Search drops `filters` whenever it falls
      // back to the local index — property-value constraints need the
      // server's — so an app asking for its own children quietly received the
      // whole drive. Wrong, and a far bigger answer than it asked for.
      return await runViewQuery(
        store,
        parseViewQuery(request as unknown as Record<string, unknown>),
      );

    case 'search':
      return await runViewSearch(
        store,
        parseViewSearch(request as unknown as Record<string, unknown>),
      );

    case 'context':
      return {
        subject: table ?? app,
        agent: store.getAgent()?.subject,
      };

    case 'create': {
      // Defaulting the parent to the app is not a convenience: it is the one
      // place a view may always write, so it is the only sensible default.
      const parent = request.parent ?? app;

      await refuseOutsideApp(store, parent, app);

      const { subject } = await writeAsApp(store, drive, app, {
        op: 'create',
        parent,
        isA: request.isA ?? [],
        propVals: request.propVals ?? {},
      });

      const created = await store.getResource(subject);

      return { subject, title: created.title, propVals: created.getPropVals() };
    }

    case 'save': {
      const subject = required(request.subject, 'subject');

      await refuseOutsideApp(store, subject, app);

      // `save` on the server only sets, so a property the view removed goes
      // as its own write. Without this, `resource.remove(p).save()` left `p`
      // in place while the view believed it gone. Removed first: if the
      // save then fails, a retry sees the property already gone rather than
      // a value the view thinks it no longer owns.
      const removed = (request.remove ?? []).filter(
        (p): p is string => typeof p === 'string' && p !== '',
      );

      if (removed.length) {
        await writeAsApp(store, drive, app, {
          op: 'remove',
          subject,
          properties: removed,
        });
      }

      await writeAsApp(store, drive, app, {
        op: 'save',
        subject,
        propVals: request.propVals ?? {},
      });
      await refresh(store, subject);

      return { subject };
    }

    case 'destroy': {
      const subject = required(request.subject, 'subject');

      await refuseOutsideApp(store, subject, app);
      await destroyAsApp(store, drive, app, subject);

      return { subject };
    }

    // The frame names a connection and brings its own public key; the user
    // signs a capability bound to that key, for that connection only, after
    // the page has checked the connection is delegated to this app. The frame
    // then calls the proxy itself. Nothing here is a credential on its own:
    // every request must also be signed with the frame's key.
    case 'proxyCapability': {
      if (!proxy)
        throw new Error('This host cannot reach the integration proxy.');

      return await proxy.capability({
        platform: required(request.platform, 'platform'),
        connectionId: required(request.connectionId, 'connectionId'),
        publicKey: required(request.publicKey, 'publicKey'),
      });
    }

    case 'proxyConnections':
      return proxy
        ? await proxy.connections(required(request.platform, 'platform'))
        : [];

    // Subscriptions are wired by the caller, which owns the frame it has to
    // post back to.
    case 'subscribe':
    case 'unsubscribe':
      return true;

    default:
      throw new Error(
        `This app asked for something the host does not do: ${request.op}`,
      );
  }
}

/** One resource, as this person's store has it. What `get` answers. */
async function readForApp(store: Store, subject: string) {
  const resource = await store.getResource(subject);

  if (resource.error) throw resource.error;

  return {
    subject: resource.subject,
    title: resource.title,
    propVals: resource.getPropVals(),
  };
}

/**
 * `store.apply` and `store.undo` for one app frame: written as the app, and
 * only under the app, like every other write it makes.
 */
export function appChanges(
  store: Store,
  drive: string,
  app: string,
): ViewChanges {
  return new ViewChanges(store, {
    authorize: subject => refuseOutsideApp(store, subject, app),
    writes: {
      create: async ({ parent, isA, propVals }) => {
        const { subject } = await writeAsApp(store, drive, app, {
          op: 'create',
          parent,
          isA,
          propVals,
        });
        // Into this store, so a query right after already lists it.
        await refresh(store, subject);

        return subject;
      },
      set: async (subject, propVals) => {
        await writeAsApp(store, drive, app, { op: 'save', subject, propVals });
        await refresh(store, subject);
      },
      remove: async (subject, properties) => {
        await writeAsApp(store, drive, app, {
          op: 'remove',
          subject,
          properties,
        });
        await refresh(store, subject);
      },
      destroy: subject => destroyAsApp(store, drive, app, subject),
    },
  });
}

/**
 * Asks the server to perform a write as the app.
 *
 * Not done in the page, because a commit is signed by whoever's key is here —
 * the user's. A write signed by the person is authored by the person and
 * bounded by what the person may reach, which makes this file's rules the only
 * thing standing between a third-party app and the whole drive. The server
 * holds the app's key, so it can sign as the app and let the ordinary rights
 * walk decide.
 *
 * The frame is never given that key: a secret in a null-origin iframe is
 * extractable and never expires.
 */
async function writeAsApp(
  store: Store,
  drive: string,
  app: string,
  request: Record<string, unknown>,
): Promise<{ subject: string }> {
  const agent = store.getAgent();

  if (!agent) throw new Error('Sign in to use this app');

  const url = `${store.getServerUrl()}/app-write`;
  const headers = await signRequest(url, agent, {});

  const response = await fetch(url, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({ drive, app, ...request }),
  });

  if (!response.ok) {
    throw new Error(
      errorMessageFromResponse(await response.text(), response.status),
    );
  }

  return (await response.json()) as { subject: string };
}

/**
 * Destroys as the app, then forgets the resource here too.
 *
 * Like `refresh`: the write bypassed this store, so its copy (and the local
 * database's, which answers queries) still held the resource, and a query
 * right after listed what the app had just deleted.
 */
async function destroyAsApp(
  store: Store,
  drive: string,
  app: string,
  subject: string,
): Promise<void> {
  await writeAsApp(store, drive, app, { op: 'destroy', subject });
  store.removeResource(subject);
}

/**
 * Pulls the server's copy of a resource the app just wrote into this page's
 * store.
 *
 * The write went through `/app-write`, not through this store, so the copy
 * cached here is the one from before it. The next `get` from the view read
 * that stale copy: an app that compares what it imports with what is stored
 * saw its own last write as missing and wrote it again. Best effort: the
 * write already succeeded, so a failed refresh is not the view's error.
 */
async function refresh(store: Store, subject: string): Promise<void> {
  // Replace rather than merge: a merge keeps properties the write removed.
  // `applyIncoming` still refuses to clobber unsaved local edits.
  await store
    .fetchResourceFromServer?.(subject, { forceOverride: true })
    .catch(() => undefined);
}

/**
 * The app's subtree, checked here as well as on the server.
 *
 * Not the authority: what an app may write is what its agent's DID is on, and
 * the rights walk decides that when the commit lands. This is the same answer
 * arrived at early, so a refusal reaches the app as an error it can show
 * rather than as a commit rejected after the fact.
 */
async function refuseOutsideApp(
  store: Store,
  subject: string,
  app: string,
): Promise<void> {
  if (await isWithinApp(store, subject, app)) return;

  throw new Error(
    'This app may only write its own data. Writing here needs rights its key does not have.',
  );
}

function required(value: string | undefined, name: string): string {
  if (typeof value !== 'string' || value === '') {
    throw new Error(`${name} is required`);
  }

  return value;
}
