import type { Store } from '@tomic/react';
import {
  CollectionBuilder,
  core,
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
  id: number;
  op: string;
  subject?: string;
  property?: string;
  value?: string;
  parent?: string;
  isA?: string[];
  propVals?: Record<string, unknown>;
}

export interface HostReply {
  id: number;
  result?: unknown;
  error?: string;
}

/** How far up a parent chain to look before deciding a subject is elsewhere. */
const MAX_DEPTH = 12;

export function isHostRequest(data: unknown): data is HostRequest {
  return (
    typeof data === 'object' &&
    data !== null &&
    (data as HostRequest).__atomic === true &&
    typeof (data as HostRequest).id === 'number'
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
  let current = subject;

  for (let depth = 0; depth < MAX_DEPTH; depth++) {
    if (current === app) return true;

    const resource = await store.getResource(current);
    const parent = resource.get(core.properties.parent) as string | undefined;

    if (!parent || parent === current) return false;

    current = parent;
  }

  return false;
}

export async function handleRequest(
  store: Store,
  app: string,
  drive: string,
  request: HostRequest,
  /** The table this app is a view of, when it is being used as one. */
  table?: string,
): Promise<unknown> {
  switch (request.op) {
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

      return {
        table: subject,
        rowClass: tableResource.get(core.properties.classtype) as
          | string
          | undefined,
      };
    }

    case 'get': {
      const resource = await store.getResource(
        required(request.subject, 'subject'),
      );

      if (resource.error) throw resource.error;

      return { subject: resource.subject, propVals: resource.getPropVals() };
    }

    case 'query': {
      // A collection, not `search`. Search drops `filters` whenever it falls
      // back to the local index — property-value constraints need the
      // server's — so an app asking for its own children quietly received the
      // whole drive. Wrong, and a far bigger answer than it asked for.
      const collection = new CollectionBuilder(store)
        .setProperty(required(request.property, 'property'))
        .setValue(required(request.value, 'value'))
        .setPageSize(500)
        .build();

      return await collection.getAllMembers();
    }

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

      return { subject, propVals: created.getPropVals() };
    }

    case 'save': {
      const subject = required(request.subject, 'subject');

      await refuseOutsideApp(store, subject, app);
      await writeAsApp(store, drive, app, {
        op: 'save',
        subject,
        propVals: request.propVals ?? {},
      });

      return { subject };
    }

    case 'destroy': {
      const subject = required(request.subject, 'subject');

      await refuseOutsideApp(store, subject, app);
      await writeAsApp(store, drive, app, { op: 'destroy', subject });

      return { subject };
    }

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
  if (value === undefined || value === '') {
    throw new Error(`${name} is required`);
  }

  return value;
}
