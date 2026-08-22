import type { Store } from '@tomic/react';
import { core } from '@tomic/react';

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
  request: HostRequest,
): Promise<unknown> {
  switch (request.op) {
    case 'app':
      return app;

    case 'get': {
      const resource = await store.getResource(required(request.subject, 'subject'));

      if (resource.error) throw resource.error;

      return { subject: resource.subject, propVals: resource.getPropVals() };
    }

    case 'query': {
      const subjects = await store.search('', {
        filters: {
          [required(request.property, 'property')]: required(request.value, 'value'),
        },
        limit: 200,
      });

      return subjects;
    }

    case 'create': {
      // Defaulting the parent to the app is not a convenience: it is the one
      // place a view may always write, so it is the only sensible default.
      const parent = request.parent ?? app;

      await refuseOutsideApp(store, parent, app);

      const created = await store.newResource({
        parent,
        isA: request.isA ?? [],
        propVals: (request.propVals ?? {}) as Record<string, never>,
      });
      await created.save();

      return { subject: created.subject, propVals: created.getPropVals() };
    }

    case 'save': {
      const subject = required(request.subject, 'subject');

      await refuseOutsideApp(store, subject, app);

      const resource = await store.getResource(subject);

      for (const [property, value] of Object.entries(request.propVals ?? {})) {
        await resource.set(property, value as never);
      }

      await resource.save();

      return { subject };
    }

    case 'destroy': {
      const subject = required(request.subject, 'subject');

      await refuseOutsideApp(store, subject, app);

      const resource = await store.getResource(subject);
      await resource.destroy();

      return { subject };
    }

    // Subscriptions are wired by the caller, which owns the frame it has to
    // post back to.
    case 'subscribe':
    case 'unsubscribe':
      return true;

    default:
      throw new Error(`This app asked for something the host does not do: ${request.op}`);
  }
}

async function refuseOutsideApp(
  store: Store,
  subject: string,
  app: string,
): Promise<void> {
  if (await isWithinApp(store, subject, app)) return;

  throw new Error(
    'This app may only write its own data. Writing elsewhere needs your permission, which is not built yet.',
  );
}

function required(value: string | undefined, name: string): string {
  if (value === undefined || value === '') {
    throw new Error(`${name} is required`);
  }

  return value;
}
