import { managedFetch } from './api';

/** A vanity subdomain the account holds, as the portal's `/api/aliases` reports it. */
export type DomainAlias = {
  label: string;
  /** The full host, rendered by the server from the current base domain. */
  host: string;
  drive_subject: string;
  created_at?: number;
  /**
   * When a node confirmed it installed the mapping. Missing means the name is
   * reserved but not routing yet.
   */
  applied_at?: number | null;
};

export type AliasAvailability = {
  label: string;
  host: string;
  available: boolean;
  /** Why not, in words meant for the person typing. */
  reason?: string | null;
};

/** The portal has no address routes (an older deployment) or answered with a page. */
function notAvailableMessage(): string {
  return 'Web addresses are not available on your account yet.';
}

function couldNotLoadMessage(): string {
  return 'Could not load your web address.';
}

function couldNotCheckMessage(): string {
  return 'Could not check that address.';
}

function couldNotSaveMessage(): string {
  return 'Could not save that address.';
}

function couldNotReleaseMessage(): string {
  return 'Could not release that address.';
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return undefined;
  }
}

export async function listAliases(
  signal?: AbortSignal,
): Promise<DomainAlias[]> {
  const response = await managedFetch('/aliases', { signal });

  if (response.status === 404) throw new Error(notAvailableMessage());
  if (!response.ok) throw new Error(couldNotLoadMessage());

  const body = await readJson(response);

  // An HTML page from a portal without this route is not a list.
  if (!Array.isArray(body)) throw new Error(notAvailableMessage());

  return body as DomainAlias[];
}

/** The portal checks, so the reserved list and the taken set stay in one place. */
export async function checkAliasAvailability(
  label: string,
  signal?: AbortSignal,
): Promise<AliasAvailability> {
  const response = await managedFetch(
    `/alias-availability?${new URLSearchParams({ label })}`,
    { signal },
  );

  if (!response.ok) throw new Error(couldNotCheckMessage());

  const body = (await readJson(response)) as AliasAvailability | undefined;

  if (!body || typeof body.available !== 'boolean') {
    throw new Error(couldNotCheckMessage());
  }

  return body;
}

async function mutate(
  path: string,
  method: 'POST' | 'PUT' | 'DELETE',
  body: unknown,
  fallback: string,
): Promise<unknown> {
  const response = await managedFetch(path, {
    method,
    ...(body === undefined
      ? {}
      : {
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        }),
  });

  if (response.status === 204) return null;

  const parsed = (await readJson(response)) as { error?: string } | undefined;

  // The portal's message is the useful one: it tells taken from reserved from
  // over-plan.
  if (!response.ok) throw new Error(parsed?.error || fallback);

  return parsed;
}

export async function reserveAlias(
  label: string,
  driveSubject: string,
): Promise<DomainAlias> {
  return (await mutate(
    '/aliases',
    'POST',
    { label, drive_subject: driveSubject },
    couldNotSaveMessage(),
  )) as DomainAlias;
}

/** Move a held name to a different label, keeping the drive it points at. */
export async function renameAlias(
  from: string,
  label: string,
): Promise<DomainAlias> {
  return (await mutate(
    `/aliases/${encodeURIComponent(from)}`,
    'PUT',
    { label },
    couldNotSaveMessage(),
  )) as DomainAlias;
}

export async function releaseAlias(label: string): Promise<void> {
  await mutate(
    `/aliases/${encodeURIComponent(label)}`,
    'DELETE',
    undefined,
    couldNotReleaseMessage(),
  );
}
