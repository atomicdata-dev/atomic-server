import { isNotFound } from './error.js';
import { core } from './ontologies/core.js';
import type { Resource } from './resource.js';
import type { Store } from './store.js';

/**
 * Standard locations are well-known resources inside a Drive (the Comments
 * folder, the default ontology, the tag list, …) that clients find by
 * following a dedicated property on the Drive itself — never by name or by
 * guessing subjects. This helper is the generic get-or-create for such a
 * pointer: read the property, or create the resource and set the pointer.
 *
 * Creation is client-side and signed by the current agent (requires write on
 * the drive). Two clients racing on first use can each create a resource and
 * LWW decides which pointer wins — harmless as long as the standard location
 * is a container/anchor rather than the source of truth (e.g. comments are
 * found via their `about` property, not by enumerating the Comments folder).
 */
export async function getOrCreateDriveLocation(
  store: Store,
  driveSubject: string,
  pointerProperty: string,
  create: { isA: string; name: string },
): Promise<string> {
  // A local-only drive has no server to ask and no other device.
  const isLocalOnly = store.isLocalOnlySubject(driveSubject);
  const askServer = store.serverConnected && !isLocalOnly;
  let drive = await store.getResource(driveSubject);
  let existing = drive.get(pointerProperty) as string | undefined;

  // The pointer may have been set by another device after this one loaded the
  // drive, and a drive that is not the open one is not pushed here. Creating
  // now would add a second location and move the pointer to it, so ask the
  // server before concluding there is none.
  if (!existing && askServer) {
    drive = await refetched(store, driveSubject, drive);
    existing = drive.get(pointerProperty) as string | undefined;
  }

  if (existing) {
    let target = await store.getResource(existing);

    if (target.error && askServer) {
      target = await refetched(store, existing, target);
    }

    if (!target.error) {
      return existing;
    }

    // Only a target the server does not have is a stale pointer, to be
    // overwritten below. A read that failed for another reason (offline,
    // unauthorized, not synced yet) says nothing about it: creating a new
    // location then would orphan the real one and what is in it.
    if (!isNotFound(target.error) || (!askServer && !isLocalOnly)) {
      throw target.error;
    }
  }

  const resource = await store.newResource({
    parent: driveSubject,
    isA: create.isA,
    propVals: { [core.properties.name]: create.name },
  });
  await resource.save();
  store.notifyResourceManuallyCreated(resource);

  await drive.set(pointerProperty, resource.subject);
  await drive.save();

  return resource.subject;
}

/** The server's copy of a resource, or `fallback` when it cannot be asked. */
async function refetched<T extends Resource>(
  store: Store,
  subject: string,
  fallback: T,
): Promise<T> {
  try {
    return (await store.fetchResourceFromServer(subject)) as T;
  } catch {
    return fallback;
  }
}
