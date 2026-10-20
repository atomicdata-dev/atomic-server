import { dataBrowser, isNotEnrolledMessage, type Store } from '@tomic/react';

const APPS = dataBrowser.properties.resources;

/**
 * Which apps the person connected (an AI assistant through MCP, for now), kept
 * as a list of Agent subjects on their private drive so account settings can
 * list them. What each app may reach is not kept here: the ACLs on the shared
 * resources are the record (see `grantsTo` in @tomic/lib).
 */
export async function listConnectedApps(
  store: Store,
  home: string,
): Promise<string[]> {
  const drive = await store.getResource(home);

  return (drive.get(APPS) as string[] | undefined) ?? [];
}

/**
 * The list entry is a convenience; the grants are the record. A node that has
 * not enrolled the home drive for sync refuses the save, which must not stop
 * the connection. Any other failure still throws.
 */
export async function rememberConnectedApp(
  store: Store,
  home: string,
  agent: string,
): Promise<void> {
  try {
    const drive = await store.getResource(home);
    drive.push(APPS, [agent], true);
    await drive.save();
  } catch (e) {
    if (!isNotEnrolledMessage(e instanceof Error ? e.message : String(e))) {
      throw e;
    }
  }
}

export async function forgetConnectedApp(
  store: Store,
  home: string,
  agent: string,
): Promise<void> {
  const drive = await store.getResource(home);
  const apps = (drive.get(APPS) as string[] | undefined) ?? [];
  await drive.set(
    APPS,
    apps.filter(subject => subject !== agent),
  );
  await drive.save();
}
