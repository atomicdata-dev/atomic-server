import { core, dataBrowser, type Store } from '@tomic/lib';

/** Only the drive's explicitly shared display fields leave local storage. */
export async function driveDisplayMetadata(store: Store, subject: string) {
  const drive = store.resources.get(subject);
  let name = drive?.get(core.properties.name);
  let emoji = drive?.get(dataBrowser.properties.emoji);

  // Background backup can run before the drive has been opened in this session.
  // Do not fetch a private drive from a remote server just to read its label.
  if (typeof name !== 'string') {
    const serialized = await store.getClientDb()?.getResource(subject);

    if (serialized) {
      const local = JSON.parse(serialized) as Record<string, unknown>;
      name = local[core.properties.name] as typeof name;
      emoji = local[dataBrowser.properties.emoji] as typeof emoji;
    }
  }

  return {
    name: typeof name === 'string' ? name : undefined,
    emoji:
      typeof emoji === 'string'
        ? emoji
        : typeof name === 'string'
          ? ''
          : undefined,
  };
}
