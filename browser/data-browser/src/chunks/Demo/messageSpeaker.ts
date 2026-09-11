// @wc-ignore-file
import { type Resource, useCreatedBy, useStore, useString } from '@tomic/react';

export const DEMO_SPEAKER = 'https://atomicdata.dev/properties/demo/speaker';
const DRIVE = 'https://atomicdata.dev/properties/drive';

/** Scripted speech is presentation, never a replacement for signed authorship. */
export function resolveDemoSpeaker(
  creator: string | undefined,
  speaker: string | undefined,
  drive: string | undefined,
  localOnly: boolean,
  manifest: { drive: string; personas: Record<string, string> } | undefined,
): string | undefined {
  return localOnly &&
    manifest &&
    drive === manifest.drive &&
    speaker &&
    Object.values(manifest.personas).includes(speaker)
    ? speaker
    : creator;
}

export function useMessageSpeaker(resource: Resource): string | undefined {
  const creator = useCreatedBy(resource);
  const [speaker] = useString(resource, DEMO_SPEAKER);
  const store = useStore();
  let manifest;

  try {
    const value = JSON.parse(
      localStorage.getItem('atomic.demoWorkspace') ?? 'null',
    );
    if (
      typeof value?.drive === 'string' &&
      value?.personas &&
      typeof value.personas === 'object'
    )
      manifest = value;
  } catch {
    /* No valid demo session. */
  }

  return resolveDemoSpeaker(
    creator,
    speaker,
    resource.get(DRIVE) as string | undefined,
    store.isLocalOnlySubject(resource.subject),
    manifest,
  );
}
