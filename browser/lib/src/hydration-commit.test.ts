import { describe, expect, it } from 'vitest';
import { JSONADParser } from './parse.js';
import { HYDRATION_COMMIT_MESSAGE, SYSTEM_COMMIT_ORIGIN } from './resource.js';
import { testStore } from './test-store.js';
import { core } from './ontologies/core.js';

const subject = 'https://example.com/legacy-doc';

async function openLegacy() {
  const t = await testStore();
  const [resource] = new JSONADParser().parse(
    {
      '@id': subject,
      [core.properties.name]: 'Old doc',
      [core.properties.isA]: [core.classes.agent],
      [core.properties.parent]: 'https://example.com',
    },
    subject,
  );
  t.store.addResource(resource);

  return { ...t, resource };
}

describe('hydrating a legacy (JSON-AD, no snapshot) resource', () => {
  it('seals the seed as one tagged system commit, newest in the oplog', async () => {
    const { resource } = await openLegacy();
    const doc = resource.getLoroDoc()!;
    const changes = [...doc.getAllChanges().values()].flat();

    expect(changes.length).toBeGreaterThan(0);
    expect(changes.every(c => c.message === HYDRATION_COMMIT_MESSAGE)).toBe(
      true,
    );
    expect(resource.getCreatedAt()).toBeUndefined();
  });

  it('writes nothing to the outbox or the server when opened', async () => {
    const { resource, store, posted } = await openLegacy();
    resource.getLoroDoc();
    // Loro delivers events in a microtask; the dirty-marking subscriber
    // would have enqueued by now.
    await new Promise(r => setTimeout(r, 20));
    await store.syncDirtyResources();

    expect(store.outbox.hasPending(subject)).toBe(false);
    expect(posted).toHaveLength(0);
    expect(SYSTEM_COMMIT_ORIGIN).toBe('origin:system');
  });

  it('a real edit afterwards is a distinct, untagged change', async () => {
    const { resource } = await openLegacy();
    await resource.set(core.properties.name, 'Edited', false);
    resource.getLoroDoc()!.commit();
    const messages = [...resource.getLoroDoc()!.getAllChanges().values()]
      .flat()
      .map(c => c.message);

    expect(messages).toContain(HYDRATION_COMMIT_MESSAGE);
    expect(messages.some(m => m !== HYDRATION_COMMIT_MESSAGE)).toBe(true);
  });
});
