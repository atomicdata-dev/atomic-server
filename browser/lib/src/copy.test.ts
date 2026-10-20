import { describe, it } from 'vitest';
import { core } from './index.js';
import { copyResource, NON_COPIED_PROPS } from './copy.js';
import { testStore } from './test-store.js';

const BLOGPOST = 'https://atomicdata.dev/classes/BlogPost';
const DRIVE = 'https://atomicdata.dev/classes/Drive';
const DOCUMENT_V2 = 'https://atomicdata.dev/classes/DocumentV2';
const PUBLIC_AGENT = 'https://atomicdata.dev/agents/publicAgent';
const RELATED = 'https://example.com/related';

describe('copyResource', () => {
  it('copies content under a new genesis and never copies rights, parent or identity', async ({
    expect,
  }) => {
    const { store } = await testStore();
    const drive = await store.newResource({ isA: DRIVE, noParent: true });
    await drive.save();
    const other = await store.newResource({ isA: DRIVE, noParent: true });
    await other.save();

    const original = await store.newResource({
      parent: drive.subject,
      isA: BLOGPOST,
      propVals: {
        [core.properties.name]: 'Cheese',
        [core.properties.read]: [PUBLIC_AGENT],
        [core.properties.write]: [PUBLIC_AGENT],
        'https://atomicdata.dev/properties/append': [PUBLIC_AGENT],
      },
    });
    await original.save();

    const { copy } = await copyResource(store, original, {
      parent: other.subject,
    });

    expect(copy.subject).not.toBe(original.subject);
    expect(copy.get(core.properties.name)).toBe('Cheese');
    expect(copy.get(core.properties.parent)).toBe(other.subject);
    expect(copy.getClasses()).toEqual([BLOGPOST]);

    for (const prop of [
      core.properties.read,
      core.properties.write,
      'https://atomicdata.dev/properties/append',
    ]) {
      expect(NON_COPIED_PROPS.has(prop)).toBe(true);
      expect(copy.get(prop)).toBe(undefined);
    }
  });

  it('rewrites references through the subject map and honours exclude and extra propVals', async ({
    expect,
  }) => {
    const { store } = await testStore();
    const drive = await store.newResource({ isA: DRIVE, noParent: true });
    await drive.save();
    const original = await store.newResource({
      parent: drive.subject,
      isA: BLOGPOST,
      propVals: {
        [core.properties.name]: 'A',
        [core.properties.description]: 'old:x',
        [RELATED]: ['old:x', 'elsewhere'],
      },
    });
    await original.save();

    const { copy } = await copyResource(store, original, {
      parent: drive.subject,
      subjects: new Map([['old:x', 'new:x']]),
      exclude: new Set([core.properties.name]),
      propVals: { [core.properties.shortname]: 'extra' },
    });

    expect(copy.get(core.properties.description)).toBe('new:x');
    expect(copy.get(RELATED)).toEqual(['new:x', 'elsewhere']);
    expect(copy.get(core.properties.name)).toBe(undefined);
    expect(copy.get(core.properties.shortname)).toBe('extra');
  });

  it('seeds a Loro body without leaking the original’s rights through the snapshot', async ({
    expect,
  }) => {
    const { store } = await testStore();
    const drive = await store.newResource({ isA: DRIVE, noParent: true });
    await drive.save();
    const original = await store.newResource({
      parent: drive.subject,
      isA: DOCUMENT_V2,
      propVals: {
        [core.properties.name]: 'Doc',
        [core.properties.read]: [PUBLIC_AGENT],
      },
    });
    original.getLoroDoc()!.getMap('doc').set('intro', 'hello');
    original.markDirty();
    await original.save();

    const { copy, version } = await copyResource(store, original, {
      parent: drive.subject,
    });

    expect(version).toBeTruthy();
    expect(copy.getLoroDoc()!.getMap('doc').get('intro')).toBe('hello');
    expect(copy.get(core.properties.parent)).toBe(drive.subject);
    expect(copy.get(core.properties.read)).toBe(undefined);
    await copy.save();
    expect(copy.get(core.properties.read)).toBe(undefined);
  });
});
