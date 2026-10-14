import { beforeAll, expect, it } from 'vitest';
import { Resource } from './resource.js';
import { LoroLoader } from './loro-loader.js';
import { core } from './ontologies/core.js';
import replay from './testdata/agent-snapshot-replay.json';

beforeAll(() => LoroLoader.initializeLoro());
const bytes = (value: string) => new Uint8Array(Buffer.from(value, 'base64'));

it.each([false, true])(
  'profile metadata reads preserve live updates and pending edits (%s)',
  async pending => {
    // Public, disposable dev-agent bytes from the browser regression. The two
    // snapshots contain identical operations in different storage block layouts.
    const resource = new Resource('atomic:agent:snapshot-replay');
    expect(resource.importLoroUpdate(bytes(replay.snapshot)).complete).toBe(
      true,
    );
    const doc = resource.getLoroDoc()!;
    doc.export({ mode: 'snapshot' });
    expect(resource.importLoroUpdate(bytes(replay.sameHistory)).complete).toBe(
      true,
    );
    doc.export({ mode: 'snapshot' });
    if (pending)
      await resource.set(
        core.properties.description,
        'Local unsaved edit',
        false,
      );
    resource.getCreatedAt();
    resource.getCreatedBy();
    expect(resource.importLoroUpdate(bytes(replay.nextUpdate)).complete).toBe(
      true,
    );
    expect(resource.getLoroDoc()).toBe(doc);
    expect(resource.get(core.properties.name)).toBe('Drive Owner');

    if (pending) {
      expect(resource.get(core.properties.description)).toBe(
        'Local unsaved edit',
      );
      expect(resource.hasUnsavedChanges()).toBe(true);
    }

    expect(
      resource.get('https://atomicdata.dev/properties/encryptionKey'),
    ).toEqual(expect.any(String));
  },
);
