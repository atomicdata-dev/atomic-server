import { expect, it } from 'vitest';
import { resumableInstallation } from './resumable-installation.js';
import { core } from './ontologies/core.js';
it('resumes the same traversal without recreating saved dependencies or identical repeated rows', async () => {
  const saved = new Map<
    string,
    { subject: string; save: () => Promise<void> }
  >();
  let serial = 0;
  const host = {
    findByLocalId: async (_drive: string, parent: string, id: string) =>
      saved.get(parent + id),
    newResource: async (options: {
      parent: string;
      propVals: Record<string, unknown>;
    }) => {
      const resource = {
        subject: `resource:${++serial}`,
        save: async () => {
          saved.set(
            options.parent + options.propVals[core.properties.localId],
            resource,
          );
        },
      };

      return resource;
    },
  };
  const options = {
    parent: 'parent',
    isA: ['class'],
    propVals: { name: 'same' },
  };
  const first = await resumableInstallation(host as never, 'drive', 'app', {
    version: 1,
  });
  const row = await first.newResource(options);
  await row.save();
  // Process lost after the first save. A fresh wrapper has no retained journal.
  const retry = await resumableInstallation(host as never, 'drive', 'app', {
    version: 1,
  });
  expect((await retry.newResource(options)).subject).toBe(row.subject);
  const second = await retry.newResource(options);
  await second.save();
  expect(second.subject).not.toBe(row.subject);
  const final = await resumableInstallation(host as never, 'drive', 'app', {
    version: 1,
  });
  expect((await final.newResource(options)).subject).toBe(row.subject);
  expect((await final.newResource(options)).subject).toBe(second.subject);
  expect(serial).toBe(2);
});
