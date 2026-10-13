import { beforeAll, expect, it, vi } from 'vitest';
import { AtomicError, ErrorType } from './error.js';
import { Store } from './store.js';
import { Resource } from './resource.js';
import { LoroLoader } from './loro-loader.js';
import { core, server } from './index.js';
beforeAll(() => LoroLoader.initializeLoro());
it('recovers a class-less partial SUB with a full GET while retaining later local edits', async () => {
  const store = new Store({ serverUrl: 'http://localhost', connect: false });
  vi.spyOn(store, 'fetchResourceFromServer').mockImplementation(
    () => new Promise(() => {}),
  );
  vi.spyOn(store, 'getProperty').mockRejectedValue(new Error('offline'));
  const subject = 'atomic:partial-sub';
  const remote = new LoroLoader.Loro.LoroDoc();
  const props = remote.getMap('properties');
  props.set(core.properties.isA, [server.classes.drive]);
  props.set(core.properties.name, 'Private home');
  remote.commit();
  const base = remote.oplogVersion();
  props.set(core.properties.description, 'Remote edit');
  remote.commit();
  expect(
    store.applyIncoming({
      subject,
      source: 'ws-sub-push',
      loroBytes: remote.export({ mode: 'update', from: base }),
    }),
  ).toBe('invalid');
  expect(
    store.applyIncoming({
      subject,
      source: 'ws-pending-get',
      loroBytes: remote.export({ mode: 'snapshot' }),
      replaceLoroDocsFromRemote: true,
    }),
  ).toBe('applied');
  const resource = store.resources.get(subject)!;
  expect(resource.hasClasses(server.classes.drive)).toBe(true);
  expect(resource.get(core.properties.description)).toBe('Remote edit');
  await resource.set(core.properties.name, 'Local edit');
  store.applyIncoming({
    subject,
    source: 'ws-pending-get',
    loroBytes: remote.export({ mode: 'snapshot' }),
    replaceLoroDocsFromRemote: true,
  });
  expect(resource.get(core.properties.name)).toBe('Local edit');
  expect(resource.hasClasses(server.classes.drive)).toBe(true);
});
it.each([false, true])(
  'a valid snapshot clears a stale read error (own echo: %s)',
  own => {
    const store = new Store({ serverUrl: 'http://localhost', connect: false });
    const subject = 'did:ad:test-read-recovery';
    const doc = new LoroLoader.Loro.LoroDoc();
    doc.getMap('properties').set(core.properties.name, 'Personal drive');
    const snapshot = doc.export({ mode: 'snapshot' });
    const resource = new Resource(subject);
    resource.importLoroUpdate(snapshot);
    resource.loading = false;
    const commitId = 'did:ad:commit:owned';
    if (own) resource.setLastCommitValue(commitId);
    resource.error = new Error('Resource not found before genesis');
    store.addResource(resource);
    const result = store.applyIncoming({
      subject,
      loroBytes: snapshot,
      commitId,
      source: 'ws-pending-get',
      replaceLoroDocsFromRemote: true,
    });
    expect(result).toBe('applied');
    expect(resource.error).toBeUndefined();
    expect(resource.get(core.properties.name)).toBe('Personal drive');
  },
);

it('an acknowledged creation clears a pre-genesis not-found lookup', () => {
  const store = new Store({ serverUrl: 'http://localhost', connect: false });
  const resource = new Resource('did:ad:late-read');
  resource.error = new AtomicError(
    'Not found before genesis',
    ErrorType.NotFound,
  );
  resource.loading = true;
  store.addResource(resource);
  store.applyIncoming({
    subject: resource.subject,
    resource,
    source: 'local-acked',
    commitId: 'did:ad:commit:created',
  });
  expect(resource.error).toBeUndefined();
  expect(resource.loading).toBe(false);
});
