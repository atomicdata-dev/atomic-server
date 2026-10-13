import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { Store } from '@tomic/lib';
import { PersistentDiagnostics } from './persistent-diagnostics';
import {
  cleanState,
  type DiagnosticState,
  type DiagnosticStorage,
} from './diagnostic-storage';
import { currentDiagnosticText, previewDiagnostics } from './diagnostic-report';

const live: PersistentDiagnostics[] = [];
beforeEach(() => {
  vi.useFakeTimers();
  vi.stubGlobal('__APP_VERSION__', 'test');
  vi.stubGlobal('__GIT_COMMIT__', 'abc123');
});
afterEach(() => {
  live.forEach(c => c.dispose());
  live.length = 0;
  vi.useRealTimers();
  vi.unstubAllGlobals();
});
class MemoryStorage implements DiagnosticStorage {
  state = cleanState(undefined);
  fail = false;
  async update(change: (state: DiagnosticState) => DiagnosticState) {
    if (this.fail) throw new Error('PRIVATE_STORAGE_ERROR');
    this.state = cleanState(change(structuredClone(this.state)));

    return structuredClone(this.state);
  }
}

async function setup(storage = new MemoryStorage()) {
  const store = new Store({ serverUrl: 'https://example.com', connect: false });
  const controller = new PersistentDiagnostics(store, storage, {
    broadcast: false,
  });
  live.push(controller);
  await controller.ready;

  return { store, controller, storage };
}

it('records by default and restores a separate session after reload without private fields', async () => {
  const first = await setup();
  first.store.diagnostics.beginSave({
    subject: 'PRIVATE_URL',
    value: 'PRIVATE_CONTENT',
  })('error');
  await first.controller.flush();
  first.controller.dispose();
  const next = await setup(first.storage);
  const report = JSON.parse(previewDiagnostics(next.store.diagnostics).text);
  expect(next.store.diagnostics.active).toBe(true);
  expect(report.previousSessions).toHaveLength(1);
  expect(
    report.previousSessions[0].events.some(
      (e: { code: string }) => e.code === 'save-error',
    ),
  ).toBe(true);
  expect(JSON.stringify(report)).not.toMatch(
    /PRIVATE_|startedAt|savedAt|epoch/,
  );
});
it('bounds all tabs together, prunes expired disk events, and keeps continuous recording', async () => {
  const first = await setup();
  const second = await setup(first.storage);
  for (let i = 0; i < 350; i++) first.store.diagnostics.beginSave({})('error');
  await first.controller.flush();
  for (let i = 0; i < 350; i++) second.store.diagnostics.beginSave({})('error');
  await second.controller.flush();
  expect(
    first.storage.state.sessions.reduce((n, s) => n + s.events.length, 0),
  ).toBe(500);
  vi.setSystemTime(Date.now() + 31 * 60_000);
  await second.controller.flush();
  expect(first.storage.state.sessions).toEqual([]);
  expect(second.store.diagnostics.active).toBe(true);
});
it('persists disabling and fences writes from stale tabs', async () => {
  const first = await setup();
  const other = await setup(first.storage);
  other.store.diagnostics.beginSave({})('error');
  await first.controller.setEnabled(false);
  await other.controller.flush();
  expect(other.controller.status).toBe('paused');
  expect(first.storage.state.sessions).toEqual([]);
  const reloaded = await setup(first.storage);
  expect(reloaded.store.diagnostics.active).toBe(false);
  await reloaded.controller.setEnabled(true);
  expect(reloaded.store.diagnostics.active).toBe(true);
});
it('keeps an opened preview frozen while the rolling buffer expires, but clears it on disable', async () => {
  const { store, controller } = await setup();
  store.diagnostics.beginSave({})('error');
  const preview = previewDiagnostics(store.diagnostics);
  vi.setSystemTime(Date.now() + 31 * 60_000);
  expect(currentDiagnosticText(store.diagnostics, preview)).toBe(preview.text);
  await controller.setEnabled(false);
  expect(currentDiagnosticText(store.diagnostics, preview)).toBeUndefined();
});
it('reports storage failure without throwing into saves and reports failed clearing honestly', async () => {
  const { store, controller, storage } = await setup();
  storage.fail = true;
  expect(() => store.diagnostics.beginSave({})('error')).not.toThrow();
  await expect(controller.flush()).resolves.toBeUndefined();
  expect(controller.capture().storage.state).toBe('memory-only');
  expect(controller.capture().storage.pendingEvents).toBeGreaterThan(0);
  await controller.setEnabled(false);
  expect(controller.status).toBe('clear-failed');
  expect(store.diagnostics.active).toBe(false);
  expect(JSON.stringify(controller.capture())).not.toContain(
    'PRIVATE_STORAGE_ERROR',
  );
});
it('strips unknown stored payloads and event fields on reads', async () => {
  const { controller, storage, store } = await setup();
  store.diagnostics.beginSave({})('error');
  await controller.flush();
  const raw = storage.state as unknown as {
    sessions: Array<{ events: Array<Record<string, unknown>> }>;
  };
  raw.sessions[0].events[0].url = 'PRIVATE_URL';
  raw.sessions[0].events.push({
    code: 'PRIVATE_CODE',
    message: 'PRIVATE_ERROR',
  });
  const clean = cleanState(raw);
  expect(JSON.stringify(clean)).not.toMatch(/PRIVATE_/);
});

it('clears on account changes and prevents an in-flight old write from restoring history', async () => {
  const { Agent, JSCryptoProvider } = await import('@tomic/lib');
  const storage = new MemoryStorage();
  const store = new Store({ serverUrl: 'https://example.com', connect: false });
  const keys = await Agent.generateKeyPair();
  store.setAgent(
    new Agent(
      new JSCryptoProvider(keys.privateKey),
      `did:ad:agent:${keys.publicKey}`,
    ),
  );
  const controller = new PersistentDiagnostics(store, storage, {
    broadcast: false,
  });
  live.push(controller);
  await controller.ready;
  store.diagnostics.beginSave({})('error');
  const preview = previewDiagnostics(store.diagnostics);
  let release!: () => void;
  const original = storage.update.bind(storage);
  vi.spyOn(storage, 'update').mockImplementationOnce(async change => {
    await new Promise<void>(resolve => {
      release = resolve;
    });

    return original(change);
  });
  const flushing = controller.flush();
  await Promise.resolve();
  store.setAgent(undefined);
  expect(currentDiagnosticText(store.diagnostics, preview)).toBeUndefined();
  release();
  await flushing;
  // reset is serialized behind the old write; a further reset waits for both.
  await controller.setEnabled(true);
  expect(storage.state.sessions).toEqual([]);
  expect(controller.capture().previousSessions).toEqual([]);
});

it('falls back to memory if IndexedDB cannot be opened', async () => {
  const storage = new MemoryStorage();
  storage.fail = true;
  const { controller, store } = await setup(storage);
  expect(store.diagnostics.active).toBe(true);
  expect(controller.status).toBe('memory-only');
  expect(controller.capture().previousSessions).toEqual([]);
});

it('does not re-enable a remotely disabled preference during an account change', async () => {
  const first = await setup();
  const stale = await setup(first.storage);
  await first.controller.setEnabled(false);
  const epoch = first.storage.state.epoch;
  const { Agent, JSCryptoProvider } = await import('@tomic/lib');
  const keys = await Agent.generateKeyPair();
  stale.store.setAgent(
    new Agent(
      new JSCryptoProvider(keys.privateKey),
      `did:ad:agent:${keys.publicKey}`,
    ),
  );
  await vi.waitFor(() => expect(first.storage.state.epoch).not.toBe(epoch));
  expect(first.storage.state.enabled).toBe(false);
  expect(stale.store.diagnostics.active).toBe(false);
});

it('does not let unavailable cross-tab messaging break clearing', async () => {
  vi.stubGlobal(
    'BroadcastChannel',
    class {
      postMessage() {
        throw new Error('messaging unavailable');
      }
      close() {}
    },
  );
  const store = new Store({ serverUrl: 'https://example.com', connect: false });
  const controller = new PersistentDiagnostics(store, new MemoryStorage());
  live.push(controller);
  await controller.ready;
  await expect(controller.setEnabled(false)).resolves.toBeUndefined();
  expect(store.diagnostics.active).toBe(false);
});
