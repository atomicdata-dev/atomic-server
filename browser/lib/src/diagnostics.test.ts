import { afterEach, describe, expect, it, vi } from 'vitest';
import { DiagnosticRecorder } from './diagnostics.js';

afterEach(() => {
  vi.useRealTimers();
});

describe('local diagnostic recorder', () => {
  it('is off by default and never retains supplied identities or errors', () => {
    const recorder = new DiagnosticRecorder();
    const resource = {
      subject: 'https://private.example/SECRET',
      title: 'PRIVATE_TEXT',
    };
    recorder.beginSave(resource)('error');
    expect(recorder.snapshot()).toEqual([]);
    recorder.start();
    recorder.beginSave(resource)('error');
    const report = JSON.stringify(recorder.snapshot());
    expect(report).toContain('save-error');
    expect(report).not.toMatch(
      /SECRET|PRIVATE_TEXT|private.example|subject|title/,
    );
    recorder.clear();
  });

  it('bounds events and clears all data when recording expires', () => {
    vi.useFakeTimers();
    const recorder = new DiagnosticRecorder();
    recorder.start();
    for (let i = 0; i < 700; i++) recorder.connection(i % 2 === 0);
    expect(recorder.snapshot()).toHaveLength(500);
    vi.advanceTimersByTime(10 * 60_000 + 10_000);
    expect(recorder.snapshot()).toEqual([]);
    recorder.connection(true);
    vi.advanceTimersByTime(20 * 60_000);
    expect(recorder.active).toBe(false);
    expect(recorder.snapshot()).toEqual([]);
  });

  it('detects a slow save and a non-draining connected queue once', () => {
    vi.useFakeTimers();
    const recorder = new DiagnosticRecorder();
    recorder.start();
    const finish = recorder.beginSave({});
    recorder.queue(2, 0, true);
    vi.advanceTimersByTime(70_000);
    expect(
      recorder.snapshot().filter(e => e.code === 'save-slow'),
    ).toHaveLength(1);
    expect(
      recorder.snapshot().filter(e => e.code === 'queue-stalled'),
    ).toHaveLength(1);
    finish('persisted');
    expect(recorder.snapshot().at(-1)?.code).toBe('save-persisted');
    recorder.clear();
  });

  it('does not call an offline queue stalled and ignores late results after clear', () => {
    vi.useFakeTimers();
    const recorder = new DiagnosticRecorder();
    recorder.start();
    recorder.queue(1, 0, false);
    const finish = recorder.beginSave({});
    vi.advanceTimersByTime(70_000);
    expect(recorder.snapshot().some(e => e.code === 'queue-stalled')).toBe(
      false,
    );
    recorder.clear();
    recorder.start();
    finish('persisted');
    expect(recorder.snapshot()).toEqual([]);
    recorder.clear();
  });
});

describe('recorder integration', () => {
  it('records real save failures without changing rejection or retaining content', async () => {
    const { Store } = await import('./store.js');
    const store = new Store({ serverUrl: 'https://example.com' });
    store.diagnostics.start();
    const { Resource } = await import('./resource.js');
    const resource = new Resource('https://private.example/SECRET', true);
    resource.setStore(store);
    await resource.set(
      'https://atomicdata.dev/properties/name',
      'PRIVATE_TEXT',
      false,
    );
    await expect(resource.save()).rejects.toThrow();
    expect(store.diagnostics.snapshot().map(event => event.code)).toContain(
      'save-error',
    );
    store.diagnostics.clear();
  });

  it('does not let a diagnostic UI listener break saves or resets', () => {
    const recorder = new DiagnosticRecorder();
    recorder.subscribe(() => {
      throw new Error('PRIVATE listener error');
    });
    expect(() => recorder.start()).not.toThrow();
    expect(() => recorder.beginSave({})('persisted')).not.toThrow();
    expect(() => recorder.clear()).not.toThrow();
  });
});

it('clears recording when the Store changes account', async () => {
  const { testStore } = await import('./test-store.js');
  const { store } = await testStore();
  store.diagnostics.start();
  store.diagnostics.connection(true);
  store.setAgent(undefined);
  expect(store.diagnostics.active).toBe(false);
  expect(store.diagnostics.snapshot()).toEqual([]);
});

it('stops collecting after expiry when background timers are delayed', () => {
  vi.useFakeTimers();
  const recorder = new DiagnosticRecorder();
  recorder.start();
  vi.setSystemTime(Date.now() + 31 * 60_000);
  recorder.connection(true);
  expect(recorder.active).toBe(false);
  expect(recorder.snapshot()).toEqual([]);
});

it('reports overlapping boundaries independently and makes truncated evidence explicit', () => {
  vi.useFakeTimers();
  const recorder = new DiagnosticRecorder();
  recorder.start();
  const target = { subject: 'PRIVATE' };
  const first = recorder.beginBoundary('server', target);
  const second = recorder.beginBoundary('server', target);
  second('ok');
  first('error');
  const events = recorder.capture().events;
  expect(events.map(e => e.attempt)).toEqual([1, 2, 2, 1]);
  expect(events[0].operation).toBe(events[3].operation);
  expect(events[1].operation).toBe(events[2].operation);
  expect(events[0].resource).toBe(events[1].resource);
  expect(events[0].operation).not.toBe(events[1].operation);
  recorder.beginBoundary('local', target);
  vi.advanceTimersByTime(610_000);
  expect(recorder.capture().completeness).toMatchObject({
    droppedAge: 5,
    unfinishedOperations: 1,
  });
  recorder.clear();
});

it('exposes local write failure through the real save path without exporting secrets', async () => {
  const { testStore, attachTestDb } = await import('./test-store.js');
  const { store } = await testStore();
  const db = attachTestDb(store);
  store.setServerConnected(false);
  const resource = await store.newResource({ noParent: true });
  await resource.set(
    'https://atomicdata.dev/properties/name',
    'PRIVATE_CONTENT',
    false,
  );
  db.putResourceWithSnapshot.mockRejectedValue(new Error('PRIVATE_DISK_ERROR'));
  store.diagnostics.start();

  try {
    await expect(resource.save()).rejects.toThrow();
    const report = JSON.parse(JSON.stringify(store.diagnostics.capture()));
    expect(report.events.map((e: { code: string }) => e.code)).toContain(
      'local-persist-error',
    );
    expect(report.events.map((e: { code: string }) => e.code)).toContain(
      'save-error',
    );
    expect(JSON.stringify(report)).not.toMatch(
      /PRIVATE_CONTENT|PRIVATE_DISK_ERROR/,
    );
  } finally {
    store.diagnostics.clear();
  }
});

it('records an unconfirmed server request separately from successful local fallback', async () => {
  const { testStore, attachTestDb } = await import('./test-store.js');
  const { store, postCommitSpy } = await testStore();
  attachTestDb(store);
  const resource = await store.newResource({ noParent: true });
  await resource.set(
    'https://atomicdata.dev/properties/name',
    'PRIVATE_CONTENT',
    false,
  );
  postCommitSpy.mockRejectedValue(new TypeError('Failed to fetch'));
  store.diagnostics.start();

  try {
    await resource.save();
    const report = JSON.parse(JSON.stringify(store.diagnostics.capture()));
    const codes = report.events.map((e: { code: string }) => e.code);
    expect(codes).toContain('server-unconfirmed');
    expect(codes).toContain('local-persist-acknowledged');
    expect(codes).toContain('save-offline');
    expect(codes).not.toContain('server-acknowledged');
    expect(JSON.stringify(report)).not.toContain('PRIVATE_CONTENT');
  } finally {
    store.diagnostics.clear();
    store.setServerConnected(false);
  }
});

it('records reconciliation cancellation and failure without drive or error identities', async () => {
  const { testStore } = await import('./test-store.js');
  const { store } = await testStore();
  store.diagnostics.start();

  try {
    store.startDriveSync();
    store.startDriveSync();
    store.failDriveSync('PRIVATE_DRIVE', 'PRIVATE_RECONCILE_ERROR');
    const report = JSON.parse(JSON.stringify(store.diagnostics.capture()));
    expect(report.events.map((e: { code: string }) => e.code)).toContain(
      'operation-cancelled',
    );
    expect(report.events.map((e: { code: string }) => e.code)).toContain(
      'reconcile-error',
    );
    expect(report.completeness.unfinishedOperations).toBe(0);
    expect(JSON.stringify(report)).not.toMatch(
      /PRIVATE_DRIVE|PRIVATE_RECONCILE_ERROR/,
    );
  } finally {
    store.diagnostics.clear();
    store.setServerConnected(false);
  }
});
