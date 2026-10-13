// @wc-ignore-file
// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { StoreEvents, core, dataBrowser } from '@tomic/react';
import {
  FLUSH_DEBOUNCE_MS,
  startDriveActivityRecorder,
} from './driveActivityRecorder';
import type { ActivityEntry } from './activityLog';

const DRIVE = 'did:ad:drive';
const AGENT = 'did:ad:agent:me';
const LOG = dataBrowser.properties.activityLog;

function setup(opts: { canWrite?: boolean; remote?: ActivityEntry[] } = {}) {
  const props: Record<string, unknown> = { [LOG]: [] };
  let saved: ActivityEntry[] | undefined;
  const drive = {
    subject: DRIVE,
    get: (p: string) => props[p],
    canWrite: vi.fn(async () => [opts.canWrite ?? true, undefined]),
    set: vi.fn(async (p: string, v: unknown) => {
      props[p] = v;
    }),
    save: vi.fn(async () => {
      saved = props[LOG] as ActivityEntry[];
    }),
  };
  let handler: (r: unknown) => void = () => undefined;
  const store = {
    getAgent: () => ({ subject: AGENT }),
    on: vi.fn((_e: unknown, h: (r: unknown) => void) => {
      handler = h;

      return () => undefined;
    }),
    // Reloading brings in whatever another writer saved meanwhile.
    reloadResource: vi.fn(async () => {
      if (opts.remote) props[LOG] = opts.remote;
    }),
    getResource: vi.fn(async (s: string) =>
      s === DRIVE ? drive : { subject: s, get: () => undefined },
    ),
  };
  const resource = (subject: string) => ({
    subject,
    get: (p: string) => (p === core.properties.parent ? DRIVE : undefined),
    getClasses: () => [] as string[],
    getCreatedAt: () => undefined,
  });

  return {
    store,
    drive,
    save: (subject: string) => handler(resource(subject)),
    saved: () => saved,
  };
}

const start = (s: ReturnType<typeof setup>) =>
  startDriveActivityRecorder(s.store as never, DRIVE);

describe('driveActivityRecorder', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(2026, 9, 8, 12, 0, 0));
  });
  afterEach(() => vi.useRealTimers());

  it('listens to ResourceSaved', () => {
    const s = setup();
    start(s);
    expect(s.store.on).toHaveBeenCalledWith(
      StoreEvents.ResourceSaved,
      expect.any(Function),
    );
  });

  it('merges into the log another writer saved meanwhile', async () => {
    const remote: ActivityEntry[] = [
      {
        subject: 'did:ad:other',
        agent: 'did:ad:agent:you',
        at: 1,
        kind: 'edited',
      },
    ];
    const s = setup({ remote });
    start(s);
    s.save('did:ad:a');
    await vi.advanceTimersByTimeAsync(FLUSH_DEBOUNCE_MS);
    expect(s.store.reloadResource).toHaveBeenCalledWith(DRIVE);
    expect(s.saved()?.map(e => e.subject)).toEqual([
      'did:ad:a',
      'did:ad:other',
    ]);
  });

  it('retries entries after a failed save and then gives up', async () => {
    const s = setup();
    s.drive.save.mockRejectedValueOnce(new Error('offline'));
    start(s);
    s.save('did:ad:a');
    await vi.advanceTimersByTimeAsync(FLUSH_DEBOUNCE_MS);
    expect(s.saved()).toBeUndefined();
    await vi.advanceTimersByTimeAsync(FLUSH_DEBOUNCE_MS);
    expect(s.saved()?.map(e => e.subject)).toEqual(['did:ad:a']);

    const f = setup();
    f.drive.save.mockRejectedValue(new Error('nope'));
    start(f);
    f.save('did:ad:b');
    await vi.advanceTimersByTimeAsync(FLUSH_DEBOUNCE_MS * 10);
    expect(f.drive.save).toHaveBeenCalledTimes(3);
  });

  it('does not write without write rights', async () => {
    const s = setup({ canWrite: false });
    start(s);
    s.save('did:ad:a');
    await vi.advanceTimersByTimeAsync(FLUSH_DEBOUNCE_MS * 2);
    expect(s.drive.set).not.toHaveBeenCalled();
    expect(s.drive.save).not.toHaveBeenCalled();
  });

  it('flushes on pagehide and on dispose', async () => {
    const s = setup();
    start(s);
    s.save('did:ad:a');
    Object.defineProperty(document, 'visibilityState', {
      configurable: true,
      get: () => 'hidden',
    });
    window.dispatchEvent(new Event('pagehide'));
    await vi.advanceTimersByTimeAsync(0);
    expect(s.saved()?.map(e => e.subject)).toEqual(['did:ad:a']);

    const s2 = setup();
    const stop = start(s2);
    s2.save('did:ad:b');
    stop();
    await vi.advanceTimersByTimeAsync(0);
    expect(s2.saved()?.map(e => e.subject)).toEqual(['did:ad:b']);
  });
});
