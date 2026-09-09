import { afterEach, describe, expect, it } from 'vitest';
import {
  applyDeterministicGlobals,
  denyAmbientGlobals,
  invokeRun,
  type RunInput,
} from './plugin-sandbox.js';

const input = (over: Partial<RunInput> = {}): RunInput => ({
  trigger: { kind: 'manual', at: 1_700_000_000_000 },
  ...over,
});

const restores: Array<() => void> = [];

afterEach(() => {
  while (restores.length) restores.pop()!();
});

describe('invokeRun', () => {
  it('serializes what run returned', async () => {
    const result = await invokeRun(
      { run: () => ({ intents: [], problems: [] }) },
      input(),
    );

    expect(result.problem).toBeUndefined();
    expect(JSON.parse(result.json!)).toEqual({ intents: [], problems: [] });
  });

  it('awaits an async run', async () => {
    const result = await invokeRun(
      { run: async () => ({ cursor: 'p2' }) },
      input(),
    );

    expect(JSON.parse(result.json!)).toEqual({ cursor: 'p2' });
  });

  it('hands run the trigger, records, config and cursor', async () => {
    let seen: RunInput | undefined;

    await invokeRun(
      { run: (i: RunInput) => ((seen = i), {}) },
      input({ records: [{ a: 1 }], config: { key: 'v' }, cursor: 'c' }),
    );

    expect(seen).toMatchObject({
      trigger: { kind: 'manual' },
      records: [{ a: 1 }],
      config: { key: 'v' },
      cursor: 'c',
    });
  });

  it('reports a module that exports no run', async () => {
    const result = await invokeRun({}, input());

    expect(result.json).toBeUndefined();
    expect(result.problem!.message).toContain('run()');
  });

  it('turns a thrown error into a problem instead of propagating', async () => {
    const result = await invokeRun(
      {
        run: () => {
          throw new TypeError('cannot read column');
        },
      },
      input(),
    );

    expect(result.problem!.message).toContain('TypeError');
    expect(result.problem!.message).toContain('cannot read column');
  });

  it('turns a rejected promise into a problem', async () => {
    const result = await invokeRun(
      { run: () => Promise.reject(new Error('nope')) },
      input(),
    );

    expect(result.problem!.message).toContain('nope');
  });

  it('reports a value that cannot be serialized', async () => {
    const result = await invokeRun(
      {
        run: () => {
          const cycle: Record<string, unknown> = {};
          cycle.self = cycle;

          return cycle;
        },
      },
      input(),
    );

    expect(result.problem!.message).toContain('serialized');
  });

  it('refuses oversized output rather than clipping it', async () => {
    const result = await invokeRun(
      { run: () => ({ blob: 'x'.repeat(500) }) },
      input(),
      { maxOutputBytes: 100 },
    );

    expect(result.json).toBeUndefined();
    expect(result.problem!.message).toContain('100');
    expect(result.problem!.message).toContain('Nothing was planned');
  });
});

describe('deterministic globals', () => {
  it('freezes the clock to the trigger time', () => {
    const scope = { Date, Math, performance } as Record<string, unknown>;
    restores.push(applyDeterministicGlobals(scope, input()));

    const Frozen = scope.Date as DateConstructor;

    expect(Frozen.now()).toBe(1_700_000_000_000);
    expect(new Frozen().getTime()).toBe(1_700_000_000_000);
  });

  it('still parses explicit dates', () => {
    const scope = { Date, Math, performance } as Record<string, unknown>;
    restores.push(applyDeterministicGlobals(scope, input()));

    const Frozen = scope.Date as DateConstructor;

    expect(new Frozen('2020-01-02T03:04:05Z').toISOString()).toBe(
      '2020-01-02T03:04:05.000Z',
    );
    expect(new Frozen(0).getTime()).toBe(0);
  });

  it('gives two runs over the same input the same random sequence', () => {
    const draw = () => {
      const scope = { Date, Math, performance } as Record<string, unknown>;
      const restore = applyDeterministicGlobals(scope, input());
      const values = [Math.random(), Math.random(), Math.random()];
      restore();

      return values;
    };

    expect(draw()).toEqual(draw());
  });

  it('varies the sequence when the input differs', () => {
    const draw = (cursor: string) => {
      const scope = { Date, Math, performance } as Record<string, unknown>;
      const restore = applyDeterministicGlobals(scope, input({ cursor }));
      const value = Math.random();
      restore();

      return value;
    };

    expect(draw('page-1')).not.toEqual(draw('page-2'));
  });

  it('restores the real clock and PRNG', () => {
    const scope = { Date, Math, performance } as Record<string, unknown>;
    const before = Math.random;
    applyDeterministicGlobals(scope, input())();

    expect(scope.Date).toBe(Date);
    expect(Math.random).toBe(before);
  });
});

describe('denied globals', () => {
  it('explains what to do instead of failing as undefined', () => {
    const scope: Record<string, unknown> = { fetch: () => undefined };
    restores.push(denyAmbientGlobals(scope).restore);

    expect(() => scope.fetch).toThrow(/no I\/O of its own/);
    expect(() => scope.fetch).toThrow(/network capability/);
  });

  it('denies globals inherited from a prototype, as in a Worker scope', () => {
    // Worker globals live on WorkerGlobalScope.prototype, not on globalThis.
    // Only checking own properties silently denied nothing at all.
    const proto = { fetch: () => 'real', indexedDB: {} };
    const scope: Record<string, unknown> = Object.create(proto);

    const result = denyAmbientGlobals(scope);
    restores.push(result.restore);

    expect(result.denied).toContain('fetch');
    expect(result.denied).toContain('indexedDB');
    expect(() => scope.fetch).toThrow();
    expect(() => scope.indexedDB).toThrow();
  });

  it('denies every ambient I/O global that is present', () => {
    const scope: Record<string, unknown> = {
      fetch: 1,
      indexedDB: 1,
      WebSocket: 1,
      localStorage: 1,
    };
    restores.push(denyAmbientGlobals(scope).restore);

    for (const name of ['fetch', 'indexedDB', 'WebSocket', 'localStorage']) {
      expect(() => scope[name]).toThrow();
    }
  });

  it('ignores globals the scope does not have', () => {
    const scope: Record<string, unknown> = {};
    const result = denyAmbientGlobals(scope);

    expect(result.denied).toEqual([]);
    expect(result.undeniable).toEqual([]);
    expect(scope.fetch).toBeUndefined();
  });

  it('reports a global it could not shadow instead of implying it did', () => {
    const scope: Record<string, unknown> = {};
    Object.defineProperty(scope, 'fetch', {
      value: () => 'real',
      configurable: false,
      writable: false,
    });

    const result = denyAmbientGlobals(scope);

    expect(result.denied).toEqual([]);
    expect(result.undeniable).toEqual(['fetch']);
  });

  it('puts an own global back', () => {
    const original = () => 'real';
    const scope: Record<string, unknown> = { fetch: original };
    denyAmbientGlobals(scope).restore();

    expect(scope.fetch).toBe(original);
  });

  it('exposes an inherited global again after restore', () => {
    const proto = { fetch: () => 'real' };
    const scope: Record<string, unknown> = Object.create(proto);
    denyAmbientGlobals(scope).restore();

    expect(scope.fetch).toBe(proto.fetch);
    expect(Object.hasOwn(scope, 'fetch')).toBe(false);
  });
});
