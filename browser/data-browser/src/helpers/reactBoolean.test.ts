import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createElement, useEffect } from 'react';
import { renderToString } from 'react-dom/server';
import { Resource, Store } from '@tomic/lib';
import { StoreContext, useBoolean } from '@tomic/react';

// Run mount effects explicitly after an actual React render. Server rendering
// alone would miss the write that used to happen when a Boolean was absent.
const effects = vi.hoisted(() => [] as Array<() => unknown>);
vi.mock('react', async importOriginal => ({
  ...(await importOriginal<typeof import('react')>()),
  useEffect: (effect: () => unknown) => effects.push(effect),
}));

const property = 'https://atomicdata.dev/properties/view-sort-desc';
beforeEach(() => {
  effects.length = 0;
});

describe('useBoolean reads', () => {
  it.each([true, false])(
    'does not write a default while loading=%s',
    async loading => {
      const store = new Store();
      const resource = new Resource('https://example.com/view');
      resource.loading = loading;
      const set = vi.spyOn(resource, 'set');

      function Reader() {
        const [value] = useBoolean(resource, property, { validate: false });

        return String(value);
      }

      expect(
        renderToString(
          createElement(
            StoreContext.Provider,
            { value: store },
            createElement(Reader),
          ),
        ),
      ).toBe('false');
      for (const effect of effects) effect();
      await Promise.resolve();
      expect(set).not.toHaveBeenCalled();
      expect(resource.get(property)).toBeUndefined();
    },
  );
  it('preserves a stored true value and still accepts an explicit false edit', async () => {
    const store = new Store();
    const resource = new Resource('https://example.com/view');
    await resource.set(property, true, false);
    let edit: ((value: boolean) => Promise<void>) | undefined;

    function Reader() {
      const [value, set] = useBoolean(resource, property, { validate: false });
      useEffect(() => {
        edit = set;
      }, [set]);

      return String(value);
    }

    expect(
      renderToString(
        createElement(
          StoreContext.Provider,
          { value: store },
          createElement(Reader),
        ),
      ),
    ).toBe('true');
    for (const effect of effects) effect();
    expect(resource.get(property)).toBe(true);
    await edit?.(false);
    expect(resource.get(property)).toBe(false);
  });
});
