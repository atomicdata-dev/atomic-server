// @vitest-environment jsdom
// @wc-ignore-file
import { describe, expect, it, vi } from 'vitest';
import { STARTER_APP_SOURCE } from './starter';

describe('starter app', () => {
  it.each([[], ['row']])(
    'keeps the latest refresh when the initial query finishes with %j',
    async (...subjects: string[]) => {
      let finishInitial!: (subjects: string[]) => void;
      const initial = new Promise<string[]>(resolve => {
        finishInitial = resolve;
      });
      const store = {
        getData: vi
          .fn()
          .mockResolvedValue({ table: 'table', rowClass: 'class' }),
        query: vi.fn().mockReturnValueOnce(initial).mockResolvedValue(['row']),
        getResource: vi.fn().mockResolvedValue({ get: () => 'Item 1' }),
        newResource: vi.fn().mockResolvedValue(undefined),
      };
      // Execute the shipped starter, including its asynchronous DOM behavior.
      const view = new Function(
        `${STARTER_APP_SOURCE.replace('export async function', 'async function')}; return view;`,
      )();
      const root = document.createElement('div');
      const rendering = view({ root, store });
      await vi.waitFor(() => expect(store.query).toHaveBeenCalledTimes(1));

      root.querySelector('button')!.click();
      await vi.waitFor(() =>
        expect(root.querySelectorAll('li')).toHaveLength(1),
      );
      finishInitial(subjects);
      await rendering;

      expect(root.querySelectorAll('li')).toHaveLength(1);
      expect(root.querySelector('li')?.textContent).toBe('Item 1');
      expect(store.newResource).toHaveBeenCalledTimes(1);
    },
  );
});
