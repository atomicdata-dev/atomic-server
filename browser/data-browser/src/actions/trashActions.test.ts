import { describe, expect, it } from 'vitest';
import { resourceActions } from './resourceActions';
import type { ActionContext } from './types';

const DRIVE = 'atomic:drive';
const TRASH = 'atomic:trash';

const make = (subject: string, parent?: string): ActionContext =>
  ({
    canWrite: true,
    drive: DRIVE,
    subject,
    store: {
      getResourceLoading: () => ({ get: () => TRASH }),
    },
    resource: {
      get: (prop: string) => (prop.endsWith('/parent') ? parent : undefined),
    },
  }) as unknown as ActionContext;

const available = (id: string, ctx: ActionContext) =>
  resourceActions.find(a => a.id === id)!.available?.(ctx) ?? true;

describe('trash and delete availability', () => {
  it('offers Move to Trash, not permanent delete, for an ordinary item', () => {
    const ctx = make('atomic:item', DRIVE);

    expect(available('trash', ctx)).toBe(true);
    expect(available('delete', ctx)).toBe(false);
  });

  it('offers only permanent delete for an item inside the Trash', () => {
    const ctx = make('atomic:item', TRASH);

    expect(available('trash', ctx)).toBe(false);
    expect(available('delete', ctx)).toBe(true);
  });

  it('never moves the drive or the Trash folder into the Trash', () => {
    for (const subject of [DRIVE, TRASH]) {
      const ctx = make(subject, undefined);

      expect(available('trash', ctx)).toBe(false);
      expect(available('delete', ctx)).toBe(true);
    }
  });
});
