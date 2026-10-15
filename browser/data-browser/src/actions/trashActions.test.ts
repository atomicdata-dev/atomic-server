import { conversations } from '@tomic/react';
import { describe, expect, it } from 'vitest';
import { resourceActions } from './resourceActions';
import type { ActionContext } from './types';

const DRIVE = 'atomic:drive';
const TRASH = 'atomic:trash';

const make = (
  subject: string,
  parent?: string,
  classes: string[] = [],
): ActionContext =>
  ({
    canWrite: true,
    drive: DRIVE,
    subject,
    store: {
      resources: new Map([[DRIVE, { get: () => TRASH }]]),
    },
    resource: {
      getClasses: () => classes,
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

  it('never offers trash or delete for a conversation', () => {
    const ctx = make('atomic:chat', undefined, [
      conversations.classes.conversation,
    ]);

    expect(available('trash', ctx)).toBe(false);
    expect(available('delete', ctx)).toBe(false);
  });
});
