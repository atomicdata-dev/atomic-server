// @wc-ignore-file
import { beforeEach, describe, expect, it, vi } from 'vitest';

const reported: Error[] = [];

vi.mock('@helpers/loggingHandlers', () => ({
  reportStoreError: (e: Error) => reported.push(e),
}));

const { handleChatSaveError, CHAT_SAVE_TOAST_ID } =
  await import('./saveErrors');

const notEnrolled = (drive = 'did:ad:abc') =>
  new Error(`Drive ${drive} is not enrolled for sync on this node.`);

beforeEach(() => {
  reported.length = 0;
  vi.spyOn(console, 'error').mockImplementation(() => undefined);
});

describe('handleChatSaveError', () => {
  it('stays silent when the node refuses the drive, but still logs', () => {
    const notify = vi.fn();
    const error = notEnrolled();

    handleChatSaveError(error, notify);

    expect(notify).not.toHaveBeenCalled();
    expect(reported).toEqual([]);
    expect(console.error).toHaveBeenCalledWith(error);
  });

  it('stays silent for a refusal passed as a plain string', () => {
    const notify = vi.fn();

    handleChatSaveError(notEnrolled().message, notify);

    expect(notify).not.toHaveBeenCalled();
  });

  it('notifies with the shared id and reports any other error', () => {
    const notify = vi.fn();
    const error = new Error('network down');

    handleChatSaveError(error, notify);

    expect(notify).toHaveBeenCalledTimes(1);
    expect(notify).toHaveBeenCalledWith({ id: CHAT_SAVE_TOAST_ID });
    expect(CHAT_SAVE_TOAST_ID).toBe('ai-chat-save');
    expect(reported).toEqual([error]);
    expect(console.error).toHaveBeenCalledWith(error);
  });

  it.each([
    ['null', null],
    ['undefined', undefined],
    ['a number', 42],
    ['a plain object', { message: 'nope' }],
    ['a string', 'boom'],
  ])('notifies without throwing for %s', (_label, value) => {
    const notify = vi.fn();

    expect(() => handleChatSaveError(value, notify)).not.toThrow();
    expect(notify).toHaveBeenCalledWith({ id: 'ai-chat-save' });
    expect(reported).toHaveLength(1);
    expect(reported[0]).toBeInstanceOf(Error);
  });
});
