import { describe, expect, it, vi } from 'vitest';
import { handleStaleChunk } from './staleChunkReload';

function memoryStorage(): Storage {
  const data = new Map<string, string>();

  return {
    getItem: key => data.get(key) ?? null,
    setItem: (key, value) => void data.set(key, value),
  } as Storage;
}

describe('handleStaleChunk', () => {
  it('prevents the error and reloads the first time', () => {
    const event = { preventDefault: vi.fn() };
    const reload = vi.fn();

    handleStaleChunk(event, reload, () => memoryStorage());

    expect(event.preventDefault).toHaveBeenCalledOnce();
    expect(reload).toHaveBeenCalledOnce();
  });

  it('lets the error through when this session already reloaded', () => {
    const storage = memoryStorage();
    const reload = vi.fn();

    handleStaleChunk({ preventDefault: vi.fn() }, reload, () => storage);

    const second = { preventDefault: vi.fn() };

    handleStaleChunk(second, reload, () => storage);

    expect(second.preventDefault).not.toHaveBeenCalled();
    expect(reload).toHaveBeenCalledOnce();
  });

  it('does not reload when sessionStorage throws', () => {
    const event = { preventDefault: vi.fn() };
    const reload = vi.fn();

    handleStaleChunk(event, reload, () => {
      throw new Error('blocked');
    });

    expect(event.preventDefault).not.toHaveBeenCalled();
    expect(reload).not.toHaveBeenCalled();
  });
});
