// @wc-ignore-file
import { beforeEach, describe, expect, it, vi } from 'vitest';
import toast from 'react-hot-toast';
import { handleZoneDrop, isZoneData } from './useSidebarDnd';

vi.mock('react-hot-toast', () => {
  const t = Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn() });

  return { default: t };
});

const deps = (favorites: string[] = [], moved = true) => ({
  favorites,
  addFavorite: vi.fn(),
  moveToTrash: vi.fn().mockResolvedValue(moved),
});

describe('sidebar drop zones', () => {
  beforeEach(() => vi.clearAllMocks());

  it('recognises zone data and not row data', () => {
    expect(isZoneData({ zone: 'trash' })).toBe(true);
    expect(isZoneData({ zone: 'favorites' })).toBe(true);
    expect(isZoneData({ parent: 'x' })).toBe(false);
    expect(isZoneData(undefined)).toBe(false);
  });

  it('adds a new favorite', async () => {
    const d = deps();
    await handleZoneDrop('favorites', 'a', d);
    expect(d.addFavorite).toHaveBeenCalledWith('a');
    expect(d.moveToTrash).not.toHaveBeenCalled();
  });

  it('does not duplicate a favorite', async () => {
    const d = deps(['a']);
    await handleZoneDrop('favorites', 'a', d);
    expect(d.addFavorite).not.toHaveBeenCalled();
    expect(toast).toHaveBeenCalled();
  });

  it('moves to trash and announces it', async () => {
    const d = deps();
    await handleZoneDrop('trash', 'a', d);
    expect(d.moveToTrash).toHaveBeenCalledWith('a');
    expect(toast.success).toHaveBeenCalled();
  });

  it('stays silent when the item was already in the trash', async () => {
    await handleZoneDrop('trash', 'a', deps([], false));
    expect(toast.success).not.toHaveBeenCalled();
  });

  it('reports a failed move', async () => {
    const d = deps();
    d.moveToTrash.mockRejectedValue(new Error('nope'));
    await handleZoneDrop('trash', 'a', d);
    expect(toast.error).toHaveBeenCalledWith('nope');
  });
});
