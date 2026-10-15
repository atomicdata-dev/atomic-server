// @wc-ignore-file
import { beforeEach, describe, expect, it, vi } from 'vitest';
import toast from 'react-hot-toast';
import { handleZoneDrop, isZoneData, zoneDropKeyframes } from './useSidebarDnd';

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

  it('leaves a conversation instead of trashing it', async () => {
    const d = {
      ...deps(),
      isConversation: vi.fn().mockReturnValue(true),
      leaveConversation: vi.fn().mockResolvedValue(undefined),
    };
    await handleZoneDrop('trash', 'chat', d);
    expect(d.leaveConversation).toHaveBeenCalledWith('chat');
    expect(d.moveToTrash).not.toHaveBeenCalled();
    expect(toast.success).toHaveBeenCalledWith('Removed from your messages');
  });

  it('still trashes a resource that is not a conversation', async () => {
    const d = {
      ...deps(),
      isConversation: vi.fn().mockReturnValue(false),
      leaveConversation: vi.fn(),
    };
    await handleZoneDrop('trash', 'a', d);
    expect(d.moveToTrash).toHaveBeenCalledWith('a');
    expect(d.leaveConversation).not.toHaveBeenCalled();
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

  it('shrinks and fades the overlay in place on a zone drop', () => {
    const [from, to] = zoneDropKeyframes({ x: 12, y: -40 });

    expect(from.transform).toBe('translate(12px, -40px) scale(1)');
    expect(to.transform).toBe('translate(12px, -40px) scale(0.2)');
    expect(to.opacity).toBe(0);
  });
});
