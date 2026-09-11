import { afterEach, describe, expect, it, vi } from 'vitest';
import { core, server, type Store } from '@tomic/react';
import { keepTemplateDemo } from './keepTemplateDemo';
import { TEMPLATE_DEMO_KEY } from './demoSession';

const demo = {
  drive: 'did:ad:preview',
  template: 'student',
  previousDrive: '',
};

function fixture() {
  const storage = new Map([[TEMPLATE_DEMO_KEY, JSON.stringify(demo)]]);
  vi.stubGlobal('localStorage', {
    getItem: (key: string) => storage.get(key) ?? null,
    removeItem: (key: string) => storage.delete(key),
  });
  const drive = {
    subject: demo.drive,
    hasClasses: () => true,
    set: vi.fn(),
    save: vi.fn(),
  };
  const home = {
    getSubjects: (): string[] => [],
    push: vi.fn(),
    save: vi.fn(),
  };
  const store = {
    isLocalOnlySubject: () => true,
    getResource: vi.fn().mockResolvedValue(drive),
    ensurePrivateDrive: vi.fn().mockResolvedValue(home),
  } as unknown as Store;

  return { store, drive, home, storage };
}

afterEach(() => vi.unstubAllGlobals());
describe('keeping edited template previews', () => {
  it('keeps the same graph and lists it before releasing the demo marker', async () => {
    const { store, drive, home, storage } = fixture();
    home.save.mockImplementation(async () => {
      expect(storage.has(TEMPLATE_DEMO_KEY)).toBe(true);
    });
    expect(await keepTemplateDemo(store, demo, 'My studies')).toBe(drive);
    expect(drive.set).toHaveBeenCalledWith(core.properties.name, 'My studies');
    expect(home.push).toHaveBeenCalledWith(server.properties.drives, [
      demo.drive,
    ]);
    expect(storage.has(TEMPLATE_DEMO_KEY)).toBe(false);
  });
  it('retains the preview for retry if saving its listing fails', async () => {
    const { store, home, storage } = fixture();
    home.save.mockRejectedValueOnce(new Error('offline'));
    home.getSubjects = () => [demo.drive];
    await expect(keepTemplateDemo(store, demo, 'Studies')).rejects.toThrow(
      'offline',
    );
    expect(storage.has(TEMPLATE_DEMO_KEY)).toBe(true);
    await keepTemplateDemo(store, demo, 'Studies');
    expect(home.save).toHaveBeenCalledTimes(2);
    expect(storage.has(TEMPLATE_DEMO_KEY)).toBe(false);
  });
  it('rejects an expired preview before writing anything', async () => {
    const { store, drive, storage } = fixture();
    storage.clear();
    await expect(keepTemplateDemo(store, demo, 'Studies')).rejects.toThrow(
      'no longer available',
    );
    expect(drive.save).not.toHaveBeenCalled();
  });
});
