import { describe, expect, it, vi } from 'vitest';
import type { Store } from '@tomic/react';
import { processAtomicResources } from './processAtomicResources';

vi.mock('@tomic/react', async importOriginal => ({
  ...(await importOriginal<typeof import('@tomic/react')>()),
  buildClassContext: vi.fn().mockResolvedValue({}),
  describeClassCompact: vi.fn(),
  toCompact: vi.fn().mockResolvedValue({ name: 'Bread', price: 3 }),
}));
vi.mock('./resourceContextProviders', () => ({
  getClassContextForAgent: vi.fn().mockResolvedValue(''),
}));

describe('attached Atomic context', () => {
  it('keeps usable context when another attachment fails to load', async () => {
    const getResource = vi
      .fn()
      .mockRejectedValueOnce(new Error('Resource not found'))
      .mockResolvedValueOnce({ title: 'Bread', getClasses: () => [] });
    const result = await processAtomicResources(
      [
        {
          id: 'missing',
          type: 'atomic-resource',
          subject: 'http://localhost:9896/app',
        },
        { id: 'bread', type: 'atomic-resource', subject: 'did:ad:bread' },
      ],
      { getResource } as unknown as Store,
    );
    expect(result.resourcesContent).toContain(
      'Could not read attached resource http://localhost:9896/app',
    );
    expect(result.resourcesContent).toContain('Resource not found');
    expect(result.resourcesContent).toContain('"price":3');
    expect(getResource).toHaveBeenCalledTimes(2);
  });
});
