import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getManagedEnrollments } from './enrollmentApi';
import { managedFetch } from './api';
import { getManagedAccount } from './session';
vi.mock('./api', () => ({ managedFetch: vi.fn() }));
vi.mock('./session', () => ({ getManagedAccount: vi.fn() }));
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(getManagedAccount).mockResolvedValue({
    email: 'test@example.com',
  } as Awaited<ReturnType<typeof getManagedAccount>>);
});
describe('hosting lookup uncertainty', () => {
  it('does not treat failed requests as no hosting', async () => {
    vi.mocked(managedFetch).mockResolvedValue(
      new Response('', { status: 503 }),
    );
    await expect(getManagedEnrollments(true)).rejects.toThrow(
      'Could not check',
    );
  });
  it('does not treat signed-out sessions as no hosting', async () => {
    vi.mocked(getManagedAccount).mockResolvedValue(null);
    await expect(getManagedEnrollments(true)).rejects.toThrow('Sign in');
  });
  it('accepts a successful empty list', async () => {
    vi.mocked(managedFetch).mockResolvedValue(Response.json([]));
    await expect(getManagedEnrollments(true)).resolves.toEqual([]);
  });
  it('rejects an unexpected response shape', async () => {
    vi.mocked(managedFetch).mockResolvedValue(Response.json({}));
    await expect(getManagedEnrollments(true)).rejects.toThrow('Invalid');
  });
});
