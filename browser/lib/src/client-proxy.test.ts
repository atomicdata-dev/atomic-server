import { expect, it, vi } from 'vitest';
import { Client } from './client.js';
it('preserves the original subject when the host returns its exact proxy URL', async () => {
  const subject = 'https://atomicdata.dev/task/v1/status';
  const client = new Client(
    vi.fn(
      async (url: string | URL | Request) =>
        new Response(
          JSON.stringify({
            '@id': String(url),
            'https://atomicdata.dev/properties/name': 'Status',
          }),
          { status: 200 },
        ),
    ) as typeof fetch,
  );
  const { resource } = await client.fetchResourceHTTP(subject, {
    from: 'http://localhost:9898',
  });
  expect(resource.error).toBeUndefined();
  expect(resource.subject).toBe(subject);
});
it('does not accept an unrelated identity returned through the proxy', async () => {
  const client = new Client(
    vi.fn(
      async () =>
        new Response(JSON.stringify({ '@id': 'https://other.example/wrong' }), {
          status: 200,
        }),
    ) as typeof fetch,
  );
  const { resource } = await client.fetchResourceHTTP(
    'https://atomicdata.dev/task/v1/status',
    { from: 'http://localhost:9898' },
  );
  expect(resource.error).toBeDefined();
});
