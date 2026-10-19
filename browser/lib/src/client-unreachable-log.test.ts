import { afterEach, describe, it, vi } from 'vitest';
import { Client, resetUnreachableWarnings } from './client.js';

describe('Client.fetchResourceHTTP unreachable server', () => {
  afterEach(() => {
    resetUnreachableWarnings();
    vi.restoreAllMocks();
  });

  it('warns once per origin and never logs an error with a stack', async ({
    expect,
  }) => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const client = new Client(async () => {
      throw new TypeError('NetworkError when attempting to fetch resource.');
    });

    const results = await Promise.all(
      ['a', 'b', 'c'].map(id =>
        client.fetchResourceHTTP(`https://down.example/drive/${id}`),
      ),
    );

    // Each resource still carries the failure for the UI.
    results.forEach(r => expect(r.resource.error).toBeDefined());
    expect(error).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0][0]).toContain('https://down.example');
  });

  it('warns per origin', async ({ expect }) => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const client = new Client(async () => {
      throw new TypeError('fail');
    });

    await client.fetchResourceHTTP('https://one.example/x');
    await client.fetchResourceHTTP('https://two.example/x');

    expect(warn).toHaveBeenCalledTimes(2);
  });

  it('keeps logging other failures loudly', async ({ expect }) => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const client = new Client(
      async () => new Response('boom', { status: 404 }),
    );

    await client.fetchResourceHTTP('https://up.example/missing');

    expect(error).toHaveBeenCalledTimes(1);
  });

  it('treats a proxy 502 naming an unreachable upstream as one warning', async ({
    expect,
  }) => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const client = new Client(
      async () =>
        new Response(
          'Error handling path Endpoint: Upstream unreachable: Error when fetching https://down.example/x',
          { status: 502 },
        ),
    );

    await client.fetchResourceHTTP('https://down.example/a');
    await client.fetchResourceHTTP('https://down.example/b');

    expect(error).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it('keeps logging other handler errors loudly', async ({ expect }) => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const client = new Client(
      async () =>
        new Response('Error handling path Endpoint: bug', { status: 500 }),
    );

    await client.fetchResourceHTTP('https://up.example/a');

    expect(error).toHaveBeenCalledTimes(1);
  });
});
