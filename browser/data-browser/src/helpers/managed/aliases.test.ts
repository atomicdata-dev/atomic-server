import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  checkAliasAvailability,
  listAliases,
  releaseAlias,
  renameAlias,
  reserveAlias,
} from './aliases';

afterEach(() => vi.restoreAllMocks());

function respond(response: Response) {
  return vi.spyOn(globalThis, 'fetch').mockResolvedValue(response);
}

describe('aliases', () => {
  it('lists the aliases the portal returns', async () => {
    respond(
      new Response(
        JSON.stringify([
          { label: 'ontola', host: 'ontola.atomic.place', drive_subject: 'd' },
        ]),
      ),
    );

    await expect(listAliases()).resolves.toHaveLength(1);
  });

  it('answers an HTML page with a plain sentence, not a parse error', async () => {
    respond(new Response('<!doctype html>', { status: 200 }));

    await expect(listAliases()).rejects.toThrow(
      'Web addresses are not available on your account yet.',
    );
  });

  it('answers a 404 with the same sentence', async () => {
    respond(new Response('nope', { status: 404 }));

    await expect(listAliases()).rejects.toThrow(
      'Web addresses are not available on your account yet.',
    );
  });

  it('asks the portal whether a name is free', async () => {
    const spy = respond(
      new Response(
        JSON.stringify({ label: 'a', host: 'a.atomic.place', available: true }),
      ),
    );

    await expect(checkAliasAvailability('a')).resolves.toMatchObject({
      available: true,
    });
    expect(String(spy.mock.calls[0][0])).toContain(
      '/alias-availability?label=a',
    );
  });

  it('reserves, renames and releases with the portal’s verbs', async () => {
    const spy = respond(
      new Response(JSON.stringify({ label: 'b', host: 'b.atomic.place' })),
    );

    await reserveAlias('b', 'did:ad:drive');
    expect(spy.mock.calls[0][1]?.method).toBe('POST');
    expect(JSON.parse(String(spy.mock.calls[0][1]?.body))).toEqual({
      label: 'b',
      drive_subject: 'did:ad:drive',
    });

    await renameAlias('b', 'c');
    expect(String(spy.mock.calls[1][0])).toContain('/aliases/b');
    expect(spy.mock.calls[1][1]?.method).toBe('PUT');

    spy.mockResolvedValue(new Response(null, { status: 204 }));
    await releaseAlias('c');
    expect(spy.mock.calls[2][1]?.method).toBe('DELETE');
  });

  it('surfaces the portal’s own message when a name is taken', async () => {
    respond(
      new Response(JSON.stringify({ error: 'That name is taken.' }), {
        status: 409,
      }),
    );

    await expect(reserveAlias('b', 'd')).rejects.toThrow('That name is taken.');
  });
});
