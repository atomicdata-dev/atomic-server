import { describe, it, vi } from 'vitest';
import { Client } from './client.js';
import { core } from './ontologies/core.js';

const DID = 'did:ad:ontology123';
const JSON_AD = {
  '@id': DID,
  [core.properties.name]: 'My ontology',
};

const jsonResponse = () =>
  new Response(JSON.stringify(JSON_AD), {
    status: 200,
    headers: { 'Content-Type': 'application/ad+json' },
  });

describe('Client.fetchResourceHTTP DID subjects', () => {
  it('resolves a DID via /did?subject= when given a serverURL', async ({
    expect,
  }) => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      expect(String(input)).toBe(
        `https://example.com/did?subject=${encodeURIComponent(DID)}`,
      );

      return jsonResponse();
    });
    const client = new Client(fetchMock);
    const { resource } = await client.fetchResourceHTTP(DID, {
      serverURL: 'https://example.com',
    });

    expect(resource.error).toBeUndefined();
    expect(resource.subject).toBe(DID);
    expect(resource.get(core.properties.name)).toBe('My ontology');
  });

  it('rewrites https://host/did:ad:… to the /did endpoint and accepts the DID @id', async ({
    expect,
  }) => {
    const httpAlias = `https://example.com/${DID}`;
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      expect(String(input)).toBe(
        `https://example.com/did?subject=${encodeURIComponent(DID)}`,
      );

      return jsonResponse();
    });
    const client = new Client(fetchMock);
    const { resource } = await client.fetchResourceHTTP(httpAlias);

    expect(resource.error).toBeUndefined();
    expect(resource.subject).toBe(DID);
    expect(resource.get(core.properties.name)).toBe('My ontology');
  });

  it('does not touch window when resolving a DID without a server URL in Node', async ({
    expect,
  }) => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const fetchMock = vi.fn();
    const client = new Client(fetchMock);
    const { resource } = await client.fetchResourceHTTP(DID);

    expect(fetchMock).not.toHaveBeenCalled();
    expect(resource.error).toBeDefined();
    expect(resource.error?.message).toMatch(/no server URL/);
    errorSpy.mockRestore();
  });

  it('does not rewrite ordinary HTTP resource URLs', async ({ expect }) => {
    const httpSubject = 'https://atomicdata.dev/ontology/core';
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      expect(String(input)).toBe(httpSubject);

      return new Response(
        JSON.stringify({
          '@id': httpSubject,
          [core.properties.name]: 'core',
        }),
        { status: 200 },
      );
    });
    const client = new Client(fetchMock);
    const { resource } = await client.fetchResourceHTTP(httpSubject);

    expect(resource.error).toBeUndefined();
    expect(resource.subject).toBe(httpSubject);
  });
});
